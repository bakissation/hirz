#!/usr/bin/env python3
"""Submits the release's unsigned XPI to addons.mozilla.org as a listed version.

Standard library only, so the job that holds the AMO API credentials runs no dependency tree
(docs/release.md, "Firefox add-on"). The flow is the documented AMO v5 API:

  1. POST /api/v5/addons/upload/            the XPI, channel listed
  2. GET  /api/v5/addons/upload/UUID/       until the validator has processed it
  3. PUT  /api/v5/addons/addon/GUID/        creates the add-on or a new version

  AMO_JWT_ISSUER=... AMO_JWT_SECRET=... scripts/amo-submit.py --xpi dist/hirz-0.1.0.xpi \\
      --metadata packaging/amo/metadata.json
  scripts/amo-submit.py --self-test

The job does not wait for Mozilla's review. Credentials come from the environment only.
"""

import argparse
import base64
import hashlib
import hmac
import http.server
import json
import os
import secrets
import sys
import threading
import time
import urllib.error
import urllib.parse
import urllib.request
import zipfile

API = "https://addons.mozilla.org"
REQUEST_TIMEOUT = 60
POLL_TIMEOUT = 15 * 60
MAX_XPI_BYTES = 32 * 1024 * 1024
LOOPBACK = ("127.0.0.1", "localhost", "::1")


def b64url(data):
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def make_jwt(issuer, secret, now=None, jti=None):
    """HS256 JWT as AMO wants it: iss, jti, iat and an exp at most five minutes later."""
    iat = int(time.time() if now is None else now)
    header = {"alg": "HS256", "typ": "JWT"}
    claims = {"iss": issuer, "jti": jti or secrets.token_hex(16), "iat": iat, "exp": iat + 60}
    signing_input = ".".join(
        b64url(json.dumps(part, separators=(",", ":")).encode()) for part in (header, claims)
    )
    mac = hmac.new(secret.encode(), signing_input.encode("ascii"), hashlib.sha256).digest()
    return signing_input + "." + b64url(mac)


def multipart(fields, file_field, file_name, file_bytes, content_type):
    boundary = "hirz" + secrets.token_hex(16)
    lines = []
    for name, value in fields.items():
        lines.append(
            (
                f"--{boundary}\r\nContent-Disposition: form-data; "
                f'name="{name}"\r\n\r\n{value}\r\n'
            ).encode()
        )
    lines.append(
        (
            f"--{boundary}\r\nContent-Disposition: form-data; "
            f'name="{file_field}"; filename="{file_name}"\r\n'
            f"Content-Type: {content_type}\r\n\r\n"
        ).encode()
    )
    lines.append(file_bytes)
    lines.append(f"\r\n--{boundary}--\r\n".encode())
    return b"".join(lines), f"multipart/form-data; boundary={boundary}"


class Amo:
    def __init__(self, issuer, secret, base=API):
        parsed = urllib.parse.urlsplit(base)
        loopback = parsed.scheme == "http" and parsed.hostname in LOOPBACK
        if base.rstrip("/") != API and not loopback:
            raise SystemExit(f"amo-submit: the API base must be {API} (or loopback for tests)")
        self.base = base.rstrip("/")
        self.issuer = issuer
        self.secret = secret

    def call(self, method, path, body=None, content_type=None, retries=0):
        url = self.base + path
        attempt = 0
        while True:
            headers = {
                "Authorization": "JWT " + make_jwt(self.issuer, self.secret),
                "Accept": "application/json",
                "User-Agent": "hirz-release",
            }
            if content_type:
                headers["Content-Type"] = content_type
            request = urllib.request.Request(url, data=body, method=method, headers=headers)
            try:
                with urllib.request.urlopen(request, timeout=REQUEST_TIMEOUT) as response:
                    return response.status, json.loads(response.read() or b"null")
            except urllib.error.HTTPError as err:
                detail = err.read(4096).decode("utf-8", "replace")
                if err.code >= 500 and attempt < retries:
                    attempt += 1
                    time.sleep(2 * attempt)
                    continue
                raise SystemExit(f"amo-submit: {method} {path} answered {err.code}: {detail}")
            except (urllib.error.URLError, TimeoutError, json.JSONDecodeError) as err:
                if attempt < retries:
                    attempt += 1
                    time.sleep(2 * attempt)
                    continue
                raise SystemExit(f"amo-submit: {method} {path} failed: {err}")


def read_manifest(xpi_path):
    try:
        with zipfile.ZipFile(xpi_path) as xpi:
            manifest = json.loads(xpi.read("manifest.json"))
    except (OSError, KeyError, zipfile.BadZipFile, json.JSONDecodeError) as err:
        raise SystemExit(f"amo-submit: {xpi_path} is not an extension archive: {err}")
    gecko = manifest.get("browser_specific_settings", {}).get("gecko", {})
    guid = gecko.get("id")
    version = manifest.get("version")
    if not isinstance(guid, str) or not isinstance(version, str) or not guid or not version:
        raise SystemExit("amo-submit: manifest.json needs a gecko id and a version")
    if not all(c.isalnum() or c in "@._-" for c in guid):
        raise SystemExit("amo-submit: the gecko id has unexpected characters")
    return guid, version


def submit(api, xpi_path, metadata_path, expect_version=None, poll_interval=5):
    size = os.path.getsize(xpi_path)
    if size == 0 or size > MAX_XPI_BYTES:
        raise SystemExit(f"amo-submit: {xpi_path} has an unexpected size: {size}")
    with open(xpi_path, "rb") as f:
        xpi = f.read()
    guid, version = read_manifest(xpi_path)
    if expect_version and version != expect_version:
        raise SystemExit(f"amo-submit: the XPI is version {version}, expected {expect_version}")
    with open(metadata_path, "rb") as f:
        metadata = json.loads(f.read())
    if not isinstance(metadata, dict) or not isinstance(metadata.get("version"), dict):
        raise SystemExit("amo-submit: the metadata file needs a version object")

    body, content_type = multipart(
        {"channel": "listed"}, "upload", os.path.basename(xpi_path), xpi, "application/x-xpinstall"
    )
    _, upload = api.call("POST", "/api/v5/addons/upload/", body, content_type)
    uuid = upload.get("uuid")
    if not isinstance(uuid, str) or not uuid.replace("-", "").isalnum():
        raise SystemExit("amo-submit: the upload answer has no uuid")
    print(f"uploaded {os.path.basename(xpi_path)} for {guid} {version}: {uuid}")

    deadline = time.monotonic() + POLL_TIMEOUT
    path = f"/api/v5/addons/upload/{uuid}/"
    while not upload.get("processed"):
        if time.monotonic() > deadline:
            raise SystemExit("amo-submit: the upload was not processed in time")
        time.sleep(poll_interval)
        _, upload = api.call("GET", path, retries=3)
    if not upload.get("valid"):
        validation = json.dumps(upload.get("validation"), indent=2)[:4000]
        raise SystemExit(f"amo-submit: validation failed:\n{validation}")
    print("validation passed")

    metadata["version"]["upload"] = uuid
    guid_path = "/api/v5/addons/addon/" + urllib.parse.quote(guid, safe="@") + "/"
    _, result = api.call("PUT", guid_path, json.dumps(metadata).encode(), "application/json")
    current = (result.get("current_version") or {}) if isinstance(result, dict) else {}
    print(f"submitted {guid}: version {current.get('version', version)} is waiting for review")


class FakeAmo(http.server.BaseHTTPRequestHandler):
    seen = []
    polls = 0
    valid = True

    def log_message(self, *args):
        pass

    def reply(self, status, payload):
        data = json.dumps(payload).encode()
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    def body(self):
        return self.rfile.read(int(self.headers.get("Content-Length", "0")))

    def authorized(self):
        auth = self.headers.get("Authorization", "")
        return auth.startswith("JWT ") and auth.count(".") == 2

    def do_POST(self):
        data = self.body()
        FakeAmo.seen.append(("POST", self.path, self.headers.get("Content-Type"), data))
        if not self.authorized():
            return self.reply(401, {"detail": "no JWT"})
        if self.path == "/api/v5/addons/upload/":
            return self.reply(201, {"uuid": "11111111-2222-3333-4444-555555555555", "processed": False})
        self.reply(404, {})

    def do_GET(self):
        FakeAmo.seen.append(("GET", self.path, None, b""))
        if not self.authorized():
            return self.reply(401, {"detail": "no JWT"})
        FakeAmo.polls += 1
        done = FakeAmo.polls >= 2
        self.reply(
            200,
            {"uuid": "11111111-2222-3333-4444-555555555555", "processed": done, "valid": FakeAmo.valid,
             "validation": {"errors": 0 if FakeAmo.valid else 1}},
        )

    def do_PUT(self):
        data = self.body()
        FakeAmo.seen.append(("PUT", self.path, self.headers.get("Content-Type"), data))
        if not self.authorized():
            return self.reply(401, {"detail": "no JWT"})
        self.reply(200, {"current_version": {"version": "0.1.0"}})


def self_test():
    # RFC 7515 appendix A.1: the HS256 example.
    key = base64.urlsafe_b64decode(
        "AyM1SysPpbyDfgZld3umj1qzKObwVMkoqQ-EstJQLr_T-1qS0gZH75aKtMN3Yj0iPS4hcgUuTwjAzZr1Z9CAow=="
    )
    signing_input = (
        "eyJ0eXAiOiJKV1QiLA0KICJhbGciOiJIUzI1NiJ9."
        "eyJpc3MiOiJqb2UiLA0KICJleHAiOjEzMDA4MTkzODAsDQogImh0dHA6Ly9leGFtcGxlLmNvbS9pc19yb290Ijp0cnVlfQ"
    )
    mac = hmac.new(key, signing_input.encode("ascii"), hashlib.sha256).digest()
    assert b64url(mac) == "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk", "HS256 known answer"

    token = make_jwt("user:1:2", "secret", now=1_700_000_000, jti="abc")
    head, claims, sig = token.split(".")
    assert json.loads(base64.urlsafe_b64decode(head + "==")) == {"alg": "HS256", "typ": "JWT"}
    assert json.loads(base64.urlsafe_b64decode(claims + "==")) == {
        "iss": "user:1:2", "jti": "abc", "iat": 1_700_000_000, "exp": 1_700_000_060,
    }
    expect = hmac.new(b"secret", f"{head}.{claims}".encode(), hashlib.sha256).digest()
    assert sig == b64url(expect)

    body, ctype = multipart({"channel": "listed"}, "upload", "x.xpi", b"\x00PK", "application/x-xpinstall")
    boundary = ctype.split("boundary=")[1].encode()
    assert body.count(b"--" + boundary) == 3 and b'name="channel"\r\n\r\nlisted' in body
    assert b'filename="x.xpi"' in body and b"\x00PK" in body

    for base in (
        "http://addons.mozilla.org",
        "https://example.com",
        "ftp://example.com",
        "http://example.com:8000",
    ):
        try:
            Amo("i", "s", base)
        except SystemExit:
            continue
        raise AssertionError(f"{base} must be refused")

    import tempfile

    with tempfile.TemporaryDirectory() as tmp:
        xpi = os.path.join(tmp, "hirz-0.1.0.xpi")
        with zipfile.ZipFile(xpi, "w") as z:
            z.writestr(
                "manifest.json",
                json.dumps({"version": "0.1.0", "browser_specific_settings": {"gecko": {"id": "hirz@example.com"}}}),
            )
        meta = os.path.join(tmp, "metadata.json")
        with open(meta, "w") as f:
            json.dump({"categories": {"firefox": ["privacy-security"]}, "version": {"license": "MIT"}}, f)

        server = http.server.ThreadingHTTPServer(("127.0.0.1", 0), FakeAmo)
        threading.Thread(target=server.serve_forever, daemon=True).start()
        try:
            api = Amo("user:1:2", "secret", f"http://127.0.0.1:{server.server_address[1]}")
            submit(api, xpi, meta, expect_version="0.1.0", poll_interval=0.01)
            calls = [(m, p) for m, p, _, _ in FakeAmo.seen]
            assert calls[0] == ("POST", "/api/v5/addons/upload/"), calls
            assert calls[-1] == ("PUT", "/api/v5/addons/addon/hirz@example.com/"), calls
            assert sum(1 for m, _ in calls if m == "GET") == 2, calls
            put = json.loads(FakeAmo.seen[-1][3])
            assert put["version"] == {"license": "MIT", "upload": "11111111-2222-3333-4444-555555555555"}
            assert put["categories"] == {"firefox": ["privacy-security"]}
            assert b'name="upload"; filename="hirz-0.1.0.xpi"' in FakeAmo.seen[0][3]

            FakeAmo.seen.clear()
            FakeAmo.polls = 0
            FakeAmo.valid = False
            try:
                submit(api, xpi, meta, poll_interval=0.01)
            except SystemExit as err:
                assert "validation failed" in str(err), err
            else:
                raise AssertionError("an invalid upload must stop the submission")
            assert all(m != "PUT" for m, _, _, _ in FakeAmo.seen)

            for wrong in ("9.9.9", "0.1", "0.1.", "0"):
                before = len(FakeAmo.seen)
                try:
                    submit(api, xpi, meta, expect_version=wrong, poll_interval=0.01)
                except SystemExit as err:
                    assert f"expected {wrong}" in str(err), err
                else:
                    raise AssertionError(f"version {wrong!r} must not match 0.1.0 (a prefix is not a match)")
                assert len(FakeAmo.seen) == before, "a version mismatch must stop before any request"
        finally:
            server.shutdown()
    print("amo-submit self-test passed")


def main():
    parser = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    parser.add_argument("--xpi", help="the unsigned extension archive of the release")
    parser.add_argument("--metadata", help="packaging/amo/metadata.json")
    parser.add_argument("--version", help="release version the XPI must carry, exactly")
    parser.add_argument("--base-url", default=API, help=argparse.SUPPRESS)
    parser.add_argument("--self-test", action="store_true")
    args = parser.parse_args()
    if args.self_test:
        self_test()
        return
    if not args.xpi or not args.metadata:
        parser.error("--xpi and --metadata are required")
    issuer = os.environ.get("AMO_JWT_ISSUER", "")
    secret = os.environ.get("AMO_JWT_SECRET", "")
    if not issuer or not secret:
        raise SystemExit("amo-submit: AMO_JWT_ISSUER and AMO_JWT_SECRET must be set")
    submit(Amo(issuer, secret, args.base_url), args.xpi, args.metadata, args.version)


if __name__ == "__main__":
    sys.exit(main())
