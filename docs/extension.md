# Firefox extension and native messaging host

The extension path lets Firefox pages use hirz passkeys directly. The extension
replaces `navigator.credentials.create()` and `get()` for public key requests,
hands them to the native messaging host `hirz-nmh`, and hands everything it does
not handle back to Firefox's own WebAuthn implementation unchanged.

The extension is deliberately thin. It holds no keys, builds no signed bytes and
makes no decision with security meaning except reading the request origin from
Firefox. The host re-validates every field.

Status: v0.1 transport spike. The host speaks the protocol below and answers
`create` and `get` with `NotHandled`, so every ceremony falls back to Firefox.
The authenticator engine is connected in a later step.

## Files

| File | World | Role |
|---|---|---|
| `extension/manifest.json` | | MV3 manifest, Firefox only |
| `extension/page/shim.js` | page (`MAIN`), `document_start`, top frame | Hooks `CredentialsContainer.prototype.create/get` and two `PublicKeyCredential` statics, snapshots options, builds result objects |
| `extension/content/relay.js` | content script (`ISOLATED`), `document_start`, top frame | Pipe between the shim and the background |
| `extension/background.js` | background event page (ES module) | Origin, tab and frame checks, one ceremony per tab, timeouts, the native port |
| `crates/hirz-nmh` | native process | Framing, envelope parsing, replies |
| `packaging/native-messaging/hirz.json` | | Native manifest template |

There is no build step: no npm packages, no bundler, no minification, no
remote code, no `eval`, no WebAssembly. The XPI is the `extension/` folder as
written.

## Manifest decisions

- `browser_specific_settings.gecko.id` is `hirz@hirz.dev`. This is a
  placeholder until the project owns a domain for the id; the native manifest's
  `allowed_extensions` must carry the same value.
- `strict_min_version` is `140.0`: `world: "MAIN"` content scripts (128),
  `Uint8Array.prototype.toBase64` / `Uint8Array.fromBase64` (133),
  `data_collection_permissions` (140).
- `data_collection_permissions.required` is `["none"]`. Request data goes only
  to a native program on the same machine, which is part of the same product,
  and nothing is sent to any server by the extension or the host.
- Permissions: `nativeMessaging` only. Host permissions `https://*/*` and
  `http://localhost/*` (any port) cover the content scripts. `tabs.get` and
  `windows.get` are used only for the `active` and `focused` flags, which need
  no permission.
- No UI in the page DOM, no popup, no options page. In v0.1 approval prompts
  are drawn by the native host (`hirz-uv`), outside the browser.

## Request flow

1. The page calls `navigator.credentials.create({publicKey})` or
   `get({publicKey})`.
2. `page/shim.js` decides whether hirz handles the call (see below). If not,
   it calls the original Firefox function with the original arguments.
3. Otherwise it reads the options field by field, once each, in WebIDL
   dictionary order, copies every BufferSource at once and encodes it as
   base64url, and writes WebAuthn L3 JSON
   (`PublicKeyCredentialCreationOptionsJSON` or
   `PublicKeyCredentialRequestOptionsJSON`). It never runs `JSON.stringify` on
   page objects, so page `toJSON` methods and getters cannot make what is shown
   differ from what is signed. The JSON is assembled from primitives with
   intrinsics captured before any page script ran.
4. `content/relay.js` checks size and shape and forwards the request over a
   `runtime.connect` port (one per page, opened lazily).
5. `background.js` takes the origin from `port.sender.origin`, which Firefox
   computes in the parent process from the sender document's principal. It
   never reads an origin from the page or the relay. It requires
   `frameId === 0`, a real tab, an `https:` origin or `http://localhost`, the
   tab to be the active tab of the focused window, and no other ceremony in
   progress in the same tab. It then sends the request to the host with
   `origin`, `topOrigin` and `crossOrigin` added and a clamped timeout.
6. The host answers. The background keeps only the expected fields of a
   credential (anything else the host sends is dropped), maps unknown error
   codes to `UnknownError`, and replies to the relay, which hands the reply to
   the shim.
7. The shim builds the result objects, or rejects with the matching exception,
   or on `NotHandled` waits until the document has focus and calls Firefox's
   own `create`/`get` with the original arguments.

### What v0.1 passes through to Firefox

The shim calls Firefox's own implementation, untouched, when:

- the call is in a frame other than the top frame (the content scripts are
  also only injected in the top frame), or the document is not a secure
  context;
- `options.publicKey` is absent, or the request also asks for another
  credential type (`password`, `identity`, `otp`, `digital`);
- `mediation` is `"conditional"` or `"silent"`;
- the `AbortSignal` is already aborted (Firefox then rejects with its reason);
- `hints` contains `"security-key"` or `"hybrid"`;
- `pubKeyCredParams` has no `public-key` entry with ES256 (-7) or EdDSA (-8)
  (an empty list means the spec defaults, which include ES256);
- `authenticatorSelection.authenticatorAttachment` is `"cross-platform"`;
- `attestation` is `"enterprise"`. `"direct"` and `"indirect"` are handled:
  attestation conveyance is a preference, and hirz answers with the `none`
  format as platform passkey providers do;
- `rp.id` (create) or `rpId` (get) is neither the page host nor a parent
  domain of it. Such requests are either invalid or need Related Origin
  Requests, which Firefox implements. The host performs the authoritative
  public suffix check;
- any value fails conversion or a cap (for example more than 64 credential
  descriptors, a credential id over 1023 bytes, a challenge over 4096 bytes,
  a `user.id` outside 1 to 64 bytes, strings over 1024 characters, options
  JSON over 64 KiB). Firefox then produces the spec-defined error itself;
- the relay is not linked, the extension context is gone, the host is not
  installed or does not answer `hello`, or the host answers `NotHandled`.

The background answers `NotHandled` (so Firefox decides) when the sender is not
a top frame of a tab, the origin is not `https:` or `http://localhost`, the
host is an IP literal, or the tab is not the active tab of the focused window.

### Statics

- `PublicKeyCredential.isUserVerifyingPlatformAuthenticatorAvailable()`
  resolves `true` when the host reports
  `userVerifyingPlatformAuthenticator: true`, otherwise it returns Firefox's
  answer.
- `PublicKeyCredential.getClientCapabilities()` returns Firefox's record with
  `userVerifyingPlatformAuthenticator` and `passkeyPlatformAuthenticator` set
  to `true` when the host reports them.
- The host's capabilities are fetched at most once per page (3 s budget) and
  cached by the background for 60 s.
- `isConditionalMediationAvailable`, `parseCreationOptionsFromJSON`,
  `parseRequestOptionsFromJSON` and the signal methods are left to Firefox.

### Result objects

Firefox gives `PublicKeyCredential` and the response interfaces no usable
constructor, so the shim creates plain objects with the native prototypes
(`instanceof PublicKeyCredential` and `Object.prototype.toString` give the
native answers) and shadows every attribute and method with an own property,
because the prototype accessors throw on objects without native internal
slots:

- credential: `id`, `rawId`, `type`, `authenticatorAttachment`, `response`,
  `getClientExtensionResults()`, `toJSON()`;
- attestation response: `clientDataJSON`, `attestationObject`,
  `getTransports()`, `getAuthenticatorData()`, `getPublicKey()` (SPKI DER as
  sent by the host), `getPublicKeyAlgorithm()`;
- assertion response: `clientDataJSON`, `authenticatorData`, `signature`,
  `userHandle`.

All buffers are `ArrayBuffer`s of the page realm. `toJSON()` returns a fresh
deep copy of the `RegistrationResponseJSON` / `AuthenticationResponseJSON` the
host sent. `getClientExtensionResults()` converts base64url members (PRF
results, large blob) back to `ArrayBuffer`s.

### Errors, abort and timeouts

Host error codes become exceptions in the page: `NotAllowedError`,
`InvalidStateError`, `NotSupportedError`, `AbortError`, `SecurityError`,
`ConstraintError` and `UnknownError` become `DOMException`s with that name,
`TypeError` becomes a `TypeError`, and anything else becomes
`NotAllowedError`.

`options.signal` is honoured: on abort the shim rejects with `signal.reason`
and sends `cancel`; the background forwards `cancel` to the host. Navigating
away or closing the tab disconnects the page port, which also cancels any host
request of that page.

The background clamps `publicKey.timeout` to 30 s ... 600 s (default 300 s);
when it expires it sends `cancel` to the host and the page gets
`NotAllowedError`. The shim keeps a last-resort guard of timeout plus 60 s.

### The page channel

The shim and the relay share the DOM but not JavaScript objects. Both run at
`document_start`, which Firefox runs before any page script. Whichever loads
second completes a short handshake over a `hirz-bootstrap` event; the shim then
passes a random 128-bit value that names two private event types
(`hirz-req-<secret>`, `hirz-res-<secret>`). Request and response payloads are
JSON strings in `CustomEvent.detail`. Page scripts cannot listen for events
whose names they do not know, so they cannot read responses or inject fake
ones.

This channel is not a security boundary. Mozilla treats the `MAIN` world as
untrusted, and a script on the page can always call the API itself or replace
it. Nothing on the channel carries identity: the origin comes only from
`sender.origin`, approvals come only from the host's own prompt, and the host
re-validates every value. If the content scripts are injected after page
scripts ran (for example into tabs that were open when the extension was
installed), the page could intercept the handshake; the result is the same as
a page faking its own WebAuthn results, which it can always do.

## Native messaging protocol (version 1)

### Transport

- stdio, started by Firefox through `runtime.connectNative("hirz")`. The
  background keeps one port open while requests are pending and closes it
  after 30 s idle. A port that fails `hello` is retried after 10 s at the
  earliest.
- Framing: a 32-bit unsigned length in native byte order, followed by that
  many bytes of UTF-8 JSON. Zero-length frames are invalid.
- Size limits: host to browser at most 1 MiB (Firefox's limit). Browser to
  host at most 256 KiB, enforced by the host before it allocates; Firefox would
  allow 4 GiB. The extension keeps options JSON under 64 KiB.
- A frame over the limit, a truncated frame or an I/O error ends the process
  with exit status 1 and one line on stderr; the stream cannot be resynced.
  EOF on stdin between frames is a clean exit with status 0. Firefox closes
  stdin first when it disconnects.
- Firefox passes two arguments: the path of the native manifest and the
  extension id. They are not an authentication mechanism (any local process
  can start the host), and the host does not rely on them.
- stdout carries only frames. Diagnostics go to stderr. `HIRZ_LOG=debug`
  logs one line per message with its type, id and size, never its contents.

### Requests (extension to host)

Every request is a JSON object with these members:

| Member | Type | Meaning |
|---|---|---|
| `v` | integer | Protocol version, `1` |
| `id` | integer, 0 ... 2^53-1 | Chosen by the extension, unique per connection; echoed in the reply |
| `type` | string | `hello`, `capabilities`, `create`, `get` or `cancel` |
| `origin` | string | `create` and `get` only. Serialized origin of the calling document, from `sender.origin` |
| `topOrigin` | string | `create` and `get` only. Origin of the top-level document. In v0.1 always equal to `origin` |
| `crossOrigin` | boolean | `create` and `get` only. Whether the caller is not same-origin with all its ancestors. Always `false` in v0.1 |
| `options` | object | `create`: `PublicKeyCredentialCreationOptionsJSON`; `get`: `PublicKeyCredentialRequestOptionsJSON` (WebAuthn Level 3), as snapshotted by the shim |

The host parses `v`, `id` and `type` strictly: they must be top-level members
spelled without escapes, appear once, `v` and `id` must be plain non-negative
integers without sign, fraction or exponent, and the whole message must be
valid JSON with at most 64 levels of nesting. Unknown members are ignored.

`options` as sent by v0.1 of the shim: defaults are filled in
(`attestation: "none"`, `attestationFormats: []`, `hints: []`,
`excludeCredentials: []` / `allowCredentials: []`, `extensions: {}`,
`authenticatorSelection.requireResidentKey: false`,
`userVerification: "preferred"`); an empty `pubKeyCredParams` is replaced with
ES256 and RS256 as the spec says; `alg` values are integers; `timeout` is
present only when the page gave one, already capped at 600000; all byte values
are unpadded base64url. Recognised extension inputs: `appid`, `appidExclude`,
`credProps`, `credentialProtectionPolicy`, `enforceCredentialProtectionPolicy`,
`largeBlob` and `prf` (`eval`, and `evalByCredential` for `get`). Other
extensions are dropped. The host must still treat every field as untrusted.

Example:

```json
{"v":1,"id":3,"type":"create","origin":"https://example.com","topOrigin":"https://example.com","crossOrigin":false,
 "options":{"attestation":"none","attestationFormats":[],
  "authenticatorSelection":{"requireResidentKey":false,"residentKey":"required","userVerification":"preferred"},
  "challenge":"fzBs4qVEMcn6T2p45Zf03dzj3eHGlykKGShTfl3aWXw","excludeCredentials":[],"extensions":{"credProps":true},
  "hints":[],"pubKeyCredParams":[{"alg":-7,"type":"public-key"},{"alg":-8,"type":"public-key"}],
  "rp":{"id":"example.com","name":"Example"},"timeout":60000,
  "user":{"displayName":"Alice","id":"YWxpY2U","name":"alice"}}}
```

### Replies (host to extension)

Success:

```json
{"v":1,"id":1,"ok":true,"version":"0.1.0-dev"}
{"v":1,"id":2,"ok":true,"capabilities":{"userVerifyingPlatformAuthenticator":true,"passkeyPlatformAuthenticator":true}}
{"v":1,"id":3,"ok":true,"credential":{ RegistrationResponseJSON }}
{"v":1,"id":4,"ok":true,"credential":{ AuthenticationResponseJSON }}
```

`credential` follows WebAuthn Level 3. For `create`: `id`, `rawId` (equal to
`id`), `type: "public-key"`, `authenticatorAttachment` (`"platform"`),
`response.clientDataJSON`, `response.attestationObject`,
`response.authenticatorData`, `response.transports` (array of strings),
`response.publicKeyAlgorithm` (integer), `response.publicKey` (SPKI DER,
optional), `clientExtensionResults`. For `get`: `id`, `rawId`, `type`,
`authenticatorAttachment`, `response.clientDataJSON`,
`response.authenticatorData`, `response.signature`, `response.userHandle`
(string or `null`), `clientExtensionResults`. Bytes are unpadded base64url.

Failure:

```json
{"v":1,"id":3,"ok":false,"error":"NotHandled"}
```

| `error` | Meaning | Page sees |
|---|---|---|
| `NotHandled` | hirz does not take this request; Firefox should | Firefox's own WebAuthn runs |
| `NotAllowedError` | User cancelled, timed out, or policy refused | `DOMException` `NotAllowedError` |
| `InvalidStateError` | A credential in `excludeCredentials` exists here | `DOMException` `InvalidStateError` |
| `NotSupportedError` | No supported algorithm or a required feature is missing | `DOMException` `NotSupportedError` |
| `SecurityError` | Origin or RP ID validation failed | `DOMException` `SecurityError` |
| `AbortError` | The request was cancelled | `DOMException` `AbortError` |
| `ConstraintError` | A required option cannot be met (for example UV) | `DOMException` `ConstraintError` |
| `UnknownError` | Internal failure | `DOMException` `UnknownError` |
| `TypeError` | Options are malformed | `TypeError` |
| `BadRequest` | The envelope could not be parsed; `id` is `null` if it could not be read | logged by the background |
| `UnsupportedVersion` | `v` is missing or not `1` | logged by the background |

`cancel` uses the `id` of the request it cancels and has no reply of its own.
If that request is still pending, the host answers it with `AbortError`;
otherwise the cancel is ignored. The extension stops waiting as soon as it
sends `cancel`.

The spike host answers `hello` with its version, `capabilities` with both
flags `true`, `create` and `get` with `NotHandled`, and ignores `cancel`.

## Native manifest and install locations

Template: `packaging/native-messaging/hirz.json`. Replace `@HIRZ_NMH_PATH@`
with the absolute path of the `hirz-nmh` binary. `name` must be `hirz`, equal
to the file name stem and to the name passed to `connectNative`;
`allowed_extensions` holds the extension id only.

| Scope | Path |
|---|---|
| Per user (development) | `~/.mozilla/native-messaging-hosts/hirz.json` |
| System (packages) | `/usr/lib/mozilla/native-messaging-hosts/hirz.json` or `/usr/lib64/mozilla/native-messaging-hosts/hirz.json` |

Packages should install the system manifest and the binary root-owned. A
per-user install is for development: anything running as the user can change
it.

Development install:

```sh
cargo build -p hirz-nmh
mkdir -p ~/.mozilla/native-messaging-hosts
sed "s#@HIRZ_NMH_PATH@#$PWD/target/debug/hirz-nmh#" packaging/native-messaging/hirz.json \
  > ~/.mozilla/native-messaging-hosts/hirz.json
```

## Snap Firefox (Ubuntu)

Verified on Ubuntu with the Firefox snap 159.0.1 and the Ubuntu build of
xdg-desktop-portal 1.21.1. The host was started from the per-user manifest
above, through the portal, and completed `hello`, `capabilities`, `create`
and `get` round trips.

How it works:

- Firefox inside the snap cannot see `~/.mozilla/native-messaging-hosts`
  (its `personal-files` plug only covers `~/.mozilla/firefox`) and cannot
  start programs outside its confinement. The snap build changes the defaults
  of `widget.use-xdg-desktop-portal.native-messaging` and
  `widget.use-xdg-desktop-portal.native-messaging-proxy` from `0` to `2`
  (auto, which means on inside a snap or Flatpak).
- With both set, Firefox first asks the `org.freedesktop.NativeMessagingProxy`
  service (xdg-native-messaging-proxy) and, when that is not installed, the
  `org.freedesktop.portal.WebExtensions` portal, which Ubuntu adds to
  xdg-desktop-portal as a distribution patch. In both cases the manifest is
  read by the service, not by Firefox, so manifests inside
  `~/snap/firefox/common/.mozilla` are not used.
- Both services run unconfined in the user session and search
  `~/.mozilla/native-messaging-hosts`, `$XDG_CONFIG_HOME/mozilla/native-messaging-hosts`
  (default `~/.config/...`), `/usr/lib/mozilla/native-messaging-hosts`,
  `/usr/lib64/mozilla/native-messaging-hosts` and the distribution libdir
  (for example `/usr/lib/x86_64-linux-gnu/mozilla/native-messaging-hosts`).
  They check `name` and `allowed_extensions`, then start the host outside the
  sandbox with the manifest path and the extension id as arguments, so the
  binary can live anywhere on the host.
- The WebExtensions portal asks the user once per host and app
  ("Allow Firefox to start WebExtension backend?") and stores the answer in
  the permission store, table `webextensions`, entry `hirz`. The proxy service
  does not ask.

What must be true for it to work:

1. A manifest named `hirz.json` in one of the host paths above, with
   `"name": "hirz"`, the extension id in `allowed_extensions` and an absolute,
   executable `path`.
2. The portal or the proxy service is available in the session
   (xdg-desktop-portal with the WebExtensions patch, as on Ubuntu, or the
   `xdg-native-messaging-proxy` package).
3. With the portal: the permission is granted. The access dialog is only
   allowed while Firefox is the focused application; otherwise the portal
   refuses and the extension sees the port disconnect with
   "An unexpected error occurred". The answer is keyed by the caller's
   permission id: `snap.firefox` for the normal Firefox app, and
   `snap.firefox_<app>` for other apps of the snap (for example
   `snap.firefox_geckodriver` for a WebDriver-launched Firefox).
   Inspect, pre-grant or revoke with:

   ```sh
   flatpak permissions webextensions
   flatpak permission-set webextensions hirz snap.firefox yes
   flatpak permission-remove webextensions hirz
   ```
4. The two `widget.use-xdg-desktop-portal.native-messaging*` preferences are
   not set to `0` by the user or by policy.

## Flatpak Firefox

Not tested. Firefox 157 and later can use xdg-native-messaging-proxy when the
preference `widget.use-xdg-desktop-portal.native-messaging-proxy` is `1` or
`2`, the proxy is installed on the host, and the Flatpak is allowed to talk to
`org.freedesktop.NativeMessagingProxy` (for example
`flatpak override --user --talk-name=org.freedesktop.NativeMessagingProxy org.mozilla.firefox`).
Treat it as experimental.

## Manual test (development)

1. Build and install the development manifest as shown above.
2. On a Snap Firefox, grant the permission (or accept the dialog on first use
   while Firefox is focused).
3. Open `about:debugging#/runtime/this-firefox`, choose "Load Temporary
   Add-on" and select `extension/manifest.json`. Click "Inspect" on the hirz
   entry to open the background console.
4. Open https://webauthn.io and register. Expected with the spike host: the
   background console logs `hirz: native host ready, version 0.1.0-dev`, and
   Firefox's own security key prompt appears, because the host answered
   `NotHandled`.
5. In the page's web console:
   `await PublicKeyCredential.isUserVerifyingPlatformAuthenticatorAvailable()`
   returns `true`, and `navigator.credentials.create.toString()` shows the hook
   rather than `[native code]`.
6. To see the host side, point the manifest at a small wrapper script that
   sets `HIRZ_LOG=debug` and redirects stderr to a file, then execs the
   binary. The log shows one line per message.

Without the host installed the extension is transparent: every ceremony goes
to Firefox, and the background console logs one warning about the missing
native application.

## Not in v0.1

- Frames other than the top frame, cross-origin iframes and Permissions
  Policy delegation.
- Conditional mediation (autofill UI) and conditional create.
- Related Origin Requests.
- Signal methods (`signalUnknownCredential` and the others).
- Detecting other extensions that hook the same functions.
- Process hardening of the host (`PR_SET_DUMPABLE`, `RLIMIT_CORE`,
  `NO_NEW_PRIVS`), which arrives with hirz-sys.
