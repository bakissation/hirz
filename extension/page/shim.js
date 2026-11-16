// MAIN world, document_start, every frame: runs with the page's privileges and is visible to it,
// so it decides nothing that matters for security. The background takes the origin and frame
// ancestry from Firefox and the native host re-validates every field.
"use strict";

(() => {
  const w = window;
  if (!w.isSecureContext) return;

  // Frames not same-origin with all their ancestors keep Firefox's API untouched (Permissions
  // Policy, user activation). Only a shortcut: the background decides again from the frame tree.
  try {
    const own = w.origin;
    let cur = w;
    for (let depth = 0; cur.parent !== cur; depth++) {
      cur = cur.parent;
      if (depth >= 32 || cur.origin !== own) return;
    }
  } catch {
    return;
  }

  const PKC = w.PublicKeyCredential;
  const CC = w.CredentialsContainer;
  const container = w.navigator.credentials;
  if (typeof PKC !== "function" || typeof CC !== "function" || !container) return;

  // Pristine references, captured before any page script can run.
  const O = Object;
  const apply = Reflect.apply;
  const create = O.create;
  const keys = O.keys;
  const defineProperty = O.defineProperty;
  const getOwnPropertyDescriptor = O.getOwnPropertyDescriptor;
  const getPrototypeOf = O.getPrototypeOf;
  const isArray = Array.isArray;
  const S = String;
  const N = Number;
  const isFiniteNumber = N.isFinite;
  const isSafeInteger = N.isSafeInteger;
  const trunc = Math.trunc;
  const toWellFormed = S.prototype.toWellFormed;
  const toLowerCase = S.prototype.toLowerCase;
  const endsWith = S.prototype.endsWith;
  const strSlice = S.prototype.slice;
  const numToString = N.prototype.toString;
  const JSONstringify = JSON.stringify;
  const JSONparse = JSON.parse;
  const P = Promise;
  const DOMExc = w.DOMException;
  const TypeErr = TypeError;
  const CE = w.CustomEvent;
  const U8 = Uint8Array;
  const AB = ArrayBuffer;
  const isView = AB.isView;
  const abSlice = AB.prototype.slice;
  const getter = (proto, name) => getOwnPropertyDescriptor(proto, name).get;
  const TA = getPrototypeOf(U8.prototype);
  const taBuffer = getter(TA, "buffer");
  const taByteOffset = getter(TA, "byteOffset");
  const taByteLength = getter(TA, "byteLength");
  const dvBuffer = getter(DataView.prototype, "buffer");
  const dvByteOffset = getter(DataView.prototype, "byteOffset");
  const dvByteLength = getter(DataView.prototype, "byteLength");
  const abByteLength = getter(AB.prototype, "byteLength");
  const toBase64 = U8.prototype.toBase64;
  const fromBase64 = U8.fromBase64;
  const detailOf = getter(CE.prototype, "detail");
  const signalAborted = getter(AbortSignal.prototype, "aborted");
  const signalReason = getter(AbortSignal.prototype, "reason");
  const AS = AbortSignal;
  const signalAny = AS.any;
  const AC = w.AbortController;
  const acSignal = getter(AC.prototype, "signal");
  const acAbort = AC.prototype.abort;
  const then = P.prototype.then;
  const addListener = EventTarget.prototype.addEventListener;
  const removeListener = EventTarget.prototype.removeEventListener;
  const dispatch = EventTarget.prototype.dispatchEvent;
  const hasFocus = Document.prototype.hasFocus;
  const getRandomValues = Crypto.prototype.getRandomValues;
  const setTimer = w.setTimeout;
  const clearTimer = w.clearTimeout;
  const attProto = w.AuthenticatorAttestationResponse.prototype;
  const asrProto = w.AuthenticatorAssertionResponse.prototype;
  const pkcProto = PKC.prototype;
  const nativeCreate = CC.prototype.create;
  const nativeGet = CC.prototype.get;
  const nativeUvpaa = PKC.isUserVerifyingPlatformAuthenticatorAvailable;
  const nativeCaps = PKC.getClientCapabilities;
  const nativeCma = PKC.isConditionalMediationAvailable;
  const crypto = w.crypto;
  const doc = w.document;
  // Same-origin with all ancestors here, so the top document is reachable. Its
  // hasFocus() is true while the tab has focus, whichever frame holds it.
  const topDoc = w.top === w ? doc : w.top.document;
  const loc = w.location;
  if (typeof toBase64 !== "function" || typeof fromBase64 !== "function") return;
  if (typeof signalAny !== "function" || typeof AC !== "function") return;

  const BOOT = "hirz-bootstrap";
  const MAX_OPTIONS_CHARS = 64 * 1024;
  const MAX_RESPONSE_CHARS = 1536 * 1024;
  const MAX_DESCRIPTORS = 64;
  const MAX_ID_BYTES = 1023;
  const MIN_CHALLENGE_BYTES = 16;
  const MAX_CHALLENGE_BYTES = 1024;
  const MAX_PRF_BYTES = 4096;
  const MAX_TEXT = 1024;
  const MAX_TIMEOUT_MS = 600000;
  const GUARD_EXTRA_MS = 60000;
  const CAPS_WAIT_MS = 3000;
  const SUPPORTED_ALGS = [-7, -8];
  const ERROR_NAMES = [
    "NotAllowedError",
    "InvalidStateError",
    "NotSupportedError",
    "AbortError",
    "SecurityError",
    "ConstraintError",
    "UnknownError",
  ];

  // Thrown while snapshotting to mean "let Firefox handle this request".
  const PASS = create(null);
  const EMPTY = O.freeze(create(null));

  const call = (fn, self, ...args) => apply(fn, self, args);
  const fail = () => {
    throw PASS;
  };

  function push(arr, value) {
    defineProperty(arr, arr.length, {
      value,
      writable: true,
      enumerable: true,
      configurable: true,
    });
  }

  function includes(arr, value) {
    for (let i = 0; i < arr.length; i++) if (arr[i] === value) return true;
    return false;
  }

  function hex(bytes) {
    let out = "";
    for (let i = 0; i < bytes.length; i++) {
      out += call(strSlice, call(numToString, bytes[i] + 256, 16), 1);
    }
    return out;
  }

  const q = (s) => JSONstringify(s);

  function jobj(entries) {
    let out = "{";
    let first = true;
    for (let i = 0; i < entries.length; i++) {
      const e = entries[i];
      if (e[1] === undefined) continue;
      out += (first ? "" : ",") + q(e[0]) + ":" + e[1];
      first = false;
    }
    return out + "}";
  }

  function jarr(items) {
    let out = "[";
    for (let i = 0; i < items.length; i++) out += (i ? "," : "") + items[i];
    return out + "]";
  }

  function dict(v) {
    if (v === undefined || v === null) return EMPTY;
    if (typeof v !== "object" && typeof v !== "function") fail();
    return v;
  }

  function text(v, max = MAX_TEXT) {
    const s = call(toWellFormed, S(v));
    if (s.length > max) fail();
    return s;
  }

  function optText(v, max = MAX_TEXT) {
    return v === undefined ? undefined : q(text(v, max));
  }

  function long(v) {
    const n = N(v);
    return isFiniteNumber(n) ? trunc(n) | 0 : 0;
  }

  function seq(v, max) {
    const out = [];
    if (v === undefined) return out;
    if (!isArray(v)) fail();
    const len = v.length;
    if (typeof len !== "number" || len > max) fail();
    for (let i = 0; i < len; i++) push(out, v[i]);
    return out;
  }

  function textList(v, maxItems, maxLen) {
    const items = seq(v, maxItems);
    const out = [];
    for (let i = 0; i < items.length; i++) push(out, text(items[i], maxLen));
    return out;
  }

  function jtextList(list) {
    const out = [];
    for (let i = 0; i < list.length; i++) push(out, q(list[i]));
    return jarr(out);
  }

  // Copies the bytes of an ArrayBuffer or ArrayBufferView at once.
  function bytesOf(src, min, max) {
    if (src === null || (typeof src !== "object" && typeof src !== "function")) fail();
    let buf = src;
    let off = 0;
    let len;
    if (apply(isView, AB, [src])) {
      try {
        buf = call(taBuffer, src);
        off = call(taByteOffset, src);
        len = call(taByteLength, src);
      } catch {
        buf = call(dvBuffer, src);
        off = call(dvByteOffset, src);
        len = call(dvByteLength, src);
      }
    } else {
      len = call(abByteLength, src);
    }
    // Throws for SharedArrayBuffer, which a BufferSource must not be.
    call(abByteLength, buf);
    if (len < min || len > max) fail();
    return new U8(new U8(buf, off, len));
  }

  const b64u = (bytes) => call(toBase64, bytes, { alphabet: "base64url", omitPadding: true });

  function jbytes(src, min, max) {
    return q(b64u(bytesOf(src, min, max)));
  }

  function optBytes(src, max) {
    return src === undefined ? undefined : jbytes(src, 0, max);
  }

  function descriptors(v) {
    const items = seq(v, MAX_DESCRIPTORS);
    const out = [];
    for (let i = 0; i < items.length; i++) {
      const d = dict(items[i]);
      const id = d.id;
      const transports = d.transports;
      const type = d.type;
      if (id === undefined || type === undefined) fail();
      push(
        out,
        jobj([
          ["id", jbytes(id, 1, MAX_ID_BYTES)],
          ["transports", transports === undefined ? undefined : jtextList(textList(transports, 16, 32))],
          ["type", q(text(type, 32))],
        ]),
      );
    }
    return jarr(out);
  }

  function prfValues(v) {
    const d = dict(v);
    const first = d.first;
    const second = d.second;
    if (first === undefined) fail();
    return jobj([
      ["first", jbytes(first, 0, MAX_PRF_BYTES)],
      ["second", optBytes(second, MAX_PRF_BYTES)],
    ]);
  }

  function prf(v, isCreate) {
    if (v === undefined) return undefined;
    const d = dict(v);
    const evalV = d.eval;
    const byCred = d.evalByCredential;
    let byCredJson;
    if (byCred !== undefined) {
      if (isCreate) fail();
      const rec = dict(byCred);
      const names = keys(rec);
      if (names.length > MAX_DESCRIPTORS) fail();
      const entries = [];
      for (let i = 0; i < names.length; i++) {
        const name = text(names[i], 2048);
        push(entries, [name, prfValues(rec[names[i]])]);
      }
      byCredJson = jobj(entries);
    }
    return jobj([
      ["eval", evalV === undefined ? undefined : prfValues(evalV)],
      ["evalByCredential", byCredJson],
    ]);
  }

  function largeBlob(v, isCreate) {
    if (v === undefined) return undefined;
    const d = dict(v);
    const read = d.read;
    const support = d.support;
    const write = d.write;
    return jobj([
      ["read", read === undefined ? undefined : q(!!read)],
      ["support", isCreate ? optText(support, 32) : undefined],
      ["write", optBytes(write, 64 * 1024)],
    ]);
  }

  function extensions(v, isCreate) {
    const d = dict(v);
    if (isCreate) {
      const appidExclude = d.appidExclude;
      const credProps = d.credProps;
      const credentialProtectionPolicy = d.credentialProtectionPolicy;
      const enforceCredentialProtectionPolicy = d.enforceCredentialProtectionPolicy;
      const lb = d.largeBlob;
      const p = d.prf;
      return jobj([
        ["appidExclude", optText(appidExclude, 2048)],
        ["credProps", credProps === undefined ? undefined : q(!!credProps)],
        ["credentialProtectionPolicy", optText(credentialProtectionPolicy, 64)],
        [
          "enforceCredentialProtectionPolicy",
          enforceCredentialProtectionPolicy === undefined ? undefined : q(!!enforceCredentialProtectionPolicy),
        ],
        ["largeBlob", largeBlob(lb, true)],
        ["prf", prf(p, true)],
      ]);
    }
    const appid = d.appid;
    const lb = d.largeBlob;
    const p = d.prf;
    return jobj([
      ["appid", optText(appid, 2048)],
      ["largeBlob", largeBlob(lb, false)],
      ["prf", prf(p, false)],
    ]);
  }

  function hints(v) {
    const list = textList(v, 8, 32);
    if (includes(list, "security-key") || includes(list, "hybrid")) fail();
    return jtextList(list);
  }

  function timeout(v) {
    if (v === undefined) return undefined;
    const n = N(v);
    if (!isFiniteNumber(n) || n < 0) return undefined;
    return trunc(n > MAX_TIMEOUT_MS ? MAX_TIMEOUT_MS : n);
  }

  // RP IDs that are not the page host or a parent of it are invalid or need Related Origin
  // Requests; Firefox handles both. The host does the authoritative public suffix check.
  function checkRpId(id) {
    if (id === undefined) return;
    const host = call(toLowerCase, loc.hostname);
    const rp = call(toLowerCase, id);
    if (rp === "" || (rp !== host && !call(endsWith, host, "." + rp))) fail();
  }

  function snapshotCreate(pk) {
    // Members are read in WebIDL dictionary order (lexicographic).
    const attestationV = pk.attestation;
    const attestationFormatsV = pk.attestationFormats;
    const selV = pk.authenticatorSelection;
    const challengeV = pk.challenge;
    const excludeV = pk.excludeCredentials;
    const extV = pk.extensions;
    const hintsV = pk.hints;
    const paramsV = pk.pubKeyCredParams;
    const rpV = pk.rp;
    const timeoutV = pk.timeout;
    const userV = pk.user;

    const attestation = attestationV === undefined ? "none" : text(attestationV, 32);
    if (attestation === "enterprise") fail();
    const attestationFormats = jtextList(textList(attestationFormatsV, 16, 32));

    const sel = dict(selV);
    const attachment = sel.authenticatorAttachment;
    const requireResidentKey = sel.requireResidentKey;
    const residentKey = sel.residentKey;
    const userVerification = sel.userVerification;
    const attachmentText = attachment === undefined ? undefined : text(attachment, 32);
    if (attachmentText === "cross-platform") fail();
    const selection = jobj([
      ["authenticatorAttachment", attachmentText === undefined ? undefined : q(attachmentText)],
      ["requireResidentKey", q(!!requireResidentKey)],
      ["residentKey", optText(residentKey, 32)],
      ["userVerification", q(userVerification === undefined ? "preferred" : text(userVerification, 32))],
    ]);

    if (challengeV === undefined || rpV === undefined || userV === undefined || paramsV === undefined) fail();
    const challenge = jbytes(challengeV, MIN_CHALLENGE_BYTES, MAX_CHALLENGE_BYTES);
    const exclude = descriptors(excludeV);
    const ext = extensions(extV, true);
    const hintList = hints(hintsV);

    const rawParams = seq(paramsV, 64);
    const params = [];
    let usable = rawParams.length === 0;
    for (let i = 0; i < rawParams.length; i++) {
      const p = dict(rawParams[i]);
      const alg = p.alg;
      const type = p.type;
      if (alg === undefined || type === undefined) fail();
      const algN = long(alg);
      const typeText = text(type, 32);
      if (typeText === "public-key" && includes(SUPPORTED_ALGS, algN)) usable = true;
      push(params, jobj([["alg", q(algN)], ["type", q(typeText)]]));
    }
    if (!usable) fail();
    if (rawParams.length === 0) {
      push(params, jobj([["alg", "-7"], ["type", q("public-key")]]));
      push(params, jobj([["alg", "-257"], ["type", q("public-key")]]));
    }

    const rp = dict(rpV);
    const rpId = rp.id;
    const rpName = rp.name;
    if (rpName === undefined) fail();
    const rpIdText = rpId === undefined ? undefined : text(rpId, 253);
    checkRpId(rpIdText);

    const user = dict(userV);
    const userDisplayName = user.displayName;
    const userId = user.id;
    const userName = user.name;
    if (userDisplayName === undefined || userId === undefined || userName === undefined) fail();

    const t = timeout(timeoutV);
    const json = jobj([
      ["attestation", q(attestation)],
      ["attestationFormats", attestationFormats],
      ["authenticatorSelection", selection],
      ["challenge", challenge],
      ["excludeCredentials", exclude],
      ["extensions", ext],
      ["hints", hintList],
      ["pubKeyCredParams", jarr(params)],
      ["rp", jobj([["id", rpIdText === undefined ? undefined : q(rpIdText)], ["name", q(text(rpName))]])],
      ["timeout", t === undefined ? undefined : q(t)],
      [
        "user",
        jobj([
          ["displayName", q(text(userDisplayName))],
          ["id", jbytes(userId, 1, 64)],
          ["name", q(text(userName))],
        ]),
      ],
    ]);
    return { json, timeout: t };
  }

  function snapshotGet(pk) {
    const allowV = pk.allowCredentials;
    const challengeV = pk.challenge;
    const extV = pk.extensions;
    const hintsV = pk.hints;
    const rpIdV = pk.rpId;
    const timeoutV = pk.timeout;
    const uvV = pk.userVerification;

    if (challengeV === undefined) fail();
    const allow = descriptors(allowV);
    const challenge = jbytes(challengeV, MIN_CHALLENGE_BYTES, MAX_CHALLENGE_BYTES);
    const ext = extensions(extV, false);
    const hintList = hints(hintsV);
    const rpId = rpIdV === undefined ? undefined : text(rpIdV, 253);
    checkRpId(rpId);
    const t = timeout(timeoutV);
    const json = jobj([
      ["allowCredentials", allow],
      ["challenge", challenge],
      ["extensions", ext],
      ["hints", hintList],
      ["rpId", rpId === undefined ? undefined : q(rpId)],
      ["timeout", t === undefined ? undefined : q(t)],
      ["userVerification", q(uvV === undefined ? "preferred" : text(uvV, 32))],
    ]);
    return { json, timeout: t };
  }

  // Returns a plan, or null to let Firefox handle the call unchanged.
  function prepare(kind, options) {
    if (options === undefined || options === null || typeof options !== "object") return null;
    const digital = options.digital;
    const identity = options.identity;
    const mediation = options.mediation;
    const otp = options.otp;
    const password = options.password;
    const publicKey = options.publicKey;
    const signal = options.signal;
    if (publicKey === undefined || publicKey === null) return null;
    if (digital !== undefined || identity !== undefined || otp !== undefined || password !== undefined) return null;
    const mediationText = mediation === undefined ? "optional" : text(mediation, 32);
    const conditional = mediationText === "conditional";
    if (mediationText === "silent" || (conditional && kind !== "get")) return null;
    if (signal !== undefined) {
      if (call(signalAborted, signal)) return null;
    }
    const pk = dict(publicKey);
    const snap = kind === "create" ? snapshotCreate(pk) : snapshotGet(pk);
    if (snap.json.length > MAX_OPTIONS_CHARS) return null;
    return { json: snap.json, timeout: snap.timeout, signal, conditional };
  }

  function define(obj, name, value) {
    defineProperty(obj, name, { value, writable: false, enumerable: true, configurable: true });
  }

  function method(obj, name, fn) {
    defineProperty(fn, "name", { value: name });
    define(obj, name, fn);
  }

  function bufferFrom(s) {
    if (typeof s !== "string") throw new TypeErr("bad base64url");
    return call(taBuffer, apply(fromBase64, U8, [s, { alphabet: "base64url" }]));
  }

  const copyBuffer = (buf) => call(abSlice, buf, 0);

  // Deep copy of parsed JSON data into fresh page objects, without consulting
  // anything the page may have added to Object.prototype or Array.prototype.
  function clone(v) {
    if (v === null || typeof v !== "object") return v;
    if (isArray(v)) {
      const out = [];
      for (let i = 0; i < v.length; i++) push(out, clone(v[i]));
      return out;
    }
    const out = {};
    const names = keys(v);
    for (let i = 0; i < names.length; i++) {
      defineProperty(out, names[i], { value: clone(v[names[i]]), writable: true, enumerable: true, configurable: true });
    }
    return out;
  }

  function extensionResults(src) {
    const out = {};
    if (!src || typeof src !== "object") return out;
    if (typeof src.appid === "boolean") out.appid = src.appid;
    if (typeof src.appidExclude === "boolean") out.appidExclude = src.appidExclude;
    if (src.credProps && typeof src.credProps.rk === "boolean") out.credProps = { rk: src.credProps.rk };
    if (src.prf && typeof src.prf === "object") {
      const p = {};
      if (typeof src.prf.enabled === "boolean") p.enabled = src.prf.enabled;
      const r = src.prf.results;
      if (r && typeof r === "object" && typeof r.first === "string") {
        p.results = { first: bufferFrom(r.first) };
        if (typeof r.second === "string") p.results.second = bufferFrom(r.second);
      }
      out.prf = p;
    }
    if (src.largeBlob && typeof src.largeBlob === "object") {
      const l = {};
      if (typeof src.largeBlob.supported === "boolean") l.supported = src.largeBlob.supported;
      if (typeof src.largeBlob.written === "boolean") l.written = src.largeBlob.written;
      if (typeof src.largeBlob.blob === "string") l.blob = bufferFrom(src.largeBlob.blob);
      out.largeBlob = l;
    }
    return out;
  }

  function buildCredential(kind, c) {
    if (!c || typeof c !== "object" || c.type !== "public-key") throw new TypeErr("bad credential");
    if (typeof c.id !== "string" || c.rawId !== c.id) throw new TypeErr("bad credential id");
    const r = c.response;
    if (!r || typeof r !== "object") throw new TypeErr("bad response");
    const rawId = bufferFrom(c.rawId);
    let response;
    if (kind === "create") {
      response = create(attProto);
      const authData = bufferFrom(r.authenticatorData);
      const publicKey = r.publicKey === undefined || r.publicKey === null ? null : bufferFrom(r.publicKey);
      const alg = r.publicKeyAlgorithm;
      if (!isSafeInteger(alg)) throw new TypeErr("bad algorithm");
      const transports = [];
      if (isArray(r.transports)) {
        for (let i = 0; i < r.transports.length; i++) {
          if (typeof r.transports[i] === "string") push(transports, r.transports[i]);
        }
      }
      define(response, "clientDataJSON", bufferFrom(r.clientDataJSON));
      define(response, "attestationObject", bufferFrom(r.attestationObject));
      method(response, "getTransports", function () {
        const out = [];
        for (let i = 0; i < transports.length; i++) push(out, transports[i]);
        return out;
      });
      method(response, "getAuthenticatorData", function () {
        return copyBuffer(authData);
      });
      method(response, "getPublicKey", function () {
        return publicKey === null ? null : copyBuffer(publicKey);
      });
      method(response, "getPublicKeyAlgorithm", function () {
        return alg;
      });
    } else {
      response = create(asrProto);
      define(response, "clientDataJSON", bufferFrom(r.clientDataJSON));
      define(response, "authenticatorData", bufferFrom(r.authenticatorData));
      define(response, "signature", bufferFrom(r.signature));
      define(
        response,
        "userHandle",
        r.userHandle === undefined || r.userHandle === null ? null : bufferFrom(r.userHandle),
      );
    }
    const cred = create(pkcProto);
    const attachment = typeof c.authenticatorAttachment === "string" ? c.authenticatorAttachment : null;
    const extJson = c.clientExtensionResults;
    define(cred, "id", c.id);
    define(cred, "rawId", rawId);
    define(cred, "type", "public-key");
    define(cred, "authenticatorAttachment", attachment);
    define(cred, "response", response);
    method(cred, "getClientExtensionResults", function () {
      return extensionResults(extJson);
    });
    method(cred, "toJSON", function () {
      return clone(c);
    });
    return cred;
  }

  function toError(name) {
    if (name === "TypeError") return new TypeErr("The request could not be processed.");
    if (includes(ERROR_NAMES, name)) return new DOMExc("The operation failed.", name);
    return new DOMExc("The operation either timed out or was not allowed.", "NotAllowedError");
  }

  const secret = hex(call(getRandomValues, crypto, new U8(16)));
  const REQ = "hirz-req-" + secret;
  const RES = "hirz-res-" + secret;
  const pending = create(null);
  let linked = false;
  let nextRid = 1;

  function emit(type, detail) {
    call(dispatch, w, new CE(type, { detail }));
  }

  function send(kind, rid, optionsJson) {
    emit(REQ, jobj([["v", "1"], ["kind", q(kind)], ["rid", q(rid)], ["options", optionsJson]]));
  }

  function onResponse(ev) {
    const detail = call(detailOf, ev);
    if (typeof detail !== "string" || detail.length > MAX_RESPONSE_CHARS) return;
    let msg;
    try {
      msg = JSONparse(detail);
    } catch {
      return;
    }
    if (!msg || msg.v !== 1 || !isSafeInteger(msg.rid)) return;
    const handler = pending[msg.rid];
    if (handler) handler(msg);
  }

  function onBoot(ev) {
    if (linked || call(detailOf, ev) !== "relay") return;
    linked = true;
    call(removeListener, w, BOOT, onBoot, true);
    call(addListener, w, RES, onResponse, true);
    emit(BOOT, "key:" + secret);
  }

  call(addListener, w, BOOT, onBoot, true);
  emit(BOOT, "shim");

  function waitForFocus() {
    return new P((resolve) => {
      const check = () => {
        if (call(hasFocus, topDoc)) resolve();
        else setTimer(check, 250);
      };
      check();
    });
  }

  // A modal request. `NotHandled` hands it to Firefox once the tab has focus.
  function ceremony(kind, plan, fallback) {
    return new P((resolve, reject) => {
      const rid = nextRid++;
      const signal = plan.signal;
      let settled = false;
      let guard = null;

      const onAbort = () => {
        if (!finish()) return;
        send("cancel", rid, undefined);
        reject(call(signalReason, signal));
      };

      function finish() {
        if (settled) return false;
        settled = true;
        delete pending[rid];
        if (guard !== null) clearTimer(guard);
        if (signal !== undefined) call(removeListener, signal, "abort", onAbort);
        return true;
      }

      pending[rid] = (msg) => {
        if (msg.ok === true) {
          if (!finish()) return;
          try {
            resolve(buildCredential(kind, msg.credential));
          } catch {
            reject(toError("UnknownError"));
          }
          return;
        }
        if (msg.error === "NotHandled") {
          delete pending[rid];
          if (guard !== null) clearTimer(guard);
          guard = null;
          (async () => {
            await waitForFocus();
            if (finish()) resolve(fallback());
          })();
          return;
        }
        if (!finish()) return;
        reject(toError(msg.error));
      };

      if (signal !== undefined) call(addListener, signal, "abort", onAbort, { once: true });
      const limit = (plan.timeout === undefined ? MAX_TIMEOUT_MS : plan.timeout) + GUARD_EXTRA_MS;
      guard = setTimer(() => {
        guard = null;
        if (!finish()) return;
        send("cancel", rid, undefined);
        reject(toError("NotAllowedError"));
      }, limit);
      send(kind, rid, plan.json);
    });
  }

  // A conditional request is always Firefox's own request: it starts at once with the page's
  // options, whether or not hirz has a passkey for the site, so the page cannot tell. hirz offers
  // its passkeys in a list once the user touches a field; if the user picks one and approves, that
  // credential settles the promise and Firefox's request is aborted through an internal signal.
  function conditionalCeremony(plan, self, args, nativeFn) {
    return new P((resolve, reject) => {
      const rid = nextRid++;
      const signal = plan.signal;
      const own = new AC();
      let settled = false;

      const onAbort = () => {
        if (!finish()) return;
        call(acAbort, own);
        reject(call(signalReason, signal));
      };

      function finish() {
        if (settled) return false;
        settled = true;
        delete pending[rid];
        if (signal !== undefined) call(removeListener, signal, "abort", onAbort);
        send("cancel", rid, undefined);
        return true;
      }

      pending[rid] = (msg) => {
        if (msg.ok !== true) return;
        let credential;
        try {
          credential = buildCredential("get", msg.credential);
        } catch {
          if (finish()) {
            call(acAbort, own);
            reject(toError("UnknownError"));
          }
          return;
        }
        if (!finish()) return;
        call(acAbort, own);
        resolve(credential);
      };

      if (signal !== undefined) call(addListener, signal, "abort", onAbort, { once: true });
      // Everything the page set is inherited; only the signal is replaced.
      const options = create(args[0]);
      const ownSignal = call(acSignal, own);
      const combined = signal === undefined ? ownSignal : apply(signalAny, AS, [[signal, ownSignal]]);
      defineProperty(options, "signal", { value: combined, writable: true, enumerable: true, configurable: true });
      const nativeArgs = [options];
      for (let i = 1; i < args.length; i++) push(nativeArgs, args[i]);
      let result;
      try {
        result = apply(nativeFn, self, nativeArgs);
      } catch (e) {
        finish();
        reject(e);
        return;
      }
      call(
        then,
        result,
        (value) => {
          if (finish()) resolve(value);
        },
        (reason) => {
          if (finish()) reject(reason);
        },
      );
      send("conditional", rid, plan.json);
    });
  }

  function run(kind, self, args, nativeFn) {
    const passthrough = () => apply(nativeFn, self, args);
    if (self !== container || !linked) return passthrough();
    let plan = null;
    try {
      plan = prepare(kind, args.length > 0 ? args[0] : undefined);
    } catch {
      plan = null;
    }
    if (plan === null) return passthrough();
    if (plan.conditional) return conditionalCeremony(plan, self, args, nativeFn);
    return ceremony(kind, plan, passthrough);
  }

  let capsPromise = null;

  function hostCapabilities() {
    if (capsPromise === null) {
      capsPromise = new P((resolve) => {
        if (!linked) {
          resolve(null);
          return;
        }
        const rid = nextRid++;
        const timer = setTimer(() => {
          delete pending[rid];
          resolve(null);
        }, CAPS_WAIT_MS);
        pending[rid] = (msg) => {
          delete pending[rid];
          clearTimer(timer);
          const c = msg.ok === true ? msg.capabilities : null;
          if (!c || typeof c !== "object") {
            resolve(null);
            return;
          }
          resolve({
            uvpaa: c.userVerifyingPlatformAuthenticator === true,
            passkey: c.passkeyPlatformAuthenticator === true,
          });
        };
        send("capabilities", rid, undefined);
      });
    }
    return capsPromise;
  }

  function replace(target, name, fn) {
    const d = getOwnPropertyDescriptor(target, name);
    if (!d || typeof d.value !== "function") return;
    defineProperty(target, name, {
      value: fn,
      writable: d.writable,
      enumerable: d.enumerable,
      configurable: d.configurable,
    });
  }

  const hooks = {
    create(...args) {
      return run("create", this, args, nativeCreate);
    },
    get(...args) {
      return run("get", this, args, nativeGet);
    },
  };

  const statics = {
    async isUserVerifyingPlatformAuthenticatorAvailable() {
      const caps = await hostCapabilities();
      if (caps && caps.uvpaa) return true;
      return apply(nativeUvpaa, PKC, []);
    },
    async getClientCapabilities() {
      const base = await apply(nativeCaps, PKC, []);
      const caps = await hostCapabilities();
      if (!caps) return base;
      const out = {};
      const names = keys(base);
      for (let i = 0; i < names.length; i++) out[names[i]] = base[names[i]];
      if (caps.uvpaa) out.userVerifyingPlatformAuthenticator = true;
      if (caps.passkey) out.passkeyPlatformAuthenticator = true;
      out.conditionalGet = true;
      return out;
    },
    // With the host reachable, hirz can offer suggestions next to Firefox's own conditional request.
    async isConditionalMediationAvailable() {
      if (await hostCapabilities()) return true;
      return apply(nativeCma, PKC, []);
    },
  };

  replace(CC.prototype, "create", hooks.create);
  replace(CC.prototype, "get", hooks.get);
  if (typeof nativeUvpaa === "function") {
    replace(PKC, "isUserVerifyingPlatformAuthenticatorAvailable", statics.isUserVerifyingPlatformAuthenticatorAvailable);
  }
  if (typeof nativeCaps === "function") {
    replace(PKC, "getClientCapabilities", statics.getClientCapabilities);
  }
  if (typeof nativeCma === "function") {
    replace(PKC, "isConditionalMediationAvailable", statics.isConditionalMediationAvailable);
  }
})();
