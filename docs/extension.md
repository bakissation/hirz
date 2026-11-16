# Firefox extension and native messaging host

The extension path lets Firefox pages use hirz passkeys directly. The extension
replaces `navigator.credentials.create()` and `get()` for public key requests,
hands them to the native messaging host `hirz-nmh`, and hands everything it does
not handle back to Firefox's own WebAuthn implementation unchanged.

The extension is deliberately thin. It holds no keys, builds no signed bytes and
makes no decision with security meaning except reading the request origin from
Firefox. The host re-validates every field.

Status: v0.1 plus conditional mediation and same-origin frames. The host
answers `create` and `get` with real passkeys from the user's vault
(`hirz-webauthn` for the client role, `hirz-core` for the authenticator,
`hirz-uv` for the approval prompt), and `list` with the accounts behind the
autofill suggestions. Without a vault on the device it answers `NotHandled`
to ceremonies and an empty list, so Firefox runs the ceremony itself.

## Files

| File | World | Role |
|---|---|---|
| `extension/manifest.json` | | MV3 manifest, Firefox only |
| `extension/page/shim.js` | page (`MAIN`), `document_start`, every frame | Hooks `CredentialsContainer.prototype.create/get` and three `PublicKeyCredential` statics, snapshots options, builds result objects |
| `extension/content/autofill.js` | content script (`ISOLATED`), `document_start`, every frame | Suggestion list for conditional mediation, in a closed shadow root |
| `extension/content/relay.js` | content script (`ISOLATED`), `document_start`, every frame | Pipe between the shim and the background; hands account lists to `autofill.js` |
| `extension/background.js` | background event page (ES module) | Origin, tab and frame-tree checks, one ceremony per tab, conditional requests, timeouts, the native port |
| `crates/hirz-nmh` | native process | Framing, the reader thread for `cancel`, the vault session, replies through `hirz_webauthn::handle` |
| `packaging/native-messaging/hirz.json` | | Native manifest template |

There is no build step: no npm packages, no bundler, no minification, no
remote code, no `eval`, no WebAssembly. The XPI is the `extension/` folder as
written.

## Manifest decisions

- `browser_specific_settings.gecko.id` is `hirz@berkati.xyz`, on the
  maintainer's domain. AMO binds the listing to this id for good, and the
  native manifest's `allowed_extensions` must carry the same value.
- `strict_min_version` is `140.0`: `world: "MAIN"` content scripts (128),
  `Uint8Array.prototype.toBase64` / `Uint8Array.fromBase64` (133),
  `data_collection_permissions` (140).
- `data_collection_permissions.required` is `["none"]`. Request data goes only
  to a native program on the same machine, which is part of the same product,
  and nothing is sent to any server by the extension or the host.
- Permissions: `nativeMessaging` and `webNavigation`. Host permissions
  `https://*/*` and `http://localhost/*` (any port) cover the content scripts.
  `tabs.get` and `windows.get` are used only for the `active` and `focused`
  flags, which need no permission.
- `webNavigation` is used for one call, `webNavigation.getAllFrames({tabId})`,
  when a request comes from a subframe; no listeners are registered. It is the
  smallest permission that gives the frame tree from the parent process
  (`frameId`, `parentFrameId`, URL). The alternatives are weaker: `tab.url`
  (visible through the host permissions, no `tabs` permission needed) names
  only the top-level document, so it cannot see a cross-origin frame in the
  middle of the chain (`a.example` embedding `b.example` embedding
  `a.example`), and it races with navigation; a frame registry fed by the
  content scripts would still need the parent links, which only
  `webNavigation` or child-reported `runtime.getFrameId(parent)` provide. The
  cost is an install-time permission line ("Access browser activity during
  navigation").
- Content scripts run with `all_frames: true` and `match_about_blank: true`.
  Firefox does not guarantee `document_start` for `about:blank` and `srcdoc`
  frames, so a page can always reach the native API in such a frame or in a
  fresh realm; that only means Firefox handles the call.
- No popup and no options page. Approval prompts are drawn by the native host
  (`hirz-uv`), outside the browser. The only UI in the page is the conditional
  mediation suggestion list, which is a hint and never an approval (see
  below).

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
   never reads an origin from the page or the relay. It requires a real tab,
   an `https:` origin or `http://localhost`, a frame that is same-origin with
   all its ancestors (see "Frames"), the tab to be the active tab of the
   focused window, and no other ceremony in progress in the same tab. It then
   sends the request to the host with `origin`, `topOrigin` and `crossOrigin`
   added and a clamped timeout.
6. The host answers. The background keeps only the expected fields of a
   credential (anything else the host sends is dropped), maps unknown error
   codes to `UnknownError`, and replies to the relay, which hands the reply to
   the shim.
7. The shim builds the result objects, or rejects with the matching exception,
   or on `NotHandled` waits until the tab has focus (the top document's
   `hasFocus()`, so it also works in frames) and calls Firefox's own
   `create`/`get` with the original arguments.

### What passes through to Firefox

The shim calls Firefox's own implementation, untouched, when:

- the call is in a frame that is not same-origin with all its ancestors (the
  shim does not even install its hooks there), or the document is not a
  secure context;
- `options.publicKey` is absent, or the request also asks for another
  credential type (`password`, `identity`, `otp`, `digital`);
- `mediation` is `"silent"`, or `"conditional"` on `create` (conditional
  create). Conditional `get` is handled, see "Conditional mediation";
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
in a tab, the frame is not same-origin with all its ancestors according to the
frame tree, the origin is not `https:` or `http://localhost`, the host is an IP
literal, or the tab is not the active tab of the focused window.

### Statics

- `PublicKeyCredential.isUserVerifyingPlatformAuthenticatorAvailable()`
  resolves `true` when the host reports
  `userVerifyingPlatformAuthenticator: true`, otherwise it returns Firefox's
  answer.
- `PublicKeyCredential.getClientCapabilities()` returns Firefox's record with
  `userVerifyingPlatformAuthenticator` and `passkeyPlatformAuthenticator` set
  to `true` when the host reports them.
- `PublicKeyCredential.isConditionalMediationAvailable()` resolves `true`
  when the host answers `capabilities` (it is reachable), otherwise it returns
  Firefox's answer. `getClientCapabilities()` then also reports
  `conditionalGet: true`. Both hold even without a vault: hirz then has no
  accounts and hands the conditional request to Firefox.
- The host's capabilities are fetched at most once per page (3 s budget) and
  cached by the background for 60 s.
- `parseCreationOptionsFromJSON`, `parseRequestOptionsFromJSON` and the
  signal methods are left to Firefox.

### Conditional mediation (passkey autofill)

A page that calls `navigator.credentials.get({mediation: "conditional",
publicKey})` gets hirz's own suggestion list under its sign-in fields instead
of Firefox's:

1. The shim snapshots the options as for a modal `get` and sends a
   `conditional` request. The promise stays pending: no timeout applies.
2. The background checks the frame like any request, then asks the host
   `list` with the origin from `sender.origin` and only `rpId` and
   `allowCredentials` of the options. The host validates the origin and RP ID
   exactly as for `get` and answers with ids and names, never key material.
3. With no account (no vault, nothing for this site, the host unreachable or
   any error), the page gets `NotHandled` and the shim calls Firefox's own
   conditional `get` with the original arguments, so Firefox's behaviour is
   kept.
4. Otherwise the background keeps the request (one per document; a newer
   conditional request ends the older one with `AbortError`) and sends the
   account list to the relay, which gives it to `autofill.js`. The page never
   receives it.
5. `autofill.js` waits for the user: a trusted click into an `input` or
   `textarea` whose `autocomplete` attribute contains the token `webauthn`,
   a Tab into such a field, or an arrow key in it. It then shows the list next
   to the field. Arrow keys and Enter, or a click on a row, choose an account;
   Escape or leaving the field closes it.
6. Choosing sends `select` with the credential id. The background accepts only
   an id from the list it got for that request, and runs a normal `get` with
   the page's options, `allowCredentials` narrowed to that id (and
   `prf.evalByCredential` to its entry), and no `mediation`. The host's prompt
   shows the site and the account; the user approves there.
7. A credential resolves the pending promise. If the user cancels the prompt
   or the ceremony fails, the request stays pending and the list can be opened
   again, as with a dismissed browser suggestion. `NotHandled` hands the
   request to Firefox.
8. Aborting the page's `AbortSignal` rejects with its reason, removes the
   list, and cancels a running host request. Navigation or closing the tab
   ends everything with the page port.

Security model:

- The list is UI only. Nothing in it carries authority: the origin still
  comes from `sender.origin`, the host validates origin and RP ID for `list`
  and again for the `get`, and every signature needs the host's own prompt.
  A page that hides, covers, restyles or moves the list, or tricks the user
  into clicking it, at most starts a `get` the user then sees and can refuse
  in the hirz prompt.
- The list is drawn in a closed shadow root attached to an element that
  `autofill.js` creates and fills before inserting it, from the isolated
  world, so page scripts never get a reference to its inside and patched DOM
  prototypes do not affect it. Names are drawn as CSS generated content
  (`content: attr(...)`), so the page's find and selection APIs do not see
  them either. Bidi and other invisible control characters are stripped and
  labels are capped at 64 characters.
- Only trusted events open the list or choose a row. Events a page script
  dispatches are untrusted, and they cannot reach nodes inside the closed
  root anyway. Programmatic `focus()` does not open the list.
- What the page can learn: before the user interacts with a `webauthn` field,
  nothing (no element is added). After that, the page can see that the
  element exists and its size, so it learns that hirz has accounts for the
  site and roughly how many. It never sees ids or names; it learns the chosen
  credential only from the credential the user approves, as with any `get`.
  The list is not filtered by what the user types, because the size of a
  filtered list would reveal names to the page.
- The list goes to the top layer (`popover="manual"`), so page `z-index` and
  modal dialogs do not hide it.

### Frames

The content scripts run in every frame. The shim installs its hooks only when
the frame can read the `origin` of every ancestor and all are equal to its
own (a cross-origin ancestor throws). That is only a shortcut so that
cross-origin frames keep Firefox's API untouched, including Permissions Policy
and user activation checks.

The decision is the background's. For a request from a subframe it calls
`webNavigation.getAllFrames` for the tab, finds the sender's frame, checks
that the frame's URL (when it has an origin) matches `sender.origin`, and
walks `parentFrameId` to the top. The request is handled only when every
ancestor's URL has exactly the sender's origin; ancestors whose URL has no
origin (`about:blank`, `srcdoc`, `blob:`, `data:`) count as cross-origin, as
does a missing frame or a chain deeper than 32. Handled frames are sent to the
host with `topOrigin` equal to `origin` and `crossOrigin: false`, which is
what WebAuthn's clientDataJSON says for a frame that is same-origin with its
ancestors (no `topOrigin` member). Everything else gets `NotHandled` and goes
to Firefox. Permissions Policy delegation to cross-origin frames is out of
scope.

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
ones. The shim sends `create`, `get`, `conditional`, `capabilities` and
`cancel`; the relay forwards only `ok`, `credential`, `capabilities` and
`error` of a reply. `select` and the account list exist only between the
relay and the background.

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
| `type` | string | `hello`, `capabilities`, `create`, `get`, `list` or `cancel` |
| `origin` | string | `create`, `get` and `list` only. Serialized origin of the calling document, from `sender.origin` |
| `topOrigin` | string | `create`, `get` and `list` only. Origin of the top-level document, from the frame tree. Equal to `origin` for everything the extension sends |
| `crossOrigin` | boolean | `create`, `get` and `list` only. Whether the caller is not same-origin with all its ancestors. Always `false`: cross-origin frames go to Firefox |
| `options` | object | `create`: `PublicKeyCredentialCreationOptionsJSON`; `get`: `PublicKeyCredentialRequestOptionsJSON` (WebAuthn Level 3), as snapshotted by the shim; `list`: `{rpId?, allowCredentials?}` |

Every message is parsed with the strict JSON reader of `hirz-proto` (UTF-8, no
duplicate keys, no lone surrogates, at most 32 levels of nesting); `v` and
`id` must be non-negative integers, `id` at most 2^53-1. Unknown members are
ignored.

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
| `UnknownError` | Internal failure, or an envelope that is not valid JSON, has no valid `id` or an unknown `type` (`id` is `null` when it could not be read) | `DOMException` `UnknownError` |

`list` (conditional mediation):

```json
{"v":1,"id":5,"type":"list","origin":"https://example.com","topOrigin":"https://example.com","crossOrigin":false,
 "options":{"rpId":"example.com","allowCredentials":[]}}
{"v":1,"id":5,"ok":true,"accounts":[{"id":"6Ze2...","name":"alice","displayName":"Alice"}]}
```

The host validates `origin`, `topOrigin`, `crossOrigin` and the RP ID exactly
as for `get` and fails with the same errors (`SecurityError`, `NotHandled`
for related origins or cross-origin frames, `NotHandled` for malformed
options). Other members of `options` are ignored. Without an allow list it
returns the RP's discoverable credentials, newest first; with one, the listed
credentials of the RP in list order. credProtect level 3 credentials are never
listed, level 2 only when they are in the allow list, since listing does not
verify the user. `name` and `displayName` are the stored user name and display
name (empty strings when absent), each at most 1024 characters; at most 64
accounts. Without a vault the list is empty. `list` never prompts, signs or
returns key material. It is answered in order with the other requests, from
the vault as it was last loaded (every `create` and `get` reloads it).

Every failure also carries `message`, a fixed diagnostic text without request
data. Options that fail validation get `NotHandled`, so Firefox produces the
spec-defined `TypeError` itself. A message whose `v` is missing or not `1`
gets `NotHandled`, so a newer extension falls back to Firefox.

`cancel` uses the `id` of the request it cancels and has no reply of its own.
If that request is still pending (queued or waiting for the user), the host
answers it with `AbortError`; otherwise the cancel is ignored. The extension
stops waiting as soon as it sends `cancel`. The host reads stdin on its own
thread, so a cancel arrives while a ceremony waits for the approval prompt.
The prompt cannot be closed from outside; it stays until the user answers or
it times out, and its approval then counts as refused, so a cancelled request
creates and signs nothing. When Firefox closes stdin, every pending request is
treated as cancelled.

Requests are answered in order, one at a time: a request that arrives while a
prompt is open waits for it (including `hello`, `capabilities` and `list`).
The background gives `list` 10 s; after that the page falls back to Firefox's
conditional request.

`capabilities` reports `userVerifyingPlatformAuthenticator` and
`passkeyPlatformAuthenticator` as `true` only when a vault exists and a
verifying approval method (polkit, fingerprint or hirz PIN) is available right
now; `extension:credProps`, `extension:credProtect` and `extension:prf` are
always `true`.

The vault is found like the CLI finds it: `HIRZ_VAULT`, else the folder
recorded in `$XDG_STATE_HOME/hirz/vault-path`, else
`$XDG_DATA_HOME/hirz/vault`; state in `HIRZ_STATE`, else
`$XDG_STATE_HOME/hirz`. Without a vault, or when it cannot be opened (logged
on stderr), `create` and `get` get `NotHandled`.

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
4. Open https://webauthn.io and register. Expected: the background console
   logs `hirz: native host ready, version 0.1.0-dev`, and a hirz prompt (not
   Firefox's own dialog) shows `webauthn.io` and "Requested by
   https://webauthn.io". Without a vault (`hirz init` not run) Firefox's own
   security key prompt appears instead.
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

### Checklist with a vault

Needs `hirz init`, an approval method (for example the polkit action) and
zenity.

1. Register on https://webauthn.io (username `alice`): one hirz prompt, then
   success; `hirz list` shows the new passkey for `webauthn.io`.
2. Authenticate with the username (allow list) and without it
   (discoverable): one prompt each, both succeed.
3. Register `alice` again: the prompt appears, then the page reports
   `InvalidStateError` (credential excluded).
4. Start a registration and press the page's abort (or close the tab) while
   the hirz prompt is open: the page gets `AbortError` at once; approving the
   still open prompt afterwards creates nothing (`hirz list` is unchanged).
5. Cancel the hirz prompt: the page gets `NotAllowedError`.
6. Set "User verification: required" with click-to-allow as the only method:
   the request fails with `NotAllowedError`.
7. With `HIRZ_LOG=debug` (wrapper script, see above) the stderr log shows one
   line per received and sent message with type, id, size and error name,
   never contents.
8. Move the vault away: registrations go to Firefox's own dialog again, and
   `isUserVerifyingPlatformAuthenticatorAvailable()` falls back to Firefox's
   answer after the 60 s capability cache expires.

### Checklist for autofill and frames

Needs a vault with at least one discoverable passkey for `webauthn.io` (step 1
above).

1. Open https://webauthn.io. In the web console,
   `await PublicKeyCredential.isConditionalMediationAvailable()` returns
   `true`. The page starts a conditional request on load; no hirz element is
   in the page yet
   (`document.querySelectorAll("[popover]").length` is `0`).
2. Click into the username field: a list "Passkey (hirz)" with the account
   appears under it. In the console, the element's `shadowRoot` is `null` and
   its `textContent` is empty.
3. Press Down then Enter (or click the row): the hirz prompt appears with
   `webauthn.io` and the account; approve: the page reports a successful
   authentication without a username being typed.
4. Repeat, cancel the hirz prompt: the page shows nothing new; click the field
   again, the list is back.
5. Programmatic focus does not open it: in the console run
   `document.querySelector("input[autocomplete*=webauthn]").focus()` after
   clicking elsewhere; no list appears.
6. Start the modal "Authenticate" button flow while the list is open (the page
   aborts its conditional request first): the list disappears and the modal
   flow shows the hirz prompt.
7. Move the vault away (or use a profile without one) and reload: clicking
   the field shows no hirz list; Firefox's own behaviour applies.
8. Frames: serve a test folder with `python3 -m http.server 8000` containing
   `top.html` with `<iframe src="/inner.html">` and
   `<iframe src="http://localhost:8001/inner.html">` (a second server on port
   8001 is a different origin), where `inner.html` calls
   `navigator.credentials.get({publicKey:{challenge:new Uint8Array(32)}})`
   from a button. In the same-origin frame the hirz prompt appears and shows
   `http://localhost:8000`; the clientDataJSON has `crossOrigin: false` and
   no `topOrigin`. In the frame from port 8001,
   `navigator.credentials.get.toString()` shows `[native code]` and the call
   goes to Firefox's own dialog.

The extension side of the checklist was also run automatically in a
throwaway headless Firefox profile through geckodriver: a temporary copy of
the extension whose `runtime.connectNative` is replaced by a stub host in
JavaScript, and local pages served by `python3 -m http.server`. It checked
that the list appears only after a trusted click, Tab or arrow key, that
synthetic events and programmatic focus do nothing, that the page sees no
shadow root and no text, that keyboard and pointer selection resolve the
pending promise with the allow list narrowed to the chosen id and without
`mediation`, that a refused prompt keeps the request pending, that abort
removes the list, that no accounts falls back to Firefox's conditional
request, that a same-origin iframe is handled with `topOrigin` equal to its
origin, that a cross-origin iframe keeps the native API, and that a request
forged by a page in a same-origin frame below a cross-origin frame gets
`NotHandled` from the background.

The automated equivalent of steps 1 to 4 of the first checklist, without
prompts, is the test module
of `crates/hirz-nmh` (`cargo test -p hirz-nmh`): it drives the host loop over
OS pipes with framed JSON, a temporary vault and an approver that exists only
in test builds, and verifies the attestation object and the assertion
signature, and `list` against a vault with mixed discoverability and
credProtect levels. `tests/process.rs` runs the real binary without a vault.

## Process hardening

At start the host sets `RLIMIT_CORE 0`, `PR_SET_DUMPABLE 0` and
`PR_SET_NO_NEW_PRIVS` (`hirz_sys::harden_process`). The helpers hirz-uv runs
(zenity, pkcheck, fprintd-verify, fprintd-list) are neither setuid nor have
file capabilities, so NO_NEW_PRIVS does not change what they can do: pkcheck
asks polkitd over D-Bus, and the password dialog belongs to the session's
polkit agent, not to hirz. polkitd identifies the host process by pid, start
time and uid from `/proc`, which stay readable for a non-dumpable process.

## Not supported yet

- Cross-origin iframes and Permissions Policy delegation (Firefox handles
  them).
- Conditional create, and a "use another device" entry in the suggestion
  list.
- Related Origin Requests.
- Signal methods (`signalUnknownCredential` and the others).
- Detecting other extensions that hook the same functions.
- Closing an open approval prompt when the request is cancelled.
