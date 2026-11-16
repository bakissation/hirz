// Background event page: the only part of the extension that talks to the native host, and the
// only place the origin comes from (MessageSender.origin, set by Firefox in the parent process, so
// the page cannot forge it). Frame ancestry comes from webNavigation, also parent-side.

const HOST_NAME = "hirz";
const PROTOCOL_VERSION = 1;
const PAGE_PORT_NAME = "hirz-page";

const HELLO_TIMEOUT_MS = 5000;
const CAPS_TIMEOUT_MS = 5000;
const CAPS_TTL_MS = 60000;
const CAPS_FAIL_TTL_MS = 5000;
const HOST_RETRY_MS = 10000;
const HOST_IDLE_MS = 30000;
const DEFAULT_TIMEOUT_MS = 300000;
const MIN_TIMEOUT_MS = 30000;
const MAX_TIMEOUT_MS = 600000;
const MAX_OPTIONS_CHARS = 64 * 1024;
const MAX_B64_CHARS = 1400 * 1024;
const LIST_TIMEOUT_MS = 10000;
const MAX_ACCOUNTS = 64;
const MAX_ID_CHARS = 1364;
const MAX_NAME_CHARS = 1024;
const MAX_FRAME_DEPTH = 32;
const MAX_JSON_DEPTH = 24;
const MAX_JSON_NODES = 20000;
const MAX_RIDS = 4096;
const MAX_TRANSPORTS = 8;
const MAX_TRANSPORT_CHARS = 32;
// Request budgets: a page cannot drive the host (vault rescans, prompts) at its own pace. Over a
// budget, `list` answers an empty list and ceremonies go to Firefox.
const DOC_LIST_GAP_MS = 500;
const DOC_LIST_MAX = 12;
const DOC_CEREMONY_MAX = 20;
const GLOBAL_LIST_GAP_MS = 100;
const GLOBAL_LIST_MAX = 60;
// Frames of one tab share this: a user touch asks once, however many same-origin frames a page has.
const TAB_LIST_GAP_MS = 1000;
const TAB_LIST_MAX = 12;
const BUDGET_WINDOW_MS = 60000;

const PASSTHROUGH = "NotHandled";
const HOST_ERRORS = new Set([
  PASSTHROUGH,
  "NotAllowedError",
  "InvalidStateError",
  "NotSupportedError",
  "AbortError",
  "SecurityError",
  "ConstraintError",
  "UnknownError",
  "TypeError",
]);
const PASS = Object.freeze({ ok: false, error: PASSTHROUGH });

const isObject = (v) => v !== null && typeof v === "object" && !Array.isArray(v);
const isB64u = (v) =>
  typeof v === "string" && v.length <= MAX_B64_CHARS && v.length % 4 !== 1 && /^[A-Za-z0-9_-]*$/.test(v);
const optB64u = (v) => v === undefined || v === null || isB64u(v);

// The host reads a request with a strict JSON reader (depth limit, no lone surrogates) and can only
// answer a rejected one with `id: null`, so such options never leave the background.
function wellFormedJson(root) {
  const stack = [[root, 1]];
  let nodes = 0;
  while (stack.length > 0) {
    const [v, depth] = stack.pop();
    if (++nodes > MAX_JSON_NODES || depth > MAX_JSON_DEPTH) return false;
    if (typeof v === "string") {
      if (!v.isWellFormed()) return false;
    } else if (typeof v === "number") {
      if (!Number.isFinite(v)) return false;
    } else if (v === null || typeof v === "boolean") {
      continue;
    } else if (Array.isArray(v)) {
      for (const item of v) stack.push([item, depth + 1]);
    } else if (isObject(v)) {
      for (const [k, item] of Object.entries(v)) {
        if (!k.isWellFormed()) return false;
        stack.push([item, depth + 1]);
      }
    } else {
      return false;
    }
  }
  return true;
}

// True when the request may be sent now, and counts it.
function allow(times, now, minGapMs, max) {
  while (times.length > 0 && now - times[0] >= BUDGET_WINDOW_MS) times.shift();
  if (times.length > 0 && now - times[times.length - 1] < minGapMs) return false;
  if (times.length >= max) return false;
  times.push(now);
  return true;
}

// Like `allow`, for the frames of one tab together; tabs with nothing recent are forgotten.
function tabListAllowed(tabId, now) {
  for (const [id, times] of tabLists) {
    while (times.length > 0 && now - times[0] >= BUDGET_WINDOW_MS) times.shift();
    if (times.length === 0) tabLists.delete(id);
  }
  const times = tabLists.get(tabId) ?? [];
  const ok = allow(times, now, TAB_LIST_GAP_MS, TAB_LIST_MAX);
  if (ok) tabLists.set(tabId, times);
  return ok;
}

let host = null;
let nextHostId = 1;
let hostFailedAt = -Infinity;
let idleTimer = null;
let capsCache = null;
let capsFlight = null;
const globalLists = [];
const tabLists = new Map();

function dropHost(h, reason) {
  if (host === h) host = null;
  for (const entry of h.pending.values()) {
    clearTimeout(entry.timer);
    entry.reject(new Error(reason));
  }
  h.pending.clear();
  try {
    h.port.disconnect();
  } catch {
    // Already gone.
  }
}

function onHostMessage(h, msg) {
  if (isObject(msg) && msg.v === PROTOCOL_VERSION && msg.id === null && msg.ok === false) {
    // The host rejected a frame it could not attribute to a request; resync with a new host.
    console.warn("hirz: native host rejected a message, restarting it");
    dropHost(h, "host rejected a message");
    return;
  }
  if (!isObject(msg) || msg.v !== PROTOCOL_VERSION || !Number.isSafeInteger(msg.id)) {
    console.warn("hirz: ignoring malformed host message");
    return;
  }
  const entry = h.pending.get(msg.id);
  if (!entry) return;
  h.pending.delete(msg.id);
  clearTimeout(entry.timer);
  entry.resolve(msg);
  scheduleIdle(h);
}

function onHostDisconnect(h, port) {
  if (!h.helloDone) hostFailedAt = Date.now();
  const why = port.error ? port.error.message : "host exited";
  console.warn("hirz: native host disconnected:", why);
  dropHost(h, why);
}

function scheduleIdle(h) {
  clearTimeout(idleTimer);
  if (h.pending.size !== 0) return;
  idleTimer = setTimeout(() => {
    if (host === h && h.pending.size === 0) dropHost(h, "idle");
  }, HOST_IDLE_MS);
}

function hostCall(h, fields, timeoutMs) {
  clearTimeout(idleTimer);
  const id = nextHostId;
  nextHostId = nextHostId >= Number.MAX_SAFE_INTEGER ? 1 : nextHostId + 1;
  const promise = new Promise((resolve, reject) => {
    const timer = setTimeout(() => {
      if (h.pending.delete(id)) {
        reject(new Error("timeout"));
        scheduleIdle(h);
      }
    }, timeoutMs);
    h.pending.set(id, { resolve, reject, timer });
    try {
      h.port.postMessage({ v: PROTOCOL_VERSION, id, ...fields });
    } catch (e) {
      h.pending.delete(id);
      clearTimeout(timer);
      reject(e);
    }
  });
  return { id, promise };
}

function cancelHostCall(h, id) {
  const entry = h.pending.get(id);
  if (!entry) return;
  h.pending.delete(id);
  clearTimeout(entry.timer);
  entry.reject(new Error("cancelled"));
  try {
    h.port.postMessage({ v: PROTOCOL_VERSION, id, type: "cancel" });
  } catch {
    // Host gone; nothing to cancel.
  }
  scheduleIdle(h);
}

async function openHost() {
  if (host) return (await host.ready) ? host : null;
  if (Date.now() - hostFailedAt < HOST_RETRY_MS) return null;
  let port;
  try {
    port = browser.runtime.connectNative(HOST_NAME);
  } catch (e) {
    hostFailedAt = Date.now();
    console.warn("hirz: cannot start native host:", e.message);
    return null;
  }
  const h = { port, pending: new Map(), helloDone: false, ready: null };
  host = h;
  port.onMessage.addListener((m) => onHostMessage(h, m));
  port.onDisconnect.addListener((p) => onHostDisconnect(h, p));
  h.ready = hostCall(h, { type: "hello" }, HELLO_TIMEOUT_MS).promise.then(
    (r) => {
      if (r.ok === true && typeof r.version === "string") {
        h.helloDone = true;
        console.info("hirz: native host ready, version", r.version);
        return true;
      }
      hostFailedAt = Date.now();
      dropHost(h, "bad hello");
      return false;
    },
    () => {
      hostFailedAt = Date.now();
      if (host === h) dropHost(h, "no hello");
      return false;
    },
  );
  return (await h.ready) ? h : null;
}

function hostCapabilities() {
  if (capsCache && Date.now() < capsCache.until) return Promise.resolve(capsCache.value);
  if (capsFlight) return capsFlight;
  capsFlight = fetchCapabilities().finally(() => {
    capsFlight = null;
  });
  return capsFlight;
}

// A failure is remembered briefly: one slow answer must not switch the capability off for every page.
async function fetchCapabilities() {
  const h = await openHost();
  let value = null;
  if (h) {
    try {
      const r = await hostCall(h, { type: "capabilities" }, CAPS_TIMEOUT_MS).promise;
      if (r.ok === true && isObject(r.capabilities)) {
        value = {
          userVerifyingPlatformAuthenticator: r.capabilities.userVerifyingPlatformAuthenticator === true,
          passkeyPlatformAuthenticator: r.capabilities.passkeyPlatformAuthenticator === true,
        };
      }
    } catch {
      value = null;
    }
  }
  capsCache = { until: Date.now() + (value ? CAPS_TTL_MS : CAPS_FAIL_TTL_MS), value };
  return value;
}

const ATTACHMENTS = new Set(["platform", "cross-platform"]);

// Only the members the shim reads, each with its expected type.
function cleanExtensionResults(src) {
  const out = {};
  if (!isObject(src)) return out;
  if (typeof src.appid === "boolean") out.appid = src.appid;
  if (typeof src.appidExclude === "boolean") out.appidExclude = src.appidExclude;
  if (isObject(src.credProps) && typeof src.credProps.rk === "boolean") {
    out.credProps = { rk: src.credProps.rk };
  }
  if (isObject(src.prf)) {
    const prf = {};
    if (typeof src.prf.enabled === "boolean") prf.enabled = src.prf.enabled;
    const r = src.prf.results;
    if (isObject(r) && isB64u(r.first)) {
      prf.results = { first: r.first };
      if (isB64u(r.second)) prf.results.second = r.second;
    }
    out.prf = prf;
  }
  if (isObject(src.largeBlob)) {
    const lb = {};
    if (typeof src.largeBlob.supported === "boolean") lb.supported = src.largeBlob.supported;
    if (typeof src.largeBlob.written === "boolean") lb.written = src.largeBlob.written;
    if (isB64u(src.largeBlob.blob)) lb.blob = src.largeBlob.blob;
    out.largeBlob = lb;
  }
  return out;
}

function cleanCredential(kind, c) {
  if (!isObject(c) || c.type !== "public-key" || !isB64u(c.id) || c.rawId !== c.id) return null;
  const r = c.response;
  if (!isObject(r) || !isB64u(r.clientDataJSON) || !isB64u(r.authenticatorData)) return null;
  if (c.authenticatorAttachment !== undefined && c.authenticatorAttachment !== null) {
    if (!ATTACHMENTS.has(c.authenticatorAttachment)) return null;
  }
  if (c.clientExtensionResults !== undefined && !isObject(c.clientExtensionResults)) return null;
  const out = {
    id: c.id,
    rawId: c.rawId,
    type: "public-key",
    authenticatorAttachment: c.authenticatorAttachment ?? "platform",
    response: { clientDataJSON: r.clientDataJSON, authenticatorData: r.authenticatorData },
    clientExtensionResults: cleanExtensionResults(c.clientExtensionResults),
  };
  if (kind === "create") {
    if (!isB64u(r.attestationObject) || !Number.isSafeInteger(r.publicKeyAlgorithm)) return null;
    if (!optB64u(r.publicKey)) return null;
    if (!Array.isArray(r.transports) || !r.transports.every((t) => typeof t === "string")) return null;
    out.response.attestationObject = r.attestationObject;
    out.response.transports = r.transports.slice(0, MAX_TRANSPORTS).map((t) => t.slice(0, MAX_TRANSPORT_CHARS));
    out.response.publicKeyAlgorithm = r.publicKeyAlgorithm;
    if (typeof r.publicKey === "string") out.response.publicKey = r.publicKey;
  } else {
    if (!isB64u(r.signature) || !optB64u(r.userHandle)) return null;
    out.response.signature = r.signature;
    out.response.userHandle = typeof r.userHandle === "string" ? r.userHandle : null;
  }
  return out;
}

function cleanAccounts(list) {
  const out = [];
  if (!Array.isArray(list)) return out;
  const seen = new Set();
  for (const a of list) {
    if (out.length >= MAX_ACCOUNTS) break;
    if (!isObject(a) || !isB64u(a.id) || a.id.length === 0 || a.id.length > MAX_ID_CHARS) continue;
    if (seen.has(a.id)) continue;
    seen.add(a.id);
    out.push({
      id: a.id,
      name: typeof a.name === "string" ? a.name.slice(0, MAX_NAME_CHARS) : "",
      displayName: typeof a.displayName === "string" ? a.displayName.slice(0, MAX_NAME_CHARS) : "",
    });
  }
  return out;
}

function canonicalB64u(s) {
  try {
    return Uint8Array.fromBase64(s, { alphabet: "base64url" }).toBase64({ alphabet: "base64url", omitPadding: true });
  } catch {
    return null;
  }
}

function narrowOptions(options, id) {
  const out = { ...options, allowCredentials: [{ type: "public-key", id }] };
  const ext = out.extensions;
  if (isObject(ext) && isObject(ext.prf) && isObject(ext.prf.evalByCredential)) {
    const want = canonicalB64u(id);
    const kept = {};
    for (const [key, value] of Object.entries(ext.prf.evalByCredential)) {
      if (canonicalB64u(key) === want) kept[key] = value;
    }
    out.extensions = { ...ext, prf: { ...ext.prf, evalByCredential: kept } };
  }
  return out;
}

const busyTabs = new Set();

function originAllowed(origin) {
  if (typeof origin !== "string") return false;
  let url;
  try {
    url = new URL(origin);
  } catch {
    return false;
  }
  if (url.origin !== origin) return false;
  const name = url.hostname;
  if (name.startsWith("[") || /^[0-9.]+$/.test(name)) return false;
  if (url.protocol === "https:") return true;
  return url.protocol === "http:" && name === "localhost";
}

// Origin of a frame URL as reported by webNavigation, or null when the URL does not
// carry one (about:blank, about:srcdoc, blob:, data:).
function urlOrigin(url) {
  try {
    const u = new URL(url);
    return u.protocol === "https:" || u.protocol === "http:" ? u.origin : null;
  } catch {
    return null;
  }
}

// From Firefox, not the page: sender.origin and the frame tree. Same-origin only when every
// ancestor's URL has exactly this origin; ancestors with no origin count as cross-origin.
async function frameContext(sender) {
  if (!sender || sender.id !== browser.runtime.id) return null;
  const tab = sender.tab;
  if (!tab || !Number.isInteger(tab.id) || tab.id < 0) return null;
  if (!Number.isInteger(sender.frameId) || sender.frameId < 0) return null;
  const origin = sender.origin;
  if (!originAllowed(origin)) return null;
  const ctx = { tabId: tab.id, frameId: sender.frameId, origin, topOrigin: origin, crossOrigin: false };
  if (sender.frameId === 0) return ctx;
  let frames;
  try {
    frames = await browser.webNavigation.getAllFrames({ tabId: tab.id });
  } catch {
    return null;
  }
  if (!Array.isArray(frames)) return null;
  const byId = new Map();
  for (const f of frames) {
    if (isObject(f) && Number.isInteger(f.frameId)) byId.set(f.frameId, f);
  }
  let frame = byId.get(sender.frameId);
  if (!frame) return null;
  const own = urlOrigin(frame.url);
  if (own !== null && own !== origin) return null;
  for (let depth = 0; frame.frameId !== 0; depth++) {
    if (depth >= MAX_FRAME_DEPTH) return null;
    frame = byId.get(frame.parentFrameId);
    if (!frame) return null;
    if (urlOrigin(frame.url) !== origin) ctx.crossOrigin = true;
  }
  ctx.topOrigin = urlOrigin(frame.url) ?? "null";
  return ctx;
}

function clampTimeout(v) {
  if (!Number.isFinite(v)) return DEFAULT_TIMEOUT_MS;
  return Math.min(MAX_TIMEOUT_MS, Math.max(MIN_TIMEOUT_MS, Math.trunc(v)));
}

async function tabIsFocused(tabId) {
  try {
    const tab = await browser.tabs.get(tabId);
    if (!tab.active) return false;
    const win = await browser.windows.get(tab.windowId);
    return win.focused === true;
  } catch {
    return false;
  }
}

function reply(state, rid, body) {
  try {
    state.port.postMessage({ v: PROTOCOL_VERSION, rid, ...body });
  } catch {
    // The page went away.
  }
}

function optionsOk(options) {
  return isObject(options) && wellFormedJson(options) && JSON.stringify(options).length <= MAX_OPTIONS_CHARS;
}

// Cross-origin frames go to Firefox, which applies Permissions Policy.
async function sameOriginContext(state) {
  const ctx = await frameContext(state.port.sender);
  return ctx && !ctx.crossOrigin ? ctx : null;
}

const ABORTED = Object.freeze({ ok: false, error: "AbortError" });

// The page may cancel at any await, and a request that was cancelled before the host heard of it
// must never reach the host (it would show a prompt for a dead request).
const cancelled = (state, rid) => state.closed || state.aborted.has(rid);

async function ceremony(state, kind, rid, options) {
  if (!optionsOk(options)) return PASS;
  const ctx = await sameOriginContext(state);
  if (!ctx) return PASS;
  if (cancelled(state, rid)) return ABORTED;
  if (!allow(state.ceremonies, Date.now(), 0, DOC_CEREMONY_MAX)) return PASS;
  if (busyTabs.has(ctx.tabId)) return { ok: false, error: "NotAllowedError" };
  busyTabs.add(ctx.tabId);
  try {
    // Firefox only runs WebAuthn for the active tab of the focused window; otherwise it answers itself.
    if (!(await tabIsFocused(ctx.tabId))) return PASS;
    if (cancelled(state, rid)) return ABORTED;
    const h = await openHost();
    if (!h) return PASS;
    if (cancelled(state, rid)) return ABORTED;
    const call = hostCall(
      h,
      {
        type: kind,
        origin: ctx.origin,
        topOrigin: ctx.topOrigin,
        crossOrigin: false,
        options,
      },
      clampTimeout(options.timeout),
    );
    state.active.set(rid, { h, id: call.id });
    let r;
    try {
      r = await call.promise;
    } catch (e) {
      if (e.message === "timeout") cancelHostCall(h, call.id);
      return { ok: false, error: e.message === "cancelled" ? "AbortError" : "NotAllowedError" };
    } finally {
      state.active.delete(rid);
    }
    if (r.ok === true) {
      const credential = cleanCredential(kind, r.credential);
      return credential ? { ok: true, credential } : { ok: false, error: "UnknownError" };
    }
    return { ok: false, error: HOST_ERRORS.has(r.error) ? r.error : "UnknownError" };
  } finally {
    busyTabs.delete(ctx.tabId);
  }
}

// The relay asks for the account list after the user touched a `webauthn` field; the list goes back
// to the relay and never to the page. Every failure is an empty list, which looks like "no
// passkeys" to the relay and shows nothing.
async function suggestAccounts(state, rid, options) {
  const none = () => reply(state, rid, { phase: "accounts", accounts: [] });
  if (cancelled(state, rid) || (state.conditional && state.conditional.busy)) return;
  if (!optionsOk(options)) return none();
  const ctx = await sameOriginContext(state);
  if (!ctx) return none();
  const now = Date.now();
  if (!allow(state.lists, now, DOC_LIST_GAP_MS, DOC_LIST_MAX)) return none();
  if (!allow(globalLists, now, GLOBAL_LIST_GAP_MS, GLOBAL_LIST_MAX)) return none();
  if (!tabListAllowed(ctx.tabId, now)) return none();
  // The user's touch implies a focused tab; a list for any other tab is not asked for.
  if (!(await tabIsFocused(ctx.tabId))) return none();
  const query = {};
  if (typeof options.rpId === "string") query.rpId = options.rpId;
  if (Array.isArray(options.allowCredentials)) query.allowCredentials = options.allowCredentials;
  const h = await openHost();
  if (!h) return none();
  let r;
  try {
    r = await hostCall(
      h,
      { type: "list", origin: ctx.origin, topOrigin: ctx.topOrigin, crossOrigin: false, options: query },
      LIST_TIMEOUT_MS,
    ).promise;
  } catch {
    return none();
  }
  if (cancelled(state, rid)) return;
  const accounts = r.ok === true ? cleanAccounts(r.accounts) : [];
  state.conditional =
    accounts.length > 0 ? { rid, options, ids: new Set(accounts.map((a) => a.id)), busy: false } : null;
  reply(state, rid, { phase: "accounts", accounts });
}

async function selectAccount(state, rid, id) {
  const c = state.conditional;
  if (!c || c.rid !== rid || typeof id !== "string" || !c.ids.has(id)) {
    reply(state, rid, { phase: "stale" });
    return;
  }
  if (c.busy) return;
  c.busy = true;
  const result = await ceremony(state, "get", rid, narrowOptions(c.options, id));
  if (state.conditional !== c) return;
  c.busy = false;
  if (result.ok === true) {
    state.conditional = null;
    reply(state, rid, result);
    return;
  }
  // The page's own request keeps running in Firefox. A refused prompt leaves the list usable, as
  // with a dismissed browser suggestion; anything else means the list is stale.
  reply(state, rid, { phase: result.error === PASSTHROUGH ? "stale" : "retry" });
}

async function onPageMessage(state, msg) {
  if (!isObject(msg) || msg.v !== PROTOCOL_VERSION || !Number.isSafeInteger(msg.rid)) return;
  const rid = msg.rid;
  switch (msg.kind) {
    case "capabilities": {
      const caps = (await sameOriginContext(state)) ? await hostCapabilities() : null;
      reply(state, rid, caps ? { ok: true, capabilities: caps } : PASS);
      return;
    }
    case "cancel": {
      if (state.aborted.size < MAX_RIDS) state.aborted.add(rid);
      if (state.conditional && state.conditional.rid === rid) state.conditional = null;
      const entry = state.active.get(rid);
      if (entry) cancelHostCall(entry.h, entry.id);
      return;
    }
    case "suggest": {
      await suggestAccounts(state, rid, msg.options);
      return;
    }
    case "select": {
      await selectAccount(state, rid, msg.id);
      return;
    }
    case "create":
    case "get": {
      if (state.rids.has(rid)) return;
      if (state.rids.size >= MAX_RIDS) {
        reply(state, rid, PASS);
        return;
      }
      state.rids.add(rid);
      const result = await ceremony(state, msg.kind, rid, msg.options);
      reply(state, rid, result);
      return;
    }
    default:
      return;
  }
}

browser.runtime.onConnect.addListener((port) => {
  if (port.name !== PAGE_PORT_NAME) {
    port.disconnect();
    return;
  }
  const state = {
    port,
    active: new Map(),
    rids: new Set(),
    aborted: new Set(),
    conditional: null,
    lists: [],
    ceremonies: [],
    closed: false,
  };
  port.onMessage.addListener((msg) => {
    onPageMessage(state, msg).catch((e) => console.error("hirz:", e));
  });
  port.onDisconnect.addListener(() => {
    state.closed = true;
    state.conditional = null;
    for (const entry of state.active.values()) cancelHostCall(entry.h, entry.id);
    state.active.clear();
  });
});
