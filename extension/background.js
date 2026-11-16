// Background event page. The only part of the extension that talks to the
// native host, and the only place the request origin comes from: Firefox sets
// MessageSender.origin in the parent process, so page scripts cannot forge it.

const HOST_NAME = "hirz";
const PROTOCOL_VERSION = 1;
const PAGE_PORT_NAME = "hirz-page";

const HELLO_TIMEOUT_MS = 5000;
const CAPS_TIMEOUT_MS = 5000;
const CAPS_TTL_MS = 60000;
const HOST_RETRY_MS = 10000;
const HOST_IDLE_MS = 30000;
const DEFAULT_TIMEOUT_MS = 300000;
const MIN_TIMEOUT_MS = 30000;
const MAX_TIMEOUT_MS = 600000;
const MAX_OPTIONS_CHARS = 64 * 1024;
const MAX_B64_CHARS = 1400 * 1024;

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

const isObject = (v) => v !== null && typeof v === "object" && !Array.isArray(v);
const isB64u = (v) =>
  typeof v === "string" && v.length <= MAX_B64_CHARS && v.length % 4 !== 1 && /^[A-Za-z0-9_-]*$/.test(v);
const optB64u = (v) => v === undefined || v === null || isB64u(v);

// ---------------------------------------------------------------------------
// Native host connection: one long-lived port, multiplexed by request id.

let host = null;
let nextHostId = 1;
let hostFailedAt = -Infinity;
let idleTimer = null;
let capsCache = null;

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
    // The host is gone; nothing left to cancel.
  }
  scheduleIdle(h);
}

// Resolves to the connected host, or null when it is not available.
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

async function hostCapabilities() {
  if (capsCache && Date.now() - capsCache.at < CAPS_TTL_MS) return capsCache.value;
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
  capsCache = { at: Date.now(), value };
  return value;
}

// ---------------------------------------------------------------------------
// Validation of what the host returns, before it reaches the page.

function cleanCredential(kind, c) {
  if (!isObject(c) || c.type !== "public-key" || !isB64u(c.id) || c.rawId !== c.id) return null;
  const r = c.response;
  if (!isObject(r) || !isB64u(r.clientDataJSON) || !isB64u(r.authenticatorData)) return null;
  if (c.authenticatorAttachment !== undefined && c.authenticatorAttachment !== null) {
    if (typeof c.authenticatorAttachment !== "string") return null;
  }
  if (c.clientExtensionResults !== undefined && !isObject(c.clientExtensionResults)) return null;
  const out = {
    id: c.id,
    rawId: c.rawId,
    type: "public-key",
    authenticatorAttachment: c.authenticatorAttachment ?? "platform",
    response: { clientDataJSON: r.clientDataJSON, authenticatorData: r.authenticatorData },
    clientExtensionResults: c.clientExtensionResults ?? {},
  };
  if (kind === "create") {
    if (!isB64u(r.attestationObject) || !Number.isSafeInteger(r.publicKeyAlgorithm)) return null;
    if (!optB64u(r.publicKey)) return null;
    if (!Array.isArray(r.transports) || !r.transports.every((t) => typeof t === "string")) return null;
    out.response.attestationObject = r.attestationObject;
    out.response.transports = [...r.transports];
    out.response.publicKeyAlgorithm = r.publicKeyAlgorithm;
    if (typeof r.publicKey === "string") out.response.publicKey = r.publicKey;
  } else {
    if (!isB64u(r.signature) || !optB64u(r.userHandle)) return null;
    out.response.signature = r.signature;
    out.response.userHandle = typeof r.userHandle === "string" ? r.userHandle : null;
  }
  return out;
}

// ---------------------------------------------------------------------------
// Pages.

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

// Everything here comes from Firefox, not from the page.
function pageContext(sender) {
  if (!sender || sender.id !== browser.runtime.id) return null;
  if (!sender.tab || !Number.isInteger(sender.tab.id) || sender.tab.id < 0) return null;
  if (sender.frameId !== 0) return null;
  if (!originAllowed(sender.origin)) return null;
  return { tabId: sender.tab.id, origin: sender.origin };
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

async function ceremony(state, kind, rid, options) {
  const ctx = state.ctx;
  if (!ctx || !isObject(options)) return { ok: false, error: PASSTHROUGH };
  if (JSON.stringify(options).length > MAX_OPTIONS_CHARS) return { ok: false, error: PASSTHROUGH };
  if (busyTabs.has(ctx.tabId)) return { ok: false, error: "NotAllowedError" };
  busyTabs.add(ctx.tabId);
  try {
    // Firefox only runs WebAuthn for the active tab of the focused window;
    // when that does not hold, let Firefox give its own answer.
    if (!(await tabIsFocused(ctx.tabId))) return { ok: false, error: PASSTHROUGH };
    const h = await openHost();
    if (!h) return { ok: false, error: PASSTHROUGH };
    if (state.closed) return { ok: false, error: "AbortError" };
    const call = hostCall(
      h,
      {
        type: kind,
        origin: ctx.origin,
        topOrigin: ctx.origin,
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

async function onPageMessage(state, msg) {
  if (!isObject(msg) || msg.v !== PROTOCOL_VERSION || !Number.isSafeInteger(msg.rid)) return;
  const rid = msg.rid;
  switch (msg.kind) {
    case "capabilities": {
      const caps = state.ctx ? await hostCapabilities() : null;
      reply(state, rid, caps ? { ok: true, capabilities: caps } : { ok: false, error: PASSTHROUGH });
      return;
    }
    case "cancel": {
      const entry = state.active.get(rid);
      if (entry) cancelHostCall(entry.h, entry.id);
      return;
    }
    case "create":
    case "get": {
      if (state.rids.has(rid)) return;
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
    ctx: pageContext(port.sender),
    active: new Map(),
    rids: new Set(),
    closed: false,
  };
  port.onMessage.addListener((msg) => {
    onPageMessage(state, msg).catch((e) => console.error("hirz:", e));
  });
  port.onDisconnect.addListener(() => {
    state.closed = true;
    for (const entry of state.active.values()) cancelHostCall(entry.h, entry.id);
    state.active.clear();
  });
});
