// ISOLATED world, document_start, every frame. A dumb pipe between page/shim.js and the
// background: it adds no identity, the background reads the origin from the sender Firefox reports.
// Conditional requests live here until the user touches a field (content/autofill.js); the account
// list goes to the autofill and never back to the page.
"use strict";

(() => {
  const autofill = globalThis.hirzAutofill;
  const BOOT = "hirz-bootstrap";
  const PORT_NAME = "hirz-page";
  const MAX_REQUEST_CHARS = 72 * 1024;
  const MAX_CONDITIONAL = 16;
  const KINDS = new Set(["create", "get", "conditional", "capabilities", "cancel"]);

  let secret = null;
  let port = null;
  const pending = new Map();
  const conditionalOptions = new Map();

  const isObject = (v) => v !== null && typeof v === "object" && !Array.isArray(v);

  function emit(type, detail) {
    window.dispatchEvent(new CustomEvent(type, { detail }));
  }

  // Only the members the shim reads; anything else the background might add stays here.
  function respond(msg) {
    if (secret === null) return;
    const out = { v: 1, rid: msg.rid, ok: msg.ok === true };
    if (out.ok && isObject(msg.credential)) out.credential = msg.credential;
    if (out.ok && isObject(msg.capabilities)) out.capabilities = msg.capabilities;
    if (!out.ok) out.error = typeof msg.error === "string" ? msg.error : "UnknownError";
    emit("hirz-res-" + secret, JSON.stringify(out));
  }

  function forget(rid) {
    pending.delete(rid);
    conditionalOptions.delete(rid);
  }

  function post(message) {
    try {
      ensurePort().postMessage(message);
    } catch {
      onPortDisconnect();
    }
  }

  function suggest(rid) {
    const options = conditionalOptions.get(rid);
    if (pending.get(rid) === "conditional" && options !== undefined) {
      post({ v: 1, kind: "suggest", rid, options });
    }
  }

  function select(rid, id) {
    if (pending.get(rid) === "conditional" && port !== null) {
      post({ v: 1, kind: "select", rid, id });
    }
  }

  function onPortMessage(msg) {
    if (!isObject(msg) || msg.v !== 1 || !pending.has(msg.rid)) return;
    const rid = msg.rid;
    if (pending.get(rid) !== "conditional") {
      pending.delete(rid);
      respond(msg);
      return;
    }
    if (!autofill) return;
    if (msg.phase === "accounts") autofill.provide(rid, msg.accounts);
    else if (msg.phase === "retry") autofill.resume(rid);
    else if (msg.phase === "stale") autofill.invalidate(rid);
    else if (msg.ok === true) {
      autofill.stop(rid);
      forget(rid);
      respond(msg);
    } else autofill.invalidate(rid);
  }

  // The background keeps no state for a conditional request, so a lost port only costs the list:
  // the request stays registered here and the next touch asks again over a new port.
  function onPortDisconnect() {
    port = null;
    for (const [rid, kind] of pending) {
      if (kind === "conditional") {
        if (autofill) autofill.invalidate(rid);
        continue;
      }
      const error = kind === "capabilities" ? "NotHandled" : "NotAllowedError";
      respond({ v: 1, rid, ok: false, error });
      pending.delete(rid);
    }
  }

  function ensurePort() {
    if (port === null) {
      port = browser.runtime.connect({ name: PORT_NAME });
      port.onMessage.addListener(onPortMessage);
      port.onDisconnect.addListener(onPortDisconnect);
    }
    return port;
  }

  function onRequest(ev) {
    ev.stopImmediatePropagation();
    const detail = ev.detail;
    if (typeof detail !== "string" || detail.length > MAX_REQUEST_CHARS) return;
    let msg;
    try {
      msg = JSON.parse(detail);
    } catch {
      return;
    }
    if (!isObject(msg) || msg.v !== 1 || !KINDS.has(msg.kind)) return;
    const rid = msg.rid;
    if (!Number.isSafeInteger(rid) || rid < 0) return;
    const out = { v: 1, kind: msg.kind, rid };
    if (msg.kind === "cancel") {
      if (!pending.has(rid)) return;
      if (pending.get(rid) === "conditional") {
        if (autofill) autofill.stop(rid);
        forget(rid);
      }
      if (port === null) return;
    } else if (msg.kind === "conditional") {
      // No answer ever goes back for it unless the user picks a passkey: Firefox's own request,
      // started by the shim, is what the page sees in every other case.
      if (pending.has(rid) || !isObject(msg.options) || !autofill) return;
      if (conditionalOptions.size >= MAX_CONDITIONAL) return;
      pending.set(rid, "conditional");
      conditionalOptions.set(rid, msg.options);
      autofill.start(rid, { request: () => suggest(rid), onSelect: (id) => select(rid, id) });
      return;
    } else {
      if (pending.has(rid)) return;
      if (msg.kind === "create" || msg.kind === "get") {
        if (!isObject(msg.options)) {
          respond({ v: 1, rid, ok: false, error: "NotHandled" });
          return;
        }
        out.options = msg.options;
      }
      pending.set(rid, msg.kind);
    }
    post(out);
  }

  // Handshake with the shim: whichever script loads second completes it synchronously, and the
  // shim hands over a random secret that names the private request and response events.
  function onBoot(ev) {
    const detail = ev.detail;
    if (secret !== null || typeof detail !== "string") return;
    if (detail === "shim") {
      emit(BOOT, "relay");
      return;
    }
    if (!detail.startsWith("key:")) return;
    const key = detail.slice(4);
    if (!/^[0-9a-f]{32}$/.test(key)) return;
    secret = key;
    window.removeEventListener(BOOT, onBoot, true);
    window.addEventListener("hirz-req-" + secret, onRequest, true);
  }

  window.addEventListener(BOOT, onBoot, true);
  emit(BOOT, "relay");
})();
