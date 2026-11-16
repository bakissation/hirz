// ISOLATED world, document_start, every frame. A dumb pipe between page/shim.js and the
// background: it adds no identity, the background reads the origin from the sender Firefox reports.
// Conditional account lists go to content/autofill.js and never back to the page.
"use strict";

(() => {
  const autofill = globalThis.hirzAutofill;
  const BOOT = "hirz-bootstrap";
  const PORT_NAME = "hirz-page";
  const MAX_REQUEST_CHARS = 72 * 1024;
  const KINDS = new Set(["create", "get", "conditional", "capabilities", "cancel"]);

  let secret = null;
  let port = null;
  const pending = new Map();

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

  function select(rid, id) {
    if (pending.get(rid) !== "conditional" || port === null) return;
    try {
      port.postMessage({ v: 1, kind: "select", rid, id });
    } catch {
      onPortDisconnect();
    }
  }

  function onPortMessage(msg) {
    if (!isObject(msg) || msg.v !== 1 || !pending.has(msg.rid)) return;
    const rid = msg.rid;
    if (pending.get(rid) === "conditional") {
      if (msg.phase === "accounts") {
        if (autofill) autofill.start(rid, msg.accounts, (id) => select(rid, id));
        else respond({ rid, ok: false, error: "NotHandled" });
        return;
      }
      if (msg.phase === "retry") {
        if (autofill) autofill.resume(rid);
        return;
      }
      if (autofill) autofill.stop(rid);
    }
    pending.delete(rid);
    respond(msg);
  }

  function onPortDisconnect() {
    port = null;
    for (const [rid, kind] of pending) {
      if (kind === "conditional" && autofill) autofill.stop(rid);
      const error = kind === "capabilities" || kind === "conditional" ? "NotHandled" : "NotAllowedError";
      respond({ v: 1, rid, ok: false, error });
    }
    pending.clear();
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
      // The shim has already settled a cancelled conditional request.
      if (pending.get(rid) === "conditional") {
        if (autofill) autofill.stop(rid);
        pending.delete(rid);
      }
      if (port === null) return;
    } else {
      if (pending.has(rid)) return;
      if (msg.kind === "create" || msg.kind === "get" || msg.kind === "conditional") {
        if (!isObject(msg.options)) {
          respond({ v: 1, rid, ok: false, error: "NotHandled" });
          return;
        }
        out.options = msg.options;
      }
      pending.set(rid, msg.kind);
    }
    try {
      ensurePort().postMessage(out);
    } catch {
      onPortDisconnect();
    }
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
