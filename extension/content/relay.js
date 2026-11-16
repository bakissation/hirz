// ISOLATED world, document_start, top frame only.
// A dumb pipe between page/shim.js and the background. It adds no identity:
// the background reads the origin from the sender that Firefox reports.
"use strict";

(() => {
  if (window.top !== window) return;

  const BOOT = "hirz-bootstrap";
  const PORT_NAME = "hirz-page";
  const MAX_REQUEST_CHARS = 72 * 1024;
  const KINDS = new Set(["create", "get", "capabilities", "cancel"]);

  let secret = null;
  let port = null;
  const pending = new Map();

  const isObject = (v) => v !== null && typeof v === "object" && !Array.isArray(v);

  function emit(type, detail) {
    window.dispatchEvent(new CustomEvent(type, { detail }));
  }

  function respond(msg) {
    if (secret === null) return;
    emit("hirz-res-" + secret, JSON.stringify(msg));
  }

  function onPortMessage(msg) {
    if (!isObject(msg) || msg.v !== 1 || !pending.has(msg.rid)) return;
    pending.delete(msg.rid);
    respond(msg);
  }

  function onPortDisconnect() {
    port = null;
    for (const [rid, kind] of pending) {
      const error = kind === "capabilities" ? "NotHandled" : "NotAllowedError";
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
      if (!pending.has(rid) || port === null) return;
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
    try {
      ensurePort().postMessage(out);
    } catch {
      onPortDisconnect();
    }
  }

  // Handshake with the shim. Both scripts run before any page script, and
  // whichever loads second completes it synchronously. The shim then hands
  // over a random secret that names the private request and response events.
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
