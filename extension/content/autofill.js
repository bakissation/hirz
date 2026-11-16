// ISOLATED world, document_start, every frame, loaded before content/relay.js.
// The suggestion list for conditional mediation (passkey autofill). It is only a
// hint: choosing an account starts a normal hirz request, and the native host still
// asks the user in its own prompt before anything is signed.
//
// What the page can and cannot see:
// - The list lives in a closed shadow root of an element this script creates and
//   attaches before the page holds a reference to it. Page scripts cannot reach the
//   nodes inside, and the names are drawn as CSS generated content, which the
//   page's find and selection APIs do not see.
// - Only trusted events count. The page can dispatch events at the element, but they
//   are untrusted and never reach the rows.
// - The element is only added after the user clicks into a field marked
//   autocomplete="webauthn", tabs into it, or presses an arrow key in it. From then
//   on the page can see that it exists and how large it is.
"use strict";

globalThis.hirzAutofill = (() => {
  const MAX_ACCOUNTS = 64;
  const MAX_LABEL = 64;
  const TAB_FOCUS_MS = 1000;
  const MIN_WIDTH = 240;
  const GAP = 2;
  // Bidi controls and other invisible formatting characters are page-chosen data.
  const UNSAFE = /[\u0000-\u001f\u007f-\u009f\u00ad\u061c\u200b-\u200f\u2028-\u202e\u2060-\u206f\ufeff]/g;

  const HOST_STYLE = [
    ["position", "fixed"],
    ["inset", "auto"],
    ["margin", "0"],
    ["padding", "0"],
    ["border", "0"],
    ["background", "transparent"],
    ["overflow", "visible"],
    ["height", "auto"],
    ["max-width", "none"],
    ["max-height", "none"],
    ["z-index", "2147483647"],
    ["color-scheme", "light dark"],
  ];

  const SHEET = `
    :host { all: initial; }
    .panel {
      box-sizing: border-box; width: 100%; max-height: 320px; overflow-y: auto;
      font: 13px/1.35 system-ui, sans-serif; color: #1b1b1f; background: #fff;
      border: 1px solid #c4c4cc; border-radius: 6px; box-shadow: 0 4px 16px rgba(0,0,0,.18);
      padding: 4px 0; user-select: none; -moz-user-select: none; cursor: default;
    }
    .head { padding: 2px 10px 4px; font-size: 11px; color: #5b5b66; }
    .head::before { content: "Passkey (hirz)"; }
    .row { padding: 6px 10px; display: flex; flex-direction: column; }
    .row.active { background: #e0e0e6; }
    .main::before { content: attr(data-t); font-weight: 600; }
    .sub::before { content: attr(data-t); font-size: 12px; color: #5b5b66; }
    .main, .sub { overflow: hidden; text-overflow: ellipsis; white-space: nowrap; }
    @media (prefers-color-scheme: dark) {
      .panel { color: #fbfbfe; background: #2b2a33; border-color: #52525e; }
      .head, .sub::before { color: #bfbfc9; }
      .row.active { background: #52525e; }
    }
  `;

  let req = null;
  let ui = null;
  let lastTabAt = -Infinity;
  let frame = 0;

  function label(v) {
    const s = typeof v === "string" ? v.replace(UNSAFE, "").trim() : "";
    const chars = Array.from(s);
    return chars.length > MAX_LABEL ? chars.slice(0, MAX_LABEL - 1).join("") + "\u2026" : s;
  }

  function isField(el) {
    if (!(el instanceof HTMLInputElement) && !(el instanceof HTMLTextAreaElement)) return false;
    const ac = el.getAttribute("autocomplete");
    return typeof ac === "string" && ac.toLowerCase().split(/\s+/).includes("webauthn");
  }

  function targetOf(ev) {
    const path = ev.composedPath();
    return path.length > 0 ? path[0] : ev.target;
  }

  function isOpen() {
    return ui !== null && ui.field !== null;
  }

  function insideUi(ev) {
    return ui !== null && ev.composedPath().includes(ui.host);
  }

  function build() {
    const host = document.createElement("div");
    const root = host.attachShadow({ mode: "closed" });
    for (const [name, value] of HOST_STYLE) host.style.setProperty(name, value, "important");
    if (typeof host.showPopover === "function") host.setAttribute("popover", "manual");
    const style = document.createElement("style");
    style.textContent = SHEET;
    const panel = document.createElement("div");
    panel.className = "panel";
    panel.setAttribute("role", "listbox");
    const head = document.createElement("div");
    head.className = "head";
    panel.append(head);
    root.append(style, panel);
    // Keep the focus in the field while the user clicks a row.
    root.addEventListener("pointerdown", (ev) => ev.preventDefault());
    root.addEventListener("mousedown", (ev) => ev.preventDefault());
    root.addEventListener("click", onRowClick);
    root.addEventListener("pointermove", onRowHover);
    return { host, panel, rows: [], field: null, active: -1 };
  }

  function render() {
    for (const row of ui.rows) row.remove();
    ui.rows = [];
    ui.active = -1;
    for (const account of req.accounts) {
      const display = label(account.displayName);
      const name = label(account.name);
      const row = document.createElement("div");
      row.className = "row";
      row.setAttribute("role", "option");
      const main = document.createElement("div");
      main.className = "main";
      main.setAttribute("data-t", display || name || "Passkey");
      row.append(main);
      if (display && name && name !== display) {
        const sub = document.createElement("div");
        sub.className = "sub";
        sub.setAttribute("data-t", name);
        row.append(sub);
      }
      ui.panel.append(row);
      ui.rows.push(row);
    }
  }

  function setActive(i) {
    if (!ui) return;
    if (ui.active >= 0 && ui.rows[ui.active]) ui.rows[ui.active].classList.remove("active");
    ui.active = i;
    const row = ui.rows[i];
    if (row) {
      row.classList.add("active");
      row.scrollIntoView({ block: "nearest" });
    }
  }

  function place() {
    frame = 0;
    if (!isOpen()) return;
    if (!ui.field.isConnected || !ui.host.isConnected) {
      hide();
      return;
    }
    const r = ui.field.getBoundingClientRect();
    const vw = document.documentElement.clientWidth;
    const vh = window.innerHeight;
    const width = Math.min(Math.max(r.width, MIN_WIDTH), Math.max(vw - 8, 0));
    const left = Math.max(4, Math.min(r.left, vw - width - 4));
    const height = ui.panel.offsetHeight;
    let top = r.bottom + GAP;
    if (top + height > vh && r.top - height - GAP >= 0) top = r.top - height - GAP;
    const s = ui.host.style;
    s.setProperty("left", `${Math.round(left)}px`, "important");
    s.setProperty("top", `${Math.round(top)}px`, "important");
    s.setProperty("width", `${Math.round(width)}px`, "important");
  }

  function schedulePlace() {
    if (frame === 0 && isOpen()) frame = window.requestAnimationFrame(place);
  }

  function show(field) {
    if (!req || req.busy || req.accounts.length === 0) return;
    if (!ui) ui = build();
    if (ui.field === field && ui.host.isConnected) return;
    ui.field = field;
    render();
    if (!ui.host.isConnected) {
      document.documentElement.append(ui.host);
      if (typeof ui.host.showPopover === "function") {
        try {
          ui.host.showPopover();
        } catch {
          // Already shown.
        }
      }
    }
    place();
  }

  function hide() {
    if (!ui) return;
    ui.field = null;
    ui.active = -1;
    if (frame !== 0) {
      window.cancelAnimationFrame(frame);
      frame = 0;
    }
    if (typeof ui.host.hidePopover === "function") {
      try {
        ui.host.hidePopover();
      } catch {
        // Not shown, or removed by the page.
      }
    }
    ui.host.remove();
  }

  function choose(i) {
    if (!req || req.busy) return;
    const account = req.accounts[i];
    if (!account) return;
    req.busy = true;
    hide();
    req.onSelect(account.id);
  }

  function onRowClick(ev) {
    if (!ev.isTrusted || !ui) return;
    const row = ev.target instanceof Element ? ev.target.closest(".row") : null;
    const i = row ? ui.rows.indexOf(row) : -1;
    if (i >= 0) choose(i);
  }

  function onRowHover(ev) {
    if (!ev.isTrusted || !ui) return;
    const row = ev.target instanceof Element ? ev.target.closest(".row") : null;
    const i = row ? ui.rows.indexOf(row) : -1;
    if (i >= 0 && i !== ui.active) setActive(i);
  }

  function onPointerDown(ev) {
    if (!ev.isTrusted || insideUi(ev)) return;
    const t = targetOf(ev);
    if (isField(t)) show(t);
    else if (isOpen()) hide();
  }

  function onFocusIn(ev) {
    if (!ev.isTrusted) return;
    const t = targetOf(ev);
    if (isField(t) && performance.now() - lastTabAt < TAB_FOCUS_MS) show(t);
  }

  function onFocusOut(ev) {
    if (isOpen() && targetOf(ev) === ui.field) hide();
  }

  function onKeyDown(ev) {
    if (!ev.isTrusted) return;
    if (ev.key === "Tab") {
      lastTabAt = performance.now();
      return;
    }
    const t = targetOf(ev);
    if (!isOpen()) {
      if ((ev.key === "ArrowDown" || ev.key === "ArrowUp") && isField(t) && req && !req.busy) {
        show(t);
        if (isOpen()) ev.preventDefault();
      }
      return;
    }
    if (t !== ui.field) return;
    const n = ui.rows.length;
    switch (ev.key) {
      case "ArrowDown":
        ev.preventDefault();
        setActive(ui.active + 1 >= n ? 0 : ui.active + 1);
        return;
      case "ArrowUp":
        ev.preventDefault();
        setActive(ui.active <= 0 ? n - 1 : ui.active - 1);
        return;
      case "Enter":
        if (ui.active >= 0) {
          ev.preventDefault();
          ev.stopImmediatePropagation();
          choose(ui.active);
        }
        return;
      case "Escape":
        hide();
        return;
      default:
        return;
    }
  }

  const LISTENERS = [
    ["pointerdown", onPointerDown],
    ["focusin", onFocusIn],
    ["focusout", onFocusOut],
    ["keydown", onKeyDown],
    ["scroll", schedulePlace],
    ["resize", schedulePlace],
  ];

  function listen(on) {
    for (const [type, fn] of LISTENERS) {
      if (on) window.addEventListener(type, fn, true);
      else window.removeEventListener(type, fn, true);
    }
  }

  function clean(accounts) {
    const out = [];
    if (!Array.isArray(accounts)) return out;
    for (const a of accounts) {
      if (out.length >= MAX_ACCOUNTS) break;
      if (a === null || typeof a !== "object" || typeof a.id !== "string" || a.id === "") continue;
      out.push({ id: a.id, name: a.name, displayName: a.displayName });
    }
    return out;
  }

  // A conditional request with accounts to offer. Replaces any earlier one.
  function start(rid, accounts, onSelect) {
    if (req) stop(req.rid);
    req = { rid, accounts: clean(accounts), onSelect, busy: false };
    listen(true);
  }

  // The request ended: resolved, aborted, superseded or the document is going away.
  function stop(rid) {
    if (!req || req.rid !== rid) return;
    listen(false);
    hide();
    req = null;
    ui = null;
  }

  // The chosen account was not used (prompt cancelled or failed): offer the list again.
  function resume(rid) {
    if (req && req.rid === rid) req.busy = false;
  }

  return Object.freeze({ start, stop, resume });
})();
