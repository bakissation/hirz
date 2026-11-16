// ISOLATED world, document_start, every frame, before content/relay.js. The suggestion list for
// conditional mediation is only a hint: the native host still asks the user before anything is
// signed. Nothing is asked of the host before the user touches a `webauthn` field, and one touch
// asks once: a trusted click in the field, a trusted Tab key release that lands in it, or an arrow
// key in it. Focus alone, which a page can cause with `focus()`, asks nothing, so a page cannot
// learn from this whether hirz holds a passkey, or test several credential lists with one touch.
// What the page can and cannot see: docs/extension.md, "Conditional mediation".
"use strict";

globalThis.hirzAutofill = (() => {
  const MAX_ACCOUNTS = 64;
  const MAX_LABEL = 64;
  // A list answer stays usable this long; an ask that got no answer is repeated after ASK_TIMEOUT_MS.
  const ACCOUNTS_TTL_MS = 5000;
  const ASK_TIMEOUT_MS = 12000;
  // Clicks on a row are ignored this long after the list appeared or moved.
  const ROW_CLICK_DELAY_MS = 500;
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
    ["opacity", "1"],
    ["visibility", "visible"],
    ["pointer-events", "auto"],
    ["transform", "none"],
    ["translate", "none"],
    ["rotate", "none"],
    ["scale", "none"],
    ["filter", "none"],
    ["clip-path", "none"],
    ["mask", "none"],
    ["mix-blend-mode", "normal"],
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
    const styled = adoptSheet(root);
    const panel = document.createElement("div");
    panel.className = "panel";
    panel.setAttribute("role", "listbox");
    const head = document.createElement("div");
    head.className = "head";
    panel.append(head);
    root.append(panel);
    // Keep the focus in the field while the user clicks a row.
    root.addEventListener("pointerdown", (ev) => ev.preventDefault());
    root.addEventListener("mousedown", (ev) => ev.preventDefault());
    root.addEventListener("click", onRowClick);
    root.addEventListener("pointermove", onRowHover);
    return {
      host,
      root,
      panel,
      rows: [],
      field: null,
      active: -1,
      styled,
      checked: false,
      shownAt: 0,
      movedAt: 0,
      pos: "",
    };
  }

  // A constructable stylesheet is not subject to the page's Content Security Policy, a `<style>`
  // element can be.
  function adoptSheet(root) {
    try {
      if (typeof CSSStyleSheet === "function" && "adoptedStyleSheets" in root) {
        const sheet = new CSSStyleSheet();
        sheet.replaceSync(SHEET);
        root.adoptedStyleSheets = [sheet];
        return root.adoptedStyleSheets.length === 1;
      }
    } catch {
      // Fall through to the element.
    }
    return false;
  }

  function appendStyleElement(root) {
    const style = document.createElement("style");
    style.textContent = SHEET;
    root.prepend(style);
  }

  // Once the list is in the document: when the adopted sheet did not take effect, use an element.
  function ensureStyled() {
    if (ui.checked) return;
    ui.checked = true;
    let applied = false;
    try {
      applied = ui.styled && getComputedStyle(ui.panel).boxSizing === "border-box";
    } catch {
      applied = false;
    }
    if (!applied) appendStyleElement(ui.root);
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
    const pos = `${Math.round(left)},${Math.round(top)},${Math.round(width)}`;
    if (pos !== ui.pos) {
      ui.pos = pos;
      ui.movedAt = performance.now();
    }
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
      ui.shownAt = performance.now();
      ensureStyled();
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
    if (performance.now() - Math.max(ui.shownAt, ui.movedAt) < ROW_CLICK_DELAY_MS) return;
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

  // The user touched a `webauthn` field: show the list, asking the host first when the last answer
  // is old. The answer arrives in `provide`.
  function open(field) {
    if (!req || req.busy) return false;
    req.want = field;
    const now = performance.now();
    if (req.answeredAt !== null && now - req.answeredAt < ACCOUNTS_TTL_MS) {
      show(field);
      return isOpen();
    }
    if (req.askedAt === null || now - req.askedAt >= ASK_TIMEOUT_MS) {
      req.askedAt = now;
      req.request();
    }
    return false;
  }

  function stillWanted(field) {
    try {
      return field.isConnected && field.matches(":focus");
    } catch {
      return false;
    }
  }

  function onPointerDown(ev) {
    if (!ev.isTrusted || insideUi(ev)) return;
    const t = targetOf(ev);
    if (isField(t)) open(t);
    else if (isOpen()) hide();
  }

  // The key is released in the field it moved the focus to; a script that calls `focus()` produces
  // a trusted focus event but no key event, and the key event is the touch.
  function onKeyUp(ev) {
    if (!ev.isTrusted || ev.key !== "Tab") return;
    const t = targetOf(ev);
    if (isField(t)) open(t);
  }

  function onFocusOut(ev) {
    if (isOpen() && targetOf(ev) === ui.field) hide();
  }

  function onKeyDown(ev) {
    if (!ev.isTrusted) return;
    const t = targetOf(ev);
    if (!isOpen()) {
      if ((ev.key === "ArrowDown" || ev.key === "ArrowUp") && isField(t) && open(t)) {
        ev.preventDefault();
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
    ["keyup", onKeyUp],
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

  function start(rid, hooks) {
    if (req) stop(req.rid);
    req = {
      rid,
      accounts: [],
      answeredAt: null,
      askedAt: null,
      want: null,
      busy: false,
      request: hooks.request,
      onSelect: hooks.onSelect,
    };
    listen(true);
  }

  function stop(rid) {
    if (!req || req.rid !== rid) return;
    listen(false);
    hide();
    req = null;
    ui = null;
  }

  // The host's answer to the last ask, for the field the user touched.
  function provide(rid, accounts) {
    if (!req || req.rid !== rid) return;
    req.accounts = clean(accounts);
    req.answeredAt = performance.now();
    req.askedAt = null;
    if (req.want !== null && req.accounts.length > 0 && stillWanted(req.want)) show(req.want);
    req.want = null;
  }

  // The list is out of date or the host is gone: forget it, ask again at the next touch.
  function invalidate(rid) {
    if (!req || req.rid !== rid) return;
    hide();
    req.accounts = [];
    req.answeredAt = null;
    req.askedAt = null;
    req.want = null;
    req.busy = false;
  }

  function resume(rid) {
    if (req && req.rid === rid) req.busy = false;
  }

  return Object.freeze({ start, stop, provide, invalidate, resume });
})();
