// Tests for extension/ without a browser: the background event page runs in its own vm context
// against a stub `browser`, and the page-side scripts (shim, autofill, relay) run against a small
// DOM stub with the background on the other end of the port. No dependencies: node:test only.
//
//   node --test scripts/extension-test.mjs
//
// What this cannot show: Firefox's own behaviour (content script worlds, Xray wrappers, the native
// conditional UI). docs/extension.md has the manual checklist for those.
import assert from "node:assert/strict";
import { randomFillSync } from "node:crypto";
import fs from "node:fs";
import path from "node:path";
import { afterEach, test } from "node:test";
import { fileURLToPath } from "node:url";
import vm from "node:vm";

const root = path.join(path.dirname(fileURLToPath(import.meta.url)), "..", "extension");
const source = (file) => fs.readFileSync(path.join(root, file), "utf8");

const BASE64URL_POLYFILL = `
  if (!Uint8Array.prototype.toBase64) {
    Uint8Array.prototype.toBase64 = function (o) {
      const s = Buffer.from(this).toString("base64url");
      return o && o.omitPadding === false ? s + "=".repeat((4 - (s.length % 4)) % 4) : s;
    };
    Uint8Array.fromBase64 = function (s) {
      if (!/^[A-Za-z0-9_-]*={0,2}$/.test(s)) throw new SyntaxError("bad base64url");
      return new Uint8Array(Buffer.from(s, "base64url"));
    };
  }
`;
vm.runInThisContext(BASE64URL_POLYFILL);

const tick = () => new Promise((r) => setImmediate(r));
async function settle(n = 12) {
  for (let i = 0; i < n; i++) await tick();
}
const b64u = (bytes) => Buffer.from(bytes).toString("base64url");
const plain = (v) => JSON.parse(JSON.stringify(v));

// ---------------------------------------------------------------------------------------------
// Background

const ORIGIN = "https://example.com";
const ACCOUNT_A = { id: b64u([1, 2, 3, 4]), name: "alice", displayName: "Alice" };
const ACCOUNT_B = { id: b64u([5, 6, 7, 8]), name: "bob", displayName: "Bob" };

function credentialJson(kind = "get", id = ACCOUNT_A.id) {
  const response = {
    clientDataJSON: b64u(Buffer.from("{}")),
    authenticatorData: b64u(new Uint8Array(37)),
  };
  if (kind === "get") {
    response.signature = b64u([9, 9, 9]);
    response.userHandle = b64u([1]);
  } else {
    response.attestationObject = b64u([1, 2]);
    response.publicKeyAlgorithm = -7;
    response.transports = ["internal"];
  }
  return {
    id,
    rawId: id,
    type: "public-key",
    authenticatorAttachment: "platform",
    response,
    clientExtensionResults: {},
  };
}

// A scriptable native host. `script(msg, host)` may return a reply body, a promise of one, or
// undefined to stay silent; the harness adds `v` and `id`.
function defaultHost(host) {
  return (msg) => {
    switch (msg.type) {
      case "hello":
        return { ok: true, version: "test" };
      case "capabilities":
        return {
          ok: true,
          capabilities: { userVerifyingPlatformAuthenticator: true, passkeyPlatformAuthenticator: true },
        };
      case "list":
        return { ok: true, accounts: host.accounts };
      case "get":
        return { ok: true, credential: credentialJson("get", host.credentialId) };
      case "create":
        return { ok: true, credential: credentialJson("create") };
      default:
        return { ok: false, error: "UnknownError" };
    }
  };
}

function makeBackground(options = {}) {
  const clock = { now: 1_000_000 };
  const log = [];
  const tab = { active: true, windowFocused: true };
  const host = {
    accounts: options.accounts ?? [ACCOUNT_A],
    credentialId: ACCOUNT_A.id,
    available: options.hostAvailable ?? true,
    ports: [],
    sent: [],
    script: null,
    delayTabs: null,
  };
  host.script = defaultHost(host);
  let onConnect = null;
  const framesFor = options.frames ?? (() => []);

  const browser = {
    runtime: {
      id: "hirz@test",
      onConnect: { addListener: (fn) => (onConnect = fn) },
      connectNative() {
        if (!host.available) throw new Error("no native application");
        const port = {
          disconnected: false,
          onMessage: { addListener: (fn) => (port.deliver = fn) },
          onDisconnect: { addListener: (fn) => (port.ondisc = fn) },
          postMessage(msg) {
            const m = plain(msg);
            host.sent.push(m);
            if (m.type === "cancel") return;
            Promise.resolve(host.script(m, port)).then((body) => {
              if (body === undefined || port.disconnected) return;
              port.deliver({ v: 1, id: m.id, ...body });
            });
          },
          disconnect() {
            port.disconnected = true;
          },
          // The host sends a frame that is not a reply to one of ours.
          emit(msg) {
            port.deliver(msg);
          },
        };
        host.ports.push(port);
        return port;
      },
    },
    // Like the real calls, these cross a process boundary: they take more than a microtask.
    tabs: {
      async get() {
        await tick();
        if (host.delayTabs) await host.delayTabs;
        return { active: tab.active, windowId: 1 };
      },
    },
    windows: {
      async get() {
        await tick();
        return { focused: tab.windowFocused };
      },
    },
    webNavigation: { async getAllFrames({ tabId }) { return framesFor(tabId); } },
  };
  const timers = new Set();
  const sandbox = {
    browser,
    console: { warn: (...a) => log.push(a.join(" ")), info() {}, error: (...a) => log.push(a.join(" ")) },
    setTimeout: (fn, ms) => {
      const t = setTimeout(fn, ms);
      t.unref();
      timers.add(t);
      return t;
    },
    clearTimeout: (t) => clearTimeout(t),
    Date: { now: () => clock.now },
    URL,
    Buffer,
  };
  const ctx = vm.createContext(sandbox);
  vm.runInContext(BASE64URL_POLYFILL, ctx);
  vm.runInContext('"use strict";\n' + source("background.js"), ctx, { filename: "background.js" });
  assert.equal(typeof onConnect, "function");

  function connectPage(sender = {}) {
    const page = {
      received: [],
      closed: false,
      onMessage: null,
      onDisconnect: null,
    };
    const port = {
      name: "hirz-page",
      sender: {
        id: "hirz@test",
        tab: { id: 7 },
        frameId: 0,
        origin: ORIGIN,
        ...sender,
      },
      onMessage: { addListener: (fn) => (page.onMessage = fn) },
      onDisconnect: { addListener: (fn) => (page.onDisconnect = fn) },
      postMessage(msg) {
        page.received.push(plain(msg));
      },
      disconnect() {},
    };
    onConnect(port);
    page.post = async (msg) => {
      page.onMessage({ v: 1, ...msg });
      await settle();
    };
    page.disconnect = () => {
      page.closed = true;
      page.onDisconnect();
    };
    page.replies = (rid) => page.received.filter((m) => m.rid === rid);
    return page;
  }
  return { browser, host, tab, clock, log, connectPage, ctx };
}

const getOptions = (extra = {}) => ({
  challenge: b64u(new Uint8Array(32)),
  rpId: "example.com",
  allowCredentials: [],
  userVerification: "preferred",
  ...extra,
});

test("background: a suggestion request lists accounts after a user touch, and never says NotHandled", async () => {
  const bg = makeBackground();
  const page = bg.connectPage();
  await page.post({ kind: "suggest", rid: 1, options: getOptions() });
  assert.deepEqual(page.replies(1), [{ v: 1, rid: 1, phase: "accounts", accounts: [ACCOUNT_A] }]);
  assert.deepEqual(
    bg.host.sent.map((m) => m.type),
    ["hello", "list"],
  );
  const list = bg.host.sent[1];
  assert.equal(list.origin, ORIGIN);
  assert.deepEqual(list.options, { rpId: "example.com", allowCredentials: [] });
});

test("background: nothing reaches the host before a suggestion request", async () => {
  const bg = makeBackground();
  const page = bg.connectPage();
  await settle();
  assert.equal(bg.host.ports.length, 0);
  assert.equal(page.received.length, 0);
});

test("background: list is only asked for the active tab of the focused window", async () => {
  for (const [label, set] of [
    ["background tab", (t) => (t.active = false)],
    ["unfocused window", (t) => (t.windowFocused = false)],
  ]) {
    const bg = makeBackground();
    set(bg.tab);
    const page = bg.connectPage();
    await page.post({ kind: "suggest", rid: 1, options: getOptions() });
    assert.deepEqual(page.replies(1), [{ v: 1, rid: 1, phase: "accounts", accounts: [] }], label);
    assert.equal(bg.host.ports.length, 0, label);
  }
});

test("background: every failure of list is an empty list, not an error", async () => {
  const cases = {
    "host missing": (bg) => (bg.host.available = false),
    "host error": (bg) => (bg.host.script = (m) => (m.type === "hello" ? { ok: true, version: "t" } : { ok: false, error: "NotHandled" })),
    "no accounts": (bg) => (bg.host.accounts = []),
  };
  for (const [label, arrange] of Object.entries(cases)) {
    const bg = makeBackground();
    arrange(bg);
    const page = bg.connectPage();
    await page.post({ kind: "suggest", rid: 1, options: getOptions() });
    assert.deepEqual(page.replies(1), [{ v: 1, rid: 1, phase: "accounts", accounts: [] }], label);
  }
});

test("background: list requests are limited per document and across documents", async () => {
  const bg = makeBackground();
  const page = bg.connectPage();
  await page.post({ kind: "suggest", rid: 1, options: getOptions() });
  await page.post({ kind: "suggest", rid: 1, options: getOptions() });
  const lists = () => bg.host.sent.filter((m) => m.type === "list").length;
  assert.equal(lists(), 1, "a second request inside the minimum gap is not sent");
  assert.deepEqual(page.replies(1)[1].accounts, []);
  for (let i = 0; i < 40; i++) {
    bg.clock.now += 1100;
    await page.post({ kind: "suggest", rid: 1, options: getOptions() });
  }
  assert.equal(lists(), 12, "at most 12 per minute for one document");
  bg.clock.now += 61_000;
  await page.post({ kind: "suggest", rid: 1, options: getOptions() });
  assert.equal(lists(), 13);
  // A second document is limited by the global budget.
  const other = bg.connectPage({ tab: { id: 8 } });
  let asked = 0;
  for (let i = 0; i < 100; i++) {
    bg.clock.now += 150;
    const before = lists();
    await other.post({ kind: "suggest", rid: i + 1, options: getOptions() });
    asked += lists() - before;
  }
  assert.ok(asked <= 12, `second document is capped by its own budget (${asked})`);
});

test("background: the frames of one tab share a minimum gap between lists", async () => {
  const bg = makeBackground();
  const lists = () => bg.host.sent.filter((m) => m.type === "list").length;
  const first = bg.connectPage();
  const second = bg.connectPage();
  await first.post({ kind: "suggest", rid: 1, options: getOptions() });
  bg.clock.now += 200;
  await second.post({ kind: "suggest", rid: 1, options: getOptions() });
  assert.equal(lists(), 1, "a second frame of the same tab inside the gap is not asked");
  assert.deepEqual(second.replies(1), [{ v: 1, rid: 1, phase: "accounts", accounts: [] }]);

  const elsewhere = bg.connectPage({ tab: { id: 8 } });
  bg.clock.now += 150;
  await elsewhere.post({ kind: "suggest", rid: 1, options: getOptions() });
  assert.equal(lists(), 2, "another tab has its own gap");

  bg.clock.now += 1100;
  await second.post({ kind: "suggest", rid: 2, options: getOptions() });
  assert.equal(lists(), 3, "after the gap the tab may ask again");
});

test("background: select runs a get narrowed to the listed id and answers with the credential", async () => {
  const bg = makeBackground({ accounts: [ACCOUNT_A, ACCOUNT_B] });
  const page = bg.connectPage();
  await page.post({ kind: "suggest", rid: 3, options: getOptions({ allowCredentials: [{ type: "public-key", id: "x" }] }) });
  await page.post({ kind: "select", rid: 3, id: ACCOUNT_B.id });
  const get = bg.host.sent.find((m) => m.type === "get");
  assert.deepEqual(get.options.allowCredentials, [{ type: "public-key", id: ACCOUNT_B.id }]);
  assert.equal(get.options.mediation, undefined);
  const last = page.replies(3).at(-1);
  assert.equal(last.ok, true);
  assert.equal(last.credential.type, "public-key");
});

test("background: select narrows prf.evalByCredential to the chosen credential", async () => {
  const bg = makeBackground({ accounts: [ACCOUNT_A, ACCOUNT_B] });
  const page = bg.connectPage();
  const prf = {
    evalByCredential: {
      [ACCOUNT_A.id]: { first: "QQ" },
      [ACCOUNT_B.id + "="]: { first: "Qg" },
    },
  };
  await page.post({ kind: "suggest", rid: 3, options: getOptions({ extensions: { prf } }) });
  await page.post({ kind: "select", rid: 3, id: ACCOUNT_B.id });
  const get = bg.host.sent.find((m) => m.type === "get");
  assert.deepEqual(Object.keys(get.options.extensions.prf.evalByCredential), [ACCOUNT_B.id + "="]);
});

test("background: select for an id that was not listed answers stale and asks the host nothing", async () => {
  const bg = makeBackground();
  const page = bg.connectPage();
  await page.post({ kind: "suggest", rid: 3, options: getOptions() });
  await page.post({ kind: "select", rid: 3, id: b64u([42]) });
  assert.deepEqual(page.replies(3).at(-1), { v: 1, rid: 3, phase: "stale" });
  assert.equal(bg.host.sent.filter((m) => m.type === "get").length, 0);
  // A background that lost its state (event page restarted) says the same.
  const fresh = makeBackground().connectPage();
  await fresh.post({ kind: "select", rid: 3, id: ACCOUNT_A.id });
  assert.deepEqual(fresh.replies(3), [{ v: 1, rid: 3, phase: "stale" }]);
});

test("background: a refused prompt keeps the list usable, a NotHandled makes it stale", async () => {
  const bg = makeBackground();
  const page = bg.connectPage();
  await page.post({ kind: "suggest", rid: 1, options: getOptions() });
  bg.host.script = (m) => (m.type === "get" ? { ok: false, error: "NotAllowedError" } : defaultHost(bg.host)(m));
  await page.post({ kind: "select", rid: 1, id: ACCOUNT_A.id });
  assert.deepEqual(page.replies(1).at(-1), { v: 1, rid: 1, phase: "retry" });
  bg.host.script = (m) => (m.type === "get" ? { ok: false, error: "NotHandled" } : defaultHost(bg.host)(m));
  await page.post({ kind: "select", rid: 1, id: ACCOUNT_A.id });
  assert.deepEqual(page.replies(1).at(-1), { v: 1, rid: 1, phase: "stale" });
});

test("background: a cancel that arrives before the host call stops the request", async () => {
  for (const kind of ["get", "create"]) {
    const bg = makeBackground();
    let release;
    bg.host.delayTabs = new Promise((r) => (release = r));
    const page = bg.connectPage();
    page.onMessage({ v: 1, kind, rid: 1, options: kind === "get" ? getOptions() : { challenge: "x" } });
    await settle();
    page.onMessage({ v: 1, kind: "cancel", rid: 1 });
    await settle();
    release();
    await settle();
    assert.equal(bg.host.sent.filter((m) => m.type === kind).length, 0, kind);
    assert.deepEqual(page.replies(1), [{ v: 1, rid: 1, ok: false, error: "AbortError" }], kind);
  }
});

test("background: a cancel while the host works reaches the host", async () => {
  const bg = makeBackground();
  bg.host.script = (m) => (m.type === "get" ? undefined : defaultHost(bg.host)(m));
  const page = bg.connectPage();
  page.onMessage({ v: 1, kind: "get", rid: 1, options: getOptions() });
  await settle();
  const get = bg.host.sent.find((m) => m.type === "get");
  page.onMessage({ v: 1, kind: "cancel", rid: 1 });
  await settle();
  assert.deepEqual(bg.host.sent.at(-1), { v: 1, id: get.id, type: "cancel" });
});

test("background: options the host's strict reader would reject never leave", async () => {
  let deep = "x";
  for (let i = 0; i < 40; i++) deep = { a: deep };
  const bad = [
    getOptions({ extensions: deep }),
    getOptions({ rpId: "ab\ud800" }),
    getOptions({ ["k\udc00"]: 1 }),
    getOptions({ big: Array.from({ length: 30000 }, () => 0) }),
  ];
  for (const options of bad) {
    const bg = makeBackground();
    const page = bg.connectPage();
    await page.post({ kind: "get", rid: 1, options });
    assert.deepEqual(page.replies(1), [{ v: 1, rid: 1, ok: false, error: "NotHandled" }]);
    assert.equal(bg.host.ports.length, 0);
    await page.post({ kind: "suggest", rid: 2, options });
    assert.deepEqual(page.replies(2), [{ v: 1, rid: 2, phase: "accounts", accounts: [] }]);
  }
});

test("background: a host reply with a null id restarts the host and fails what was pending", async () => {
  const bg = makeBackground();
  bg.host.script = (m) => (m.type === "get" ? undefined : defaultHost(bg.host)(m));
  const page = bg.connectPage();
  page.onMessage({ v: 1, kind: "get", rid: 1, options: getOptions() });
  await settle();
  bg.host.ports[0].emit({ v: 1, id: null, ok: false, error: "UnknownError", message: "invalid JSON" });
  await settle();
  assert.deepEqual(page.replies(1), [{ v: 1, rid: 1, ok: false, error: "NotAllowedError" }]);
  assert.ok(bg.host.ports[0].disconnected);
});

test("background: ceremonies are limited per document and then go to Firefox", async () => {
  const bg = makeBackground();
  const page = bg.connectPage();
  for (let rid = 1; rid <= 25; rid++) await page.post({ kind: "get", rid, options: getOptions() });
  const gets = bg.host.sent.filter((m) => m.type === "get").length;
  assert.equal(gets, 20);
  assert.deepEqual(page.replies(25), [{ v: 1, rid: 25, ok: false, error: "NotHandled" }]);
});

test("background: capabilities failures are remembered briefly and requests share one call", async () => {
  const bg = makeBackground();
  let answers = 0;
  bg.host.script = (m) => {
    if (m.type !== "capabilities") return defaultHost(bg.host)(m);
    answers++;
    return answers === 1 ? { ok: false, error: "UnknownError" } : defaultHost(bg.host)(m);
  };
  const page = bg.connectPage();
  await Promise.all([
    page.post({ kind: "capabilities", rid: 1 }),
    page.post({ kind: "capabilities", rid: 2 }),
  ]);
  assert.equal(answers, 1);
  assert.deepEqual(page.replies(1), [{ v: 1, rid: 1, ok: false, error: "NotHandled" }]);
  bg.clock.now += 6000;
  await page.post({ kind: "capabilities", rid: 3 });
  assert.equal(page.replies(3)[0].ok, true);
  bg.clock.now += 30_000;
  await page.post({ kind: "capabilities", rid: 4 });
  assert.equal(answers, 2, "a good answer is kept for 60 s");
});

test("background: only the expected members of a credential are passed on", async () => {
  const bg = makeBackground();
  bg.host.script = (m) => {
    if (m.type !== "get") return defaultHost(bg.host)(m);
    const c = credentialJson("get");
    c.clientExtensionResults = {
      appid: false,
      credProps: { rk: true, extra: 1 },
      prf: { enabled: true, results: { first: "AAAA", second: 5, junk: 1 }, junk: 1 },
      largeBlob: { supported: true, junk: 1 },
      unknown: { x: 1 },
    };
    c.extra = "x";
    c.response.extra = "y";
    return { ok: true, credential: c, extra: 1 };
  };
  const page = bg.connectPage();
  await page.post({ kind: "get", rid: 1, options: getOptions() });
  const r = page.replies(1)[0];
  assert.deepEqual(Object.keys(r.credential).sort(), [
    "authenticatorAttachment",
    "clientExtensionResults",
    "id",
    "rawId",
    "response",
    "type",
  ]);
  assert.deepEqual(Object.keys(r.credential.response).sort(), [
    "authenticatorData",
    "clientDataJSON",
    "signature",
    "userHandle",
  ]);
  assert.deepEqual(r.credential.clientExtensionResults, {
    appid: false,
    credProps: { rk: true },
    prf: { enabled: true, results: { first: "AAAA" } },
    largeBlob: { supported: true },
  });
});

test("background: a sender in a cross-origin frame or an odd origin gets NotHandled", async () => {
  const bg = makeBackground({
    frames: () => [
      { frameId: 0, parentFrameId: -1, url: "https://other.example/" },
      { frameId: 4, parentFrameId: 0, url: ORIGIN + "/inner" },
    ],
  });
  const page = bg.connectPage({ frameId: 4 });
  await page.post({ kind: "get", rid: 1, options: getOptions() });
  assert.deepEqual(page.replies(1), [{ v: 1, rid: 1, ok: false, error: "NotHandled" }]);
  const odd = bg.connectPage({ origin: "http://example.com" });
  await odd.post({ kind: "get", rid: 1, options: getOptions() });
  assert.deepEqual(odd.replies(1), [{ v: 1, rid: 1, ok: false, error: "NotHandled" }]);
  assert.equal(bg.host.sent.filter((m) => m.type === "get").length, 0);
});

// ---------------------------------------------------------------------------------------------
// Page side: shim, autofill and relay against the background

class FakeStyle {
  constructor() {
    this.props = new Map();
  }
  setProperty(name, value, priority) {
    this.props.set(name, { value, priority });
  }
}

class FakeNode {
  constructor(tag) {
    this.tag = tag;
    this.children = [];
    this.attrs = new Map();
    this.style = new FakeStyle();
    this.isConnected = false;
    this.parent = null;
    this.listeners = new Map();
    this.className = "";
    this.rect = { left: 10, top: 10, bottom: 40, width: 300, height: 30 };
    this.adoptedStyleSheets = [];
    this.shadow = null;
  }
  setConnected(v) {
    this.isConnected = v;
    for (const c of this.children) c.setConnected(v);
    if (this.shadow) this.shadow.setConnected(v);
  }
  append(...nodes) {
    for (const n of nodes) {
      n.parent = this;
      this.children.push(n);
      n.setConnected(this.isConnected);
    }
  }
  prepend(...nodes) {
    for (const n of nodes.reverse()) {
      n.parent = this;
      this.children.unshift(n);
      n.setConnected(this.isConnected);
    }
  }
  remove() {
    if (this.parent) this.parent.children = this.parent.children.filter((c) => c !== this);
    this.parent = null;
    this.setConnected(false);
  }
  setAttribute(k, v) {
    this.attrs.set(k, String(v));
  }
  getAttribute(k) {
    return this.attrs.get(k) ?? null;
  }
  attachShadow() {
    this.shadow = new FakeNode("#shadow");
    this.shadow.isConnected = this.isConnected;
    return this.shadow;
  }
  closest(sel) {
    for (let n = this; n; n = n.parent) if (sel === ".row" && n.className === "row") return n;
    return null;
  }
  matches(sel) {
    return sel === ":focus" && globalThis.document.activeElement === this;
  }
  addEventListener(type, fn) {
    const list = this.listeners.get(type) ?? [];
    list.push(fn);
    this.listeners.set(type, list);
  }
  fire(type, ev) {
    for (const fn of this.listeners.get(type) ?? []) fn(ev);
  }
  getBoundingClientRect() {
    return this.rect;
  }
  get offsetHeight() {
    return 100;
  }
  scrollIntoView() {}
  showPopover() {}
  hidePopover() {}
  get classList() {
    const self = this;
    return {
      add(c) {
        self.className = `${self.className} ${c}`.trim();
      },
      remove(c) {
        self.className = self.className.split(" ").filter((x) => x !== c).join(" ");
      },
    };
  }
}
class FakeInput extends FakeNode {}
class FakeTextArea extends FakeNode {}

class FakeWindow extends EventTarget {
  constructor() {
    super();
    this.recorded = new Map();
  }
  addEventListener(type, fn, opts) {
    const list = this.recorded.get(type) ?? [];
    list.push(fn);
    this.recorded.set(type, list);
    super.addEventListener(type, fn, opts);
  }
  removeEventListener(type, fn, opts) {
    this.recorded.set(type, (this.recorded.get(type) ?? []).filter((f) => f !== fn));
    super.removeEventListener(type, fn, opts);
  }
  // A UI event: plain object, so isTrusted can be true.
  fireUi(type, ev) {
    for (const fn of this.recorded.get(type) ?? []) fn(ev);
  }
  requestAnimationFrame(fn) {
    return setTimeout(fn, 0);
  }
  cancelAnimationFrame(id) {
    clearTimeout(id);
  }
}

const SAVED = {};
const GLOBAL_NAMES = [
  "window", "document", "browser", "hirzAutofill", "performance", "Document", "Crypto", "Element",
  "HTMLInputElement", "HTMLTextAreaElement", "getComputedStyle", "CSSStyleSheet",
];

function installGlobals(values) {
  for (const name of GLOBAL_NAMES) {
    if (!(name in SAVED)) SAVED[name] = Object.getOwnPropertyDescriptor(globalThis, name);
  }
  for (const [name, value] of Object.entries(values)) {
    Object.defineProperty(globalThis, name, { value, configurable: true, writable: true });
  }
}

function restoreGlobals() {
  for (const name of GLOBAL_NAMES) {
    if (SAVED[name]) Object.defineProperty(globalThis, name, SAVED[name]);
    else delete globalThis[name];
  }
}
afterEach(restoreGlobals);

// A page with the three content scripts loaded, wired to a real background through ports.
function makePage(options = {}) {
  const clock = { now: 50_000 };
  const bg = makeBackground(options.background ?? {});
  const win = new FakeWindow();
  const doc = {
    hasFocus: () => true,
    activeElement: null,
    documentElement: new FakeNode("html"),
    createElement: (tag) => new FakeNode(tag),
  };
  doc.documentElement.isConnected = true;
  class FakeDocument {
    hasFocus() {
      return true;
    }
  }
  Object.setPrototypeOf(doc, FakeDocument.prototype);
  class FakeCrypto {
    getRandomValues(a) {
      return randomFillSync(a);
    }
  }
  class FakeResponse {}
  class FakeAttestation extends FakeResponse {}
  class FakeAssertion extends FakeResponse {}
  function PublicKeyCredential() {}
  PublicKeyCredential.isUserVerifyingPlatformAuthenticatorAvailable = async () => false;
  PublicKeyCredential.getClientCapabilities = async () => ({});
  PublicKeyCredential.isConditionalMediationAvailable = async () => false;
  function CredentialsContainer() {}
  const native = { gets: [], creates: [], impl: null };
  CredentialsContainer.prototype.create = function (opts) {
    native.creates.push(opts);
    return new Promise(() => {});
  };
  CredentialsContainer.prototype.get = function (opts) {
    return native.impl(opts);
  };
  const container = new CredentialsContainer();
  Object.assign(win, {
    window: win,
    parent: null,
    top: null,
    origin: ORIGIN,
    isSecureContext: true,
    location: { hostname: "example.com" },
    document: doc,
    crypto: new FakeCrypto(),
    navigator: { credentials: container },
    PublicKeyCredential,
    CredentialsContainer,
    AuthenticatorAttestationResponse: FakeAttestation,
    AuthenticatorAssertionResponse: FakeAssertion,
    DOMException,
    CustomEvent,
    AbortController,
    setTimeout,
    clearTimeout,
    innerHeight: 800,
  });
  win.parent = win;
  win.top = win;
  doc.documentElement.clientWidth = 1000;

  // Ports between the relay and the background.
  const connections = [];
  const runtime = {
    connect({ name }) {
      const relaySide = {
        name,
        listeners: [],
        disc: [],
        closed: false,
        onMessage: { addListener: (fn) => relaySide.listeners.push(fn) },
        onDisconnect: { addListener: (fn) => relaySide.disc.push(fn) },
        postMessage(msg) {
          if (relaySide.closed) throw new Error("port closed");
          const m = plain(msg);
          setImmediate(() => !relaySide.closed && bgPage.onMessage({ ...m }));
        },
      };
      const bgPage = bg.connectPage(options.sender ?? {});
      const post = bgPage.onMessage;
      bgPage.onMessage = post;
      // Deliver what the background wrote to the relay.
      const origPush = bgPage.received.push.bind(bgPage.received);
      bgPage.received.push = (m) => {
        origPush(m);
        setImmediate(() => !relaySide.closed && relaySide.listeners.forEach((fn) => fn(plain(m))));
      };
      relaySide.suspend = () => {
        relaySide.closed = true;
        bgPage.disconnect();
        setImmediate(() => relaySide.disc.forEach((fn) => fn()));
      };
      connections.push({ relaySide, bgPage });
      return relaySide;
    },
  };
  installGlobals({
    window: win,
    document: doc,
    Document: FakeDocument,
    Crypto: FakeCrypto,
    Element: FakeNode,
    HTMLInputElement: FakeInput,
    HTMLTextAreaElement: FakeTextArea,
    browser: { runtime },
    getComputedStyle: (el) => ({
      boxSizing:
        el.parent && (el.parent.adoptedStyleSheets.length > 0 || el.parent.children.some((c) => c.tag === "style"))
          ? "border-box"
          : "content-box",
    }),
    CSSStyleSheet: options.noAdopt
      ? undefined
      : class {
          replaceSync(css) {
            this.css = css;
          }
        },
    performance: { now: () => clock.now },
  });
  for (const file of ["page/shim.js", "content/autofill.js", "content/relay.js"]) {
    vm.runInThisContext(source(file), { filename: file });
  }
  // The shim's own event: whatever the relay answers on the private channel.
  const toPage = [];
  const origDispatch = EventTarget.prototype.dispatchEvent;
  win.dispatchEvent = function (ev) {
    if (typeof ev.type === "string" && ev.type.startsWith("hirz-res-")) toPage.push(ev.detail);
    return origDispatch.call(this, ev);
  };

  const field = new FakeInput("input");
  field.setAttribute("autocomplete", "username webauthn");
  doc.documentElement.append(field);

  const page = {
    win,
    doc,
    bg,
    clock,
    native,
    container,
    field,
    toPage,
    connections,
    gestures: {
      touch(target = field) {
        doc.activeElement = target;
        win.fireUi("pointerdown", { isTrusted: true, target, composedPath: () => [target] });
      },
      // The key goes down in the previous element, moves the focus, and comes up in the field.
      focusByTab(target = field) {
        win.fireUi("keydown", { isTrusted: true, key: "Tab", target: doc, composedPath: () => [doc] });
        doc.activeElement = target;
        win.fireUi("focusin", { isTrusted: true, target, composedPath: () => [target] });
        win.fireUi("keyup", { isTrusted: true, key: "Tab", target, composedPath: () => [target] });
      },
      // What a page's `focus()` produces: a trusted focus event and no key or pointer event.
      focusByScript(target = field) {
        doc.activeElement = target;
        win.fireUi("focusin", { isTrusted: true, target, composedPath: () => [target] });
      },
    },
    list() {
      return doc.documentElement.children.find((c) => c.shadow && c.attrs.has("popover"));
    },
    rows() {
      const host = page.list();
      return host ? host.shadow.children.find((c) => c.className === "panel").children.filter((c) => c.className === "row") : [];
    },
    click(row) {
      const host = page.list();
      host.shadow.fire("click", { isTrusted: true, target: row });
    },
    advance(ms) {
      clock.now += ms;
      bg.clock.now += ms;
    },
  };
  return page;
}

// Firefox's own conditional request as the shim sees it: reads the options the way WebIDL does,
// and ends when its signal aborts.
function nativeConditional(page) {
  const reads = { challenge: 0, mediation: 0 };
  page.native.impl = (opts) => {
    const pk = opts.publicKey;
    void pk.challenge;
    void opts.mediation;
    const call = { opts, signal: opts.signal, resolve: null, reject: null };
    page.native.gets.push(call);
    return new Promise((resolve, reject) => {
      call.resolve = resolve;
      call.reject = reject;
      call.signal?.addEventListener("abort", () => reject(call.signal.reason ?? new DOMException("aborted", "AbortError")));
    });
  };
  return reads;
}

function conditionalArgs(page, extra = {}) {
  const counts = { challenge: 0, signal: 0 };
  const publicKey = {
    get challenge() {
      counts.challenge++;
      return new Uint8Array(32);
    },
    allowCredentials: [],
    rpId: "example.com",
  };
  const options = {
    mediation: "conditional",
    publicKey,
    get signal() {
      counts.signal++;
      return extra.signal;
    },
  };
  return { options, counts };
}

test("page: a conditional get starts Firefox's own request at once and asks nothing of the host", async () => {
  for (const hasAccounts of [true, false]) {
    const page = makePage({ background: { accounts: hasAccounts ? [ACCOUNT_A] : [], hostAvailable: hasAccounts } });
    nativeConditional(page);
    const { options, counts } = conditionalArgs(page);
    const promise = page.container.get(options);
    assert.equal(page.native.gets.length, 1, "Firefox's request starts synchronously");
    assert.equal(counts.challenge, 2, "the options are read once by the shim and once by Firefox");
    await settle();
    assert.equal(page.bg.host.ports.length, 0, "no host call before a user touch");
    assert.deepEqual(page.toPage, [], "nothing is ever sent back to the page world");
    page.native.gets[0].resolve("native credential");
    assert.equal(await promise, "native credential");
  }
});

test("page: hirz with a passkey and hirz without look the same to the page until the user touches a field", async () => {
  const traces = [];
  for (const accounts of [[ACCOUNT_A], []]) {
    const page = makePage({ background: { accounts } });
    nativeConditional(page);
    const { options, counts } = conditionalArgs(page);
    void page.container.get(options);
    await settle(10);
    page.advance(60_000);
    await settle(10);
    traces.push({
      nativeCalls: page.native.gets.length,
      reads: counts.challenge,
      toPage: page.toPage,
      domChanges: page.doc.documentElement.children.length,
      hostPorts: page.bg.host.ports.length,
    });
  }
  assert.deepEqual(traces[0], traces[1]);
});

test("page: touching the field shows hirz's list, choosing a row settles with the hirz credential and aborts Firefox's request", async () => {
  const page = makePage({ background: { accounts: [ACCOUNT_A, ACCOUNT_B] } });
  nativeConditional(page);
  const { options } = conditionalArgs(page);
  const promise = page.container.get(options);
  await settle();
  assert.equal(page.list(), undefined);

  page.gestures.touch();
  await settle(10);
  assert.equal(page.rows().length, 2);
  assert.equal(page.rows()[0].children[0].getAttribute("data-t"), "Alice");

  page.advance(600);
  page.click(page.rows()[1]);
  await settle(12);
  const get = page.bg.host.sent.find((m) => m.type === "get");
  assert.deepEqual(get.options.allowCredentials, [{ type: "public-key", id: ACCOUNT_B.id }]);
  assert.equal(get.options.mediation, undefined);
  const credential = await promise;
  assert.equal(credential.type, "public-key");
  assert.equal(credential.id, ACCOUNT_A.id);
  assert.equal(page.native.gets[0].signal.aborted, true, "Firefox's request was aborted");
  assert.equal(page.list(), undefined, "the list is gone");
});

test("page: a click on a row right after the list appeared is ignored", async () => {
  const page = makePage();
  nativeConditional(page);
  void page.container.get(conditionalArgs(page).options);
  page.gestures.touch();
  await settle(10);
  const row = page.rows()[0];
  page.advance(100);
  page.click(row);
  await settle(10);
  assert.equal(page.bg.host.sent.filter((m) => m.type === "get").length, 0);
  page.advance(500);
  page.click(row);
  await settle(10);
  assert.equal(page.bg.host.sent.filter((m) => m.type === "get").length, 1);
});

test("page: the list host element pins the properties a page could use to hide it", async () => {
  const page = makePage();
  nativeConditional(page);
  void page.container.get(conditionalArgs(page).options);
  page.gestures.touch();
  await settle(10);
  const style = page.list().style.props;
  for (const [name, value] of [
    ["opacity", "1"],
    ["visibility", "visible"],
    ["pointer-events", "auto"],
    ["transform", "none"],
    ["filter", "none"],
    ["clip-path", "none"],
  ]) {
    assert.deepEqual(style.get(name), { value, priority: "important" }, name);
  }
});

test("page: the list uses an adopted stylesheet, and a style element when that does not take effect (suspicion 1)", async () => {
  const adopted = makePage();
  nativeConditional(adopted);
  void adopted.container.get(conditionalArgs(adopted).options);
  adopted.gestures.touch();
  await settle(10);
  const root = adopted.list().shadow;
  assert.equal(root.adoptedStyleSheets.length, 1);
  assert.ok(!root.children.some((c) => c.tag === "style"));

  const fallback = makePage({ noAdopt: true });
  nativeConditional(fallback);
  void fallback.container.get(conditionalArgs(fallback).options);
  fallback.gestures.touch();
  await settle(10);
  assert.ok(fallback.list().shadow.children.some((c) => c.tag === "style"));
});

test("page: a Tab into the field opens the list, a synthetic event does not", async () => {
  const page = makePage();
  nativeConditional(page);
  void page.container.get(conditionalArgs(page).options);
  await settle();
  page.win.fireUi("pointerdown", { isTrusted: false, target: page.field, composedPath: () => [page.field] });
  await settle();
  assert.equal(page.bg.host.ports.length, 0);
  page.gestures.focusByTab();
  await settle(10);
  assert.equal(page.rows().length, 1);
});

test("page: focus() alone asks nothing, even right after a Tab press", async () => {
  const page = makePage();
  nativeConditional(page);
  void page.container.get(conditionalArgs(page).options);
  await settle();
  page.win.fireUi("keydown", { isTrusted: true, key: "Tab", target: page.doc, composedPath: () => [page.doc] });
  page.gestures.focusByScript();
  await settle(10);
  assert.equal(page.bg.host.ports.length, 0, "a Tab key down that did not end in the field is not a touch");
  assert.equal(page.list(), undefined);
});

test("page: one Tab press tests one credential list, not several", async () => {
  const page = makePage();
  nativeConditional(page);
  const lists = () => page.bg.host.sent.filter((m) => m.type === "list");
  void page.container.get(conditionalArgs(page).options);
  await settle();
  page.gestures.focusByTab();
  await settle(10);
  assert.equal(lists().length, 1);
  assert.equal(page.rows().length, 1);

  // The page starts a second conditional request with other credential ids and focuses the field
  // again, twice, each time a little later than the minimum gap between two lists.
  void page.container.get(conditionalArgs(page).options);
  await settle();
  for (let i = 0; i < 2; i++) {
    page.advance(510);
    page.gestures.focusByScript();
    await settle(10);
  }
  assert.equal(lists().length, 1, "the page learned the answer for one list per touch");

  page.advance(510);
  page.gestures.focusByTab();
  await settle(10);
  assert.equal(lists().length, 2, "the next touch asks again");
});

test("page: touches are answered from the last list for a few seconds, then ask again", async () => {
  const page = makePage();
  nativeConditional(page);
  void page.container.get(conditionalArgs(page).options);
  const lists = () => page.bg.host.sent.filter((m) => m.type === "list").length;
  page.gestures.touch();
  await settle(10);
  page.gestures.touch();
  page.gestures.touch();
  await settle(10);
  assert.equal(lists(), 1);
  page.advance(5100);
  page.gestures.touch(new FakeInput("input"));
  page.doc.activeElement = page.field;
  page.gestures.touch();
  await settle(10);
  assert.equal(lists(), 2);
});

test("page: a touch with no accounts shows nothing and the empty answer is remembered", async () => {
  const page = makePage({ background: { accounts: [] } });
  nativeConditional(page);
  void page.container.get(conditionalArgs(page).options);
  page.gestures.touch();
  page.gestures.touch();
  await settle(10);
  assert.equal(page.list(), undefined);
  assert.equal(page.bg.host.sent.filter((m) => m.type === "list").length, 1);
  assert.deepEqual(page.toPage, []);
});

test("page: aborting the page's signal rejects with its reason, ends Firefox's request and removes the list", async () => {
  const page = makePage();
  nativeConditional(page);
  const controller = new AbortController();
  const { options } = conditionalArgs(page, { signal: controller.signal });
  const promise = page.container.get(options);
  const outcome = promise.then(() => "resolved", (e) => e);
  page.gestures.touch();
  await settle(10);
  assert.equal(page.rows().length, 1);
  const reason = new Error("page gave up");
  controller.abort(reason);
  assert.equal(await outcome, reason);
  assert.equal(page.native.gets[0].signal.aborted, true);
  await settle();
  assert.equal(page.list(), undefined);
});

test("page: Firefox's own result settles the promise and cancels a running hirz prompt", async () => {
  const page = makePage();
  nativeConditional(page);
  page.bg.host.script = (m) => (m.type === "get" ? undefined : defaultHost(page.bg.host)(m));
  const promise = page.container.get(conditionalArgs(page).options);
  page.gestures.touch();
  await settle(10);
  page.advance(600);
  page.click(page.rows()[0]);
  await settle(10);
  const get = page.bg.host.sent.find((m) => m.type === "get");
  assert.ok(get);
  page.native.gets[0].resolve("native result");
  assert.equal(await promise, "native result");
  await settle(10);
  assert.deepEqual(page.bg.host.sent.at(-1), { v: 1, id: get.id, type: "cancel" });
});

test("page: when Firefox rejects its request the page sees the same rejection", async () => {
  const page = makePage();
  nativeConditional(page);
  const promise = page.container.get(conditionalArgs(page).options);
  const failure = new DOMException("replaced", "AbortError");
  page.native.gets[0].reject(failure);
  await assert.rejects(promise, (e) => e === failure);
});

test("page: a suspended background only costs the list; the next touch asks again (suspicion 2)", async () => {
  const page = makePage();
  nativeConditional(page);
  const promise = page.container.get(conditionalArgs(page).options);
  page.gestures.touch();
  await settle(10);
  assert.equal(page.rows().length, 1);
  page.connections[0].relaySide.suspend();
  await settle(10);
  assert.equal(page.list(), undefined, "the list is hidden");
  assert.deepEqual(page.toPage, [], "the page learns nothing");

  page.advance(1000);
  page.gestures.touch();
  await settle(10);
  assert.equal(page.connections.length, 2, "a new port wakes the background");
  assert.equal(page.rows().length, 1);
  page.advance(600);
  page.click(page.rows()[0]);
  const credential = await promise;
  assert.equal(credential.type, "public-key");
});

test("page: a modal get with NotHandled still goes to Firefox once the tab has focus", async () => {
  const page = makePage({ background: { hostAvailable: false } });
  const seen = [];
  page.native.impl = (opts) => {
    seen.push(opts);
    return Promise.resolve("native");
  };
  const options = { publicKey: { challenge: new Uint8Array(32), rpId: "example.com" } };
  const result = await page.container.get(options);
  assert.equal(result, "native");
  assert.equal(seen[0], options, "unchanged options object");
});

test("page: challenges and credential ids outside the host's limits go to Firefox without a host call", async () => {
  const page = makePage();
  const seen = [];
  page.native.impl = (opts) => {
    seen.push(opts);
    return Promise.resolve("native");
  };
  const shortChallenge = { publicKey: { challenge: new Uint8Array(8), rpId: "example.com" } };
  const longChallenge = { publicKey: { challenge: new Uint8Array(1025), rpId: "example.com" } };
  const emptyId = {
    publicKey: {
      challenge: new Uint8Array(32),
      rpId: "example.com",
      allowCredentials: [{ type: "public-key", id: new Uint8Array(0) }],
    },
  };
  for (const options of [shortChallenge, longChallenge, emptyId]) {
    assert.equal(await page.container.get(options), "native");
  }
  assert.equal(seen.length, 3);
  await settle();
  assert.equal(page.bg.host.ports.length, 0);
});

test("page: a modal get is answered by the host with a credential object", async () => {
  const page = makePage();
  const options = { publicKey: { challenge: new Uint8Array(32), rpId: "example.com" } };
  const credential = await page.container.get(options);
  assert.equal(credential.type, "public-key");
  assert.equal(credential.id, ACCOUNT_A.id);
  assert.equal(page.bg.host.sent.find((m) => m.type === "get").origin, ORIGIN);
});

test("page: aborting a modal get at once never reaches the host", async () => {
  const page = makePage();
  const controller = new AbortController();
  const options = { publicKey: { challenge: new Uint8Array(32), rpId: "example.com" }, signal: controller.signal };
  const promise = page.container.get(options);
  const outcome = promise.then(() => "resolved", (e) => e);
  controller.abort();
  const failure = await outcome;
  assert.equal(failure.name, "AbortError");
  await settle(15);
  assert.equal(page.bg.host.sent.filter((m) => m.type === "get").length, 0);
});

test("page: a modal get that the host does not take goes to Firefox with the original arguments", async () => {
  const page = makePage();
  page.bg.host.script = (m) => (m.type === "get" ? { ok: false, error: "NotHandled" } : defaultHost(page.bg.host)(m));
  const seen = [];
  page.native.impl = (opts) => {
    seen.push(opts);
    return Promise.resolve("from firefox");
  };
  const options = { publicKey: { challenge: new Uint8Array(32), rpId: "example.com" } };
  assert.equal(await page.container.get(options), "from firefox");
  assert.equal(seen[0], options);
});
