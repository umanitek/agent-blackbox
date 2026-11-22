// Draws the core dashboard's agent views (dashboard/static/agent_*.js) in Node with a minimal
// DOM stand-in — no browser, no server: fetch answers from a fixture of REAL core API answers.
//
//   node tests/plugins/agent_views_render.mjs <fixture.json>
//   fixture: {"scripts": [paths], "answers": [[path prefix, JSON answer], ...], "hash": "#agents/..."}
//   -> stdout: {"root": <outline of #agent-instances-root>, "page": <outline of the page window>,
//               "fetched": [paths], "errors": [...]}
// An outline line is "<indent>tag.class.class[href=…] text" — the text each element holds itself.
import { readFileSync } from "node:fs";
import vm from "node:vm";

const fixture = JSON.parse(readFileSync(process.argv[2], "utf8"));

class Element {
  constructor(tag) { this.tagName = tag.toUpperCase(); this.children = []; this.attributes = {}; this.className = ""; this.hidden = false;
                     this.listeners = {}; this.ownText = ""; this.style = {}; this.parentNode = null; }
  get childNodes() { return this.children; }
  get textContent() { return this.ownText + this.children.map((child) => child.textContent).join(""); }
  set textContent(value) { this.children = []; this.ownText = String(value); }
  appendChild(child) { child.parentNode = this; this.children.push(child); return child; }
  replaceChildren(...nodes) { this.children = []; this.ownText = ""; nodes.forEach((node) => this.appendChild(node)); }
  replaceWith(node) { const siblings = this.parentNode.children; node.parentNode = this.parentNode; siblings[siblings.indexOf(this)] = node; }
  setAttribute(name, value) { this.attributes[name] = String(value); if (name === "id") this.id = String(value); }
  getAttribute(name) { return name in this.attributes ? this.attributes[name] : null; }
  addEventListener(type, handler) { (this.listeners[type] = this.listeners[type] || []).push(handler); }
  removeEventListener() {}
  click() { (this.listeners.click || []).forEach((handler) => handler({ target: this, preventDefault() {} })); }
  get elements() { const out = []; const walk = (node) => node.children.forEach((child) => { if (child.name) out.push(child); walk(child); }); walk(this); return out; }
  find(test) { if (test(this)) return this; for (const child of this.children) { const hit = child.find(test); if (hit) return hit; } return null; }
}

function outline(node, depth = 0) {
  if (!node) return [];
  const classes = node.className ? "." + node.className.split(/\s+/).filter(Boolean).join(".") : "";
  const link = node.href ? `[href=${node.href}]` : "";
  const flags = (node.hidden ? "[hidden]" : "") + (node.disabled ? "[disabled]" : "");
  const line = "  ".repeat(depth) + node.tagName.toLowerCase() + classes + link + flags + (node.ownText ? " " + node.ownText : "");
  return [line].concat(...node.children.map((child) => outline(child, depth + 1)));
}

const body = new Element("body");
const root = body.appendChild(new Element("div"));
root.setAttribute("id", "agent-instances-root");
root.hidden = true;
const documentListeners = {};
const document = {
  body, readyState: "loading", hidden: false,   // scripts run while the page parses, as at the end of <body>
  createElement: (tag) => new Element(tag),
  getElementById: (id) => body.find((node) => node.id === id),
  addEventListener: (type, handler) => { (documentListeners[type] = documentListeners[type] || []).push(handler); },
  removeEventListener() {},
};
const fetched = [], errors = [];
const location = { hash: fixture.hash || "", pathname: "/", search: "" };
const windowListeners = {};
const context = {
  document, location, URLSearchParams, console, Promise, Date, Math, Number, String, Array, Object, JSON, RegExp, Error, isNaN,
  history: { replaceState: (_state, _title, url) => { location.hash = String(url).includes("#") ? String(url).slice(String(url).indexOf("#")) : ""; } },
  setTimeout() {}, clearTimeout() {},
  addEventListener: (type, handler) => { (windowListeners[type] = windowListeners[type] || []).push(handler); },
  fetch: (path) => {
    fetched.push(path);
    const hit = fixture.answers.find(([prefix]) => path.startsWith(prefix));
    if (!hit) return Promise.resolve({ ok: false, status: 404, json: () => Promise.resolve({}) });
    return Promise.resolve({ ok: true, status: 200, json: () => Promise.resolve(hit[1]) });
  },
};
context.window = context;
vm.createContext(context);
for (const script of fixture.scripts) {
  try { vm.runInContext(readFileSync(script, "utf8"), context, { filename: script }); } catch (error) { errors.push(String(error && error.stack)); }
}
document.readyState = "interactive";
(documentListeners.DOMContentLoaded || []).forEach((handler) => handler());
const settle = async () => { for (let i = 0; i < 20; i++) await new Promise((resolve) => setImmediate(resolve)); };
await settle();
for (const click of fixture.clicks || []) {   // [text of a button] — e.g. "Show more"
  const button = body.find((node) => node.tagName === "BUTTON" && node.ownText === click && !node.hidden);
  if (button) button.click(); else errors.push("no button " + click);
  await settle();
}
const page = body.find((node) => (node.className || "").includes("ai-view"));
process.stdout.write(JSON.stringify({ root: outline(root), page: page && !page.hidden ? outline(page) : [], fetched, errors }));
