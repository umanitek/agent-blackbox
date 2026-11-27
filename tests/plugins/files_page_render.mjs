// Draws File Shield's page (shields/files/page/files.html) in Node with a minimal DOM stand-in — no
// browser, no server: its inline page script runs against fetch answers from a fixture of REAL
// File Shield API answers, and every POST is recorded.
//
//   node tests/plugins/files_page_render.mjs <files.html> <fixture.json>
//   fixture: {"answers": [[url suffix, JSON answer], ...], "post": {url suffix: [status, JSON answer]},
//             "clicks": [[host element id, button text], ...]}
//   -> stdout: {"hosts": {id: outline}, "posts": [[name, body], ...], "errors": [...]}
// An outline line is "<indent>tag.class text" — the text each element holds itself.
import { readFileSync } from "node:fs";
import vm from "node:vm";

const [htmlPath, fixturePath] = process.argv.slice(2);
const fixture = JSON.parse(readFileSync(fixturePath, "utf8"));
const html = readFileSync(htmlPath, "utf8");

class Element {
  constructor(tag) { this.tagName = tag.toUpperCase(); this.children = []; this.attributes = {}; this.className = ""; this.listeners = {};
                     this.ownText = ""; this.style = {}; this.value = ""; }
  get textContent() { return this.ownText + this.children.map((child) => child.textContent).join(""); }
  set textContent(value) { this.children = []; this.ownText = String(value); }
  appendChild(child) { this.children.push(child); return child; }
  setAttribute(name, value) { this.attributes[name] = String(value); }
  addEventListener(type, handler) { (this.listeners[type] = this.listeners[type] || []).push(handler); }
  click() { (this.listeners.click || []).forEach((handler) => handler({ target: this, preventDefault() {} })); }
  find(test) { if (test(this)) return this; for (const child of this.children) { const hit = child.find(test); if (hit) return hit; } return null; }
}
function outline(node, depth = 0) {
  if (!node) return [];
  const classes = node.className ? "." + node.className.split(/\s+/).filter(Boolean).join(".") : "";
  const line = "  ".repeat(depth) + node.tagName.toLowerCase() + classes + (node.ownText ? " " + node.ownText : "");
  return [line].concat(...node.children.map((child) => outline(child, depth + 1)));
}
const hosts = {};
for (const match of html.matchAll(/<(\w+)[^>]*\sid="([^"]+)"[^>]*>/g)) { const node = new Element(match[1]); node.id = match[2]; hosts[match[2]] = node; }
const document = { getElementById: (id) => hosts[id] || null, createElement: (tag) => new Element(tag),
                   createTextNode: (text) => { const node = new Element("#text"); node.ownText = String(text); return node; } };
const posts = [], errors = [];
const answer = (status, json) => Promise.resolve({ ok: status < 400, status, json: () => Promise.resolve(json) });
const context = {
  encodeURIComponent, document, console, Promise, Date, Math, Number, String, Array, Object, JSON, setInterval() {}, setTimeout() {},
  fetch: (url, options) => {
    if (url.endsWith("/api/session")) return answer(200, { token: "t" });
    if (options && options.method === "POST") {
      const name = url.split("/").pop();
      posts.push([name, JSON.parse(options.body)]);
      const [status, json] = (fixture.post || {})[name] || [200, {}];
      return answer(status, json);
    }
    const hit = fixture.answers.find(([suffix]) => url.endsWith(suffix));
    return hit ? answer(200, hit[1]) : answer(404, {});
  },
};
vm.createContext(context);
const scripts = [...html.matchAll(/<script>([\s\S]*?)<\/script>/g)].map((match) => match[1]);
// The dashboard's shared scripts the page loads by address (the permission card), from the tree.
const STATIC = new URL("../../plugins/blackbox/dashboard/static/", import.meta.url);
const SHARED = { "/permission-card.js": "permission_card.js" };
for (const match of html.matchAll(/<script src="([^"]+)"><\/script>/g)) {
  if (SHARED[match[1]]) vm.runInContext(readFileSync(new URL(SHARED[match[1]], STATIC), "utf8"), context);
}
try { vm.runInContext(scripts[scripts.length - 1], context); } catch (error) { errors.push(String(error && error.stack)); }
const settle = async () => { for (let i = 0; i < 20; i++) await new Promise((resolve) => setImmediate(resolve)); };
await settle();
for (const [hostId, text] of fixture.clicks || []) {
  const button = hosts[hostId] && hosts[hostId].find((node) => node.tagName === "BUTTON" && node.ownText === text);
  if (button) button.click(); else errors.push(`no button ${text} in #${hostId}`);
  await settle();
}
const wanted = ["permissions", "permission-restart", "permission-rules", "permission-never", "permissions-note"];
process.stdout.write(JSON.stringify({ hosts: Object.fromEntries(wanted.map((id) => [id, outline(hosts[id])])), posts, errors }));
