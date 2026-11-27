// Draws the dashboard's Security page (dashboard/static/security.html + permission_card.js +
// security.js) in Node with a minimal DOM stand-in — no browser, no server: its scripts run against
// fetch answers from a fixture of REAL API answers, and every POST is recorded.
//
//   node tests/plugins/security_page_render.mjs <static folder> <fixture.json>
//   fixture: {"answers": [[url prefix, JSON answer], ...] (longest prefix wins),
//             "post": {url: [status, JSON answer]},
//             "actions": [["click", host id, button text] | ["change", element id or host id, value]]}
//   -> stdout: {"hosts": {id: outline}, "posts": [[url, body], ...], "gets": [url, ...], "hidden": {id: bool}, "errors": [...]}
// An outline line is "<indent>tag.class text" — the text each element holds itself.
import { readFileSync } from "node:fs";
import vm from "node:vm";

const [folder, fixturePath] = process.argv.slice(2);
const fixture = JSON.parse(readFileSync(fixturePath, "utf8"));
const html = readFileSync(`${folder}/security.html`, "utf8");

class Element {
  constructor(tag) { this.tagName = tag.toUpperCase(); this.children = []; this.attributes = {}; this.className = ""; this.listeners = {};
                     this.ownText = ""; this.style = {}; this.value = ""; this.hidden = false; this.disabled = false; this.dataset = {}; }
  get textContent() { return this.ownText + this.children.map((child) => child.textContent).join(""); }
  set textContent(value) { this.children = []; this.ownText = String(value); }
  appendChild(child) { this.children.push(child); if (this.tagName === "SELECT" && child.selected) this.value = child.value; return child; }
  append(...nodes) { nodes.forEach((node) => this.appendChild(node)); }
  replaceChildren() { this.children = []; this.ownText = ""; }
  setAttribute(name, value) { this.attributes[name] = String(value); }
  addEventListener(type, handler) { (this.listeners[type] = this.listeners[type] || []).push(handler); }
  fire(type) { (this.listeners[type] || []).forEach((handler) => handler({ target: this, preventDefault() {} })); }
  click() { this.fire("click"); }
  find(test) { if (test(this)) return this; for (const child of this.children) { const hit = child.find(test); if (hit) return hit; } return null; }
}
function outline(node, depth = 0) {
  if (!node) return [];
  const classes = node.className ? "." + node.className.split(/\s+/).filter(Boolean).join(".") : "";
  const pressed = node.attributes["aria-pressed"] === "true" ? " [pressed]" : "";
  const line = "  ".repeat(depth) + node.tagName.toLowerCase() + classes + pressed + (node.ownText ? " " + node.ownText : "");
  return [line].concat(...node.children.map((child) => outline(child, depth + 1)));
}
const hosts = {};
for (const match of html.matchAll(/<(\w+)([^>]*)\sid="([^"]+)"([^>]*)>/g)) {
  const node = new Element(match[1]); node.id = match[3]; node.hidden = /\shidden[\s>]/.test(match[2] + match[4] + ">");
  node.disabled = /\sdisabled/.test(match[2] + match[4]); hosts[match[3]] = node;
}
const document = { getElementById: (id) => hosts[id] || null, createElement: (tag) => new Element(tag),
                   createTextNode: (text) => { const node = new Element("#text"); node.ownText = String(text); return node; } };
const posts = [], gets = [], errors = [];
const answer = (status, json) => Promise.resolve({ ok: status < 400, status, json: () => Promise.resolve(json), clone() { return this; } });
const fetch = (url, options) => {
  if (url.endsWith("/api/session")) return answer(200, { token: "t" });
  if (options && options.method === "POST") {
    posts.push([url, JSON.parse(options.body)]);
    const [status, json] = (fixture.post || {})[url] || [200, { ok: true }];
    return answer(status, json);
  }
  gets.push(url);
  const hits = fixture.answers.filter(([prefix]) => url === prefix || url.startsWith(prefix + "?"));
  const exact = hits.find(([prefix]) => url === prefix) || hits.sort((a, b) => b[0].length - a[0].length)[0];
  return exact ? answer(200, exact[1]) : answer(404, {});
};
const context = { location: { search: "" }, document, fetch, console, Promise, Date, Math, Number, String, Array, Object, JSON, URLSearchParams,
                  encodeURIComponent, setInterval() {}, setTimeout() {} };
context.window = context;   // as in a browser: the page's globals live on window
vm.createContext(context);
const settle = async () => { for (let i = 0; i < 30; i++) await new Promise((resolve) => setImmediate(resolve)); };
try {
  for (const name of ["permission_card.js", "security.js"]) vm.runInContext(readFileSync(`${folder}/${name}`, "utf8"), context);
} catch (error) { errors.push(String(error && error.stack)); }
await settle();
for (const [kind, hostId, value] of fixture.actions || []) {
  const host = hosts[hostId];
  if (kind === "click") {
    const button = host && (host.tagName === "BUTTON" ? host : host.find((node) => node.tagName === "BUTTON" && node.ownText === value));
    if (button) button.click(); else errors.push(`no button ${value} in #${hostId}`);
  } else {
    const field = host && host.find((node) => node.tagName === "SELECT" || node.tagName === "INPUT");
    if (field) { field.value = value; field.fire("change"); } else errors.push(`no field in #${hostId}`);
  }
  await settle();
}
const wanted = ["sec-mode-help", "sec-perms", "sec-perm-rules", "sec-perm-note", "sec-perm-scope", "sec-checks", "sec-checks-note",
                "sec-mode-note", "sec-limits-note", "sec-always", "sec-never", "sec-hook-limit", "sec-mode-audit", "sec-mode-block"];
process.stdout.write(JSON.stringify({ hosts: Object.fromEntries(wanted.map((id) => [id, outline(hosts[id])])), posts, gets,
                                      hidden: { "sec-limits": hosts["sec-limits"].hidden }, errors }));
