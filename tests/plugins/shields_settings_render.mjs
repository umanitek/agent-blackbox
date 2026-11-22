// Draws shields.js's Settings groups and its Protected-files rows for a settings view, in Node,
// with a minimal DOM stand-in (no browser, no server): what the page would put in #set-shields.
//
//   node tests/plugins/shields_settings_render.mjs <shields.js> <view.json>
//   -> stdout: {"settings": "<html of #set-shields>", "pathRows": "<html>"}
import { readFileSync } from "node:fs";
import vm from "node:vm";

const [scriptPath, viewPath] = process.argv.slice(2);
const hosts = {};
function element() {
  return { innerHTML: "", hidden: false, className: "", style: {}, setAttribute() {}, getAttribute() { return null; },
           querySelector() { return element(); }, querySelectorAll() { return []; }, insertAdjacentHTML() {},
           appendChild() {}, addEventListener() {} };
}
const document = {
  body: element(),
  getElementById(id) { return (hosts[id] = hosts[id] || element()); },
  querySelector() { return null; }, querySelectorAll() { return []; },
  createElement() { return element(); }, addEventListener() {},
};
const context = { window: {}, document, localStorage: { getItem() { return null; }, setItem() {} },
                  setTimeout() {}, setInterval() {}, clearTimeout() {}, console };
vm.createContext(context);
vm.runInContext(readFileSync(scriptPath, "utf8"), context);
const esc = (text) => String(text == null ? "" : text).replace(/&/g, "&amp;").replace(/</g, "&lt;")
  .replace(/>/g, "&gt;").replace(/"/g, "&quot;").replace(/'/g, "&#39;");
const never = () => new Promise(() => {});
const ui = context.window.BlackboxShields.mount({ esc, getJSON: never, postJSON: never, toast() {}, shortWhen() { return ""; },
                                                  openSettings() {}, lockScroll() {}, unlockScroll() {}, onSettingsChange() {} });
ui.settings.load(JSON.parse(readFileSync(viewPath, "utf8")));
ui.settings.render();
process.stdout.write(JSON.stringify({ settings: document.getElementById("set-shields").innerHTML, pathRows: ui.settings.pathRows() }));
