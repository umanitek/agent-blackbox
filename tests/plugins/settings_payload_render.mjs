// Runs the dashboard Settings page's own state functions (dashboard/static/index.html: defaultSetState,
// normalizeSettings, buildPayload …) in Node — no browser, no server — and prints what Save would post.
// The functions are taken from the page by name, so the test exercises the code the person runs.
//
//   node tests/plugins/settings_payload_render.mjs <index.html> <settings view.json> [<edits.json>]
//   -> stdout: {"payload": {...}, "toggle": <what the auto-attach box shows>}
// <edits.json>: fields the person changes after the page loaded ({"discover": false}); "reset": true
// presses "Reset to defaults" first.
import { readFileSync } from "node:fs";
import vm from "node:vm";

const [pagePath, viewPath, editsPath] = process.argv.slice(2);
const page = readFileSync(pagePath, "utf8");

function block(start, open, close) {
  const at = page.indexOf(start);
  if (at < 0) throw new Error(`not in the page: ${start}`);
  let depth = 0;
  for (let i = page.indexOf(open, at); i < page.length; i++) {
    if (page[i] === open) depth++;
    else if (page[i] === close && --depth === 0) return page.slice(at, i + 1) + (open === "[" ? ";" : "");
  }
  throw new Error(`unbalanced: ${start}`);
}

const source = [
  block("var SEV_ORDER", "[", "]"),
  block("var SET_SCALARS", "[", "]"), block("var SET_LISTS", "[", "]"),
  block("function sevOk(", "{", "}"), block("function defaultSetState(", "{", "}"),
  block("function defaultValues(", "{", "}"), block("function normalizeSettings(", "{", "}"),
  block("function buildPayload(", "{", "}"), block("function onlyServedOrChanged(", "{", "}"),
].join("\n");
const context = { shieldsUI: { settings: { payload() { return {}; } } }, setState: null, result: null };
vm.createContext(context);
vm.runInContext("var setState = null;\n" + source, context);
const view = JSON.parse(readFileSync(viewPath, "utf8"));
const edits = editsPath ? JSON.parse(readFileSync(editsPath, "utf8")) : {};
context.view = view;
context.edits = edits;
vm.runInContext(`
  setState = normalizeSettings(view);
  if (edits.reset) setState = defaultSetState();
  Object.keys(edits).forEach(function (key) { if (key !== "reset") setState[key] = edits[key]; });
  result = { payload: buildPayload(), toggle: !!setState.auto_attach };
`, context);
process.stdout.write(JSON.stringify(context.result));
