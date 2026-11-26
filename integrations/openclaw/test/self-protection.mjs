/**
 * The stand-in rule the plugin uses while Blackbox's service is not answering
 * (src/selfProtection.ts): what touches Blackbox is refused, a plain read is not.
 *   node integrations/openclaw/test/self-protection.mjs
 * Exits non-zero on any mismatch; prints "PASS <n> cases" on success.
 */
import { ownCoreTouched } from "../src/selfProtection.ts";

const URL = "http://127.0.0.1:9700";
const exec = (command) => ["exec", { command }];
const REFUSED = [
  exec("rm -rf ~/.hermes/blackbox"), exec("sed -i '' 's/block/audit/' ~/.hermes/config.yaml"), exec("echo '{}' > ~/.openclaw/openclaw.json"),
  exec("openclaw plugins disable blackbox"), exec("openclaw --profile work plugins uninstall blackbox"), exec("openclaw config set plugins.allow '[]'"),
  exec("hermes plugins disable blackbox"), exec("launchctl bootout gui/501/ai.umanitek.blackbox-dashboard"), exec("pkill -f blackbox"),
  exec("curl -X POST http://127.0.0.1:9700/api/settings -d '{}'"), exec("curl -s http://127.0.0.1:9700/api/session"), exec("python3 -m http.server 9700"),
  exec("cat ~/.hermes/config.yaml > ./x && rm ~/.hermes/config.yaml"), exec("cat ~/.openclaw/openclaw.json | sh"), exec("sh -c 'rm -rf ~/.hermes'"),
  exec("BLACKBOX_MODE=audit openclaw agent"), exec("HERMES_HOME=./h hermes chat"), exec("cd ~/.hermes\nrm config.yaml"),
  ["write", { path: "~/.openclaw/openclaw.json", content: "{}" }], ["edit", { path: "~/.openclaw-work/openclaw.json", old_string: "block", new_string: "audit" }],
  ["write", { path: "./x.sh", content: "rm -rf ~/.hermes/blackbox\n" }], ["browser", { url: "http://localhost:9700/#settings" }],
  ["process", { action: "start", command: "rm -rf ~/.hermes/blackbox" }],
];
const ALLOWED = [
  exec("ls -la"), exec("npm test"), exec("cat ~/.hermes/config.yaml"), exec("grep -n mode ~/.openclaw/openclaw.json"), exec("git status"),
  exec("curl -s http://127.0.0.1:9700/api/findings"), exec("rm -rf ./node_modules"), exec("python3 -m http.server 8000"),
  ["read", { path: "~/.openclaw/openclaw.json" }], ["write", { path: "~/.openclaw/workspace/notes.md", content: "hello" }],
  ["write", { path: "./src/app.ts", content: "export const x = 1;\n" }], exec("cat ~/.ssh/blackbox_canary"), exec("grep -rn blackbox ./docs"),
  ["write", { path: "./notes/blackbox.md", content: "what the blackbox plugin does\n" }], ["exec", { command: "cd ~/.openclaw/workspace && ls" }],
];
const failures = [];
for (const [tool, params] of REFUSED) if (!ownCoreTouched(tool, params, URL)) failures.push({ expected: "refused", tool, params });
for (const [tool, params] of ALLOWED) if (ownCoreTouched(tool, params, URL)) failures.push({ expected: "allowed", tool, params });
if (ownCoreTouched("exec", { command: "curl -X POST http://127.0.0.1:9700/api/settings" }, "") !== null) failures.push({ expected: "no page without an address" });
if (failures.length) {
  console.error(JSON.stringify(failures, null, 2));
  process.exit(1);
}
console.log(`PASS ${REFUSED.length + ALLOWED.length + 1} cases`);
