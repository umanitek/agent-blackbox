"""The OpenClaw bridge ships as ONE file, in step with its source (2026-11-20).

OpenClaw 2026.11.6 prepares a plugin in a worker that asks OpenClaw's main process to map every
sibling file the plugin imports and waits 15 s for each answer; on a busy machine the answer
comes late, the load fails ("Plugin preparation callback timed out") and OpenClaw refuses to run
the agent at all. Seen on two macOS VMs with real OpenClaw 2026.11.6: the 22-file source failed
every time, the bundle loaded every time. So `integrations/openclaw/dist/index.js` (built from
`src/` by `npm run build`) is what `package.json` names and what an install copies.

These tests need no OpenClaw and no esbuild: the bundle's first line carries a fingerprint of
`src/`, recomputed here, so editing the source without rebuilding fails the ordinary suite
(LES-008 / LES-029). Node, when present, parses the bundle and loads it for real (LES-037).
"""

from __future__ import annotations

import hashlib
import json
import re
import shutil
import subprocess
from pathlib import Path

import pytest

from _blackbox_loader import load_blackbox

REPO = Path(__file__).resolve().parents[2]
BRIDGE = REPO / "integrations" / "openclaw"
BUNDLE = BRIDGE / "dist" / "index.js"
REBUILD = "run `npm run build` in integrations/openclaw and commit dist/"

plugin_copy = load_blackbox("attach.plugin_copy")


def _source_fingerprint() -> str:
    """The same sum build.mjs writes: sorted relative path, NUL, bytes (CRLF as LF), NUL."""
    digest = hashlib.sha256()
    source = BRIDGE / "src"
    for path in sorted(p for p in source.rglob("*") if p.is_file()):
        digest.update(path.relative_to(source).as_posix().encode())
        digest.update(b"\0")
        digest.update(path.read_bytes().replace(b"\r\n", b"\n"))
        digest.update(b"\0")
    return digest.hexdigest()


def test_the_bundle_was_built_from_the_source_as_it_is_now():
    first_line = BUNDLE.read_text(encoding="utf-8").splitlines()[0]
    recorded = re.search(r"source sha256:([0-9a-f]{64})", first_line)
    assert recorded, "dist/index.js has no source fingerprint: " + REBUILD
    assert recorded.group(1) == _source_fingerprint(), "src/ changed since dist/index.js was built: " + REBUILD


def test_openclaw_is_pointed_at_the_bundle_and_nothing_else():
    package = json.loads((BRIDGE / "package.json").read_text(encoding="utf-8"))
    assert package["openclaw"]["extensions"] == ["./dist/index.js"]
    assert "dist" in package["files"]


def test_the_bundle_imports_no_sibling_file():
    # The property that matters: a sibling import is what makes OpenClaw's loader call back.
    text = BUNDLE.read_text(encoding="utf-8")
    assert not re.findall(r"""(?:from|import)\s*\(?\s*["']\.{1,2}/""", text)
    outside = set(re.findall(r"""from\s+["']([^"'.][^"']*)["']""", text))
    assert {name for name in outside if not name.startswith("node:")} == {"openclaw/plugin-sdk/plugin-entry"}


def test_the_word_list_the_bundle_reads_sits_beside_it():
    assert (BRIDGE / "dist" / "bip39-english.txt").read_bytes() == (BRIDGE / "src" / "bip39-english.txt").read_bytes()


def test_an_installed_copy_carries_the_bundle(tmp_path):
    kept = set(plugin_copy._openclaw_ignore("", ["dist", "src", "node_modules", "test", "package.json"]))
    assert kept == {"node_modules", "test"}   # dist and src travel; deps and tests do not
    copy = tmp_path / "_openclaw"
    shutil.copytree(BRIDGE, copy, ignore=plugin_copy._openclaw_ignore)
    assert (copy / "dist" / "index.js").is_file() and plugin_copy._is_openclaw_plugin_dir(copy)


def test_a_copy_without_its_entry_file_is_not_wired_into_openclaw(tmp_path):
    # A copy made by a Blackbox that still skipped dist/: wiring it would break the user's OpenClaw.
    copy = tmp_path / "_openclaw"
    shutil.copytree(BRIDGE, copy, ignore=shutil.ignore_patterns("dist", "node_modules"))
    assert not plugin_copy._is_openclaw_plugin_dir(copy)


LOADER = """
import { register } from "node:module";
const hooks = `export async function resolve(specifier, context, next) {
  if (specifier === "openclaw/plugin-sdk/plugin-entry")
    return { url: "data:text/javascript,export const definePluginEntry = (entry) => entry;", shortCircuit: true };
  return next(specifier, context);
}`;
register("data:text/javascript," + encodeURIComponent(hooks));
"""

RUN = """
const entry = (await import(process.env.BLACKBOX_TEST_BUNDLE)).default;
const hooks = [];
const api = { on: (name) => hooks.push(name), logger: { debug() {}, info() {}, warn() {}, error() {} },
              pluginConfig: { blackboxHome: process.env.BLACKBOX_TEST_HOME, dkgUrl: "http://127.0.0.1:9", dashboardUrl: "" } };
entry.register(api);
console.log(JSON.stringify({ id: entry.id, hooks }));
process.exit(0);
"""


@pytest.fixture
def node():
    found = shutil.which("node")
    if not found:
        pytest.skip("node is not installed here (CI has it)")
    return found


def test_node_parses_the_bundle(node):
    result = subprocess.run([node, "--check", str(BUNDLE)], capture_output=True, text=True, timeout=60, check=False)
    assert result.returncode == 0, result.stderr[-800:]


def test_the_bundle_loads_and_registers_every_hook(node, tmp_path):
    (tmp_path / "loader.mjs").write_text(LOADER, encoding="utf-8")
    (tmp_path / "run.mjs").write_text(RUN, encoding="utf-8")
    env = {"PATH": str(Path(node).parent), "HOME": str(tmp_path), "BLACKBOX_TEST_BUNDLE": BUNDLE.as_uri(),
           "BLACKBOX_TEST_HOME": str(tmp_path / "blackbox")}
    result = subprocess.run([node, "--import", (tmp_path / "loader.mjs").as_uri(), str(tmp_path / "run.mjs")],
                            capture_output=True, text=True, timeout=60, check=False, env=env, cwd=str(tmp_path))
    assert result.returncode == 0, result.stderr[-1200:]
    loaded = json.loads(result.stdout.strip().splitlines()[-1])
    manifest = json.loads((BRIDGE / "openclaw.plugin.json").read_text(encoding="utf-8"))
    assert loaded["id"] == manifest["id"] == "blackbox"
    assert sorted(loaded["hooks"]) == sorted(manifest["hooks"]["registers"])


VERDICTS = """
import { readFileSync } from "node:fs";
const { detectCustomFileAccess } = await import(process.env.BLACKBOX_TEST_BUNDLE);
const fixture = JSON.parse(readFileSync(process.env.BLACKBOX_TEST_FIXTURE, "utf8"));
const got = fixture.calls.map(({ tool, args }) => ({ tool, args,
  findings: detectCustomFileAccess(tool, args, fixture.protectedPaths).map((f) => ({ identifier: f.identifier, evidence: f.evidence })) }));
console.log(JSON.stringify(got));
process.exit(0);
"""


def test_the_shipped_bundle_judges_shell_and_code_calls_as_hermes_does(node, tmp_path):
    # KI-509: `exec cat ~/.ssh/id_rsa` ran through OpenClaw in Block mode while Hermes blocked it.
    # The fixture holds Hermes' own verdicts (tests/parity/generate_shell_files.py): what must be
    # caught through a shell or code tool and what must stay allowed. Judged by the file that ships.
    fixture = REPO / "tests" / "parity" / "shell_files_fixtures.json"
    (tmp_path / "loader.mjs").write_text(LOADER, encoding="utf-8")
    (tmp_path / "verdicts.mjs").write_text(VERDICTS, encoding="utf-8")
    env = {"PATH": str(Path(node).parent), "HOME": str(tmp_path), "BLACKBOX_TEST_BUNDLE": BUNDLE.as_uri(),
           "BLACKBOX_TEST_FIXTURE": str(fixture)}
    result = subprocess.run([node, "--import", (tmp_path / "loader.mjs").as_uri(), str(tmp_path / "verdicts.mjs")],
                            capture_output=True, text=True, timeout=60, check=False, env=env, cwd=str(tmp_path))
    assert result.returncode == 0, result.stderr[-1200:]
    expected = json.loads(fixture.read_text(encoding="utf-8"))["calls"]
    got = json.loads(result.stdout.strip().splitlines()[-1])
    differing = [(want, have) for want, have in zip(expected, got, strict=True) if want != have]
    assert not differing, differing[:3]
    caught = [case for case in expected if case["findings"]]
    assert len(caught) >= 14 and len(expected) - len(caught) >= 6   # both kinds are really exercised


AS_OPENCLAW_RUNS_IT = """
import { readFileSync } from "node:fs";
const entry = (await import(process.env.BLACKBOX_TEST_BUNDLE)).default;
const manifest = JSON.parse(readFileSync(process.env.BLACKBOX_TEST_MANIFEST, "utf8"));
// What OpenClaw hands a plugin: every default the manifest declares, then the operator's entries.
const pluginConfig = Object.fromEntries(Object.entries(manifest.configSchema.properties)
  .filter(([, schema]) => "default" in schema).map(([key, schema]) => [key, schema.default]));
// dashboardUrl "" unless a test names a service: a developer's own Blackbox on :9700 must never answer here.
Object.assign(pluginConfig, { dashboardUrl: process.env.BLACKBOX_TEST_SERVICE || "" }, JSON.parse(process.env.BLACKBOX_TEST_ENTRY),
              { blackboxHome: process.env.BLACKBOX_TEST_HOME, dkgUrl: "http://127.0.0.1:9" });
const handlers = {};
entry.register({ on: (name, handler) => { handlers[name] = handler; }, pluginConfig,
                 logger: { debug() {}, info() {}, warn() {}, error() {} } });
const verdicts = {};
for (const command of JSON.parse(process.env.BLACKBOX_TEST_COMMANDS)) {
  const answer = await handlers.before_tool_call({ toolName: "exec", params: { command }, toolCallId: "t", runId: "r" },
                                                 { sessionKey: "agent:research:main" });
  verdicts[command] = Boolean(answer && answer.block);
}
console.log(JSON.stringify(verdicts));
process.exit(0);
"""

CANARY_READS = ["cat ~/.ssh/blackbox_canary", "cp -r ~/.ssh /tmp/ssh-copy",
                "python3 -c \"import os; print(open(os.path.expanduser('~/.ssh/blackbox_canary')).read())\""]
HARMLESS = ["echo hello from openclaw", "cat ~/.ssh/blackbox_canary.example", "ls -la ~/.ssh/"]


def _blocked(node, tmp_path, entry: dict, *, commands: list[str] | None = None, service: str = "") -> dict:
    (tmp_path / "loader.mjs").write_text(LOADER, encoding="utf-8")
    (tmp_path / "hook.mjs").write_text(AS_OPENCLAW_RUNS_IT, encoding="utf-8")
    env = {"PATH": str(Path(node).parent), "HOME": str(tmp_path), "BLACKBOX_TEST_BUNDLE": BUNDLE.as_uri(),
           "BLACKBOX_TEST_MANIFEST": str(BRIDGE / "openclaw.plugin.json"), "BLACKBOX_TEST_HOME": str(tmp_path / "blackbox"),
           "BLACKBOX_TEST_ENTRY": json.dumps(entry), "BLACKBOX_TEST_SERVICE": service,
           "BLACKBOX_TEST_COMMANDS": json.dumps(CANARY_READS + HARMLESS if commands is None else commands)}
    result = subprocess.run([node, "--import", (tmp_path / "loader.mjs").as_uri(), str(tmp_path / "hook.mjs")],
                            capture_output=True, text=True, timeout=60, check=False, env=env, cwd=str(tmp_path))
    assert result.returncode == 0, result.stderr[-1200:]
    return json.loads(result.stdout.strip().splitlines()[-1])


def test_with_only_the_manifests_defaults_the_hook_still_blocks_a_protected_read(node, tmp_path):
    # Seen on real OpenClaw 2026.11.6: the hook ran and blocked nothing. OpenClaw fills in every
    # default the manifest declares, and `protectedPaths: []` was one — handed to the plugin as
    # "the operator protects nothing", which switched the built-in list off. The detectors passed
    # every test that called them directly; only the config OpenClaw really builds showed it.
    verdicts = _blocked(node, tmp_path, {"mode": "block"})
    assert {command: verdicts[command] for command in CANARY_READS} == dict.fromkeys(CANARY_READS, True)
    assert {command: verdicts[command] for command in HARMLESS} == dict.fromkeys(HARMLESS, False)


def test_the_operators_own_list_is_the_one_applied_and_audit_mode_blocks_nothing(node, tmp_path):
    only_secrets = _blocked(node, tmp_path, {"mode": "block", "protectedPaths": ["~/secrets"]})
    assert not any(only_secrets.values())            # ~/.ssh is not on THIS operator's list
    assert not any(_blocked(node, tmp_path, {"mode": "audit"}).values())


def test_the_manifest_declares_no_default_for_the_protected_path_list():
    schema = json.loads((BRIDGE / "openclaw.plugin.json").read_text(encoding="utf-8"))["configSchema"]["properties"]
    assert "default" not in schema["protectedPaths"]


# ------------------------------------------------------------------ asking Blackbox itself for the verdict

MALWARE_INSTALL = "npm install a-package-the-verified-graph-lists"
#: A verdict in the shape guard.tool_call_verdict returns (tests/plugins/test_blackbox_guard_verdict.py
#: holds that shape to the Hermes hook): a verified malware package, blocked.
SERVICE_VERDICT = {
    "findings": [{"identifier": "dep:npm:a-package-the-verified-graph-lists@*", "category": "dependency",
                  "severity": "critical", "title": "Known malicious package", "tool_name": "exec", "matched": "npm",
                  "evidence": "npm:a-package-the-verified-graph-lists@*", "confirmed": True, "source": "public",
                  "kind": "malware", "fields": {}}],
    "blocked": ["dep:npm:a-package-the-verified-graph-lists@*"], "decision": "block",
    "message": "Blackbox blocked this tool call — it matched 1 known threat in the threat graph",
}


@pytest.fixture
def service():
    """A stand-in for Blackbox's local service: hands out a session token, answers the verdict
    route with whatever ``state["answer"]`` holds, and remembers what it was asked."""
    import http.server
    import threading

    state: dict = {"answer": (200, SERVICE_VERDICT), "asked": [], "tokens": []}

    class Handler(http.server.BaseHTTPRequestHandler):
        def log_message(self, *args):   # quiet
            return

        def _send(self, status: int, body: dict) -> None:
            raw = json.dumps(body).encode()
            self.send_response(status)
            self.send_header("content-type", "application/json")
            self.send_header("content-length", str(len(raw)))
            self.end_headers()
            self.wfile.write(raw)

        def do_GET(self):
            self._send(200, {"token": "session-token"}) if self.path == "/api/session" else self._send(404, {})

        def do_POST(self):
            body = json.loads(self.rfile.read(int(self.headers.get("content-length") or 0)) or b"{}")
            state["tokens"].append(self.headers.get("x-blackbox-token"))
            state["asked"].append(body)
            self._send(*state["answer"])

    server = http.server.ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    state["url"] = f"http://127.0.0.1:{server.server_address[1]}"
    yield state
    server.shutdown()


def test_what_blackbox_says_is_what_the_openclaw_agent_gets(node, tmp_path, service):
    # KI-509: a verified malware package installed through OpenClaw while Hermes blocked it.
    # The plugin has no rule for this package; the block comes from Blackbox's own answer.
    verdicts = _blocked(node, tmp_path, {"mode": "audit"}, commands=[MALWARE_INSTALL], service=service["url"])
    assert verdicts == {MALWARE_INSTALL: True}
    assert service["asked"] == [{"tool_name": "exec", "args": {"command": MALWARE_INSTALL}}]
    assert service["tokens"] == ["session-token"]   # asked as a local process, with the session token
    row = json.loads((tmp_path / "blackbox" / "findings.openclaw.jsonl").read_text(encoding="utf-8").splitlines()[-1])
    assert row["framework"] == "openclaw" and row["finding"]["identifier"] == SERVICE_VERDICT["blocked"][0]
    assert row["detail"]["decision"] == "block" and row["detail"]["agent"] == "research"   # which agent, and what was done


@pytest.mark.parametrize("answer", [
    (503, {"error": "verdict unavailable"}),                                   # the service could not tell
    (200, {"findings": "nonsense"}),                                           # not a verdict
    (200, {"findings": [], "blocked": ["dep:npm:not-among-the-findings@*"]}),   # a block that names no finding
])
def test_when_blackbox_cannot_answer_the_built_in_checks_decide(node, tmp_path, service, answer):
    service["answer"] = answer
    verdicts = _blocked(node, tmp_path, {"mode": "block"}, service=service["url"],
                        commands=["cat ~/.ssh/blackbox_canary", MALWARE_INSTALL, "echo hello"])
    assert verdicts == {"cat ~/.ssh/blackbox_canary": True, MALWARE_INSTALL: False, "echo hello": False}
    assert len(service["asked"]) == 1   # after one failure it stops asking for a while (no timeout per call)


def test_a_service_that_is_not_running_costs_nothing_and_the_built_in_checks_decide(node, tmp_path):
    verdicts = _blocked(node, tmp_path, {"mode": "block"}, service="http://127.0.0.1:9",
                        commands=["cat ~/.ssh/blackbox_canary", "echo hello"])
    assert verdicts == {"cat ~/.ssh/blackbox_canary": True, "echo hello": False}
