"""File Shield, Layer 2 — AI agents inside an OS sandbox built from the protected list
(plugins/blackbox/shields/files/sandbox; proposal "Process-level file protection" §03, local-only).

Amos, 2026-11-21: protection at the process level, so an agent can not get around it with a
script, a compiled program or an interpreter. Decisions honoured: D7 (agents keep ``sudo`` — so
the sandbox is a per-agent choice, off by default), D10 (Cursor/Windsurf relaunched inside it).

Contracts (red on the base: f50143f2ac had no sandbox, no ``sandboxed`` option, no canary):
* on THIS Mac, a REAL Seatbelt sandbox from the generated profile refuses a protected file to
  ``cat``, a grandchild, a python child, a symlink, a hard link, ``mv``/``rm`` and a rename of the
  folder above it — and allows the file beside it and a new file in that folder;
* Blackbox's own places are never changed from inside; the canary proves a session is inside;
* the launcher Blackbox writes starts the real agent inside the sandbox (end to end, fake agent);
* the setting: off by default, only known command-line agents, removing one waits for approval;
* sync writes the profile, launchers and the PATH block, and takes them away again;
* a sandbox refusal the helper reports becomes a File Shield hit (local, agent "agent-sandbox").
"""

from __future__ import annotations

import os
import shutil
import subprocess
import sys
from pathlib import Path

import pytest

from plugins.blackbox import approvals, audit
from plugins.blackbox.kernel import config as config_mod
from plugins.blackbox.kernel import shell_path
from plugins.blackbox.shields.files import api, changes, events, mode as files_mode, sandbox
from plugins.blackbox.shields.files.sandbox import places as places_mod
from plugins.blackbox.shields.files.sandbox.platform import macos
from plugins.blackbox.shields.shield_api import ShieldApiError

VAULT = "~/Documents/Vault"
REAL = pytest.mark.skipif(sys.platform != "darwin" or not os.access(macos.SANDBOX_EXEC, os.X_OK),
                          reason="a real Seatbelt sandbox needs macOS")


@pytest.fixture(autouse=True)
def home(tmp_path, monkeypatch):
    real = tmp_path.resolve()
    monkeypatch.setenv("HOME", str(real))
    monkeypatch.setenv("BLACKBOX_HOME", str(real / "bb"))
    (real / "Documents" / "Vault").mkdir(parents=True)
    (real / "Documents" / "Vault" / "secret.txt").write_text("secret", encoding="utf-8")
    (real / "Documents" / "beside.txt").write_text("fine", encoding="utf-8")
    changes.reset()
    yield real
    changes.reset()


@pytest.fixture
def entry(monkeypatch):
    state = {"mode": "audit", "shields": {"file-shield": {"enabled": True, "protected": [VAULT], "sandboxed": ["claude-code"]}}}
    monkeypatch.setattr(config_mod, "_blackbox_entry", lambda: state)
    return state


def _mode(sandboxed=("claude-code",), enabled=True):
    return files_mode.build(enabled=enabled, protected=(VAULT,), sandboxed=tuple(sandboxed))


def _run(profile: Path, script: str) -> subprocess.CompletedProcess:
    return subprocess.run([macos.SANDBOX_EXEC, "-f", str(profile), "/bin/sh", "-c", script],
                          capture_output=True, text=True, timeout=30, check=False)


# -- the policy -------------------------------------------------------------------------------

def test_the_policy_names_items_keys_own_places_and_the_folders_above(home):
    policy = places_mod.build([VAULT, "~/notes.txt"], [str(home / "bb" / "*.pem"), str(home / "keys")],
                              own=[str(home / "bb")], canary=str(home / "bb" / "sandbox" / "canary"),
                              is_folder=lambda item: not item.endswith(".txt"))
    assert policy.denied_folders == (str(home / "Documents" / "Vault"), str(home / "keys"))
    assert str(home / "notes.txt") in policy.denied_files and policy.canary in policy.denied_files
    assert policy.denied_globs == (str(home / "bb" / "*.pem"),)
    assert policy.no_write == (str(home / "bb"),)
    assert str(home / "Documents") in policy.no_rename and str(home) in policy.no_rename and "/" not in policy.no_rename


def test_the_profile_refuses_what_the_policy_names_and_allows_the_rest():
    policy = places_mod.Places(("/Users/me/Vault",), ("/Users/me/a \"b\".txt",), ("/Users/me/bb/*.pem",),
                               ("/Users/me/bb",), ("/Users/me",), "/Users/me/bb/sandbox/canary")
    text = macos.render(policy)
    assert text.startswith("(version 1)") and "(allow default)" in text
    assert '(subpath "/Users/me/Vault")' in text and '(literal "/Users/me/a \\"b\\".txt")' in text
    assert '(regex #"^/Users/me/bb/[^/]*\\.pem$")' in text
    assert "(deny file-write*\n  (subpath \"/Users/me/bb\"))" in text
    assert "(deny file-write-unlink\n  (literal \"/Users/me\"))" in text
    assert "(deny lsopen)" in text and '"localhost:22"' in text


# -- a REAL sandbox on this Mac ---------------------------------------------------------------

@REAL
def test_a_real_sandbox_refuses_every_route_to_a_protected_item_and_allows_the_rest(home):
    sandbox.sync(_mode())
    profile = sandbox.profile_path()
    vault = home / "Documents" / "Vault"
    (home / "link.txt").symlink_to(vault / "secret.txt")
    script = f"""
cat '{vault}/secret.txt' >/dev/null 2>&1; echo cat=$?
sh -c "sh -c 'cat {vault}/secret.txt' >/dev/null 2>&1; echo grandchild=\\$?"
python3 -c "open('{vault}/secret.txt').read()" >/dev/null 2>&1; echo python=$?
cat '{home}/link.txt' >/dev/null 2>&1; echo symlink=$?
ln '{vault}/secret.txt' '{home}/hard.txt' 2>/dev/null; echo hardlink=$?
mv '{vault}/secret.txt' '{home}/moved.txt' 2>/dev/null; echo mv=$?
rm -f '{vault}/secret.txt' 2>/dev/null; echo rm=$?
mv '{home}/Documents' '{home}/Docs2' 2>/dev/null; echo rename_above=$?
ls '{vault}' >/dev/null 2>&1; echo list=$?
cat '{home}/Documents/beside.txt' >/dev/null; echo beside=$?
echo new > '{home}/Documents/new.txt'; echo write_beside=$?
echo x > '{home}/bb/evil' 2>/dev/null; echo write_blackbox=$?
cat '{sandbox.canary_path()}' >/dev/null 2>&1; echo canary=$?
"""
    lines = dict(line.split("=", 1) for line in _run(profile, script).stdout.split())
    refused = ("cat", "grandchild", "python", "symlink", "hardlink", "mv", "rm", "rename_above", "list",
               "write_blackbox", "canary")
    assert {name: lines[name] for name in refused} == {name: "1" for name in refused}, lines
    assert lines["beside"] == "0" and lines["write_beside"] == "0", lines
    assert (vault / "secret.txt").read_text(encoding="utf-8") == "secret"


@REAL
def test_the_launcher_starts_the_real_agent_inside_the_sandbox_end_to_end(home):
    sandbox.sync(_mode())
    fake = home / "fakebin"
    fake.mkdir()
    agent = fake / "claude"
    agent.write_text(f"#!/bin/sh\ncat '{home}/Documents/Vault/secret.txt' >/dev/null 2>&1; echo read=$?; "
                     "echo inside=${BLACKBOX_AGENT_SANDBOX:-0}\n", encoding="utf-8")
    agent.chmod(0o755)
    env = {**os.environ, "PATH": f"{sandbox.launcher_dir()}:{fake}:/usr/bin:/bin"}
    env.pop("BLACKBOX_AGENT_SANDBOX", None)
    done = subprocess.run(["claude"], capture_output=True, text=True, timeout=30, env=env, check=False)
    assert done.stdout.split() == ["read=1", "inside=1"], (done.stdout, done.stderr)


@REAL
def test_the_canary_proves_a_session_is_inside_and_a_variable_can_not_fake_it(home):
    sandbox.sync(_mode())
    code = "import sys; sys.path[:0]=[]; from pathlib import Path\n" \
           f"try:\n open({str(sandbox.canary_path())!r}).read(1); print('outside')\nexcept PermissionError: print('inside')"
    inside = subprocess.run([macos.SANDBOX_EXEC, "-f", str(sandbox.profile_path()), sys.executable, "-c", code],
                            capture_output=True, text=True, timeout=30, check=False)
    faked = subprocess.run([sys.executable, "-c", code], capture_output=True, text=True, timeout=30, check=False,
                           env={**os.environ, "BLACKBOX_AGENT_SANDBOX": "1"})
    assert (inside.stdout.strip(), faked.stdout.strip()) == ("inside", "outside")
    assert sandbox.proven() is False   # this test process is outside


# -- sync: profile, launchers, PATH ---------------------------------------------------------

@REAL
def test_sync_writes_launchers_and_the_path_block_and_takes_them_away(home):
    sandbox.sync(_mode(("claude-code", "codex")))
    folder = sandbox.launcher_dir()
    assert sorted(path.name for path in folder.iterdir()) == ["claude", "codex"]
    assert os.access(folder / "claude", os.X_OK) and sandbox.profile_path().is_file()
    assert shell_path.present(home) and str(folder) in (home / ".zshrc").read_text(encoding="utf-8")
    sandbox.sync(_mode(("codex",)))
    assert sorted(path.name for path in folder.iterdir()) == ["codex"]
    sandbox.sync(_mode(()))
    assert list(folder.iterdir()) == [] and not shell_path.present(home)


def test_the_path_block_goes_last_once_and_leaves_the_persons_lines(home):
    (home / ".zshrc").write_text("export PATH=/opt/mine:$PATH\n", encoding="utf-8")
    (home / ".bashrc").write_text("alias ll='ls -l'", encoding="utf-8")
    shell_path.add(home / "bin")
    shell_path.add(home / "bin")
    text = (home / ".zshrc").read_text(encoding="utf-8")
    assert text.count(shell_path.BEGIN) == 1 and text.startswith("export PATH=/opt/mine:$PATH\n")
    assert text.rstrip().endswith(shell_path.END)
    assert shell_path.remove(home) == [home / ".zshrc", home / ".bashrc"]
    assert (home / ".zshrc").read_text(encoding="utf-8") == "export PATH=/opt/mine:$PATH\n"
    assert (home / ".bashrc").read_text(encoding="utf-8") == "alias ll='ls -l'\n"


# -- the setting -----------------------------------------------------------------------------

def test_no_agent_is_sandboxed_until_the_person_picks_one_and_only_known_cli_agents_can_be(entry):
    assert files_mode.from_entry({"shields": {"file-shield": {"enabled": True}}}).options[files_mode.OPT_SANDBOXED] == ()
    assert files_mode.validate({"shields": {"file-shield": {"sandboxed": ["claude-code", "gemini-cli"]}}})[2] == []
    for bad in (["nobody"], ["windsurf"], "claude-code", [3]):
        assert files_mode.validate({"shields": {"file-shield": {"sandboxed": bad}}})[2], bad
    assert any(field.key == "sandboxed" and field.kind == "multi-pick" for field in files_mode.fields())


def test_taking_an_agent_out_of_the_sandbox_waits_for_the_person_and_adding_one_does_not(entry):
    current = approvals.Current(settings={}, shields={"file-shield": {"enabled": True, "protected": [VAULT],
                                                                       "sandboxed": ["claude-code"]}},
                                allow_lists={"file-shield": frozenset()})
    out = approvals.reasons("/api/settings", {"shields": {"file-shield": {"sandboxed": []}}}, current)
    added = approvals.reasons("/api/settings", {"shields": {"file-shield": {"sandboxed": ["claude-code", "codex"]}}}, current)
    assert out and "claude-code" in out[0] and added == []


def test_opening_an_editor_protected_says_why_it_can_not(entry, monkeypatch):
    with pytest.raises(ShieldApiError) as unknown:
        api.open_protected(None, {"app": "notepad"})
    entry["shields"]["file-shield"]["enabled"] = False
    with pytest.raises(ShieldApiError) as off:
        api.open_protected(None, {"app": "cursor"})
    assert unknown.value.status == 400 and off.value.status == 409


# -- refusals the helper reads from the system log --------------------------------------------

def test_a_sandbox_refusal_in_a_protected_item_becomes_a_file_shield_hit_and_one_event(entry, home):
    inside = str(home / "Documents" / "Vault" / "secret.txt")
    kept = changes.record([{"path": inside, "kind": "denied", "program": "python3.14", "ts": 100},
                           {"path": str(home / "Documents" / "beside.txt"), "kind": "denied", "program": "cat"}],
                          files_mode.current(), now=200)
    assert [(c.kind, c.program, c.item) for c in kept] == [("denied", "python3.14", VAULT)]
    hits = events.hits()
    assert hits and hits[0]["agent"] == "agent-sandbox" and hits[0]["route"] == "sandbox" and hits[0]["decision"] == "block"
    shown = [event for event in events.report() if VAULT in event.story]
    assert len(shown) == 1 and shown[0].outcome == "blocked" and "python3.14" in shown[0].title
    assert not audit.read_findings(limit=5)[0].get("reported")


def test_a_malformed_program_name_is_refused(entry, home):
    with pytest.raises(ShieldApiError):
        changes.record([{"path": str(home / "x"), "kind": "denied", "program": "p" * 65}], files_mode.current())


def test_uninstall_takes_the_launchers_off_path(home):
    from types import SimpleNamespace
    from plugins.blackbox.setup import uninstall_outside
    shell_path.add(home / "bb" / "agent-bin")
    report: list[str] = []
    uninstall_outside._remove_agent_hooks(SimpleNamespace(agent_hooks=(), addons=()), report)
    assert not shell_path.present(home) and any("off PATH" in line for line in report)


@REAL
def test_inside_the_sandbox_another_app_can_not_be_driven_and_agent_tools_still_run(home):
    """Coordinator 2026-11-22: close osascript / AppleEvents and `open -a` where it does not break
    the agent CLIs. Red on 8758124777 (osascript drove Finder from inside)."""
    sandbox.sync(_mode())
    secret = home / "Documents" / "Vault" / "secret.txt"
    script = f"""
osascript -e 'tell application "Finder" to get name' >/dev/null 2>&1; echo osascript=$?
osascript -l JavaScript -e '1' >/dev/null 2>&1; echo jxa=$?
automator -h >/dev/null 2>&1; echo automator=$?
shortcuts list >/dev/null 2>&1; echo shortcuts=$?
open -a TextEdit '{secret}' >/dev/null 2>&1; echo open=$?
python3 -c 'print(1)' >/dev/null 2>&1; echo python=$?
git --version >/dev/null 2>&1; echo git=$?
/bin/zsh -c 'echo ok' >/dev/null 2>&1; echo zsh=$?
"""
    lines = dict(line.split("=", 1) for line in _run(sandbox.profile_path(), script).stdout.split())
    assert all(lines[name] != "0" for name in ("osascript", "jxa", "automator", "shortcuts", "open")), lines
    assert all(lines[name] == "0" for name in ("python", "git", "zsh")), lines
    for agent in ("claude", "codex"):   # the real agent CLIs, when this Mac has them
        found = shutil.which(agent)
        if found:
            done = subprocess.run([macos.SANDBOX_EXEC, "-f", str(sandbox.profile_path()), found, "--version"],
                                  capture_output=True, text=True, timeout=60, check=False)
            assert done.returncode == 0, (agent, done.stderr)
