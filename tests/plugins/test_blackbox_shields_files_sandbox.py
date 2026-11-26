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
    # A machine where agents can be sandboxed (a Mac; Linux once the launcher is installed), whatever
    # runs the test: on a CI runner without the launcher, sync() writes nothing (PR #63's Linux CI)
    monkeypatch.setattr(sandbox.platform, "unavailable", lambda: None)
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
    assert sorted(path.name for path in folder.iterdir() if path.is_file()) == ["claude", "codex"]
    assert os.access(folder / "claude", os.X_OK) and sandbox.profile_path().is_file()
    assert shell_path.present(home) and str(folder) in (home / ".zshrc").read_text(encoding="utf-8")
    sandbox.sync(_mode(("codex",)))
    assert sorted(path.name for path in folder.iterdir() if path.is_file()) == ["codex"]
    sandbox.sync(_mode(()))
    assert list(folder.iterdir()) == [] and not shell_path.present(home)


def test_the_path_block_is_written_last_once_and_leaves_the_persons_lines(home):
    (home / ".zshrc").write_text("export PATH=/opt/mine:$PATH\n", encoding="utf-8")
    (home / ".bashrc").write_text("alias ll='ls -l'", encoding="utf-8")
    shell_path.add(home / "bin")
    shell_path.add(home / "bin")
    text = (home / ".zshrc").read_text(encoding="utf-8")
    assert text.count(shell_path.BEGIN) == 1 and text.startswith("export PATH=/opt/mine:$PATH\n")
    assert text.rstrip().endswith(shell_path.END)
    assert shell_path.remove(home) == [home / ".zshrc", home / ".zshenv", home / ".bashrc"]   # .zshenv: every zsh
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
    assert out == ["Take Claude Code out of the agent sandbox (File Shield)"] and added == []   # KI-538: words, not ids


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


# -- the PATH block can not be undone (KI-535, E2E full4 2026-11-22) -------------------------------

def test_the_profile_closes_every_shell_startup_file_to_writes(home):
    text = macos.render(sandbox.policy(_mode()))
    for name in shell_path.STARTUP_FILES:
        assert f'(literal "{home / name}")' in text, name


@REAL
def test_a_real_sandbox_can_not_write_create_or_remove_a_shell_startup_file(home):
    (home / ".zshrc").write_text("export EDITOR=vim\n", encoding="utf-8")
    sandbox.sync(_mode())
    before = (home / ".zshrc").read_text(encoding="utf-8")
    script = f"""
echo 'export PATH=/evil:$PATH' >> '{home}/.zshrc' 2>/dev/null; echo append=$?
printf '' > '{home}/.zshrc' 2>/dev/null; echo truncate=$?
mv '{home}/.zshrc' '{home}/z.bak' 2>/dev/null; echo move=$?
rm -f '{home}/.zshrc' 2>/dev/null; echo remove=$?
echo 'export PATH=/evil:$PATH' > '{home}/.zlogin' 2>/dev/null; echo create=$?
echo ok > '{home}/Documents/notes.txt'; echo elsewhere=$?
"""
    lines = dict(line.split("=", 1) for line in _run(sandbox.profile_path(), script).stdout.split())
    assert {k: lines[k] for k in ("append", "truncate", "move", "remove", "create")} == dict.fromkeys(
        ("append", "truncate", "move", "remove", "create"), "1"), lines
    assert lines["elsewhere"] == "0"
    assert (home / ".zshrc").read_text(encoding="utf-8") == before and not (home / ".zlogin").exists()


def test_an_agent_may_edit_its_own_lines_of_a_startup_file_but_never_the_block(home):
    from plugins.blackbox.detection import detect_guard_tamper
    (home / ".zshrc").write_text("autoload -U compinit\nexport EDITOR=vim\n", encoding="utf-8")
    shell_path.add(home / "bb" / "agent-bin")
    zshrc = str(home / ".zshrc")
    text = (home / ".zshrc").read_text(encoding="utf-8")
    block = shell_path.section(text)
    refused = [
        ("Edit", {"file_path": zshrc, "old_string": block, "new_string": ""}),
        ("Edit", {"file_path": zshrc, "old_string": shell_path.END, "new_string": shell_path.END + "\nexport PATH=/x:$PATH"}),
        ("Write", {"file_path": zshrc, "content": "autoload -U compinit\n"}),
        ("Bash", {"command": f"sed -i '' '/Blackbox agent sandbox/d' {zshrc}"}),
        ("Bash", {"command": "echo 'export PATH=/evil:$PATH' >> ~/.zshrc"}),
    ]
    allowed = [
        ("Edit", {"file_path": zshrc, "old_string": "export EDITOR=vim", "new_string": "export EDITOR=nano"}),
        ("Edit", {"file_path": zshrc, "old_string": "autoload -U compinit", "new_string": "autoload -Uz compinit"}),
        ("Write", {"file_path": zshrc, "content": "export EDITOR=nano\n" + block + "\n"}),
        ("Bash", {"command": "cat ~/.zshrc"}),
    ]
    for tool, args in refused:
        assert detect_guard_tamper(tool, args), (tool, args)
    for tool, args in allowed:
        assert not detect_guard_tamper(tool, args), (tool, args)


def test_an_agents_edit_of_the_persons_own_lines_is_judged_on_the_file_it_leaves(home):
    """KI-539 (E2E full5 2026-11-22): Claude Code's Edit of ``alias gs='git status'`` in a ~/.zshrc
    holding the block was refused as "Change to Blackbox's own settings" — the hook runner had turned
    the edit into a whole-file write of the new snippet. Through the runner, as a real hook sends it."""
    from plugins.blackbox.agent_hooks.protect import runner
    from plugins.blackbox.detection import detect_guard_tamper
    (home / ".zshrc").write_text("alias gs='git status'\n# Hermes Agent — ensure ~/.local/bin is on PATH\n"
                                 "export PATH=\"$HOME/.local/bin:$PATH\"\n", encoding="utf-8")
    shell_path.add(home / "bb" / "agent-bin")
    zshrc = str(home / ".zshrc")

    def judged(tool_input: dict, tool: str = "Edit") -> bool:
        name, args = runner._canonical(tool, tool_input)
        return bool(detect_guard_tamper(name, args))

    assert not judged({"file_path": zshrc, "old_string": "alias gs='git status'", "new_string": "alias gs='git status -sb'"})
    assert not judged({"file_path": zshrc, "old_string": "# Hermes Agent — ensure ~/.local/bin is on PATH",
                       "new_string": "# Hermes Agent — ensure ~/.local/bin is on PATH (edited)"})
    assert not judged({"file_path": zshrc, "edits": [{"old_string": "alias gs='git status'", "new_string": "alias gs='git st'"}]},
                      "MultiEdit")
    assert not judged({"command": "echo \"alias gl='git log'\" >> ~/.zshrc"}, "Bash")
    # …and never anything that leaves the block changed, or sends an agent round the launcher.
    block = shell_path.section((home / ".zshrc").read_text(encoding="utf-8"))
    assert judged({"file_path": zshrc, "old_string": block, "new_string": ""})
    assert judged({"file_path": zshrc, "old_string": "alias gs='git status'", "new_string": "alias claude=/opt/real/claude"})
    assert judged({"file_path": zshrc, "old_string": "alias gs='git status'", "new_string": "export PATH=/evil:$PATH"})
    assert judged({"command": "echo 'alias codex=/opt/codex' >> ~/.zshrc"}, "Bash")
    assert judged({"command": "echo hi > ~/.zshrc"}, "Bash")
    assert judged({"command": "echo \"$(cat /tmp/x)\" >> ~/.zshrc"}, "Bash")
    assert judged({"command": "echo hi >> ~/.zshrc; sed -i '' '/Blackbox/d' ~/.zshrc"}, "Bash")


def test_a_line_the_person_adds_after_the_block_is_theirs_never_an_alarm(home, entry):
    """KI-540 (E2E full5 2026-11-22): appending ``alias gl='git log'`` below the block raised "Something
    removed …" and rewrote the person's ~/.zshrc to move the block back to the end."""
    from plugins.blackbox.shields.files import alerts
    sandbox.sync(_mode())
    zshrc = home / ".zshrc"
    zshrc.write_text(zshrc.read_text(encoding="utf-8") + "alias gl='git log'\nexport PATH=/opt/mine:$PATH\n", encoding="utf-8")
    mine = zshrc.read_text(encoding="utf-8")
    sandbox.sync(_mode())
    assert zshrc.read_text(encoding="utf-8") == mine
    assert sandbox.restorations() == [] and alerts.alerts() == []
    assert shell_path.intact(sandbox.launcher_dir(), home)


def test_blackboxs_own_older_block_is_upgraded_quietly(home, entry):
    from plugins.blackbox.shields.files import alerts
    folder = sandbox.launcher_dir()
    sandbox.sync(_mode())
    zshrc = home / ".zshrc"
    zshrc.write_text("export EDITOR=vim\n" + shell_path._legacy_block(folder), encoding="utf-8")
    sandbox.sync(_mode())
    assert shell_path.intact(folder, home) and zshrc.read_text(encoding="utf-8").startswith("export EDITOR=vim\n")
    assert sandbox.restorations() == [] and alerts.alerts() == []


@pytest.mark.skipif(not (shutil.which("zsh") and shutil.which("bash")), reason="needs zsh and bash")
def test_the_block_puts_the_launcher_first_again_before_every_prompt_in_zsh_and_bash(home):
    """A PATH line the person adds after the block can not put the real agent first (KI-540)."""
    folder = home / "agent bin"
    script = home / "rc"
    script.write_text(shell_path.block(folder) + "PATH=/later:$PATH\n", encoding="utf-8")
    zsh = subprocess.run(["zsh", "-fc", f"source '{script}'; source '{script}'; for f in $precmd_functions; do $f; done; "
                          "print -r -- ${#precmd_functions}; print -r -- ${PATH%%:*}"],
                         capture_output=True, text=True, timeout=30, check=True)
    bash = subprocess.run(["bash", "--norc", "-c", f"source '{script}'; source '{script}'; eval \"$PROMPT_COMMAND\"; "
                           "echo \"$PROMPT_COMMAND\"; echo \"${PATH%%:*}\""],
                          capture_output=True, text=True, timeout=30, check=True)
    assert zsh.stdout.splitlines() == ["1", str(folder)]
    assert bash.stdout.splitlines() == [shell_path.FUNCTION, str(folder)]


def test_without_the_block_a_startup_file_is_the_persons_own(home):
    from plugins.blackbox.detection import detect_guard_tamper
    (home / ".zshrc").write_text("export EDITOR=vim\n", encoding="utf-8")
    assert not detect_guard_tamper("Bash", {"command": "echo 'export PATH=/opt/x:$PATH' >> ~/.zshrc"})
    assert not detect_guard_tamper("Write", {"file_path": str(home / ".zshrc"), "content": "export EDITOR=nano\n"})


def test_a_removed_or_changed_block_is_put_back_and_the_person_is_told(home, entry):
    from plugins.blackbox.shields.files import alerts
    sandbox.sync(_mode())
    assert sandbox.restorations() == [] and alerts.alerts() == []
    zshrc = home / ".zshrc"
    zshrc.write_text(zshrc.read_text(encoding="utf-8").replace(str(sandbox.launcher_dir()), "/elsewhere"), encoding="utf-8")
    sandbox.sync(_mode())
    assert shell_path.intact(sandbox.launcher_dir(), home)
    zshrc.write_text("export EDITOR=vim\n", encoding="utf-8")   # the block taken out
    sandbox.sync(_mode())
    assert shell_path.intact(sandbox.launcher_dir(), home)
    rows = sandbox.restorations()
    assert len(rows) == 2 and rows[0]["files"] == [str(zshrc)]
    kinds = [alert["kind"] for alert in alerts.alerts()]
    assert kinds.count("path-restored") == 2


def test_the_first_time_the_block_is_written_is_not_a_restoration(home):
    sandbox.sync(_mode())
    sandbox.sync(_mode())
    assert sandbox.restorations() == []


# -- opening an editor protected (KI-534, E2E full4 2026-11-22) ------------------------------------

def _fake_editor(home: Path, body: str) -> tuple[dict, Path]:
    import plistlib
    bundle = home / "Apps" / "Fake.app"
    (bundle / "Contents" / "MacOS").mkdir(parents=True)
    with open(bundle / "Contents" / "Info.plist", "wb") as handle:
        plistlib.dump({"CFBundleExecutable": "Fake"}, handle)
    program = bundle / "Contents" / "MacOS" / "Fake"
    program.write_text("#!/bin/sh\n" + body, encoding="utf-8")
    program.chmod(0o755)
    return {"fake": ("Fake", str(bundle))}, home / "fake.log"


@REAL
def test_an_editor_that_dies_inside_the_sandbox_is_reported_never_called_starting(home):
    sandbox.sync(_mode())
    apps, log = _fake_editor(home, 'echo "sandbox initialization failed: Operation not permitted" >&2; exit 133\n')
    with pytest.raises(RuntimeError, match="stopped right after starting"):
        macos.open_app("fake", str(sandbox.profile_path()), apps=apps, log=str(log), started_seconds=2)
    assert "sandbox initialization failed" in log.read_text(encoding="utf-8")


@REAL
def test_an_editor_starts_inside_the_sandbox_with_its_own_sandbox_off_and_is_called_running(home):
    sandbox.sync(_mode())
    marker = home / "args.txt"
    apps, log = _fake_editor(home, f'echo "$@" > "{marker}"\ncat "{home}/Documents/Vault/secret.txt" 2>/dev/null; '
                                   f'echo "vault=$?" >> "{marker}"\nexec sleep 3\n')   # ends by itself
    message = macos.open_app("fake", str(sandbox.profile_path()), apps=apps, log=str(log), started_seconds=1.5)
    assert message == "Fake is running inside Blackbox's sandbox."
    text = marker.read_text(encoding="utf-8")
    assert "--no-sandbox" in text and "vault=1" in text   # inside Blackbox's sandbox: the vault is refused


def test_the_editor_offer_says_what_running_protected_means(entry):
    apps = sandbox.status(files_mode.current())["apps"]
    assert apps and all("web-page sandbox off" in app["note"] for app in apps)


# -- refusals are counted one by one, and the sandbox is not an agent (KI-538) --------------------

def test_every_refusal_is_its_own_row_even_with_the_same_path_in_one_session(home):
    finding = {"identifier": "files:folder-hit", "severity": "critical", "title": "x", "evidence": "read /v/plan.txt — protected folder /v",
               "confirmed": False, "source": "custom", "tool_name": "terminal"}
    for call in ("call-1", "call-2", "call-3"):
        audit.record_for("claude-code", event="pre_tool_call", findings=[dict(finding)],
                         detail={"session_id": "claude-code:abc", "tool_call_id": call, "decision": "block"})
    rows = [row for row in audit.read_findings(limit=50) if row["identifier"] == "files:folder-hit"]
    assert len(rows) == 3


def test_sandbox_refusals_are_counted_each_and_the_recorder_is_not_listed_as_an_agent(home, entry):
    vault = str(home / "Documents" / "Vault")
    changes.record([{"path": f"{vault}/secret.txt", "kind": "denied", "program": "cat"}] * 3, files_mode.current())
    hits = [hit for hit in events.hits(limit=50) if hit["agent"] == audit.SANDBOX_RECORDER]
    assert len(hits) == 3
    assert audit.SANDBOX_RECORDER not in audit.local_frameworks()
    assert audit.SANDBOX_RECORDER not in audit.local_active_frameworks()


# -- the picker's choices (BB-SHIELDS-001) ----------------------------------------------------

def _sandbox_options():
    field = next(field for field in files_mode.fields() if field.key == files_mode.OPT_SANDBOXED)
    return {option.id: option for option in field.options}


def test_every_sandbox_choice_carries_its_real_status_never_an_empty_one(home, monkeypatch):
    """BB-SHIELDS-001: each choice arrived with status "" and was drawn "not available"."""
    monkeypatch.setattr(sandbox.platform, "unavailable", lambda: None)
    bin_dir = home / ".local" / "bin"
    bin_dir.mkdir(parents=True)
    (bin_dir / "claude").write_text("#!/bin/sh\n", encoding="utf-8")
    (bin_dir / "claude").chmod(0o755)
    monkeypatch.setenv("PATH", "/nonexistent")
    options = _sandbox_options()
    assert all(option.status for option in options.values())
    assert options["claude-code"].status == "supported" and options["hermes"].status == "supported"
    assert options["codex"].status == "not installed" and options["codex"].note
    monkeypatch.setattr(sandbox.platform, "unavailable", lambda: "No sandbox here.")
    assert {(option.status, option.note) for option in _sandbox_options().values()} == {("unavailable", "No sandbox here.")}
