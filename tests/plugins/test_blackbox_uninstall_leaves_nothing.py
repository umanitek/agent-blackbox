"""After ``blackbox uninstall`` nothing of Blackbox's is left and everything of the person's is as it was.

Founder question (2026-11-23, after security round 4): does uninstalling leave the system clean?
Everything Blackbox adds to a person's home — the plugin and its Hermes entry, Blackbox's data
folder with the agent sandbox's launchers, the setuid-free ``ps`` and the stand-ins, the brew shim
and its client, the Hermes agent's sandboxed shells and its execute_code launcher, the PATH block
in ``~/.zshrc`` and ``~/.zshenv``, coding agents' hook entries, an add-on folder, the login
services, the DKG node's home and the ``blackbox`` command — is put in place here by the REAL code
that installs it (in a temporary HOME), then the REAL uninstall runs (services, the helper and
sudo are fakes that record). The tree is compared before and after: every file of the person's
byte for byte, and nothing else. A second run (an uninstall that crashed halfway, run again) changes
nothing and fails on nothing. The VM's before/after snapshot in round 5 is the real proof.
"""

from __future__ import annotations

import dataclasses
import json
import os
import sys
from pathlib import Path

import pytest

from plugins.blackbox.setup import uninstall
from plugins.blackbox.setup.platform import macos as platform_macos

#: The person's own files before Blackbox: a config with comments, shell startup files with their
#: own lines, Claude Code's settings with their own hook, another DKG node, an unrelated plugin.
PERSON = {
    ".hermes/config.yaml": "# my Hermes\nmodel:\n  default: nous/hermes-4   # the model\nplugins:\n  enabled:\n    - browser\n",
    ".zshrc": "# my zshrc\nexport EDITOR=vim\nalias ll='ls -la'\n",
    ".zshenv": "export LANG=en_US.UTF-8\n",
    ".claude/settings.json": json.dumps({"theme": "dark", "hooks": {"PreToolUse": [
        {"matcher": "Bash", "hooks": [{"type": "command", "command": "echo my own hook"}]}]}}, indent=2) + "\n",
    ".dkg/config.json": "foreman's node",
    ".hermes/plugins/someone_elses/__init__.py": "",
    ".local/bin/hermes": "#!/bin/sh\nexec real-hermes\n",
    "Documents/notes.md": "mine\n",
    ".hermes/SOUL.md": "my agent's soul\n",   # Hermes's own file, the person's to keep
}
#: Hermes's own records, written by Hermes whenever its config is read (a dated copy of the last good
#: config): the host's, not Blackbox's, and a person's real Hermes home already has them.
HOST_RECORDS = (".hermes/backups/",)


@pytest.fixture(autouse=True)
def os_services(monkeypatch):
    """The login services are removed through ``setup/platform/<os>``; these plans are macOS's
    unless a test says otherwise (``_on``), whatever machine runs the suite."""
    monkeypatch.setattr(uninstall, "os_platform", platform_macos)


def _tree(root: Path) -> dict[str, bytes]:
    files = {str(path.relative_to(root)): path.read_bytes() for path in sorted(root.rglob("*"))
             if path.is_file() or path.is_symlink()}
    return {name: data for name, data in files.items() if not name.startswith(HOST_RECORDS)}


@pytest.fixture
def home(tmp_path, monkeypatch):
    root = (tmp_path / "user").resolve()
    for name, text in PERSON.items():
        (root / name).parent.mkdir(parents=True, exist_ok=True)
        (root / name).write_text(text, encoding="utf-8")
    monkeypatch.setenv("HOME", str(root))
    monkeypatch.setenv("HERMES_HOME", str(root / ".hermes"))
    monkeypatch.delenv("BLACKBOX_HOME", raising=False)
    monkeypatch.delenv("BLACKBOX_DKG_HOME", raising=False)
    return root


def _install_everything(home: Path) -> None:
    """Every piece Blackbox puts in a home, by the code that puts it there."""
    from plugins.blackbox.agent_hooks import set_protection
    from plugins.blackbox.attach import attach_hermes
    from plugins.blackbox.kernel import constants
    from plugins.blackbox.shields.files import mode as files_mode, sandbox
    attach_hermes(home / ".hermes")                                    # the plugin + config entry
    config = home / ".hermes" / "config.yaml"
    config.write_text(config.read_text(encoding="utf-8") + "  entries:\n    blackbox:\n      mode: audit\n"
                      "      shields:\n        file-shield:\n          sandbox_declined: [codex]\n", encoding="utf-8")
    assert set_protection("claude-code", True)["ok"]                    # a coding agent's hooks
    if sys.platform == "darwin" and os.access("/usr/bin/sandbox-exec", os.X_OK):
        picked = files_mode.build(enabled=True, protected=("~/Documents",), sandboxed=("claude-code", "hermes"))
        sandbox.sync(picked)                                            # launchers, PATH block, ps, stand-ins, brew shim
        sandbox.enter_hermes_process(picked, {"PATH": "/usr/bin:/bin"})  # Hermes shells + execute_code launcher
        assert (home / ".zshrc").read_text(encoding="utf-8") != PERSON[".zshrc"]
    addon = home / ".hermes" / "plugins" / "example_addon"            # an add-on beside the plugin
    addon.mkdir(parents=True)
    (addon / "blackbox-addon.json").write_text('{"extends": "blackbox"}', encoding="utf-8")
    (addon / "__init__.py").write_text("", encoding="utf-8")
    dkg = constants.blackbox_dkg_home()                                 # the node's home, its marker and keys
    dkg.mkdir(parents=True, exist_ok=True)
    (dkg / uninstall.DKG_HOME_MARKER).write_text("{}", encoding="utf-8")
    (dkg / "daemon.pid").write_text("2147483646", encoding="utf-8")    # no such process
    (constants.blackbox_home() / "audit.jsonl").write_text('{"event": 1}\n', encoding="utf-8")
    agents = home / "Library" / "LaunchAgents"                         # the login services
    agents.mkdir(parents=True, exist_ok=True)
    for label in uninstall.LAUNCHD_LABELS:
        (agents / f"{label}.plist").write_text("<plist/>", encoding="utf-8")
    (home / ".local" / "bin" / "blackbox").write_text(f"#!/bin/sh\n# {uninstall.SHIM_MARKER}\n", encoding="utf-8")


def _uninstall(home: Path) -> list[str]:
    plan = dataclasses.replace(uninstall.build_plan(homes=[home / ".hermes"], purge=True, keep_logs=False), system="Darwin")
    return uninstall.execute(plan, run=lambda command: 0, stop_dashboard=lambda port: [], run_as_admin=lambda command: 0)


def test_uninstall_leaves_the_persons_files_byte_identical_and_nothing_of_blackboxs(home):
    before = _tree(home)
    _install_everything(home)
    assert _tree(home) != before
    _uninstall(home)
    after = _tree(home)
    left = sorted(set(after) - set(before))
    assert left == [], f"left behind: {left}"
    changed = sorted(name for name in before if after.get(name) != before[name])
    assert changed == [], {name: after.get(name, b"<gone>").decode("utf-8", "replace") for name in changed}
    empty = sorted(str(path.relative_to(home)) for path in home.rglob("*") if path.is_dir() and not any(path.iterdir()))
    assert not [name for name in empty if "blackbox" in name.lower()], empty


def test_an_uninstall_run_again_after_stopping_halfway_finishes_and_changes_nothing_more(home):
    before = _tree(home)
    _install_everything(home)
    _uninstall(home)
    once = _tree(home)
    _uninstall(home)   # a second run: idempotent, and it does not fail on what is already gone
    assert _tree(home) == once == before


def test_a_second_uninstall_says_blackbox_is_not_installed_and_changes_nothing(home, capsys):
    """KI-611 (round 5, bb-r5-clean): the second `hermes blackbox uninstall` exited 0 but made a NEW
    ~/blackbox-backup-<time>/ (a README and an EMPTY keys/ folder, "kept your keys in …") and deleted
    a re-created cursor file. Now: no backup without keys, and a second run touches nothing."""
    import argparse
    before = _tree(home)
    _install_everything(home)
    plan = dataclasses.replace(uninstall.build_plan(homes=[home / ".hermes"], purge=False, keep_logs=False), system="Darwin")
    uninstall.execute(plan, run=lambda command: 0, stop_dashboard=lambda port: [], run_as_admin=lambda command: 0)
    assert not list(home.glob("blackbox-backup-*")), "a backup folder with no keys in it"
    once = _tree(home)
    assert once == before
    args = argparse.Namespace(purge=False, keep_logs=False, dry_run=False, yes=True, remove_host=False)
    assert uninstall.cmd_uninstall(args) == 0
    assert "Blackbox is not installed here: nothing to remove." in capsys.readouterr().out
    assert _tree(home) == once and not list(home.glob("blackbox-backup-*"))


def test_a_look_at_hermes_sessions_never_recreates_a_deleted_blackbox_home(home):
    """KI-611: ~/.hermes/blackbox/agent-hooks/hermes-cursor.json came back after the uninstall
    deleted Blackbox's home — a process still looking wrote it again."""
    from plugins.blackbox.agent_hooks import hermes_sessions
    from plugins.blackbox.kernel import constants
    assert not constants.blackbox_home().exists()
    assert hermes_sessions.catch_up() == 0
    assert not constants.blackbox_home().exists()


# ── KI-610 / KI-611: a clean Mac — no Hermes before; Blackbox's installer set up the host ──────────
INSTALL_SH = Path(__file__).resolve().parents[2] / "scripts" / "blackbox-install.sh"
MANIFEST_FUNCTIONS = ("install_path_exists", "install_host_paths", "install_own_dirs", "install_startup_files",
                      "install_manifest_begin", "install_manifest_write")
#: The block Hermes's own setup appended to ~/.zshrc in round 5 (the person's lines above it stay).
HERMES_PATH_BLOCK = '\n# Hermes Agent — ensure ~/.local/bin is on PATH\nexport PATH="$HOME/.local/bin:$PATH"\n'


def _shell(home: Path, record: Path, call: str) -> None:
    import re
    import subprocess
    text = INSTALL_SH.read_text(encoding="utf-8")
    bodies = []
    for name in MANIFEST_FUNCTIONS:
        found = re.search(rf"^{name}\(\)\s*\{{.*?^\}}\n", text, re.MULTILINE | re.DOTALL)
        assert found is not None, name
        bodies.append(found.group(0))
    script = "\n".join([f'HOME="{home}"', f'HERMES_HOME="{home}/.hermes"', f'BLACKBOX_HOME="{home}/.hermes/blackbox"',
                        f'BLACKBOX_INSTALL_ROOT="{home}/agent-blackbox"', f'INSTALL_RECORD_DIR="{record}"', *bodies, call])
    done = subprocess.run(["/bin/bash", "-c", script], capture_output=True, text=True, timeout=60, check=False)
    assert done.returncode == 0, done.stderr


def _install_on_a_clean_mac(home: Path, record: Path) -> None:
    """The installer's run: its manifest step before and after, the host it sets up, then Blackbox."""
    record.mkdir()
    _shell(home, record, "install_manifest_begin")
    checkout = home / "agent-blackbox"                                  # the Hermes checkout = Blackbox's repo
    (checkout / "hermes_cli").mkdir(parents=True)
    (checkout / "plugins" / "blackbox").mkdir(parents=True)
    (checkout / "plugins" / "blackbox" / "plugin.yaml").write_text("kind: backend\n", encoding="utf-8")
    (checkout / "venv" / "bin").mkdir(parents=True)
    (checkout / "venv" / "bin" / "hermes").write_text("#!/bin/sh\n", encoding="utf-8")
    (home / ".hermes").mkdir()
    (home / ".hermes" / "config.yaml").write_text("model:\n  default: x\n", encoding="utf-8")
    (home / ".hermes" / "installs").mkdir()
    (home / ".hermes" / "installs" / "venv.bin").write_bytes(b"\0" * 4096)
    bin_dir = home / ".local" / "bin"
    bin_dir.mkdir(parents=True, exist_ok=True)
    for name in ("hermes", "hermes-acp", "hermes-agent"):
        (bin_dir / name).symlink_to(checkout / "venv" / "bin" / "hermes")
    (bin_dir / "uv").write_text("uv", encoding="utf-8")
    (home / ".local" / "share" / "uv").mkdir(parents=True)
    (home / ".local" / "share" / "uv" / "python").write_text("py", encoding="utf-8")
    (home / ".config" / "openui").mkdir(parents=True)
    (home / ".config" / "openui" / "telemetry.json").write_text('{"distinctId": "x"}', encoding="utf-8")
    with (home / ".zshrc").open("a", encoding="utf-8") as zshrc:
        zshrc.write(HERMES_PATH_BLOCK)
    _install_everything(home)                                          # Blackbox, its services' folder included
    _shell(home, record, "install_manifest_write")


@pytest.fixture
def clean_mac(home):
    """The person's home on a Mac with no Hermes: their own files, ~/Library without LaunchAgents."""
    import shutil
    shutil.rmtree(home / ".hermes")
    (home / ".local" / "bin" / "hermes").unlink()
    (home / ".local" / "bin").rmdir()
    (home / ".local").rmdir()
    (home / "Library").mkdir()
    return home


def _uninstall_clean(home: Path, remove_host: bool) -> list[str]:
    plan = dataclasses.replace(uninstall.build_plan(homes=[home / ".hermes"], purge=True, keep_logs=False), system="Darwin")
    assert plan.manifest.has_host
    return uninstall.execute(plan, run=lambda command: 0, stop_dashboard=lambda port: [], run_as_admin=lambda command: 0,
                             remove_host=remove_host)


def _empty_folders(home: Path) -> list[str]:
    return sorted(str(path.relative_to(home)) for path in home.rglob("*") if path.is_dir() and not any(path.iterdir()))


def test_on_a_clean_mac_yes_removes_the_host_and_the_home_is_as_it_was_byte_for_byte(clean_mac, tmp_path):
    """KI-610: ~/agent-blackbox, ~/.hermes, ~/.local/bin/hermes*, uv's files, the telemetry id and the
    Hermes PATH block in ~/.zshrc all stayed. With a yes, exactly what the manifest lists goes."""
    before, empty_before = _tree(clean_mac), _empty_folders(clean_mac)
    _install_on_a_clean_mac(clean_mac, tmp_path / "record")
    report = _uninstall_clean(clean_mac, remove_host=True)
    after = _tree(clean_mac)
    assert sorted(set(after) - set(before)) == [], f"left behind: {sorted(set(after) - set(before))}"
    assert [name for name in before if after.get(name) != before[name]] == []   # .zshrc byte-identical
    assert _empty_folders(clean_mac) == empty_before                            # no empty LaunchAgents, .local, .config
    assert any("took the installer's lines out of" in line for line in report)


def test_on_a_clean_mac_no_keeps_the_host_with_blackbox_switched_off_in_it(clean_mac, tmp_path, capsys):
    """KI-610 (c): kept, the host must not list Blackbox as "enabled · bundled"; KI-611: the empty
    ~/Library/LaunchAgents the installer made goes either way."""
    from plugins.blackbox.kernel import yaml_files
    _install_on_a_clean_mac(clean_mac, tmp_path / "record")
    plan = uninstall.build_plan(homes=[clean_mac / ".hermes"], purge=True, keep_logs=False)
    assert uninstall.host_question(plan).startswith("Blackbox also set up the Hermes host it runs in (")
    assert uninstall.host_question(plan).endswith("). Remove it too? [y/N] ")
    _uninstall_clean(clean_mac, remove_host=False)
    plugins = yaml_files.load_yaml(clean_mac / ".hermes" / "config.yaml").get("plugins") or {}
    assert "blackbox" in (plugins.get("disabled") or []) and "blackbox" not in (plugins.get("enabled") or [])
    assert (clean_mac / "agent-blackbox").is_dir() and (clean_mac / ".local" / "bin" / "hermes").is_symlink()
    assert HERMES_PATH_BLOCK in (clean_mac / ".zshrc").read_text(encoding="utf-8")   # Hermes still needs it
    assert not (clean_mac / "Library" / "LaunchAgents").exists()
    assert "Kept the Hermes host" in uninstall.host_kept_note(plan) and "~/agent-blackbox" in uninstall.host_kept_note(plan)


def test_a_hermes_the_person_had_before_blackbox_is_never_offered_for_removal(home, tmp_path):
    record = tmp_path / "record"
    record.mkdir()
    _shell(home, record, "install_manifest_begin")
    _install_everything(home)
    _shell(home, record, "install_manifest_write")
    plan = uninstall.build_plan(homes=[home / ".hermes"], purge=True, keep_logs=False)
    assert not plan.manifest.has_host and home / ".hermes" not in plan.manifest.host


def test_a_planted_manifest_can_not_reach_outside_the_home(home, tmp_path):
    from plugins.blackbox.kernel import constants
    from plugins.blackbox.setup import install_manifest
    outside = tmp_path / "outside"
    outside.mkdir()
    (home / "link-out").symlink_to(outside)
    folder = constants.blackbox_home() / install_manifest.FOLDER
    folder.mkdir(parents=True)
    (folder / install_manifest.MANIFEST).write_text("\n".join([
        f"host\t{outside}", f"host\t{home}", f"host\t{home}/../escape", "host\trelative/path", f"host\t{home}/link-out/x",
        f"host\t{home}/Documents/notes.md"]) + "\n", encoding="utf-8")
    manifest = install_manifest.read(constants.blackbox_home())
    assert manifest.host == (home / "Documents" / "notes.md",)   # the only one inside the home (as written)
