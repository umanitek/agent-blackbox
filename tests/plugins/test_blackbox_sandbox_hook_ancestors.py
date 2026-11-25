"""Every agent's hook and plugin place, and EVERY folder above it up to the home, stays where it is
for a sandboxed agent; and Blackbox's own hook that is removed or changed outside Blackbox is put
back and said (HIGH).

Security finding 2026-11-24 (Linux round L4, kernels 7.0 and 6.8, real Claude Code and Codex): only
the hook folders themselves were pinned, so ``mv ~/Documents/Cline`` and ``mv ~/.config/opencode``
succeeded inside the sandbox; a planted ``~/Documents/Cline/Hooks/TaskStart`` took the place of
Blackbox's, Blackbox's OpenCode plugin was moved away, and 90 s later nothing was put back and
nobody was told. LES-137: the place list is ONE definition (the agent catalogue,
``kernel.agent_hosts``) and every layer — the Linux policy, the macOS Seatbelt profile, the hook
judgement — refuses every entry (the drift test below). The REAL Seatbelt test runs on macOS; the
Linux kernel proof is the helper's own ``tests/sandbox_linux.rs`` plus the fix wave's VM run.
"""

from __future__ import annotations

import os
import subprocess
import sys
from pathlib import Path

import pytest

from plugins.blackbox import agent_hooks, audit
from plugins.blackbox.agent_hooks.protect import config_edit, foreign_hooks, hook_watch
from plugins.blackbox.detection.paths.guard_settings import detect_guard_tamper
from plugins.blackbox.kernel import agent_hosts
from plugins.blackbox.shields.files import changes, mode as files_mode, sandbox
from plugins.blackbox.shields.files.sandbox import platform
from plugins.blackbox.shields.files.sandbox.platform.linux import profile as linux_profile
from plugins.blackbox.shields.files.sandbox.platform.macos import profile as macos_profile

REAL_SEATBELT = pytest.mark.skipif(sys.platform != "darwin" or not os.access("/usr/bin/sandbox-exec", os.X_OK),
                                   reason="a real Seatbelt sandbox needs macOS")


@pytest.fixture
def home(tmp_path, monkeypatch):
    real = tmp_path.resolve()
    (real / ".hermes" / "blackbox").mkdir(parents=True)
    (real / ".hermes" / "config.yaml").write_text("plugins:\n  enabled:\n    - blackbox\n", encoding="utf-8")
    monkeypatch.setenv("HOME", str(real))
    monkeypatch.setenv("HERMES_HOME", str(real / ".hermes"))
    monkeypatch.delenv("BLACKBOX_HOME", raising=False)
    monkeypatch.setattr(platform, "startup_places", lambda folder: ([], [], []))
    changes.reset()
    yield real
    changes.reset()


def _hook_places(home: Path) -> list[Path]:
    """Every file an agent takes hooks from, as the catalogue names it."""
    out = []
    for host in agent_hosts.HOSTS:
        target = host.config_path(home)
        out += [target / event for event in host.events] if host.style == "scripts" else [target]
        out += list(host.companion_paths(home))
    return out


def _ancestors_in_home(place: Path, home: Path) -> list[str]:
    return [str(folder) for folder in place.parents if folder == home or home in folder.parents]


def test_every_folder_above_every_hook_place_up_to_the_home_is_refused_by_every_layer(home):
    places = sandbox.policy(files_mode.build(enabled=True, sandboxed=("claude-code",)))
    wanted = sorted({folder for place in _hook_places(home) for folder in _ancestors_in_home(place, home)})
    assert {str(home / "Documents" / "Cline"), str(home / ".config" / "opencode"), str(home / "Documents")} <= set(wanted)
    missing = [folder for folder in wanted if folder not in places.no_rename]
    assert not missing, f"not pinned in the policy: {missing}"
    linux = linux_profile.render(places, home=str(home), runtime="/run/user/1000").splitlines()
    assert not [folder for folder in wanted if f"pin {folder}" not in linux], "the Linux policy must pin each"
    macos = macos_profile.render(places).splitlines()
    start = macos.index("(deny file-write-unlink")
    unlink = "\n".join(macos[start:start + 1 + next(i for i, line in enumerate(macos[start + 1:]) if not line.startswith("  "))])
    assert not [folder for folder in wanted if f'(literal "{folder}")' not in unlink], "Seatbelt must deny renaming each"
    refused = [folder for folder in wanted
               if not detect_guard_tamper("terminal", {"command": f"mv {folder} {home}/moved-away"})]
    assert not refused, f"the hook judgement let these move: {refused}"


def _plant_hooks(home: Path) -> None:
    for place in _hook_places(home):
        if "Cline" in str(place) or "opencode" in str(place):
            place.parent.mkdir(parents=True, exist_ok=True)
            place.write_text(f"# Blackbox Agent Hooks ({config_edit.MARK})\n", encoding="utf-8")
    (home / "Documents" / "Other").mkdir(parents=True, exist_ok=True)


@REAL_SEATBELT
def test_a_sandboxed_program_can_not_move_a_hook_folders_parent_away(home):
    _plant_hooks(home)
    sandbox.sync(files_mode.build(enabled=True, sandboxed=("claude-code",)))
    script = f"""
mv '{home}/Documents/Cline' '{home}/cline-moved' 2>/dev/null; echo cline=$?
mv '{home}/.config/opencode' '{home}/opencode-moved' 2>/dev/null; echo opencode=$?
mv '{home}/.config' '{home}/config-moved' 2>/dev/null; echo config=$?
mv '{home}/Documents/Other' '{home}/Documents/Other2' 2>/dev/null; echo other=$?
"""
    done = subprocess.run(["/usr/bin/sandbox-exec", "-f", str(sandbox.profile_path()), "/bin/sh", "-c", script],
                          capture_output=True, text=True, timeout=30, check=False)
    lines = dict(line.split("=", 1) for line in done.stdout.split() if "=" in line)
    assert lines == {"cline": "1", "opencode": "1", "config": "1", "other": "0"}, lines
    assert (home / "Documents" / "Cline" / "Hooks").is_dir() and (home / ".config" / "opencode" / "plugin").is_dir()


# ------------------------------------------------------------------ the hook watch (every route)

@pytest.fixture
def protected(home):
    for kind in ("cline", "opencode"):
        assert agent_hooks.set_protection(kind, True)["ok"]
    return home


def _findings() -> list[dict]:
    return [row for row in audit.read_findings(limit=50) if row.get("identifier") == hook_watch.HOOK_CHANGED_ID]


def test_a_hook_moved_away_and_replaced_outside_blackbox_is_put_back_and_said(protected):
    home = protected
    cline_hooks = agent_hosts.BY_ID["cline"].config_path(home)
    ours = (cline_hooks / "TaskStart").read_text(encoding="utf-8")
    plugin = agent_hosts.BY_ID["opencode"].config_path(home)
    os.rename(home / "Documents" / "Cline", home / "cline-moved")          # what the agent did in L4
    cline_hooks.mkdir(parents=True)
    (cline_hooks / "TaskStart").write_text("#!/bin/sh\necho planted\n", encoding="utf-8")
    os.rename(home / ".config" / "opencode", home / "opencode-moved")
    plugin.parent.mkdir(parents=True)
    (plugin.parent / "x.js").write_text("// planted\n", encoding="utf-8")
    done = agent_hooks.keep_hooks()
    # Security finding 2026-11-25-linux-hook-watch-puts-blackbox-s-hook-ba (L5): the planted x.js stays
    # loaded beside OpenCode's restored plugin, so that one is NOT "restored", and x.js is its own finding.
    restored = {row["kind"]: row["restored"] for row in done if row["lost"] != [str(plugin.parent / "x.js")]}
    assert restored == {"cline": True, "opencode": False}, done
    added = [row for row in audit.read_findings(limit=50) if row.get("identifier") == foreign_hooks.FOREIGN_HOOK_ID]
    assert len(added) == 1 and added[0]["fields"]["path"] == str(plugin.parent / "x.js") and (plugin.parent / "x.js").exists()
    assert "x.js" in next(row["evidence"] for row in _findings() if "OpenCode" in row["evidence"])
    assert (cline_hooks / "TaskStart").read_text(encoding="utf-8") == ours
    assert config_edit.MARK in plugin.read_text(encoding="utf-8")
    replaced = list((home / ".hermes" / "blackbox" / "agent-hooks" / "replaced").iterdir())
    assert [path.read_text(encoding="utf-8") for path in replaced] == ["#!/bin/sh\necho planted\n"]
    assert {row["severity"] for row in _findings()} == {"high"} and len(_findings()) == 2
    assert agent_hooks.keep_hooks() == [], "an intact hook is not said again"


def test_a_hook_folder_turned_into_a_link_is_not_written_through_but_said(protected, tmp_path_factory):
    home = protected
    elsewhere = tmp_path_factory.mktemp("elsewhere").resolve()
    os.rename(home / ".config" / "opencode", home / "opencode-moved")
    os.symlink(elsewhere, home / ".config" / "opencode")
    done = agent_hooks.keep_hooks()
    assert done == [{"kind": "opencode", "restored": False, "lost": done[0]["lost"]}]
    assert list(elsewhere.iterdir()) == [], "nothing is written through a link"
    assert "could not put it back safely" in _findings()[0]["evidence"]


def test_an_agent_the_person_removed_is_forgotten_not_re_created(protected, monkeypatch):
    home = protected
    monkeypatch.setattr(agent_hosts.shutil, "which", lambda *args, **kwargs: None)   # no opencode command here
    import shutil
    shutil.rmtree(home / ".config" / "opencode")
    assert agent_hooks.keep_hooks() == [] and not (home / ".config" / "opencode").exists()
    assert hook_watch.known(f"opencode:{agent_hosts.BY_ID['opencode'].config_path(home)}") == {}


def test_blackboxs_own_install_and_stop_are_never_taken_for_tampering(protected):
    assert agent_hooks.set_protection("opencode", True)["ok"]      # an upgrade rewrites the files
    assert agent_hooks.set_protection("cline", False)["ok"]        # the person stops protecting it
    assert agent_hooks.keep_hooks() == [] and _findings() == []


def _added() -> list[dict]:
    return [row for row in audit.read_findings(limit=50) if row.get("identifier") == foreign_hooks.FOREIGN_HOOK_ID]


def test_a_lone_foreign_plugin_or_an_extra_hook_is_said_kept_and_names_its_writer(protected):
    """Security finding 2026-11-25-linux-hook-watch-puts-blackbox-s-hook-ba (Linux round L5): a lone
    planted OpenCode plugin, or an extra Cline hook beside Blackbox's, raised nothing. Each is one HIGH
    finding, the writer named from an allowed tool call that wrote it; nothing is deleted."""
    home = protected
    plugin_dir = agent_hosts.BY_ID["opencode"].config_path(home).parent
    hooks = agent_hosts.BY_ID["cline"].config_path(home)
    audit.record_for("codex", event="pre_tool_call", detail={"decision": "", "tool_name": "terminal",
                     "args": {"command": f"printf x > {plugin_dir}/evil.js"}})
    (plugin_dir / "evil.js").write_text("export default {}\n", encoding="utf-8")
    (hooks / "PreCompact").write_text("#!/bin/sh\n", encoding="utf-8")
    done = agent_hooks.keep_hooks()
    assert {row["kind"] for row in done} == {"opencode", "cline"}
    added = {row["fields"]["path"]: row for row in _added()}
    assert set(added) == {str(plugin_dir / "evil.js"), str(hooks / "PreCompact")}
    assert added[str(plugin_dir / "evil.js")]["fields"]["writer"] == "codex" and "written by codex" in added[str(plugin_dir / "evil.js")]["evidence"]
    assert added[str(hooks / "PreCompact")]["fields"]["writer"] == "" and added[str(hooks / "PreCompact")]["severity"] == "high"
    assert (plugin_dir / "evil.js").exists() and (hooks / "PreCompact").exists(), "alert and keep, never delete"
    assert agent_hooks.keep_hooks() == [], "said once"


def test_the_persons_own_plugins_from_before_blackbox_are_not_alerts(home):
    """A plugin the person had before Blackbox installed is theirs: no finding, and it keeps loading."""
    plugin_dir = agent_hosts.BY_ID["opencode"].config_path(home).parent
    plugin_dir.mkdir(parents=True)
    (plugin_dir / "mine.js").write_text("export default {}\n", encoding="utf-8")
    assert agent_hooks.set_protection("opencode", True)["ok"]
    assert agent_hooks.keep_hooks() == [] and _added() == [] and (plugin_dir / "mine.js").exists()
