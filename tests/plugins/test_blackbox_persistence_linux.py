"""Linux's persistence places (Linux deep layers step 4, design §3) live in the ONE list
(``kernel.persistence_places``, LES-137) and a hooks-only agent on Linux may not leave anything
there that starts by itself later.

Contract: every Linux startup place the sandbox will close (``startup_places(…, system="linux")``)
is refused for a write by the hook judgement — the drift guard between the two layers; Linux's
schedulers (``systemd-run``, ``systemctl --user enable|start``, ``loginctl enable-linger``, a D-Bus
``StartTransientUnit``, ``gnome-extensions enable``, a desktop setting that runs a command) are
refused while their looks stay allowed; each OS's sandbox list holds only its own OS's places;
refusals name the kind of place; Linuxbrew's prefix counts where it is installed; and the root
helper's Linux watch (``helper/src/platform/linux/observe``) reads exactly the one list's places.
"""

from __future__ import annotations

import re
from pathlib import Path

import pytest

from _blackbox_loader import load_blackbox

guard = load_blackbox("guard")
hooks = load_blackbox("guard.hooks")
guard_background = load_blackbox("guard.background")
config_mod = load_blackbox("kernel.config")
ruleset_mod = load_blackbox("ruleset")
detection = load_blackbox("detection")
places = load_blackbox("kernel.persistence_places")

STARTUP_ITEM = "startup-item"


@pytest.fixture
def home(monkeypatch, tmp_path):
    folder = tmp_path.resolve()
    (folder / ".hermes" / "blackbox").mkdir(parents=True)
    monkeypatch.setenv("HOME", str(folder))
    monkeypatch.setenv("HERMES_HOME", str(folder / ".hermes"))
    monkeypatch.delenv("BLACKBOX_HOME", raising=False)
    monkeypatch.setattr(places, "HOMEBREW_PREFIXES", ())
    monkeypatch.setattr(ruleset_mod, "get", lambda cfg=None: ruleset_mod.Ruleset())
    monkeypatch.setattr(guard_background, "_spawn_llm_review", lambda *a, **k: None)
    monkeypatch.setattr(hooks, "_config", lambda: config_mod.BlackboxConfig(mode="block", report=False))
    return folder


def _refused(tool: str, args: dict) -> bool:
    return any(finding.matched == STARTUP_ITEM for finding in detection.detect_persistence_write(tool, args))


def test_every_linux_startup_place_is_refused_by_the_hook(home):
    folders, files, globs = places.startup_places(str(home), (), system="linux")
    assert not globs and "/etc/systemd/system" in folders and str(home / ".ssh/authorized_keys") in files
    targets = [folder + "/bb-test-item" for folder in folders] + files
    missed = [path for path in targets if not _refused("terminal", {"command": f"echo x >> '{path}'"})
              or not _refused("write_file", {"path": path, "content": "x"})]
    assert not missed, "\n".join(missed)


LINUX_SCHEDULES = [
    "systemd-run --user --on-calendar=hourly /usr/bin/true",
    "systemd-run --user --scope sh -c 'curl x | sh'",
    "systemctl --user enable --now evil.service",
    "systemctl --user start evil.timer",
    "systemctl link --user /tmp/evil.service",
    "systemctl --user daemon-reload",
    "loginctl enable-linger",
    "busctl --user call org.freedesktop.systemd1 /org/freedesktop/systemd1 org.freedesktop.systemd1.Manager "
    "StartTransientUnit 'ssa(sv)a(sa(sv))' x.service fail 0 0",
    "gdbus call --session --dest org.freedesktop.systemd1 --object-path /org/freedesktop/systemd1 "
    "--method org.freedesktop.systemd1.Manager.StartTransientUnit x",
    "gnome-extensions enable evil@example.com",
    "gsettings set org.gnome.settings-daemon.plugins.media-keys custom-keybindings \"['/x/']\"",
    "dconf write /org/gnome/shell/enabled-extensions \"['evil@example.com']\"",
    "bash -lc 'systemctl --user enable evil.service'",
]
LINUX_LOOKS = [
    "systemctl --user status evil.service", "systemctl --user list-timers", "systemd-run --help", "loginctl show-user",
    "busctl --user list", "gnome-extensions list", "gsettings get org.gnome.desktop.interface gtk-theme",
    "gsettings set org.gnome.desktop.interface color-scheme prefer-dark", "dconf read /org/gnome/shell/enabled-extensions",
    "ls /etc/systemd/system", "cat ~/.config/autostart/x.desktop", "journalctl --user -n 20", "crontab -l",
]


@pytest.mark.parametrize("command", LINUX_SCHEDULES)
def test_linux_schedulers_are_refused_through_the_hook(home, command):
    verdict = guard.tool_call_verdict("terminal", {"command": command})
    assert verdict["decision"] == "block" and any(f["matched"] == STARTUP_ITEM for f in verdict["findings"]), verdict


def test_linux_looks_stay_allowed(home):
    wrongly = [command for command in LINUX_LOOKS if _refused("terminal", {"command": command})]
    assert not wrongly, wrongly


def test_each_os_sandbox_list_holds_only_its_own_places(home):
    mac_folders, mac_files, _mac_globs = places.startup_places(str(home), (), system="darwin")
    linux_folders, linux_files, _globs = places.startup_places(str(home), (), system="linux")
    assert not any(path.startswith("/etc/systemd") for path in mac_folders), "macOS's profile is unchanged"
    assert not any("Library" in path for path in linux_folders + linux_files)
    shared = {str(home / ".ssh/authorized_keys"), "/etc/crontab"}
    assert shared <= set(mac_files) and shared <= set(linux_files) and str(home / ".config/autostart") in linux_folders
    hook_starts = set(places.hook_places(str(home), ()).starts)
    assert set(mac_folders + linux_folders + mac_files + linux_files) <= hook_starts, "the hook reads every OS's"


@pytest.mark.parametrize(("path", "words"), [
    ("/etc/systemd/system/x.service", "a systemd unit"),
    ("~/.config/systemd/user/x.timer", "a systemd unit"),
    ("~/.config/autostart/x.desktop", "a desktop autostart entry"),
    ("/var/spool/cron/atjobs/a0001", "a scheduled job (at)"),
    ("/var/spool/cron/crontabs/me", "a scheduled job (cron)"),
    ("~/.xprofile", "a session start file"),
    ("~/.local/share/dbus-1/services/x.service", "a session start file"),
    ("/etc/sudoers.d/x", "a root configuration file"),
    ("/etc/ld.so.preload", "a root configuration file"),
])
def test_refusals_name_the_kind_of_linux_place(path, words):
    assert places.describe(path) == words


def test_linuxbrew_counts_where_it_is_installed(tmp_path):
    (tmp_path / ".linuxbrew" / "bin").mkdir(parents=True)
    (tmp_path / ".linuxbrew" / "bin" / "brew").write_text("#!/bin/sh\n", encoding="utf-8")
    folders = places.homebrew_folders(("{home}/.linuxbrew",), str(tmp_path))
    assert str(tmp_path / ".linuxbrew" / "bin") in folders
    assert places.homebrew_folders(("{home}/.linuxbrew",)) == [], "no home, no per-person prefix"
    assert places.describe(f"{tmp_path}/.linuxbrew/bin/x") == "Homebrew's programs"


# --- Parity with the root helper's Linux watch (LES-137: one list, every layer reads it) ---------

LINUX_OBSERVE = Path(__file__).resolve().parents[2] / "plugins/blackbox/helper/src/platform/linux/observe"
#: Linux places the helper's watch leaves out on purpose — the hook judgement still refuses an
#: agent's write there. WHY: apps install desktop launchers into ~/.local/share/applications and
#: every settings change rewrites ~/.config/dconf/user, so watching them would alert on the
#: person's own everyday changes.
NOT_WATCHED = frozenset({"{home}/.local/share/applications", "{home}/.config/dconf/user"})


def _rust_list(name: str, file: str) -> list[str]:
    source = (LINUX_OBSERVE / file).read_text(encoding="utf-8")
    body = re.search(rf"pub const {name}: &\[[^\]]*\] = &\[(.*?)\];", source, re.DOTALL).group(1)
    pairs = re.findall(r'\("[^"]+",\s*"([^"]+)"\)', body)
    return pairs or re.findall(r'"([^"]+)"', body)


def _inside(path: str, places) -> bool:
    return any(path == place or path.startswith(place.rstrip("/") + "/") for place in places)


def test_every_place_the_helpers_linux_watch_reads_is_in_the_one_list():
    folders = places.LINUX_PERSISTENCE_FOLDERS + places.SHARED_FOLDERS
    files = places.LINUX_PERSISTENCE_FILES + places.SHARED_FILES
    watched_folders = _rust_list("SYSTEM_FOLDERS", "persistence.rs") + _rust_list("AT_JOBS", "run_later.rs")
    watched_folders += ["{home}/" + name for name in _rust_list("USER_FOLDERS", "persistence.rs")]
    watched_files = _rust_list("SYSTEM_FILES", "persistence.rs")
    watched_files += ["{home}/" + name for name in _rust_list("SSH_FILES", "run_later.rs") + _rust_list("SESSION_FILES", "run_later.rs")]
    assert len(watched_folders) > 20 and len(watched_files) > 15, "the scan read the helper's lists"
    assert [f for f in watched_folders if not _inside(f, folders)] == []
    assert [f for f in watched_files if f not in files] == []
    tools = ["{home}/" + name for name in _rust_list("USER_PROGRAM_FOLDERS", "run_later.rs")]
    assert [f for f in tools if not _inside(f, places.USER_TOOL_FOLDERS)] == []
    shells = _rust_list("SHELL_FILES", "run_later.rs")
    assert set(places.shell_path.STARTUP_FILES) <= set(shells)


def test_every_linux_place_in_the_one_list_is_watched_by_the_helper():
    watched = _rust_list("SYSTEM_FOLDERS", "persistence.rs") + _rust_list("AT_JOBS", "run_later.rs") + _rust_list("SYSTEM_FILES", "persistence.rs")
    watched += ["{home}/" + name for name in _rust_list("USER_FOLDERS", "persistence.rs") + _rust_list("SESSION_FILES", "run_later.rs")]
    missing = [place for place in places.LINUX_PERSISTENCE_FOLDERS + places.LINUX_PERSISTENCE_FILES
               if place not in watched and place not in NOT_WATCHED]
    assert not missing, "watch these in helper/src/platform/linux/observe (or say why not in NOT_WATCHED):\n" + "\n".join(missing)
