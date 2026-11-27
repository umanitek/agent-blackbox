"""Sandbox permissions — ``user-apps``: opening an app the person installed themselves
(plugins/blackbox/shields/files/sandbox/brokered/open_apps.py, platform/root_owned.py,
platform/macos/opener.py, platform/linux/opener.py, permissions.refused; engine build 2026-11-27).

Before, the broker opened only apps root holds (independent review 2026-11-26, finding 1), and an
app the person dragged into ``/Applications`` was refused with no way to allow it. Contracts (red
on the base 138eafb5bd):
* blocked (the default): an app the person installed is refused, and the refusal names user-apps;
* ask: ONE request, for user-apps; allow: opened, while open-apps still decides as for any app;
  open-apps blocked refuses whatever user-apps says;
* found only when the person or root owns the bundle and every folder above it, nobody else may
  write it, it resolves inside the folder it is in (never a link out), and it is no app driver;
* a bare LaunchServices refusal the hook read asks open-apps, never user-apps.
"""

from __future__ import annotations

import os
import stat
from types import SimpleNamespace

import pytest

from plugins.blackbox.kernel import config as config_mod
from plugins.blackbox.shields.files.sandbox import brokered, permissions, platform as sandbox_platform
from plugins.blackbox.shields.files.sandbox.permissions import requests
from plugins.blackbox.shields.files.sandbox.platform import root_owned
from plugins.blackbox.shields.files.sandbox.platform.linux import opener as linux_opener
from plugins.blackbox.shields.files.sandbox.platform.macos import opener
from plugins.blackbox.shields.shield_api import ShieldApiError, ShieldContext
from tests.waiting import wait_until

PERSON_UID, OTHER_UID, STAFF_GID = 501, 502, 20


def _bundle(folder, name="Brave"):
    programs = folder / f"{name}.app" / "Contents" / "MacOS"
    programs.mkdir(parents=True)
    (programs / name).write_text("#!/bin/sh\n", encoding="utf-8")
    (folder / f"{name}.app").chmod(0o755)
    return folder / f"{name}.app"


def _above_home_is_roots(monkeypatch, home):
    """The test's home sits in a shared temp folder (``/private/var/tmp`` is everyone's to write):
    the folders above it read as a real home's would (root's, 755); the home itself is real."""
    def lstat(path):
        if path == str(home) or path.startswith(str(home) + "/"):
            return os.lstat(path)
        return SimpleNamespace(st_uid=0, st_gid=0, st_mode=stat.S_IFDIR | 0o755)
    for module in (opener, linux_opener):
        monkeypatch.setattr(module, "held_by", lambda path, **kw: root_owned.held_by(path, lstat=lstat, **kw))
    monkeypatch.setattr(opener, "entries_held", lambda folder, **kw: root_owned.entries_held(folder, lstat=lstat, **kw))


@pytest.fixture()
def setting(monkeypatch, tmp_path):
    real = tmp_path.resolve()
    real.chmod(0o755)
    _above_home_is_roots(monkeypatch, real)
    monkeypatch.setenv("HOME", str(real))
    monkeypatch.setenv("BLACKBOX_HOME", str(real / "bb"))
    (real / "bb").mkdir()
    (real / "shop").mkdir()
    (real / "shop" / "a.pdf").write_text("pdf", encoding="utf-8")
    apps = real / "Applications"
    apps.mkdir()
    _bundle(apps)
    state: dict = {"shields": {"file-shield": {"enabled": True}}}
    monkeypatch.setattr(config_mod, "_blackbox_entry", lambda: state)
    monkeypatch.setattr(sandbox_platform, "find_app", lambda name: "")   # no root-held app of that name
    monkeypatch.setattr(sandbox_platform, "find_person_app", lambda name: opener.find_person_app(name, folders=(str(apps),)))
    monkeypatch.setattr(sandbox_platform, "is_driver", opener.is_driver)
    opened: list = []
    monkeypatch.setattr(sandbox_platform, "open_with", lambda app, files: opened.append(os.path.basename(app)) or 0)
    requests.reset()
    yield state, opened, real
    requests.reset()


def _context():
    return ShieldContext(network_indicators=lambda: None, ask_assistant=lambda message: None,
                         tool_call_verdict=lambda tool, args: {"decision": "", "findings": []})


def _open(home):
    return brokered.API_WRITES["open-app"](_context(), {"argv": ["-a", "Brave", "a.pdf"], "cwd": str(home / "shop")})


def _rules(state, **modes):
    state["agent_sandbox"] = {"permissions": [{"permission": name.replace("_", "-"), "mode": mode} for name, mode in modes.items()]}


def test_an_app_the_person_installed_is_refused_by_default_naming_user_apps(setting):
    state, opened, home = setting
    _rules(state, open_apps="allow")
    with pytest.raises(ShieldApiError) as refused:
        _open(home)
    assert refused.value.status == 403 and "user-apps" in refused.value.message and opened == []
    assert requests.pending() == []


def test_on_ask_one_request_is_raised_for_user_apps_only(setting):
    state, opened, home = setting
    _rules(state, open_apps="ask", user_apps="ask")
    for _ in range(2):
        with pytest.raises(ShieldApiError) as waiting:
            _open(home)
        assert waiting.value.status == brokered.WAITING
    assert [each.permission for each in requests.pending()] == ["user-apps"] and opened == []


def test_allowed_it_opens_and_open_apps_still_decides(setting):
    state, opened, home = setting
    _rules(state, open_apps="allow", user_apps="allow")
    started = _open(home)

    def ended():
        job = brokered.API_READS["action-job"](_context(), {"job": started["job"], "from": "0"})
        return job if job["done"] else None
    done = wait_until(ended, what="the opening ended")
    assert done["exit"] == 0 and opened == ["Brave.app"]
    _rules(state, open_apps="block", user_apps="allow")
    with pytest.raises(ShieldApiError) as refused:
        _open(home)
    assert refused.value.status == 403 and "Opening files in apps" in refused.value.message and opened == ["Brave.app"]


def test_a_person_app_is_found_only_by_the_person_finder(setting):
    _, _, home = setting
    apps = str(home / "Applications")
    assert opener.find_person_app("Brave", folders=(apps,)) == str(home / "Applications" / "Brave.app")
    assert opener.find_person_app("Brave.app", folders=(apps,)).endswith("Brave.app")
    assert opener.find_app("Brave") == ""   # root-only finder: unchanged


def test_a_link_out_of_the_folder_and_a_driver_are_never_found(setting):
    _, _, home = setting
    (home / "Downloads").mkdir()
    _bundle(home / "Downloads", "Sneaky")
    (home / "Applications" / "Sneaky.app").symlink_to(home / "Downloads" / "Sneaky.app")
    _bundle(home / "Applications", "Terminal")
    _bundle(home / "Applications", "Ghostty")
    apps = (str(home / "Applications"),)
    assert [opener.find_person_app(name, folders=apps) for name in ("Sneaky", "Terminal", "ghostty")] == ["", "", ""]


def test_a_bundle_anyone_else_may_write_is_never_found(setting):
    _, _, home = setting
    (home / "Applications" / "Brave.app").chmod(0o777)
    assert opener.find_person_app("Brave", folders=(str(home / "Applications"),)) == ""


def _facts(uid, gid, mode):
    return SimpleNamespace(st_uid=uid, st_gid=gid, st_mode=stat.S_IFDIR | mode)


@pytest.mark.parametrize("bundle, held", [
    ((PERSON_UID, STAFF_GID, 0o755), True),
    ((0, 0, 0o755), True),
    ((OTHER_UID, STAFF_GID, 0o755), False),      # another user's app: never
    ((PERSON_UID, STAFF_GID, 0o775), False),     # every member of staff may change it
])
def test_the_person_or_root_must_hold_every_level(bundle, held, monkeypatch):
    monkeypatch.setattr(os.path, "realpath", lambda path: path)
    tree = {"/": (0, 0, 0o755), "/Users": (0, 0, 0o755), "/Users/me": (PERSON_UID, STAFF_GID, 0o750),
            "/Users/me/Applications": (PERSON_UID, STAFF_GID, 0o755), "/Users/me/Applications/X.app": bundle}

    def lstat(path):
        if path not in tree:
            raise FileNotFoundError(path)
        return _facts(*tree[path])
    owners = frozenset({0, PERSON_UID})
    assert root_owned.held_by("/Users/me/Applications/X.app", owners=owners, lstat=lstat) is held
    assert root_owned.held_by_root("/Users/me/Applications/X.app", lstat=lstat) is False


def test_linux_finds_the_persons_own_entry_only_through_the_person_finder(setting):
    _, _, home = setting
    data = home / ".local" / "share"
    (data / "applications").mkdir(parents=True)
    (data / "applications" / "viewer.desktop").write_text("[Desktop Entry]\nName=Viewer\nExec=/bin/true %f\n", encoding="utf-8")
    (data / "applications" / "term.desktop").write_text("[Desktop Entry]\nName=Term\nExec=xterm\nTerminal=true\n", encoding="utf-8")
    for folder in (home / ".local", data, data / "applications"):
        folder.chmod(0o755)
    assert linux_opener.find_app("viewer", folders=[str(data)]) == ""
    assert linux_opener.find_person_app("viewer", folders=[str(data)]) == str(data / "applications" / "viewer.desktop")
    assert linux_opener.find_person_app("term", folders=[str(data)]) == ""


def test_a_bare_launchservices_refusal_asks_open_apps_never_user_apps(setting):
    state, _, home = setting
    _rules(state, open_apps="ask", user_apps="ask")
    assert permissions.refused("open-app", "claude-code", "s-1", str(home / "shop"))
    assert [each.permission for each in requests.pending()] == ["open-apps"]
