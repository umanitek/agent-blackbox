"""Sandbox permissions — the broker opens only apps a sandboxed agent can not have built
(plugins/blackbox/shields/files/sandbox/platform/root_owned.py, platform/macos/opener.py,
platform/linux/opener.py, brokered/open_apps.py; independent review 2026-11-26, finding 1, HIGH).

The sandbox refuses writes by a deny list, so an agent may write wherever the person may:
``~/Applications``, ``~/.local/share/applications`` or a bundle the person owns. The broker opens an
app OUTSIDE the sandbox, so an app it found there could be the agent's own program. Contracts (red
on the base 30b94edf83):
* an app is found only in a system app folder, never ``~/Applications``;
* an app is found only when root holds the bundle and every folder above it (an owner or a
  writer other than root refuses it; ``/Applications``' own ``admin`` group write is accepted);
* the one-word Finder route, and every file handed to an app, refuses an app bundle.
"""

from __future__ import annotations

import os
import stat
from types import SimpleNamespace

import pytest

from plugins.blackbox.kernel import config as config_mod
from plugins.blackbox.shields.files.sandbox import platform as sandbox_platform
from plugins.blackbox.shields.files.sandbox.brokered import open_apps
from plugins.blackbox.shields.files.sandbox.platform import root_owned
from plugins.blackbox.shields.files.sandbox.platform.linux import opener as linux_opener
from plugins.blackbox.shields.files.sandbox.platform.macos import opener
from plugins.blackbox.shields.shield_api import ShieldApiError

ADMIN_GID = 80
PERSON_UID = 501


@pytest.fixture()
def home(monkeypatch, tmp_path):
    real = tmp_path.resolve()
    monkeypatch.setenv("HOME", str(real))
    monkeypatch.setenv("BLACKBOX_HOME", str(real / "bb"))
    (real / "bb").mkdir()
    monkeypatch.setattr(config_mod, "_blackbox_entry", lambda: {"shields": {"file-shield": {"enabled": True}}})
    return real


def _bundle(folder, name="Preview"):
    programs = folder / f"{name}.app" / "Contents" / "MacOS"
    programs.mkdir(parents=True)
    (programs / name).write_text("#!/bin/sh\n", encoding="utf-8")
    return folder / f"{name}.app"


def test_an_app_in_the_persons_own_applications_folder_is_never_found(home, monkeypatch):
    _bundle(home / "Applications")
    monkeypatch.setattr(opener, "trusted", lambda bundle: True)   # even a bundle that passed the owner check
    assert opener.find_app("Preview") in ("", "/System/Applications/Preview.app")
    assert not opener.find_app("Preview").startswith(str(home))


def test_an_app_the_person_owns_is_never_found(home, monkeypatch):
    _bundle(home / "Apps")
    monkeypatch.setattr(opener, "APP_FOLDERS", (str(home / "Apps"),))
    assert opener.find_app("Preview") == ""   # a temp folder is the person's: so the agent's too


def test_linux_never_starts_an_entry_from_the_persons_data_folder(home):
    apps = home / ".local" / "share" / "applications"
    apps.mkdir(parents=True)
    (apps / "viewer.desktop").write_text("[Desktop Entry]\nName=Viewer\nExec=/bin/true %f\n", encoding="utf-8")
    assert linux_opener.find_app("viewer", folders=[str(home / ".local" / "share")]) == ""
    assert linux_opener.find_app("Viewer", folders=[str(home / ".local" / "share")]) == ""


def _facts(uid, gid, mode):
    return SimpleNamespace(st_uid=uid, st_gid=gid, st_mode=mode)


@pytest.mark.parametrize("tree, held", [
    ({"/": (0, 0, 0o755), "/Applications": (0, ADMIN_GID, 0o775), "/Applications/X.app": (0, 0, 0o755)}, True),
    ({"/": (0, 0, 0o755), "/Applications": (0, ADMIN_GID, 0o775), "/Applications/X.app": (PERSON_UID, ADMIN_GID, 0o755)}, False),
    ({"/": (0, 0, 0o755), "/Applications": (0, ADMIN_GID, 0o775), "/Applications/X.app": (0, ADMIN_GID, 0o775)}, False),
    ({"/": (0, 0, 0o755), "/Applications": (0, 0, 0o777), "/Applications/X.app": (0, 0, 0o755)}, False),
    ({"/": (0, 0, 0o755), "/Applications": (PERSON_UID, 0, 0o755), "/Applications/X.app": (0, 0, 0o755)}, False),
])
def test_root_holds_a_path_only_when_root_holds_every_folder_above_it(tree, held, monkeypatch):
    monkeypatch.setattr(os.path, "realpath", lambda path: path)

    def lstat(path):
        if path not in tree:
            raise FileNotFoundError(path)
        uid, gid, mode = tree[path]
        return _facts(uid, gid, stat.S_IFDIR | mode)
    assert root_owned.held_by_root("/Applications/X.app", shared_parents={"/Applications"}, lstat=lstat) is held


@pytest.mark.parametrize("argv", [["Evil.app"], ["Plain"], ["-a", "Preview", "Evil.app"]])
def test_an_app_bundle_is_never_opened_as_a_folder_or_a_file(home, monkeypatch, argv):
    _bundle(home, "Evil")
    _bundle(home, "Plain").rename(home / "Plain")   # a bundle by shape, whatever its name
    monkeypatch.setattr(sandbox_platform, "find_app", lambda name: "/System/Applications/Preview.app")
    monkeypatch.setattr(sandbox_platform, "is_driver", lambda path: False)
    with pytest.raises(ShieldApiError) as refused:
        open_apps.parse(argv, str(home))
    assert refused.value.status == 403
