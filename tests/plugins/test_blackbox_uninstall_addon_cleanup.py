"""``blackbox uninstall`` removes what an add-on's manifest says its companion app left — and nothing
a manifest asks for beyond its own app's places.

KI-612's generic half (security round 5, bb-r5-clean): a companion app moved to the Trash gets no
word from macOS, so its Keychain item, caches, WebKit data and activity history stayed after the
core's uninstall. An add-on's manifest (``blackbox-addon.json``) may now carry ``cleanup.<os>``:
``app_id``, ``paths``, ``keychain`` (service/account) and ``preferences_domain``. Every item is
checked; planted manifests that try to reach elsewhere are refused item by item and named.
"""

from __future__ import annotations

import argparse
import dataclasses
import json
from pathlib import Path

import pytest

from plugins.blackbox.kernel import os_layout
from plugins.blackbox.setup import addon_cleanup, uninstall
from plugins.blackbox.setup.platform import macos as platform_macos
from plugins.blackbox.setup.platform import macos

APP = "com.example.companion"


@pytest.fixture(autouse=True)
def os_services(monkeypatch):
    """The login services are removed through ``setup/platform/<os>``; these plans are macOS's
    unless a test says otherwise (``_on``), whatever machine runs the suite."""
    monkeypatch.setattr(uninstall, "os_platform", platform_macos)


@pytest.fixture
def home(tmp_path, monkeypatch):
    root = (tmp_path / "user").resolve()
    (root / ".hermes" / "plugins").mkdir(parents=True)
    (root / ".hermes" / "config.yaml").write_text("plugins:\n  enabled:\n    - blackbox\n", encoding="utf-8")
    monkeypatch.setenv("HOME", str(root))
    monkeypatch.setenv("HERMES_HOME", str(root / ".hermes"))
    monkeypatch.delenv("BLACKBOX_HOME", raising=False)
    monkeypatch.setattr(os_layout, "os_folder", lambda sys_platform=None: "macos")
    monkeypatch.setattr(addon_cleanup, "platform", macos)   # the macOS strategy, its tools faked by the runner
    return root


def _addon(home: Path, cleanup: dict, name: str = "example_addon") -> Path:
    folder = home / ".hermes" / "plugins" / name
    folder.mkdir()
    (folder / "__init__.py").write_text("", encoding="utf-8")
    (folder / "blackbox-addon.json").write_text(json.dumps({"extends": "blackbox", "cleanup": {"macos": cleanup}}),
                                                encoding="utf-8")
    return folder


def _left(home: Path, *places: str) -> list[Path]:
    made = []
    for place in places:
        path = home / "Library" / place
        path.parent.mkdir(parents=True, exist_ok=True)
        if place.endswith(".plist") or place.endswith(".json"):
            path.write_text("x", encoding="utf-8")
        else:
            path.mkdir()
            (path / "activity-history.json").write_text("{}", encoding="utf-8")
        made.append(path)
    return made


def _plan(home: Path):
    return dataclasses.replace(uninstall.build_plan(homes=[home / ".hermes"], purge=True, keep_logs=False), system="Darwin")


def test_what_a_companion_app_left_is_shown_then_removed_with_its_keychain_item(home, capsys):
    made = _left(home, f"Application Support/{APP}", f"Caches/{APP}", f"WebKit/{APP}", f"HTTPStorages/{APP}",
                 f"Preferences/{APP}.plist", f"Saved Application State/{APP}.savedState", f"Logs/{APP}")
    _addon(home, {"app_id": APP, "paths": [f"~/Library/{path.relative_to(home / 'Library')}" for path in made],
                  "keychain": [{"service": APP, "account": "approval-key"}], "preferences_domain": APP})
    plan = _plan(home)
    lines = uninstall.describe(plan)
    assert sum("remove what an add-on left" in line for line in lines) == len(made) + 2
    assert not [line for line in lines if "NOT removed" in line]
    args = argparse.Namespace(purge=True, keep_logs=False, dry_run=True, yes=False, remove_host=False)
    assert uninstall.cmd_uninstall(args) == 0 and f"the Keychain item {APP} / approval-key" in capsys.readouterr().out
    assert all(path.exists() for path in made)   # a dry run changes nothing
    ran = []
    report = uninstall.execute(plan, run=lambda command: ran.append(list(command)) or 0, stop_dashboard=lambda port: [],
                               run_as_admin=lambda command: 0)
    assert not [path for path in made if path.exists()]
    assert ["/usr/bin/security", "delete-generic-password", "-s", APP, "-a", "approval-key"] in ran
    assert ["/usr/bin/defaults", "delete", APP] in ran
    assert f"removed the Keychain item {APP} / approval-key" in report


@pytest.mark.parametrize("raw, why", [
    ("~/Documents/notes.md", "only directly under ~/Library"),
    ("/etc/hosts", "only directly under ~/Library"),
    (f"~/Library/{APP}", "only directly under ~/Library"),
    ("~/Library/Caches/com.example.other", "not named after"),
    (f"~/Library/Caches/{APP}/../../Documents", "no wildcards or '..'"),
    ("~/Library/Caches/*", "no wildcards or '..'"),
    (f"~/Library/Mail/{APP}", "only directly under ~/Library"),
])
def test_a_path_outside_the_apps_own_places_is_refused_and_named(home, raw, why):
    _addon(home, {"app_id": APP, "paths": [raw]})
    plan = _plan(home)
    assert plan.addon_cleanup.items == () and why in plan.addon_cleanup.skipped[0]
    assert any("NOT removed" in line for line in uninstall.describe(plan))


def test_a_link_out_of_library_is_never_followed(home, tmp_path):
    outside = tmp_path / "outside"
    (outside / "keep").mkdir(parents=True)
    (home / "Library" / "Caches").mkdir(parents=True)
    (home / "Library" / "Caches" / APP).symlink_to(outside / "keep")          # the entry itself a link
    (home / "Library" / "Logs").symlink_to(outside)                            # a folder on the way a link
    (outside / APP).mkdir()
    _addon(home, {"app_id": APP, "paths": [f"~/Library/Caches/{APP}", f"~/Library/Logs/{APP}"]})
    plan = _plan(home)
    assert plan.addon_cleanup.items == () and len(plan.addon_cleanup.skipped) == 2
    uninstall.execute(plan, run=lambda command: 0, stop_dashboard=lambda port: [], run_as_admin=lambda command: 0)
    assert (outside / "keep").is_dir() and (outside / APP).is_dir()


@pytest.mark.parametrize("app_id", ["com.apple.Safari", "notreversedns", "com..example", "-x.example", "com.example/../x"])
def test_an_app_id_that_is_not_its_own_reverse_dns_name_removes_nothing(home, app_id):
    target = _left(home, f"Caches/{app_id}")[0] if "/" not in app_id else None
    _addon(home, {"app_id": app_id, "paths": [f"~/Library/Caches/{app_id}"], "keychain": [{"service": app_id, "account": "a"}]})
    plan = _plan(home)
    assert plan.addon_cleanup.items == () and "not a reverse-DNS name of its own" in plan.addon_cleanup.skipped[0]
    if target is not None:
        uninstall.execute(plan, run=lambda command: 0, stop_dashboard=lambda port: [], run_as_admin=lambda command: 0)
        assert target.exists()


def test_a_foreign_keychain_service_or_preferences_domain_is_refused(home):
    _addon(home, {"app_id": APP, "keychain": [{"service": "com.example.bank", "account": "login"}],
                  "preferences_domain": "com.apple.finder"})
    plan = _plan(home)
    assert plan.addon_cleanup.items == () and len(plan.addon_cleanup.skipped) == 2


def test_a_failed_item_is_reported_and_the_next_one_still_removed(home):
    made = _left(home, f"Caches/{APP}")
    _addon(home, {"app_id": APP, "paths": [f"~/Library/Caches/{APP}"], "keychain": [{"service": APP, "account": "a"}]})
    # The item is there (find answers 0) but its removal fails (every other command answers 1).
    report = uninstall.execute(_plan(home), run=lambda command: 0 if "find-generic-password" in command else 1,
                               stop_dashboard=lambda port: [], run_as_admin=lambda command: 0)
    assert f"could not remove the Keychain item {APP} / a" in report and not made[0].exists()
