"""The agent sandbox keeps every add-on beside the plugin closed to writes, as it keeps the plugin
(plugins/blackbox/shields/files/sandbox: policy, places.build, platform/macos.render).

Private security finding 2026-11-22-agent-sandbox-does-not-cover-add-on-fold… (security round 3):
the kernel profile's own places were Blackbox's data folder and the plugin only. The add-on folders
(``kernel.addons``) and the places add-ons declare were guarded by the hook alone. Real Seatbelt
runs below: inside the sandbox an add-on's folder, its manifest and a planted manifest are refused;
the profile follows an add-on that appears after it was written; outside them nothing changes.
"""

from __future__ import annotations

import json
import os
import subprocess
import sys
from pathlib import Path

import pytest

from plugins.blackbox.kernel import addons
from plugins.blackbox.shields.files import mode as files_mode, sandbox
from plugins.blackbox.shields.files.sandbox import places as places_mod
from plugins.blackbox.shields.files.sandbox.platform import macos

REAL = pytest.mark.skipif(sys.platform != "darwin" or not os.access(macos.SANDBOX_EXEC, os.X_OK),
                          reason="a real Seatbelt sandbox needs macOS")


def _addon(plugins: Path, name: str) -> Path:
    folder = plugins / name
    folder.mkdir(parents=True)
    (folder / "__init__.py").write_text("", encoding="utf-8")
    (folder / addons.MANIFEST).write_text(json.dumps({"extends": "blackbox"}), encoding="utf-8")
    return folder


@pytest.fixture
def home(tmp_path, monkeypatch):
    real = tmp_path.resolve()
    monkeypatch.setenv("HOME", str(real))
    monkeypatch.setenv("BLACKBOX_HOME", str(real / "bb"))
    plugins = real / ".hermes" / "plugins"
    (plugins / "blackbox").mkdir(parents=True)
    monkeypatch.setattr(sandbox, "_PLUGIN", plugins / "blackbox")
    addons.clear()
    yield real
    addons.clear()


def _mode():
    return files_mode.build(enabled=True, protected=("~/Documents/Vault",), sandboxed=("claude-code",))


def _run(script: str) -> dict[str, str]:
    done = subprocess.run([macos.SANDBOX_EXEC, "-f", str(sandbox.profile_path()), "/bin/sh", "-c", script],
                          capture_output=True, text=True, timeout=30, check=False)
    return dict(line.split("=", 1) for line in done.stdout.split() if "=" in line)


def test_the_policy_holds_every_add_on_folder_its_declared_places_and_every_manifest(home):
    plugins = home / ".hermes" / "plugins"
    companion = _addon(plugins, "example_companion")
    (plugins / "not_an_addon").mkdir()
    data = home / "Library" / "Example"
    data.mkdir(parents=True)
    addons.declare([str(data)])
    rules = sandbox.policy(_mode())
    assert str(companion) in rules.no_write and str(data) in rules.no_write
    assert str(plugins / "not_an_addon") not in rules.no_write
    assert rules.no_write_globs == (str(plugins / "*" / addons.MANIFEST),)


def test_a_manifest_pattern_is_made_canonical_before_its_wildcard(tmp_path):
    real = tmp_path.resolve() / "real"
    real.mkdir()
    (tmp_path / "link").symlink_to(real)
    assert places_mod._canonical_glob(str(tmp_path / "link" / "*" / "m.json")) == str(real / "*" / "m.json")


@REAL
def test_inside_the_sandbox_an_add_on_and_its_manifest_cannot_be_changed_and_none_can_be_planted(home):
    plugins = home / ".hermes" / "plugins"
    sandbox.sync(_mode())   # written before the add-on exists, as at install
    companion = _addon(plugins, "example_companion")
    (plugins / "other").mkdir()
    sandbox.sync(_mode())   # the next sync (the helper's watch plan, every ~2 s) follows it
    # The round's two routes: append to the manifest, and a script that builds the folder's name.
    script = home / "ad.py"
    script.write_text("import os, sys\np = os.path.join(sys.argv[1], 'example' + sys.argv[2], 'x.txt')\n"
                      "try:\n    open(p, 'w').write('x'); os.remove(p); print('wrote=0')\nexcept OSError:\n    print('wrote=1')\n",
                      encoding="utf-8")
    lines = _run(f"""
echo ' ' >> '{companion / addons.MANIFEST}' 2>/dev/null; echo manifest=$?
/usr/bin/python3 '{script}' '{plugins}' _companion
rm -f '{companion / "__init__.py"}' 2>/dev/null; echo remove=$?
mkdir -p '{plugins / "planted"}' && echo '{{"extends": "blackbox"}}' > '{plugins / "planted" / addons.MANIFEST}' 2>/dev/null; echo plant=$?
echo x > '{plugins / "other" / "notes.txt"}' 2>/dev/null; echo beside=$?
""")
    assert (lines["manifest"], lines["wrote"], lines["remove"], lines["plant"], lines["beside"]) == ("1", "1", "1", "1", "0"), lines
    assert json.loads((companion / addons.MANIFEST).read_text(encoding="utf-8")) == {"extends": "blackbox"}
    assert (companion / "__init__.py").exists() and not (plugins / "planted" / addons.MANIFEST).exists()
