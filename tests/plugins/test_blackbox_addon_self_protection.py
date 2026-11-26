"""An add-on's folder and the places it declares are Blackbox too: an agent may not delete,
move or edit them (found by an add-on's end-to-end test on a fresh VM, 2026-11-21: ``rm -rf`` of
the add-on's folder under ``~/.hermes/plugins`` was not flagged at all, so an agent could silently
remove DNS Shield, the firewall and every protection the add-on brings).

The plugin names no add-on: each folder beside the plugin that carries the add-on manifest
(``kernel.addons.MANIFEST``) is guarded in every Hermes home, the manifest name itself is guarded
(an agent can neither plant an add-on nor unmake one), and an add-on declares its other places
through the extension point (``Registrar.protect_places`` → ``kernel.addons``)."""

from __future__ import annotations

import pytest

from plugins.blackbox.detection import detect_guard_tamper
from plugins.blackbox.kernel import addons as guarded_extra
from plugins.blackbox.shields.extensions import Registrar


@pytest.fixture
def home(tmp_path, monkeypatch):
    hermes = tmp_path / "hermes-home"
    (hermes / "plugins" / "blackbox").mkdir(parents=True)
    (hermes / "plugins" / "example_addon").mkdir(parents=True)
    (hermes / "plugins" / "example_addon" / "__init__.py").write_text("", encoding="utf-8")
    (hermes / "plugins" / "example_addon" / guarded_extra.MANIFEST).write_text('{"extends": "blackbox"}', encoding="utf-8")
    monkeypatch.setenv("HERMES_HOME", str(hermes))
    monkeypatch.setenv("BLACKBOX_HOME", str(hermes / "blackbox"))
    guarded_extra.clear()
    yield hermes
    guarded_extra.clear()


@pytest.mark.parametrize("tool,args", [
    ("terminal", {"command": "rm -rf {addon}"}),
    ("terminal", {"command": "mv {addon} /tmp/gone"}),
    ("terminal", {"command": "rm {addon}/__init__.py"}),
    ("terminal", {"command": "find {home}/plugins -name 'example_addon' -exec rm -rf {{}} +"}),
    ("terminal", {"command": "echo '' > {addon}/__init__.py"}),
    ("write_file", {"path": "{addon}/__init__.py", "content": ""}),
    ("patch", {"path": "{addon}/__init__.py", "old_string": "x", "new_string": "y"}),
])
def test_an_agent_removing_or_editing_an_add_on_is_refused(home, tool, args):
    addon = home / "plugins" / "example_addon"
    filled = {key: value.format(addon=addon, home=home) for key, value in args.items()}
    findings = detect_guard_tamper(tool, filled)
    assert findings and all(f.source == "custom" and f.severity == "critical" for f in findings)


def test_reading_an_add_on_is_left_alone(home):
    addon = home / "plugins" / "example_addon"
    assert detect_guard_tamper("terminal", {"command": f"ls -la {addon} && cat {addon}/__init__.py"}) == []


def test_a_place_an_add_on_declares_is_guarded(home, tmp_path):
    data = tmp_path / "Library" / "Application Support" / "ExampleApp"
    data.mkdir(parents=True)
    assert detect_guard_tamper("terminal", {"command": f"rm -rf '{data}'"}) == []   # not yet declared
    Registrar(provider_package="example").protect_places([str(data)])
    assert detect_guard_tamper("terminal", {"command": f"rm -rf '{data}'"})


def test_another_programs_config_an_add_on_hooks_into_is_guarded_only_where_blackbox_is(home, tmp_path):
    settings = tmp_path / "agent" / "settings.json"
    settings.parent.mkdir(parents=True)
    settings.write_text('{"theme": "dark", "hooks": {"PreToolUse": [{"command": "python3 blackbox runner.py"}]}}', encoding="utf-8")
    Registrar(provider_package="example").protect_places([str(settings)], editable_configs=["settings.json"])
    assert detect_guard_tamper("patch", {"path": str(settings), "old_string": '"dark"', "new_string": '"light"'}) == []
    assert detect_guard_tamper("patch", {"path": str(settings), "old_string": "python3 blackbox runner.py", "new_string": ""})
    assert detect_guard_tamper("write_file", {"path": str(settings), "content": "{}"})   # a whole-file write drops the hook


@pytest.mark.parametrize("tool,args", [
    ("terminal", {"command": "rm {addon}/blackbox-addon.json"}),
    ("write_file", {"path": "{home}/plugins/planted/blackbox-addon.json", "content": '{{"extends": "blackbox"}}'}),
])
def test_an_agent_can_neither_unmake_nor_plant_an_add_on_manifest(home, tool, args):
    addon = home / "plugins" / "example_addon"
    filled = {key: value.format(addon=addon, home=home) for key, value in args.items()}
    assert detect_guard_tamper(tool, filled)


def test_a_plugin_folder_without_the_manifest_is_not_an_add_on(home):
    other = home / "plugins" / "someone_elses_plugin"
    other.mkdir()
    (other / "__init__.py").write_text("", encoding="utf-8")
    assert guarded_extra.found(home / "plugins") == ("example_addon",)
    assert detect_guard_tamper("terminal", {"command": f"rm -rf {other}"}) == []
