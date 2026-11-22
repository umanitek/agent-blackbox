"""The shields' extension point (plugins/blackbox/shields/extensions.py), 2026-11-21.

The public plugin carries only what works on its own; an add-on registered beside it adds the
rest. Contracts: an add-on is a package folder beside the plugin that declares itself with the
add-on manifest (``blackbox-addon.json``, ``{"extends": "blackbox"}``) and registers through the
plugin's package entries; a folder without the manifest is never loaded; its own shields join the registry; its extension of a
shield merges endpoints, unlocks options, adds findings (claimed by the gate), decorates the card
and adds events; an add-on that fails to load contributes nothing and the plugin keeps working;
an extension's detector that raises adds nothing while the shield's own findings stay.
"""

from __future__ import annotations

import dataclasses
import textwrap

import pytest

from plugins.blackbox import shields
from plugins.blackbox.detection import Finding
from plugins.blackbox.shields import extensions, trader
from plugins.blackbox.shields.contract import StatusRow, StatusSection
from plugins.blackbox.shields.network import lockdown, mode as network_mode

LOCKED = network_mode.build(enabled=True, protections=(network_mode.LOCKDOWN,))


@pytest.fixture(autouse=True)
def fresh_registry(tmp_path, monkeypatch):
    monkeypatch.setenv("BLACKBOX_HOME", str(tmp_path / "bb"))
    shields.reload_registry()
    yield
    shields.reload_registry()


def _listed(tool_name, args, mode):
    return [lockdown.finding("network:listed-host", tool_name, host, "is on a public list")
            for host in lockdown.hosts_in(args) if host.endswith("tracker.example")]


def _addon(**changes):
    registrar = extensions.Registrar(provider_package="example_addon")
    parts = dict(
        shield_id=network_mode.SHIELD_ID, provider="Example add-on", unlocks=frozenset({"dns", "firewall"}),
        api=shields.ShieldApi(reads={"overview": lambda context, params: {"ok": True}}),
        detect=_listed, claims=("network:listed-host",),
        status=lambda mode, card: dataclasses.replace(card, sections=card.sections + (
            StatusSection("Helper", "", (StatusRow(icon="●", state="active", text="Network helper running", sub=""),)),)))
    registrar.extend(extensions.ShieldExtension(**{**parts, **changes}))
    return registrar


def test_an_extension_unlocks_options_merges_its_api_and_adds_claimed_findings():
    extensions.use(_addon())
    network = shields.get(network_mode.SHIELD_ID)
    assert shields.unlocked(network_mode.SHIELD_ID) == {"dns", "firewall"}
    assert network_mode.default_protections() == (network_mode.DNS,)
    options = {option.id: option.status for field in network.settings_fields() for option in field.options}
    assert options["dns"] == "supported" and options["cut"] == "needs-helper"
    assert shields.call_api(network_mode.SHIELD_ID, "GET", "overview", None, {}) == {"ok": True}
    found = network.detect("terminal", {"command": "curl https://ads.tracker.example/p"}, LOCKED)
    assert {f.identifier for f in found} == {"network:listed-host", lockdown.LOCKDOWN_ID}
    assert network.claims({"identifier": "network:listed-host"}) and network.claims({"identifier": lockdown.LOCKDOWN_ID})
    assert [section.title for section in network.status(LOCKED).sections] == ["Protections", "System protection helper", "Helper"]


def test_an_add_on_shield_joins_the_registry_after_the_plugins_own():
    registrar = _addon()
    registrar.register_shield(dataclasses.replace(trader.TRADER, id="file-shield", name="File Shield"))
    extensions.use(registrar)
    assert [shield.id for shield in shields.all_shields()] == ["trader", "network-shield", "file-shield"]


def test_an_extensions_detector_that_raises_adds_nothing_and_the_shields_own_findings_stay():
    def broken(*_args):
        raise RuntimeError("add-on bug")
    extensions.use(_addon(detect=broken))
    found = shields.get(network_mode.SHIELD_ID).detect("terminal", {"command": "curl https://x.unknown-host.com/"}, LOCKED)
    assert [f.identifier for f in found] == [lockdown.LOCKDOWN_ID]


def _write_addon(root, body, name="example_addon", manifest='{"extends": "blackbox"}'):
    folder = root / name
    folder.mkdir()
    (folder / "__init__.py").write_text(textwrap.dedent(body), encoding="utf-8")
    if manifest is not None:
        (folder / "blackbox-addon.json").write_text(manifest, encoding="utf-8")


def test_an_add_on_is_found_by_its_manifest_and_reaches_the_plugin_through_its_entries(tmp_path):
    _write_addon(tmp_path, """
        from ..blackbox import shields
        def register(registrar):
            registrar.extend(shields.ShieldExtension(shield_id="network-shield", provider="Example add-on",
                                                     unlocks=frozenset({"cut"})))
            registrar.add_routes(lambda app: None)
    """)
    extensions.load("plugins.blackbox", tmp_path / "blackbox")
    assert extensions.providers() == ["example_addon"] and extensions.problems() == []
    assert shields.unlocked(network_mode.SHIELD_ID) == {"cut"} and len(shields.addon_routes()) == 1


def test_a_broken_add_on_contributes_nothing_and_the_plugin_keeps_working(tmp_path):
    _write_addon(tmp_path, """
        def register(registrar):
            registrar.register_shield(object())
            raise RuntimeError("half registered")
    """)
    extensions.load("plugins.blackbox", tmp_path / "blackbox")
    assert extensions.providers() == [] and "half registered" in extensions.problems()[0]
    assert [shield.id for shield in shields.all_shields()] == ["trader", "network-shield", "file-shield"]
    assert shields.unlocked(network_mode.SHIELD_ID) == frozenset()
    found = shields.get(network_mode.SHIELD_ID).detect("terminal", {"command": "curl https://x.unknown-host.com/"}, LOCKED)
    assert [f.identifier for f in found] == [lockdown.LOCKDOWN_ID]
    assert isinstance(found[0], Finding)


def test_an_extension_that_brings_packs_must_bring_its_page_and_attack_table(tmp_path):
    with pytest.raises(ValueError):
        extensions.Registrar(provider_package="x").extend(
            extensions.ShieldExtension(shield_id=network_mode.SHIELD_ID, provider="x", packs=tmp_path))


@pytest.mark.parametrize("name,manifest", [
    ("no_manifest", None),
    ("wrong_target", '{"extends": "something-else"}'),
    ("not_json", "extends: blackbox"),
    ("not-a-package", '{"extends": "blackbox"}'),
])
def test_a_folder_that_does_not_declare_itself_an_add_on_is_never_loaded(tmp_path, name, manifest):
    _write_addon(tmp_path, """
        def register(registrar):
            raise AssertionError("must not be loaded")
    """, name=name, manifest=manifest)
    extensions.load("plugins.blackbox", tmp_path / "blackbox")
    assert extensions.providers() == [] and extensions.problems() == []


def test_every_declared_add_on_is_loaded_in_name_order(tmp_path):
    for name in ("second_addon", "first_addon"):
        _write_addon(tmp_path, "def register(registrar):\n    pass\n", name=name)
    extensions.load("plugins.blackbox", tmp_path / "blackbox")
    assert extensions.providers() == ["first_addon", "second_addon"]
