"""Every agent, now and later, on one yes: ``blackbox attach --all --auto`` and the Settings switch (2026-11-19).

Amos: "every new profile and every new instance, automatically, always protected moving forward".
The Hermes catalog review (KI-429 / LES-067) forbids a silent default, so the yes is asked once
(the installers, Desktop's setup switch) and saved as ``auto_attach`` through ONE writer, which
these tests drive through the real CLI parser, the real settings API and the real dashboard sweep:
a profile created AFTER the yes is protected by the next rescan, with no further step.
"""

from __future__ import annotations

import argparse

import pytest

try:
    import hermes_yaml as yaml  # Hermes 0.21.7+
except ImportError:  # older Hermes
    import yaml

from _blackbox_loader import load_blackbox

attach = load_blackbox("attach")
cli = load_blackbox("cli")
config_mod = load_blackbox("kernel.config")
settings = load_blackbox("kernel.settings")


@pytest.fixture
def machine(tmp_path, monkeypatch):
    """A fake home: the main Hermes home (with a config) and one profile, Blackbox's own folder apart."""
    home = tmp_path / "home"
    main = home / ".hermes"
    (main / "profiles" / "work").mkdir(parents=True)
    (main / "config.yaml").write_text(yaml.safe_dump({"plugins": {"enabled": []}}), encoding="utf-8")
    monkeypatch.setattr("pathlib.Path.home", lambda: home)
    monkeypatch.setenv("HERMES_HOME", str(main))
    monkeypatch.setenv("BLACKBOX_HOME", str(tmp_path / "bb"))
    monkeypatch.delenv("BLACKBOX_AUTO_ATTACH", raising=False)
    return main


def _protected(home):
    path = home / "config.yaml"
    return path.exists() and attach.enabled_list_has(yaml.safe_load(path.read_text(encoding="utf-8")), "blackbox")


def _attach(capsys, *argv):
    parser = argparse.ArgumentParser(prog="blackbox")
    cli.setup_cli(parser)
    args = parser.parse_args(["attach", *argv])
    return args.func(args), capsys.readouterr().out


def test_attach_all_auto_protects_every_agent_and_saves_the_yes(machine, capsys):
    code, out = _attach(capsys, "--all", "--auto")
    assert code == 0 and "protected automatically" in out
    assert _protected(machine) and _protected(machine / "profiles" / "work")
    assert config_mod.load_blackbox_config().auto_attach is True


def test_no_auto_saves_the_no_and_leaves_protected_agents_protected(machine, capsys):
    _attach(capsys, "--all", "--auto")
    code, out = _attach(capsys, "--no-auto")
    assert code == 0 and "not protected automatically" in out
    assert config_mod.load_blackbox_config().auto_attach is False
    assert _protected(machine / "profiles" / "work")


def test_auto_and_no_auto_cannot_be_given_together(machine, capsys):
    with pytest.raises(SystemExit):
        _attach(capsys, "--auto", "--no-auto")


def test_a_dry_run_never_saves_the_setting(machine, capsys):
    _attach(capsys, "--all", "--auto", "--dry-run")
    assert config_mod.load_blackbox_config().auto_attach is False


def test_the_settings_api_reads_and_writes_the_switch(machine):
    assert settings.read_settings()["auto_attach"] is False
    assert settings.write_settings({"auto_attach": True})["ok"] is True
    assert settings.read_settings()["auto_attach"] is True
    refused = settings.write_settings({"auto_attach": "yes"})
    assert refused["ok"] is False and settings.read_settings()["auto_attach"] is True


def test_a_profile_made_after_the_yes_is_protected_by_the_next_dashboard_sweep(machine, capsys):
    pytest.importorskip("fastapi")
    from fastapi.testclient import TestClient

    _attach(capsys, "--all", "--auto")
    server = load_blackbox("dashboard.server")
    later = machine / "profiles" / "made-after-install"
    with TestClient(server.create_app(), base_url="http://127.0.0.1:9700") as client:
        later.mkdir()   # `hermes profile create` after the install
        token = {"X-Blackbox-Token": client.get("/api/session").json()["token"]}
        assert client.post("/api/agents/rescan", headers=token).status_code == 200
    assert _protected(later)


def test_without_the_yes_a_later_profile_stays_unprotected(machine, capsys):
    pytest.importorskip("fastapi")
    from fastapi.testclient import TestClient

    _attach(capsys, str(machine))   # only the installer's own home
    server = load_blackbox("dashboard.server")
    later = machine / "profiles" / "made-after-install"
    with TestClient(server.create_app(), base_url="http://127.0.0.1:9700") as client:
        later.mkdir()
        token = {"X-Blackbox-Token": client.get("/api/session").json()["token"]}
        client.post("/api/agents/rescan", headers=token)
    assert not _protected(later)


# ------------------------------------------------------------------ what the dashboard shows of it


coverage = load_blackbox("attach.coverage")


@pytest.mark.parametrize("kind, target, label", [
    ("hermes", "/u/.hermes", "Hermes (main)"),
    ("hermes", "/u/.hermes/profiles/coder", "Hermes · coder"),
    ("hermes", "/u/.hermes/profiles/agent-blackbox", "Blackbox assistant"),
    ("openclaw", "/u/.openclaw", "OpenClaw"),
    ("openclaw", "/u/.openclaw-work", "OpenClaw · work"),
])
def test_every_agent_is_named_the_way_the_dashboard_labels_its_findings(kind, target, label):
    assert coverage.agent_label(kind, target) == label


def test_coverage_lists_unprotected_agents_but_never_one_switched_off(machine, capsys):
    other = machine / "profiles" / "other"
    other.mkdir()
    _attach(capsys, str(machine))
    attach.attach_hermes(other)
    attach.detach_hermes(other)   # the operator's choice: never nagged about
    view = attach.coverage()
    assert view["auto_attach"] is False
    assert [agent["label"] for agent in view["unprotected"]] == ["Hermes · work"]


def test_the_sweep_notes_only_agents_it_newly_protected(machine, capsys):
    _attach(capsys, str(machine))
    before = {item["seq"] for item in coverage.RECENT.recent()}
    targets = {("hermes", str(machine)), ("hermes", str(machine / "profiles" / "work"))}
    rows = attach.protect_automatically(targets)
    assert len(rows) == 2 and _protected(machine / "profiles" / "work")
    new = [item for item in coverage.RECENT.recent() if item["seq"] not in before]
    assert [item["label"] for item in new] == ["Hermes · work"]   # the main home was protected already


def test_the_dashboard_announces_a_new_agent_and_protect_all_saves_the_yes(machine, capsys):
    pytest.importorskip("fastapi")
    from fastapi.testclient import TestClient

    _attach(capsys, str(machine))
    server = load_blackbox("dashboard.server")
    with TestClient(server.create_app(), base_url="http://127.0.0.1:9700") as client:
        token = {"X-Blackbox-Token": client.get("/api/session").json()["token"]}
        assert client.get("/agent-coverage.js").status_code == 200
        assert client.post("/api/agent-coverage/protect-all").status_code in (400, 403)   # no token: refused
        answer = client.post("/api/agent-coverage/protect-all", headers=token)
        assert answer.status_code == 200 and answer.json()["ok"] is True
    assert config_mod.load_blackbox_config().auto_attach is True and _protected(machine / "profiles" / "work")
    assert attach.coverage()["unprotected"] == []


# ------------------------------------------------------------------ one list of settings for both runtimes


def test_openclaw_is_handed_the_operators_protected_paths_and_block_level(machine, tmp_path):
    # 2026-11-20: under OpenClaw the bridge ran on its own defaults (and an empty protected-path
    # list), so what the operator set in the dashboard did not reach OpenClaw agents.
    import json

    workspace = machine.parent / ".openclaw"
    workspace.mkdir()
    (workspace / "openclaw.json").write_text(json.dumps({"plugins": {}}), encoding="utf-8")
    assert settings.write_settings({"mode": "block", "block_severity": "high", "protected_paths": ["~/secrets", "*.pem"]})["ok"]
    attach.attach_openclaw(workspace)
    config = json.loads((workspace / "openclaw.json").read_text(encoding="utf-8"))["plugins"]["entries"]["blackbox"]["config"]
    assert (config["mode"], config["blockSeverity"], config["protectedPaths"]) == ("block", "high", ["~/secrets", "*.pem"])
