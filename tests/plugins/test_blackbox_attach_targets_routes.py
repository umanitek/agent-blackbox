"""The dashboard's agent list and per-agent switch act only on agents this machine has (review 2026-11-26, MED).

- ``GET /api/attach-targets`` lists an agent the operator switched off (unticked, ``declined``), so
  it can be switched back on; it used to vanish from the list.
- ``POST /api/agents/protection`` refuses (400) a target that is not a discovered agent and writes
  nothing there; it used to copy the plugin and write a ``config.yaml`` into any folder named.
"""

from __future__ import annotations

from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from plugins.blackbox import attach
from plugins.blackbox.dashboard import server


@pytest.fixture
def machine(tmp_path, monkeypatch):
    """A home with one Hermes install and one named profile; Blackbox's own folder apart."""
    home = tmp_path / "home"
    hermes = home / ".hermes"
    profile = hermes / "profiles" / "work"
    profile.mkdir(parents=True)
    (hermes / "config.yaml").write_text("plugins:\n  enabled: []\n", encoding="utf-8")
    monkeypatch.setattr(Path, "home", lambda: home)
    monkeypatch.setenv("HERMES_HOME", str(hermes))
    monkeypatch.setenv("BLACKBOX_HOME", str(tmp_path / "bb"))
    client = TestClient(server.create_app(), base_url="http://127.0.0.1:9700")   # no startup: no background loops
    client.headers["X-Blackbox-Token"] = client.get("/api/session").json()["token"]
    return client, profile, tmp_path


def test_a_switched_off_agent_stays_listed_to_switch_back_on(machine):
    client, profile, _ = machine
    attach.attach_hermes(profile)
    attach.detach_hermes(profile)
    rows = {row["target"]: row for row in client.get("/api/attach-targets").json()["targets"] if row.get("kind") == "hermes"}
    assert str(profile) in rows
    assert rows[str(profile)]["protected"] is False and rows[str(profile)]["declined"] is True


def test_a_folder_that_is_no_discovered_agent_is_refused_and_untouched(machine):
    client, _, tmp_path = machine
    stranger = tmp_path / "somewhere"
    stranger.mkdir()
    (stranger / "config.yaml").write_text("keep: me\n", encoding="utf-8")
    answer = client.post("/api/agents/protection", json={"targets": [{"kind": "hermes", "target": str(stranger), "enabled": True}]})
    assert answer.status_code == 400
    assert not (stranger / "plugins").exists()
    assert (stranger / "config.yaml").read_text(encoding="utf-8") == "keep: me\n"


def test_a_discovered_agent_named_another_way_is_switched_on(machine):
    client, profile, _ = machine
    spelled = str(profile) + "/"
    answer = client.post("/api/agents/protection", json={"targets": [{"kind": "hermes", "target": spelled, "enabled": True}]})
    assert answer.status_code == 200, answer.json()
    assert attach.is_attached("hermes", profile)
