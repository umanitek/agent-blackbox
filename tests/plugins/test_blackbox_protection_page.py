"""The Protection page over HTTP: the tamper counts, the protection log's check and the watch rules.

Contracts (2026-11-24): ``GET /api/protection`` shows each refused tamper attempt counted, the log's
check and every watch rule with its hits; adding and blocking a rule need the session token and
apply at once; taking a blocking rule off or back to watch through ``/api/settings`` is held for
the person (428) and nothing changes; a finding that names a package or host is turned into a
pre-filled rule; the page and its script are served.
"""

from __future__ import annotations

import pytest
from fastapi.testclient import TestClient

from plugins.blackbox import audit, guard
from plugins.blackbox.dashboard import server
from plugins.blackbox.kernel import threat_ids

SELF = {"identifier": threat_ids.fileaccess_identifier("terminal", threat_ids.SELF_PROTECTION),
        "matched": threat_ids.SELF_PROTECTION, "severity": "critical", "title": "Blackbox's own settings"}


@pytest.fixture(autouse=True)
def _home(tmp_path, monkeypatch):
    monkeypatch.setenv("BLACKBOX_HOME", str(tmp_path / "blackbox"))
    monkeypatch.setenv("HERMES_HOME", str(tmp_path / "hermes"))
    (tmp_path / "hermes").mkdir()


def _post(client, path, body):
    token = client.get("/api/session").json()["token"]
    return client.post(path, json=body, headers={"X-Blackbox-Token": token})


def _rule(client, value):
    return next(r for r in client.get("/api/protection").json()["rules"] if r["value"] == value)


def test_the_page_shows_tamper_counts_the_log_check_and_the_watch_rules():
    audit.record_for("codex", event="pre_tool_call", findings=[SELF], detail={"blocked": [SELF["identifier"]]})
    with TestClient(server.create_app(), base_url="http://127.0.0.1:9700") as client:
        assert client.post("/api/protection/watch", json={"kind": "package", "value": "npm:left-pad"}).status_code in (401, 403)
        assert _post(client, "/api/protection/watch", {"kind": "package", "value": "npm:left-pad"}).json()["ok"]
        assert _post(client, "/api/protection/watch", {"kind": "host", "value": "not a host"}).status_code == 400
        guard.tool_call_verdict("terminal", {"command": "npm install left-pad"}, agent="cursor")
        answer = client.get("/api/protection").json()
        assert answer["tamper"]["self-protection"]["count"] == 1 and answer["tamper"]["self-protection"]["last_agent"] == "codex"
        assert (answer["log"]["state"], answer["log"]["seq"]) == ("ok", 1)
        assert [(r["value"], r["state"], r["hits"]) for r in answer["rules"]] == [("npm:left-pad", "watch", 1)]
        assert client.get("/protection").status_code == 200 and client.get("/protection.js").status_code == 200


def test_blocking_applies_at_once_and_stopping_a_block_waits_for_the_person():
    with TestClient(server.create_app(), base_url="http://127.0.0.1:9700") as client:
        _post(client, "/api/protection/watch", {"kind": "host", "value": "files.example.top"})
        rule = _rule(client, "files.example.top")
        assert _post(client, "/api/protection/watch/promote", {"rule_id": rule["rule_id"]}).json()["ok"]
        assert _rule(client, "files.example.top")["state"] == "enforce"
        back = {"watch_rules": {"rules": [{"kind": "host", "value": "files.example.top", "state": "watch"}]}}
        assert _post(client, "/api/settings", back).status_code == 428          # held for the person
        assert _post(client, "/api/settings", {"watch_rules": {"rules": []}}).status_code == 428
        assert _rule(client, "files.example.top")["state"] == "enforce"


def test_a_finding_is_turned_into_a_prefilled_rule():
    finding = {"identifier": "dependency:npm:left-pad", "title": "Malicious package left-pad",
               "fields": {"ecosystem": "npm", "package_name": "left-pad"}}
    with TestClient(server.create_app(), base_url="http://127.0.0.1:9700") as client:
        assert _post(client, "/api/protection/watch/suggest", {"finding": finding}).json()["suggestion"]["value"] == "npm:left-pad"
        assert _post(client, "/api/protection/watch/suggest", {"finding": {"matched": "hello"}}).json() == {"suggestion": None}
