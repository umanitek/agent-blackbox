"""Notices from one source never hold back another's, and an SSH login is one notice
(KI-PENDING-b3bd8e, agents campaign pass 3, 2026-11-22: every SSH login raised "Someone connected
remotely" + "A remote session ended"; 30 short SSH calls used up the per-minute budget and an
agent's elevation notice was then held as ``rate``).

Contracts: each source (an AI agent's security notices, the shields, lifecycle, digest) has its
own per-minute budget; a remote session's END is kept but not pushed unless the person turned
lifecycle notices on.
"""

from __future__ import annotations

import pytest

from plugins.blackbox import notify, shields
from plugins.blackbox.notify import deliver, feed, policy, sources
from plugins.blackbox.notify.model import Delivery
from plugins.blackbox.shields.network import notices

NOW = 1_795_000_000.0


@pytest.fixture(autouse=True)
def _fresh():
    feed.reset()
    deliver.claim("", 0)
    yield
    feed.reset()


def _remote(kind: str, ts: float) -> shields.ShieldAlert:
    return shields.ShieldAlert(key=f"network:{kind}:{ts}", kind=kind, ts=ts, severity="high" if kind.endswith("new") else "info",
                               title="Network Shield · x", text="x",
                               category="lifecycle" if kind.endswith("ended") else "security")


def test_a_storm_of_ssh_logins_never_holds_back_an_agents_security_notice():
    alerts: list = []
    findings: list = []
    shown: list = []
    collector = sources.Collector(read_alerts=lambda: list(alerts), read_findings=lambda: list(findings), read_live=lambda: {"products": []})
    pump = deliver.Pump(collector=collector, send=lambda notice, details: shown.append(notice.kind) or Delivery("delivered", "ok"),
                        read_policy=lambda: policy.parse({"per_minute": 6}))
    pump.step(NOW)
    for number in range(30):                                  # 30 short SSH calls in one minute
        alerts += [_remote("remote-session-new", NOW + number), _remote("remote-session-ended", NOW + number + 0.5)]
    findings.append({"identifier": "agent:elevation-request", "category": "escalation", "severity": "high", "title": "sudo",
                     "evidence": "", "framework": "gemini-cli", "workspace": "/w/p", "source": "public", "decision": "",
                     "ts": NOW + 40, "session_id": "gemini-cli:aaaaaaaaaaaaaaaa", "tool_call_id": "t1", "fields": {}})
    pump.step(NOW + 45)
    assert "elevation-request" in shown                       # the agent's notice got through
    assert shown.count("shield:remote-session-new") == 6      # the shields' own budget
    assert "shield:remote-session-ended" not in shown         # a session's end is not pushed (lifecycle is off)


def test_the_end_of_a_remote_session_is_a_lifecycle_notice(monkeypatch):
    monkeypatch.setattr(notices.api, "alerts", lambda: [
        {"kind": "remote-session-new", "ts": NOW, "severity": "high", "text": "Someone logged in over SSH from 10.0.0.2."},
        {"kind": "remote-session-ended", "ts": NOW + 1, "severity": "info", "text": "The SSH session from 10.0.0.2 ended."}])
    monkeypatch.setattr(notices.system_report, "snapshot", dict)
    by_kind = {alert.kind: alert.category for alert in notices.shield_alerts()}
    assert by_kind == {"remote-session-new": "security", "remote-session-ended": "lifecycle"}


def test_each_source_has_its_own_budget():
    limiter = deliver.Limiter()
    assert all(limiter.allow(NOW, 2, "shields") for _ in range(2)) and not limiter.allow(NOW, 2, "shields")
    assert limiter.allow(NOW, 2, "agents") and limiter.allow(NOW, 2, "agents")
