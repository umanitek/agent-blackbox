"""B3 contract: findings flow to the community graph — gated, identified, off-path.

The write-path invariants of the community-graph build:

* CommunitySharePolicy truth table — the single gate chain (KI-002/003).
* Shares target the COMMUNITY graph id, never the verified graph.
* The share runs on a background thread; the hook returns first (KI-033).
* Fallback identity → no share, local audit intact (KI-003, Sentinel).
* Daily cap enforced at the call site (KI-002 part 2).
* Privacy: no prompt/command/evidence text in any emitted quad.
* IOC reports carry iocType (KI-024); IDN domains converge (KI-026).
* Every attempt lands in the durable reports ledger (KI-015).
"""

from __future__ import annotations

import threading
import time

import pytest

from plugins.blackbox import audit, constants, detection, hooks, quads
from plugins.blackbox.config import BlackboxConfig
from plugins.blackbox.dkg_client import DkgError


DEV_GRAPH = "0x51E5dE758A45c8b64048E29918421F0bdD6D5d5C/agent-blackbox-community-dev"
REPORTER = "0xabc0000000000000000000000000000000000001"

CFG_ON = BlackboxConfig(report=True, community_graph_id=DEV_GRAPH)


@pytest.fixture
def bb_home(monkeypatch, tmp_path):
    """Isolated BLACKBOX_HOME so rate state + ledgers never touch the real one."""
    monkeypatch.setenv("BLACKBOX_HOME", str(tmp_path / "bbhome"))
    return tmp_path / "bbhome"


@pytest.fixture(autouse=True)
def _fresh_reporter_cache(monkeypatch):
    monkeypatch.setattr(hooks, "_reporter_cache", {})


class FakeClient:
    """Captures share calls; resolves a real-looking identity."""

    def __init__(self, fail=False):
        self.shares = []
        self.fail = fail

    def agent_identity(self):
        return {"agentAddress": REPORTER}

    def status(self):
        return {}

    def share_knowledge_asset(self, cg_id, name, q, **kw):
        if self.fail:
            raise DkgError("simulated node failure with a Bearer sk-secret-token inside")
        self.shares.append((cg_id, name, q))
        return {"state": "succeeded"}


def _finding(identifier="dep:npm:evil-pkg@1.0.0", source="public", **kw):
    base = dict(
        identifier=identifier,
        category="dependency",
        severity="critical",
        title="test threat",
        source=source,
        confirmed=source == "public",
    )
    base.update(kw)
    return detection.Finding(**base)


# ---------------------------------------------------------------------------
# CommunitySharePolicy — the truth table
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("cfg", "source", "identifier", "reporter", "expected"),
    [
        (CFG_ON, "public", "dep:npm:x@1", REPORTER, True),
        (CFG_ON, "community", "dep:npm:x@1", REPORTER, True),
        (CFG_ON, "heuristic", "dep:npm:x@1", REPORTER, True),
        (CFG_ON, "custom", "dep:npm:x@1", REPORTER, False),
        (CFG_ON, "llm", "dep:npm:x@1", REPORTER, False),
        (CFG_ON, "secret", "secret:aws", REPORTER, False),
        (CFG_ON, "public", "", REPORTER, False),  # no identifier
        (CFG_ON, "public", "dep:npm:x@1", None, False),  # no identity (KI-003)
        (BlackboxConfig(report=False, community_graph_id=DEV_GRAPH), "public", "dep:npm:x@1", REPORTER, False),
        (BlackboxConfig(report=True, community_graph_id=""), "public", "dep:npm:x@1", REPORTER, False),
    ],
)
def test_policy_truth_table(cfg, source, identifier, reporter, expected):
    policy = hooks.CommunitySharePolicy(cfg)
    finding = {"identifier": identifier, "source": source}
    allowed, _why = policy.decide(finding, reporter)
    assert allowed is expected


# ---------------------------------------------------------------------------
# The two-graph invariant: shares go to the community graph, never verified
# ---------------------------------------------------------------------------


def test_share_targets_community_graph_never_verified(bb_home):
    client = FakeClient()
    hooks._share_sighting(client, CFG_ON, _finding().to_dict(), REPORTER)
    assert len(client.shares) == 1
    cg_id, _name, _q = client.shares[0]
    assert cg_id == DEV_GRAPH
    assert cg_id != CFG_ON.context_graph_id


# ---------------------------------------------------------------------------
# The pipeline: gate inline, share off-path
# ---------------------------------------------------------------------------


def _run_pipeline(monkeypatch, cfg, findings, client=None, reporter=REPORTER):
    """Drive _report_and_audit with a fake client; capture spawned shares."""
    client = client or FakeClient()
    spawned = []
    monkeypatch.setattr(hooks, "DkgClient", lambda *a, **k: client)
    monkeypatch.setattr(hooks, "_reporter_address", lambda c: reporter)
    monkeypatch.setattr(audit, "write_private_audit_ka", lambda *a, **k: None)
    monkeypatch.setattr(
        hooks,
        "_spawn_community_share",
        lambda c, cf, f, r: spawned.append((f["identifier"], r)),
    )
    hooks._report_and_audit(cfg, "pre_tool_call", findings, {})
    return spawned, client


def test_pipeline_shares_when_gate_open(monkeypatch, bb_home):
    spawned, _ = _run_pipeline(monkeypatch, CFG_ON, [_finding()])
    assert spawned == [("dep:npm:evil-pkg@1.0.0", REPORTER)]


def test_pipeline_never_shares_when_report_off(monkeypatch, bb_home):
    cfg = BlackboxConfig(report=False, community_graph_id=DEV_GRAPH)
    spawned, _ = _run_pipeline(monkeypatch, cfg, [_finding()])
    assert spawned == []


def test_no_share_without_identity_but_audit_survives(monkeypatch, bb_home):
    """KI-003: fallback identity refuses to share; the local audit still lands."""
    recorded = []
    monkeypatch.setattr(audit, "record", lambda **kw: recorded.append(kw))
    spawned, _ = _run_pipeline(monkeypatch, CFG_ON, [_finding()], reporter=None)
    assert spawned == []
    assert recorded, "local audit must survive an identity failure"


def test_excluded_sources_never_spawn(monkeypatch, bb_home):
    for source in ("custom", "llm", "secret"):
        spawned, _ = _run_pipeline(
            monkeypatch, CFG_ON, [_finding(identifier=f"x:{source}", source=source)]
        )
        assert spawned == [], source


def test_cooldown_suppresses_repeat_share(monkeypatch, bb_home):
    spawned1, _ = _run_pipeline(monkeypatch, CFG_ON, [_finding()])
    spawned2, _ = _run_pipeline(monkeypatch, CFG_ON, [_finding()])
    assert len(spawned1) == 1
    assert spawned2 == []


def test_daily_cap_enforced_at_call_site(monkeypatch, bb_home):
    """KI-002 part 2: allow_report() finally has its caller."""
    cfg = BlackboxConfig(report=True, community_graph_id=DEV_GRAPH, daily_report_limit=1)
    findings = [_finding("dep:npm:a@1"), _finding("dep:npm:b@1"), _finding("dep:npm:c@1")]
    spawned, _ = _run_pipeline(monkeypatch, cfg, findings)
    assert len(spawned) == 1


def test_hook_returns_before_share_completes(monkeypatch, bb_home):
    """KI-033: the share lifecycle must never stall the hook."""
    started = threading.Event()
    finished = threading.Event()

    def slow_share(client, cfg, finding, reporter):
        started.set()
        time.sleep(1.5)
        finished.set()

    client = FakeClient()
    monkeypatch.setattr(hooks, "DkgClient", lambda *a, **k: client)
    monkeypatch.setattr(hooks, "_reporter_address", lambda c: REPORTER)
    monkeypatch.setattr(audit, "write_private_audit_ka", lambda *a, **k: None)
    monkeypatch.setattr(hooks, "_share_sighting", slow_share)

    t0 = time.monotonic()
    hooks._report_and_audit(CFG_ON, "pre_tool_call", [_finding()], {})
    elapsed = time.monotonic() - t0

    assert elapsed < 1.0, f"hook blocked on the share ({elapsed:.2f}s)"
    assert started.wait(3.0), "share worker never started"
    assert finished.wait(3.0), "share worker never finished"


# ---------------------------------------------------------------------------
# Privacy regression guard
# ---------------------------------------------------------------------------


def test_no_evidence_text_in_emitted_quads(bb_home):
    secret_text = "SUPER-SECRET-PROMPT-CONTENT rm -rf /home/amos/project"
    finding = _finding(
        matched=secret_text,
        evidence=secret_text,
        fields={"ecosystem": "npm", "package_name": "evil-pkg", "package_version": "1.0.0"},
    )
    client = FakeClient()
    hooks._share_sighting(client, CFG_ON, finding.to_dict(), REPORTER)
    (_cg, _name, q) = client.shares[0]
    serialized = "\n".join(str(v) for quad in q for v in dict(quad).values())
    assert "SUPER-SECRET-PROMPT" not in serialized
    assert "/home/amos" not in serialized
    assert "evil-pkg" in serialized  # the reviewable coordinates DO travel


# ---------------------------------------------------------------------------
# Report construction correctness (KI-024, KI-026)
# ---------------------------------------------------------------------------


def test_ioc_report_carries_ioc_type():
    q = quads.build_report_quads(
        identifier="ioc:domain:evil.example",
        category="ioc",
        severity="high",
        reporter_address=REPORTER,
        ioc_type="domain",
    )
    serialized = ["|".join(str(v) for v in dict(quad).values()) for quad in q]
    assert any(constants.IOC_TYPE_PRED in row and "domain" in row for row in serialized)


def test_idn_and_punycode_domains_share_one_identifier():
    assert quads.ioc_identifier("domain", "münchen.example") == quads.ioc_identifier(
        "domain", "xn--mnchen-3ya.example"
    )
    assert quads.ioc_identifier("url", "https://münchen.example/pfad") == quads.ioc_identifier(
        "url", "https://xn--mnchen-3ya.example/pfad"
    )


def test_ascii_ioc_values_unchanged():
    assert quads.ioc_identifier("domain", "Evil.Example.") == "ioc:domain:evil.example"


# ---------------------------------------------------------------------------
# The durable reports ledger (KI-015)
# ---------------------------------------------------------------------------


def test_ledger_records_success(bb_home):
    hooks._share_sighting(FakeClient(), CFG_ON, _finding().to_dict(), REPORTER)
    rows = audit.read_share_ledger()
    assert len(rows) == 1
    assert rows[0]["ok"] is True
    assert rows[0]["identifier"] == "dep:npm:evil-pkg@1.0.0"
    assert rows[0]["subject"].startswith("urn:guardian:report:")


def test_ledger_records_failure_with_sanitized_error(bb_home):
    hooks._share_sighting(FakeClient(fail=True), CFG_ON, _finding().to_dict(), REPORTER)
    rows = audit.read_share_ledger()
    assert len(rows) == 1
    assert rows[0]["ok"] is False
    assert "sk-secret-token" not in rows[0]["error"]  # Bearer token redacted
    assert "[REDACTED]" in rows[0]["error"]


def test_share_failure_is_fail_open(bb_home):
    hooks._share_sighting(FakeClient(fail=True), CFG_ON, _finding().to_dict(), REPORTER)
