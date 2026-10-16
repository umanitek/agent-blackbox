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

from plugins.blackbox import audit, detection
from plugins.blackbox.guard import hooks
from plugins.blackbox import community as community_pkg
from plugins.blackbox.community import sharing as community_sharing
from plugins.blackbox.kernel import identity as kernel_identity
from plugins.blackbox.guard import reporting as guard_reporting
from plugins.blackbox.community import report_builder
from plugins.blackbox.kernel import threat_ids
from plugins.blackbox.kernel import constants
from plugins.blackbox.kernel.config import BlackboxConfig
from plugins.blackbox.kernel.dkg_client import DkgError


DEV_GRAPH = "0x51E5dE758A45c8b64048E29918421F0bdD6D5d5C/agent-blackbox-community-dev"
REPORTER = "0xabc0000000000000000000000000000000000001"

CFG_ON = BlackboxConfig(report=True, context_graph_id=DEV_GRAPH)


@pytest.fixture
def bb_home(monkeypatch, tmp_path):
    """Isolated BLACKBOX_HOME so rate state + ledgers never touch the real one."""
    monkeypatch.setenv("BLACKBOX_HOME", str(tmp_path / "bbhome"))
    return tmp_path / "bbhome"


@pytest.fixture(autouse=True)
def _fresh_reporter_cache(monkeypatch):
    monkeypatch.setattr(kernel_identity, "_reporter_cache", {})


TEST_NETWORK = "test-network-id"


class FakeClient:
    """Captures share calls; resolves a real-looking identity."""

    def __init__(self, fail=False):
        self.shares = []
        self.fail = fail

    def agent_identity(self):
        return {"agentAddress": REPORTER}

    def status(self):
        return {"networkId": TEST_NETWORK}  # real nodes always report one; signing needs it (R0b)

    def share_knowledge_asset(self, cg_id, name, q, **kw):
        if self.fail:
            raise DkgError("simulated node failure with a Bearer sk-secret-token inside")
        self.shares.append((cg_id, name, q))
        return {"state": "succeeded"}


def _fields_for(identifier):
    """The share fields a real detector attaches to *identifier* (the R1 schema
    validates them at the gate): package parts + reason for a malware
    dependency, type + context for an IOC."""
    if identifier.startswith("dep:"):
        ecosystem, package = identifier[len("dep:"):].split(":", 1)
        name, version = package.rsplit("@", 1)
        return {"ecosystem": ecosystem, "package_name": name, "package_version": version, "kind": "malware",
                "reason": "install-hook"}
    if identifier.startswith("ioc:"):
        return {"ioc_type": identifier.split(":")[1], "ioc_context": "fetched-by-tool"}
    return {}


def _finding(identifier="dep:npm:evil-pkg@1.0.0", source="public", **kw):
    base = dict(
        identifier=identifier,
        category="dependency",
        severity="critical",
        title="test threat",
        source=source,
        confirmed=source == "public",
        fields=_fields_for(identifier),
    )
    base.update(kw)
    return detection.Finding(**base)


def _shareable(identifier, **kw):
    """A gate-input dict for *identifier* with its real fields; *kw* overrides."""
    finding = {"identifier": identifier, "category": identifier.split(":")[0], "severity": "high",
               "fields": _fields_for(identifier)}
    finding["category"] = "dependency" if identifier.startswith("dep:") else finding["category"]
    finding.update(kw)
    return finding


# ---------------------------------------------------------------------------
# CommunitySharePolicy — the truth table
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("cfg", "source", "identifier", "reporter", "expected"),
    [
        (CFG_ON, "public", "dep:npm:x@1", REPORTER, True),
        (CFG_ON, "community", "dep:npm:x@1", REPORTER, False),  # decision 22 / KI-158: never auto-shared
        (CFG_ON, "heuristic", "dep:npm:x@1", REPORTER, True),
        (CFG_ON, "custom", "dep:npm:x@1", REPORTER, False),
        (CFG_ON, "llm", "dep:npm:x@1", REPORTER, False),
        (CFG_ON, "secret", "secret:aws", REPORTER, False),
        (CFG_ON, "public", "", REPORTER, False),  # no identifier
        (CFG_ON, "public", "dep:npm:x@1", None, False),  # no identity (KI-003)
        (BlackboxConfig(report=False, context_graph_id=DEV_GRAPH), "public", "dep:npm:x@1", REPORTER, False),
        (BlackboxConfig(report=True, context_graph_id=""), "public", "dep:npm:x@1", REPORTER, False),
    ],
)
def test_policy_truth_table(cfg, source, identifier, reporter, expected):
    policy = community_sharing.CommunitySharePolicy(cfg)
    allowed, _why = policy.decide(_shareable(identifier, source=source), reporter)
    assert allowed is expected


# ---------------------------------------------------------------------------
# Decision 22 (Refine R0): what leaves automatically is narrowed (KI-157/158)
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("finding, shares", [
    ({"source": "public", "kind": "vulnerability"}, False),                         # verified-tier vulnerability
    ({"source": "heuristic", "fields": {**_fields_for("dep:npm:x@1"), "kind": None,
                                        "advisory_id": "GHSA-xxxx-yyyy"}}, False),  # OSV-vulnerable candidate
    ({"source": "heuristic", "fields": {**_fields_for("dep:npm:x@1"), "advisory_id": "MAL-2026-1234"}}, True),  # OSV malicious
    ({"source": "public", "kind": "malware"}, True),                                # verified malware match
    ({"source": "heuristic", "kind": "malware"}, True),                             # self-discovered malware
    ({"source": "community"}, False),                                               # community-only match
    ({"source": "heuristic"}, True),                                                # self-discovered, no advisory
])
def test_decision_22_share_gate(finding, shares):
    finding = _shareable("dep:npm:x@1", **finding)
    ok, why = community_sharing.CommunitySharePolicy(CFG_ON).decide(finding, REPORTER)
    assert ok is shares, why


def test_community_only_ioc_match_flags_but_never_auto_shares(monkeypatch, bb_home):
    """KI-158 end to end through the real reporting pipeline: the finding is
    audited (it flags here) but nothing is spawned for the community graph."""
    recorded = []
    monkeypatch.setattr(audit, "record", lambda **kw: recorded.append(kw))
    spawned, _ = _run_pipeline(monkeypatch, CFG_ON, [_finding(source="community", identifier="ioc:domain:listed.example",
                                                              category="ioc")])
    assert spawned == []
    assert recorded and recorded[0]["findings"][0]["identifier"] == "ioc:domain:listed.example"


def test_verified_match_still_auto_shares(monkeypatch, bb_home):
    spawned, _ = _run_pipeline(monkeypatch, CFG_ON, [_finding(source="public", identifier="ioc:domain:verified.example",
                                                              category="ioc")])
    assert [ident for ident, _ in spawned] == ["ioc:domain:verified.example"]


# ---------------------------------------------------------------------------
# The two-graph invariant: shares go to the community graph, never verified
# ---------------------------------------------------------------------------


def test_a_sighting_goes_to_the_verified_graphs_shared_memory_never_its_verified_memory(bb_home):
    """One graph (2026-10-16): a sighting is shared into the verified graph's SHARED
    memory — ``share_knowledge_asset``, which writes the community sub-graph and never
    publishes. Only the curator publishes to the graph's Verified Memory."""
    client = FakeClient()
    community_sharing._share_sighting(client, CFG_ON, _finding().to_dict(), REPORTER)
    assert [(cg_id, name.startswith("report-")) for cg_id, name, _q in client.shares] == [(CFG_ON.context_graph_id, True)]


# ---------------------------------------------------------------------------
# The pipeline: gate inline, share off-path
# ---------------------------------------------------------------------------


def _run_pipeline(monkeypatch, cfg, findings, client=None, reporter=REPORTER):
    """Drive _report_and_audit with a fake client; capture spawned shares."""
    client = client or FakeClient()
    spawned = []
    monkeypatch.setattr(guard_reporting, "DkgClient", lambda *a, **k: client)
    monkeypatch.setattr(kernel_identity, "reporter_address", lambda c: reporter)
    monkeypatch.setattr(audit, "write_private_audit_ka", lambda *a, **k: None)
    monkeypatch.setattr(community_pkg, "spawn_community_share",
        lambda c, cf, f, r: spawned.append((f["identifier"], r)),
    )
    guard_reporting._report_and_audit(cfg, "pre_tool_call", findings, {})
    return spawned, client


def test_pipeline_shares_when_gate_open(monkeypatch, bb_home):
    spawned, _ = _run_pipeline(monkeypatch, CFG_ON, [_finding()])
    assert spawned == [("dep:npm:evil-pkg@1.0.0", REPORTER)]


def test_pipeline_never_shares_when_report_off(monkeypatch, bb_home):
    cfg = BlackboxConfig(report=False, context_graph_id=DEV_GRAPH)
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
    cfg = BlackboxConfig(report=True, context_graph_id=DEV_GRAPH, daily_report_limit=1)
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
    monkeypatch.setattr(guard_reporting, "DkgClient", lambda *a, **k: client)
    monkeypatch.setattr(kernel_identity, "reporter_address", lambda c: REPORTER)
    monkeypatch.setattr(audit, "write_private_audit_ka", lambda *a, **k: None)
    monkeypatch.setattr(community_sharing, "_share_sighting", slow_share)

    t0 = time.monotonic()
    guard_reporting._report_and_audit(CFG_ON, "pre_tool_call", [_finding()], {})
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
        fields={"ecosystem": "npm", "package_name": "evil-pkg", "package_version": "1.0.0", "kind": "malware",
                "reason": "install-hook"},
    )
    client = FakeClient()
    community_sharing._share_sighting(client, CFG_ON, finding.to_dict(), REPORTER)
    (_cg, _name, q) = client.shares[0]
    serialized = "\n".join(str(v) for quad in q for v in dict(quad).values())
    assert "SUPER-SECRET-PROMPT" not in serialized
    assert "/home/amos" not in serialized
    assert "evil-pkg" in serialized  # the reviewable coordinates DO travel


# ---------------------------------------------------------------------------
# Report construction correctness (KI-024, KI-026)
# ---------------------------------------------------------------------------


def test_ioc_report_carries_ioc_type():
    q = report_builder.build_report_quads(
        identifier="ioc:domain:evil.example",
        category="ioc",
        severity="high",
        reporter_address=REPORTER,
        ioc_type="domain",
        ioc_context="fetched-by-tool",
    )
    serialized = ["|".join(str(v) for v in dict(quad).values()) for quad in q]
    assert any(constants.IOC_TYPE_PRED in row and "domain" in row for row in serialized)


def test_idn_and_punycode_domains_share_one_identifier():
    assert threat_ids.ioc_identifier("domain", "münchen.example") == threat_ids.ioc_identifier(
        "domain", "xn--mnchen-3ya.example"
    )
    assert threat_ids.ioc_identifier("url", "https://münchen.example/pfad") == threat_ids.ioc_identifier(
        "url", "https://xn--mnchen-3ya.example/pfad"
    )


def test_ascii_ioc_values_unchanged():
    assert threat_ids.ioc_identifier("domain", "Evil.Example.") == "ioc:domain:evil.example"


# ---------------------------------------------------------------------------
# The durable reports ledger (KI-015)
# ---------------------------------------------------------------------------


def test_ledger_records_success(bb_home):
    community_sharing._share_sighting(FakeClient(), CFG_ON, _finding().to_dict(), REPORTER)
    rows = audit.read_share_ledger()
    assert len(rows) == 1
    assert rows[0]["ok"] is True
    assert rows[0]["identifier"] == "dep:npm:evil-pkg@1.0.0"
    assert rows[0]["subject"].startswith("urn:guardian:report:")


def test_ledger_records_failure_with_sanitized_error(bb_home):
    community_sharing._share_sighting(FakeClient(fail=True), CFG_ON, _finding().to_dict(), REPORTER)
    rows = audit.read_share_ledger()
    assert len(rows) == 1
    assert rows[0]["ok"] is False
    assert "sk-secret-token" not in rows[0]["error"]  # Bearer token redacted
    assert "[REDACTED]" in rows[0]["error"]


def test_share_failure_is_fail_open(bb_home):
    community_sharing._share_sighting(FakeClient(fail=True), CFG_ON, _finding().to_dict(), REPORTER)


# ---------------------------------------------------------------------------
# Share outcomes (Refine R0, KI-180 / KI-104): never a fake failure, never a
# fake success
# ---------------------------------------------------------------------------

# The daemon's exact reply on DKG 10.0.20 when the report already exists sealed
# (captured on the R0P bench, 2026-10-01).
_SEALED_REPLY = ('POST /api/knowledge-assets -> 500: {"error":"Assertion \\"report-x\\" is not an active '
                 'Working Memory draft; reopen it before mutating it"}')


class _SendClient:
    def __init__(self, result=None, raises=None):
        self.result, self.raises, self.calls = result, raises, 0

    def share_knowledge_asset(self, graph, name, quads):
        self.calls += 1
        if self.raises is not None:
            raise self.raises
        return self.result if self.result is not None else {"state": "succeeded"}


def _send(client, name="report-x"):
    return community_sharing.send_report(client, DEV_GRAPH, name, [])


def test_new_report_is_accepted(bb_home):
    outcome, _ = _send(_SendClient())
    assert outcome is community_sharing.ShareOutcome.ACCEPTED


def test_10_0_20_already_sealed_reply_is_same_version_not_failure(bb_home):
    """KI-180: this used to be ledgered as a FAILED share."""
    outcome, detail = _send(_SendClient(raises=DkgError(_SEALED_REPLY)))
    assert outcome is community_sharing.ShareOutcome.REJECTED_SAME_VERSION
    assert "sealed" in detail


def test_idempotent_answer_is_same_version_not_success(bb_home):
    """KI-104: a same-version re-share used to count as a new contribution."""
    outcome, _ = _send(_SendClient(result={"name": "report-x", "idempotent": True}))
    assert outcome is community_sharing.ShareOutcome.REJECTED_SAME_VERSION


def test_a_report_already_accepted_is_not_resent(bb_home):
    audit.record_share_outcome(identifier="ioc:x", category="ioc", severity="high", subject="s",
                               asset_name="report-x", ok=True, outcome="accepted")
    client = _SendClient()
    outcome, _ = _send(client)
    assert outcome is community_sharing.ShareOutcome.REJECTED_SAME_VERSION
    assert client.calls == 0                      # no network call at all


@pytest.mark.parametrize("error", [DkgError("POST /api/knowledge-assets -> 503: busy"), RuntimeError("node exploded")])
def test_other_errors_fail(error, bb_home):
    outcome, detail = _send(_SendClient(raises=error))
    assert outcome is community_sharing.ShareOutcome.FAILED and detail


def test_the_ledger_records_the_outcome(bb_home):
    finding = {"identifier": "ioc:domain:x.example", "category": "ioc", "severity": "high", "fields": {}}
    community_sharing._ledger_share(finding, "s", "report-y", ok=False, error="d", outcome="already-shared")
    row = audit.read_share_ledger(limit=1)[0]
    assert row["outcome"] == "already-shared" and row["ok"] is False


def test_auto_share_of_an_existing_report_is_ledgered_as_already_shared(bb_home):
    """KI-180 end to end through the share worker: a 10.0.20 'already sealed'
    reply lands in the ledger as already-shared — not as a FAILED share."""

    class _NodeHoldsIt(_SendClient):
        def status(self):
            return {"networkId": TEST_NETWORK}

    finding = {"identifier": "ioc:domain:again.example", "category": "ioc", "severity": "high",
               "fields": {"ioc_type": "domain", "ioc_context": "fetched-by-tool"}}
    community_sharing._share_sighting(_NodeHoldsIt(raises=DkgError(_SEALED_REPLY)), CFG_ON, finding, REPORTER)
    row = audit.read_share_ledger(limit=1)[0]
    assert row["identifier"] == "ioc:domain:again.example"
    assert row["outcome"] == "already-shared" and row["ok"] is False
