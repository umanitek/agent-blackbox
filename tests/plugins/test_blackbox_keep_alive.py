"""Refine R5 — keep-alive: each author keeps its own live reports on the network,
and readers keep a counted threat locally after its network copies expire.

* Epoch naming is pure: one window per ``epoch_days``, ``<base>-e<epoch>``.
* The live-reports store remembers only ACCEPTED reports, is idempotent by
  name, retires reports past their lifetime, forgets retracted ones, is bounded.
* The publish step sends the SAME signed quads under this epoch's copy name,
  ledgers ``kept-alive`` (never a new contribution), treats "already shared"
  as done, stops the beat on the first refusal, and is off at epoch 0 / sharing off.
* Every share path feeds the store on ACCEPTED (hook share, retry drain,
  ``blackbox report``); a dispute never does; a retraction ends keep-alive.
* Reader persistence: a counted threat that vanished from the read stays
  ``networkLive: no`` for ≤ 90 days and within its lifetime; uncounted ones
  do not; an unavailable read keeps everything (expiry never fires on it).
"""

from __future__ import annotations

import json
import time

import pytest

from _community_rows import GRAPH, NETWORK, Reporter, signed_row
from test_blackbox_community_ruleset import FakeClient
from plugins.blackbox import audit
from plugins.blackbox.community import keep_alive, report_builder, share_retry, sharing
from plugins.blackbox.community.keep_alive import LiveReportStore, copy_name, current_epoch
from plugins.blackbox.community.report_cli import statement_verbs
from plugins.blackbox.community.report_signer import ReportSigner
from plugins.blackbox.dashboard.safe_payloads import graph_tier_item
from plugins.blackbox.kernel.config import BlackboxConfig
from plugins.blackbox.kernel.dkg_client import DkgError
from plugins.blackbox.ruleset import Ruleset
from plugins.blackbox.ruleset import community_tier

CFG = BlackboxConfig(report=True, context_graph_id=GRAPH)          # epoch = 10 days by default
THREAT = "ioc:domain:slow-burn.example"
DAY = 86_400.0
NOW = 1_800_000_000.0


@pytest.fixture(autouse=True)
def home(monkeypatch, tmp_path):
    monkeypatch.setenv("BLACKBOX_HOME", str(tmp_path / "bbhome"))


def _signer(reporter: Reporter) -> ReportSigner:
    return ReportSigner(private_key=reporter.key, environment=NETWORK, graph=GRAPH)


def _quads(reporter: Reporter, identifier: str = THREAT):
    return report_builder.build_report_quads(identifier=identifier, category="ioc", severity="high",
                                             reporter_address=reporter.address, ioc_type="domain", ioc_context="in-tool-output",
                                             signer=_signer(reporter))


def _remember(store: LiveReportStore, name: str, identifier: str = THREAT, epoch: int = 1):
    return store.remember(graph=GRAPH, name=name, identifier=identifier, subject=f"urn:guardian:report:x:{name}",
                          severity="high", quads=[{"s": "a", "p": "b", "o": "c"}], epoch=keep_alive.Epoch(epoch))


class _Node:
    """Accepts shares and records their names; can refuse, or answer "already sealed"."""

    def __init__(self, refuse=False, sealed=False):
        self.names = []
        self.refuse, self.sealed = refuse, sealed

    def status(self):
        return {"networkId": NETWORK}

    def share_knowledge_asset(self, cg_id, name, quads, **kw):
        if self.refuse:
            raise DkgError("CONTEXT_GRAPH_NOT_FOUND")
        if self.sealed:
            raise DkgError("asset is not an active working memory draft")
        self.names.append((cg_id, name, list(quads)))
        return {"state": "succeeded"}


# ------------------------------------------------------------------ epochs (pure)


def test_epochs_are_fixed_windows_and_zero_when_off():
    assert current_epoch(NOW, 10.0) == int(NOW // (10 * DAY))
    assert current_epoch(NOW + 10 * DAY, 10.0) == current_epoch(NOW, 10.0) + 1
    window_start = current_epoch(NOW, 10.0) * 10 * DAY
    assert current_epoch(window_start + 10 * DAY - 1, 10.0) == current_epoch(NOW, 10.0)   # one window, one copy
    assert current_epoch(NOW, 0) == 0 and current_epoch(NOW, -1) == 0
    assert copy_name("report-abc", keep_alive.Epoch(2083)) == "report-abc-e2083"


# ------------------------------------------------------------------ the store


def test_remember_is_idempotent_by_name_and_keeps_the_first_share_time(tmp_path):
    clock = [NOW]
    store = LiveReportStore(tmp_path / "live.json", clock=lambda: clock[0])
    first = _remember(store, "report-a", epoch=1)
    clock[0] += DAY
    again = store.remember(graph=GRAPH, name="report-a", identifier=THREAT, subject="s", severity="high",
                           quads=[{"changed": "quads are ignored"}], epoch=keep_alive.Epoch(2))
    assert again.first_shared == first.first_shared and again.quads == first.quads and again.last_epoch == 2
    assert [r.name for r in store.all()] == ["report-a"]


def test_due_is_by_epoch_and_retires_reports_past_their_lifetime(tmp_path):
    store = LiveReportStore(tmp_path / "live.json", clock=lambda: NOW)
    _remember(store, "report-ip", identifier="ioc:ip:203.0.113.7", epoch=1)      # 47-day lifetime
    _remember(store, "report-dom", identifier=THREAT, epoch=1)                   # 300 days
    _remember(store, "report-fresh", identifier=THREAT, epoch=2)
    assert [r.name for r in store.due(keep_alive.Epoch(2), NOW)] == ["report-ip", "report-dom"]
    assert [r.name for r in store.due(keep_alive.Epoch(2), NOW + 48 * DAY)] == ["report-dom"]
    assert [r.name for r in store.all()] == ["report-dom", "report-fresh"]      # the IP report retired for good
    store.mark_published("report-dom", keep_alive.Epoch(2))
    assert store.due(keep_alive.Epoch(2), NOW + 48 * DAY) == []


def test_forget_ends_every_report_of_the_identifier_and_the_store_is_bounded(tmp_path):
    store = LiveReportStore(tmp_path / "live.json", clock=lambda: NOW)
    _remember(store, "report-a", identifier=THREAT)
    _remember(store, "report-b", identifier="ioc:domain:other.example")
    assert store.forget_identifier(THREAT) == 1 and [r.name for r in store.all()] == ["report-b"]
    clock = [NOW]
    bounded = LiveReportStore(tmp_path / "many.json", clock=lambda: clock[0])
    for i in range(keep_alive.MAX_LIVE + 5):
        clock[0] += 1
        _remember(bounded, f"report-{i}")
    names = {r.name for r in bounded.all()}
    assert len(names) == keep_alive.MAX_LIVE and "report-0" not in names and f"report-{keep_alive.MAX_LIVE + 4}" in names


def test_a_garbage_store_file_is_an_empty_store(tmp_path):
    (tmp_path / "live.json").write_text("{nope", encoding="utf-8")
    assert LiveReportStore(tmp_path / "live.json").all() == []


# ------------------------------------------------------------------ the publish step


def test_due_reports_are_copied_under_the_epoch_name_with_the_same_quads(tmp_path):
    store = LiveReportStore(tmp_path / "live.json", clock=lambda: NOW)
    reporter = Reporter("0xauthor")
    quads = _quads(reporter)
    store.remember(graph=GRAPH, name="report-abc", identifier=THREAT, subject="urn:guardian:report:x:1",
                   severity="high", quads=quads, epoch=keep_alive.Epoch(current_epoch(NOW, 10.0)))
    node = _Node()
    later = NOW + 10 * DAY                                        # the next window
    epoch = current_epoch(later, 10.0)
    assert keep_alive.publish_due_copies(node, CFG, store, now=later) == 1
    assert node.names == [(GRAPH, copy_name("report-abc", epoch), quads)]
    row = audit.read_share_ledger(limit=1)[0]
    assert row["outcome"] == keep_alive.OUTCOME_KEPT_ALIVE and row["ok"] is True
    assert row["asset_name"] == copy_name("report-abc", epoch) and row["category"] == "ioc"
    assert keep_alive.publish_due_copies(node, CFG, store, now=later) == 0 and len(node.names) == 1   # once per window


def test_an_already_sealed_copy_counts_as_published_and_a_refusal_ends_the_beat(tmp_path):
    store = LiveReportStore(tmp_path / "live.json", clock=lambda: NOW)
    _remember(store, "report-a", epoch=1)
    _remember(store, "report-b", epoch=1)
    assert keep_alive.publish_due_copies(_Node(sealed=True), CFG, store, now=NOW) == 0
    assert store.due(current_epoch(NOW, 10.0), NOW) == []                      # both marked for this epoch
    _remember(store, "report-c", epoch=1)
    _remember(store, "report-d", epoch=1)
    node = _Node(refuse=True)
    assert keep_alive.publish_due_copies(node, CFG, store, now=NOW) == 0
    assert len(store.due(current_epoch(NOW, 10.0), NOW)) == 2                  # still due for the next refresh
    assert audit.read_share_ledger(limit=5) == []                              # no ledger noise for refusals or sealed copies


def test_the_beat_is_capped_and_off_at_epoch_zero_or_with_sharing_off(tmp_path):
    store = LiveReportStore(tmp_path / "live.json", clock=lambda: NOW)
    for i in range(keep_alive.MAX_COPIES_PER_BEAT + 3):
        _remember(store, f"report-{i}", epoch=1)
    node = _Node()
    assert keep_alive.publish_due_copies(node, CFG, store, now=NOW) == keep_alive.MAX_COPIES_PER_BEAT
    assert keep_alive.publish_due_copies(node, CFG, store, now=NOW) == 3
    off = BlackboxConfig(report=True, context_graph_id=GRAPH, community_keepalive_epoch_days=0)
    _remember(store, "report-off", epoch=1)
    assert keep_alive.publish_due_copies(_Node(), off, store, now=NOW) == 0
    assert keep_alive.publish_due_copies(_Node(), BlackboxConfig(report=False, context_graph_id=GRAPH), store, now=NOW) == 0
    keep_alive.remember_accepted_share(off, name="report-never", identifier=THREAT, subject="s", severity="high",
                                       quads=[], store=store)
    assert "report-never" not in {r.name for r in store.all()}


def test_only_this_nodes_own_accepted_shares_are_ever_copied(tmp_path):
    """The curator never re-shares others' reports: the store is fed only by this
    node's ACCEPTED shares, so an empty store publishes nothing whatever the graph holds."""
    node = _Node()
    assert keep_alive.publish_due_copies(node, CFG, LiveReportStore(tmp_path / "live.json"), now=NOW + 10 * DAY) == 0
    assert node.names == []


# ------------------------------------------------------------------ the share paths feed the store


def test_the_hook_share_path_remembers_an_accepted_report(monkeypatch):
    reporter = Reporter("0xhook")
    monkeypatch.setattr(sharing.report_signer, "resolve_report_signer", lambda client, graph: _signer(reporter))
    finding = {"identifier": THREAT, "category": "ioc", "severity": "high", "fields": {"ioc_type": "domain", "ioc_context": "in-tool-output"}}
    node = _Node()
    sharing._share_sighting(node, CFG, finding, reporter.address)
    live = LiveReportStore().all()
    assert [r.identifier for r in live] == [THREAT] and live[0].name == node.names[0][1]
    assert list(live[0].quads) == node.names[0][2] and live[0].last_epoch == current_epoch(time.time(), 10.0)
    sharing._share_sighting(_Node(refuse=True), CFG, {**finding, "identifier": "ioc:domain:refused.example"}, reporter.address)
    assert [r.identifier for r in LiveReportStore().all()] == [THREAT]        # a refused share is not remembered


def test_the_retry_drain_remembers_a_report_accepted_on_retry(tmp_path):
    queue = share_retry.ShareRetryQueue(tmp_path / "q.json", clock=lambda: NOW + 100)
    reporter = Reporter("0xretry")
    share_retry.queue_failed_share(graph=GRAPH, name="report-r", identifier=THREAT, category="ioc", severity="high",
                                   subject="urn:guardian:report:x:r", quads=_quads(reporter), error="refused", queue=queue,
                                   now=NOW)
    assert share_retry.retry_due_shares(_Node(), CFG, queue) == 1
    assert [r.name for r in LiveReportStore().all()] == ["report-r"]


def test_blackbox_report_remembers_and_a_dispute_never_does():
    reporter = Reporter("0xmanual")
    statement_verbs.send_and_record(_Node(), CFG, identifier=THREAT, category="ioc", severity="high",
                                    subject="s", name="report-m", quads=_quads(reporter), keep_alive=True)
    statement_verbs.send_and_record(_Node(), CFG, identifier=THREAT, category="false-positive", severity="info",
                                    subject="s:fp", name="fp-m", quads=[])
    assert [r.name for r in LiveReportStore().all()] == ["report-m"]


def test_a_retraction_ends_keep_alive_for_the_identifier(capsys):
    reporter = Reporter("0xretract")
    store = LiveReportStore()
    _remember(store, "report-gone", identifier=THREAT)
    _remember(store, "report-stays", identifier="ioc:domain:other.example")
    assert statement_verbs.submit_retraction(_Node(), CFG, THREAT, reporter.address, _signer(reporter)) == 0
    assert [r.name for r in store.all()] == ["report-stays"]


# ------------------------------------------------------------------ reader persistence


def _counted(identifier=THREAT, **extra):
    return {identifier: {"identifier": identifier, "severity": "high", "source": "community", "reporterCount": 2,
                         "firstSeen": NOW - 5 * DAY, "stage": "corroborated", "enforcement": "flag", "counted": "2",
                         **extra}}


def _authorised_empty():
    client = FakeClient(report_rows=[])
    client.graphs = [{"id": GRAPH, "subscribed": True, "synced": True}]
    return client


def _long_empty(rs):
    """*rs* as a prior whose reads have been empty long enough to be believed (KI-262:
    one empty read is not; see test_blackbox_trust_read.py for the witness rule itself)."""
    rs.community_empty_since = NOW - 2 * community_tier.EMPTY_READ_WITNESS_SECONDS
    return rs


def test_a_counted_threat_that_vanished_from_the_network_is_kept_locally(monkeypatch):
    monkeypatch.setattr(community_tier.time, "time", lambda: NOW)
    prior = _long_empty(Ruleset())
    prior.community = _counted()
    rs = Ruleset()
    community_tier.apply_community_tier(rs, _authorised_empty(), CFG, prior)
    kept = rs.community[THREAT]
    assert kept["networkLive"] == "no" and kept["keptSince"] == NOW and kept["stage"] == "corroborated"
    assert THREAT in rs.ioc                                                     # still matchable: enforcement is unchanged
    # a later generation keeps the original vanish time, and the 90-day window counts from it
    monkeypatch.setattr(community_tier.time, "time", lambda: NOW + 89 * DAY)
    again = Ruleset()
    community_tier.apply_community_tier(again, _authorised_empty(), CFG, rs)
    assert again.community[THREAT]["keptSince"] == NOW
    monkeypatch.setattr(community_tier.time, "time", lambda: NOW + 91 * DAY)
    gone = Ruleset()
    community_tier.apply_community_tier(gone, _authorised_empty(), CFG, again)
    assert THREAT not in gone.community


def test_uncounted_or_expired_threats_are_not_kept_and_a_live_read_is_marked_live(monkeypatch):
    monkeypatch.setattr(community_tier.time, "time", lambda: NOW)
    prior = _long_empty(Ruleset())
    prior.community = {**_counted("ioc:domain:uncounted.example", counted="0"),
                       **_counted("ioc:ip:203.0.113.9", firstSeen=NOW - 48 * DAY)}     # past the 47-day IP lifetime
    rs = Ruleset()
    community_tier.apply_community_tier(rs, _authorised_empty(), CFG, prior)
    assert rs.community == {}
    live = Ruleset()
    community_tier.apply_community_tier(live, FakeClient(report_rows=[signed_row(THREAT, Reporter("0xlive"))]), CFG, prior)
    assert live.community[THREAT]["networkLive"] == "yes" and "keptSince" not in live.community[THREAT]


def test_the_reapply_path_carries_kept_threats_too(monkeypatch):
    monkeypatch.setattr(community_tier.time, "time", lambda: NOW)
    rs = _long_empty(Ruleset())
    rs.community = _counted()
    community_tier.reapply_community_tier(rs, _authorised_empty(), CFG)        # prior IS rs
    assert rs.community[THREAT]["networkLive"] == "no"


def test_the_dashboard_payload_and_graph_entries_carry_network_live():
    rs = Ruleset()
    rs.community = _counted(networkLive="no", keptSince=NOW)
    entry = next(e for e in rs.graph_entries("community") if e["identifier"] == THREAT)
    assert entry["networkLive"] == "no" and entry["keptSince"] == NOW
    assert graph_tier_item(entry, community=True)["networkLive"] == "no"
    assert graph_tier_item({"identifier": THREAT, "severity": "high"}, community=True)["networkLive"] == "yes"
    assert "networkLive" not in graph_tier_item(entry, community=False)


def test_the_store_file_holds_no_unexpected_fields(tmp_path):
    store = LiveReportStore(tmp_path / "live.json", clock=lambda: NOW)
    _remember(store, "report-a")
    data = json.loads((tmp_path / "live.json").read_text(encoding="utf-8"))
    assert set(data["live"][0]) == {"name", "graph", "identifier", "subject", "severity", "quads", "first_shared", "last_epoch"}


def test_a_transient_empty_view_during_a_replay_never_wipes_the_tier(monkeypatch):
    """KI-210 (bench 2026-10-02 23:23Z): a catalog replay after a peer reconnect emptied the
    shared-memory view for ~3 minutes while the graph still held every report. An authorised-empty
    read in that window keeps last-good; a genuinely empty graph (the probe counts nothing) applies."""
    monkeypatch.setattr(community_tier.time, "time", lambda: NOW)
    prior = Ruleset()
    prior.community = _counted()
    client = _authorised_empty()
    monkeypatch.setattr(community_tier.community, "community_fingerprint", lambda c, cfg: "ThreatReport=7:urn:x")
    rs = Ruleset()
    community_tier.apply_community_tier(rs, client, CFG, prior)
    assert rs.community == prior.community and THREAT in rs.ioc                     # last-good, still matchable
    monkeypatch.setattr(community_tier.community, "community_fingerprint", lambda c, cfg: "")
    rs2 = Ruleset()
    community_tier.apply_community_tier(rs2, _authorised_empty(), CFG, _long_empty(prior))
    assert THREAT in rs2.community and rs2.community[THREAT]["networkLive"] == "no"   # truly empty: R5 keeps counted threats locally
    uncounted = _long_empty(Ruleset())
    uncounted.community = _counted(counted="0")
    rs3 = Ruleset()
    community_tier.apply_community_tier(rs3, _authorised_empty(), CFG, uncounted)
    assert rs3.community == {}
