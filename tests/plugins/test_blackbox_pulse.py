"""Refine R16 — the community pulse re-applies the community tier between refreshes (KI-202)."""

from __future__ import annotations

import threading
import time

import pytest

from _community_rows import GRAPH, NETWORK, Reporter, signed_row
from plugins.blackbox import community, ruleset
from plugins.blackbox.community import pulse as pulse_module
from plugins.blackbox.kernel.config import BlackboxConfig
from plugins.blackbox.ruleset import community_tier, compiler, refresh_cycle
from plugins.blackbox.ruleset import pulse_beat

VM_GRAPH = GRAPH   # one graph (2026-10-16): the community lives in the verified graph's shared memory
THREAT = "ioc:domain:fresh.example"


@pytest.fixture(autouse=True)
def home(monkeypatch, tmp_path):
    monkeypatch.setenv("BLACKBOX_HOME", str(tmp_path / "bbhome"))
    community.PULSE.reset()
    monkeypatch.setattr(refresh_cycle, "_memory", refresh_cycle._new_memory())
    monkeypatch.setattr(community_tier.community, "ensure_community_subscription", lambda client, cfg: None)
    yield
    community.PULSE.reset()


class _Clock:
    def __init__(self, now=1_800_000_000.0):
        self.now = now

    def __call__(self):
        return self.now


class _Graph:
    """A community graph whose report rows can grow between probes."""

    def status(self):
        return {"networkId": NETWORK}

    def context_graphs(self):
        return [{"id": GRAPH, "subscribed": True, "synced": True}]

    def __init__(self, reports=(), disputes=(), statements=()):
        self.reports = list(reports)
        self.disputes = list(disputes)
        self.statements = list(statements)                         # curator statements in shared memory (R3-attest)
        self.probes = 0
        self.reads = 0                                             # report-page reads (the costly part)

    def query(self, sparql, cg_id, view=None, on_error=None, **kw):
        if "GROUP BY ?t" in sparql:                                 # the grouped fingerprint
            self.probes += 1
            rows = []
            for kind, items in (("ThreatReport", self.reports), ("FalsePositive", self.disputes),
                                ("CuratorStatement", self.statements)):
                if items:
                    rows.append({"t": f"http://umanitek.ai/ontology/guardian/{kind}", "n": str(len(items)),
                                 "last": max(r["r"] for r in items)})
            return rows
        if "g:FalsePositive" in sparql:
            served, self.disputes = list(self.disputes), self.disputes
            return served if not kw.get("_served") else []
        if "g:ThreatReport" in sparql and "?identifier" in sparql:
            self.reads += 1
            served, self.reports = list(self.reports), self.reports    # the pager stops on a short page
            return served if not kw.get("_served") else []
        return []


# ------------------------------------------------------------------ the probe


def test_the_fingerprint_is_count_and_newest_subject_and_fails_open():
    graph = _Graph([signed_row(THREAT, Reporter("0xa"))])
    fp = pulse_module.fingerprint(graph, BlackboxConfig(context_graph_id=GRAPH))
    assert fp.startswith("ThreatReport=1:urn:guardian:report:")
    assert pulse_module.fingerprint(graph, BlackboxConfig(context_graph_id="")) is None

    class _Down(_Graph):
        def query(self, *a, **kw):
            return kw.get("on_error")
    assert pulse_module.fingerprint(_Down(), BlackboxConfig(context_graph_id=GRAPH)) is None


def test_the_first_probe_is_a_baseline_and_only_a_different_graph_counts_as_changed():
    clock = _Clock()
    pulse = pulse_module.CommunityPulse(clock=clock)
    cfg = BlackboxConfig(context_graph_id=GRAPH)
    graph = _Graph([signed_row(THREAT, Reporter("0xa"))])
    assert pulse.due(20) and not pulse.due(20)               # one slot per interval
    assert pulse.changed(graph, cfg) is False                 # baseline
    assert pulse.changed(graph, cfg) is False                 # same graph
    graph.reports.append(signed_row("ioc:domain:second.example", Reporter("0xb")))
    assert pulse.changed(graph, cfg) is True                  # a new report arrived
    assert pulse.changed(graph, cfg) is False                 # and is now the baseline
    clock.now += 20
    assert pulse.due(20) and not pulse.due(0)                 # 0 = off


def test_a_new_dispute_changes_the_fingerprint_too():
    """Bench finding 2026-10-02: statements arrived only on the full refresh — the grouped probe counts them."""
    from _community_rows import signed_dispute_row
    pulse = pulse_module.CommunityPulse(clock=_Clock())
    cfg = BlackboxConfig(context_graph_id=GRAPH)
    graph = _Graph([signed_row(THREAT, Reporter("0xa"))])
    assert pulse.changed(graph, cfg) is False and pulse.report_count == 1
    graph.disputes.append(signed_dispute_row(THREAT, Reporter("0xb")))
    assert pulse.changed(graph, cfg) is True and pulse.report_count == 1   # a dispute, not a report
    assert pulse_module.fingerprint(graph, cfg).startswith("FalsePositive=1:")


def test_a_failed_probe_never_reports_a_change():
    pulse = pulse_module.CommunityPulse(clock=_Clock())
    cfg = BlackboxConfig(context_graph_id=GRAPH)
    graph = _Graph([signed_row(THREAT, Reporter("0xa"))])
    assert pulse.changed(graph, cfg) is False

    class _Flaky(_Graph):
        def query(self, *a, **kw):
            return kw.get("on_error")
    assert pulse.changed(_Flaky(), cfg) is False
    graph.reports.append(signed_row("ioc:domain:second.example", Reporter("0xb")))
    assert pulse.changed(graph, cfg) is True                  # the baseline survived the failed probe


# ------------------------------------------------------------------ in the ruleset


def test_a_changed_graph_re_applies_the_community_tier_and_writes_it_through(monkeypatch):
    """The whole beat: probe → changed → reapply onto the cached generation → disk + memory."""
    cfg = BlackboxConfig(report=True, context_graph_id=VM_GRAPH, community_poll_interval=20)
    graph = _Graph([signed_row(THREAT, Reporter("0xa"))])
    monkeypatch.setattr(pulse_beat, "DkgClient", lambda *a, **k: graph)
    rs = compiler.Ruleset(context_graph_id=VM_GRAPH)
    rs.synced_at = time.time()
    refresh_cycle._memory.store(rs)
    community.PULSE.changed(graph, cfg)                       # baseline, as a full refresh would leave it
    graph.reports.append(signed_row("ioc:domain:second.example", Reporter("0xb")))
    assert pulse_beat.pulse(cfg) is True
    for _ in range(100):                                      # the beat runs in a background thread
        if THREAT in refresh_cycle.peek(cfg).community:
            break
        time.sleep(0.05)
    applied = refresh_cycle.peek(cfg).community
    assert THREAT in applied and "ioc:domain:second.example" in applied
    assert pulse_beat.pulse(cfg) is False                  # the interval has not passed


def test_a_process_that_starts_with_an_empty_tier_applies_the_reports_already_there(monkeypatch):
    """Bench finding 2026-10-02: B's dashboard baselined on A's report and never applied it — the
    first full refresh was an hour away. The first probe now applies when the cached tier is empty."""
    cfg = BlackboxConfig(report=True, context_graph_id=VM_GRAPH, community_poll_interval=20)
    graph = _Graph([signed_row(THREAT, Reporter("0xa"))])          # the report is ALREADY there
    monkeypatch.setattr(pulse_beat, "DkgClient", lambda *a, **k: graph)
    rs = compiler.Ruleset(context_graph_id=VM_GRAPH)
    rs.synced_at = time.time()
    refresh_cycle._memory.store(rs)                                   # no community tier yet
    assert pulse_beat.pulse(cfg) is True                              # first beat = baseline probe
    for _ in range(100):
        if THREAT in refresh_cycle.peek(cfg).community:
            break
        time.sleep(0.05)
    assert THREAT in refresh_cycle.peek(cfg).community
    assert refresh_cycle.peek(cfg).community_fingerprint == pulse_module.fingerprint(graph, cfg)   # KI-208: travels with the tier
    # KI-208: a NEW process (no probe yet) whose cached tier was applied at a different
    # fingerprint applies the change on its first beat instead of baselining blind …
    community.PULSE.reset()
    graph.reports.append(signed_row("ioc:domain:other.example", Reporter("0xb")))
    community.PULSE._last_probe = 0.0
    assert pulse_beat.pulse(cfg) is True
    for _ in range(100):
        if "ioc:domain:other.example" in refresh_cycle.peek(cfg).community:
            break
        time.sleep(0.05)
    assert "ioc:domain:other.example" in refresh_cycle.peek(cfg).community
    # … and a new process whose cached tier matches the graph does not re-read it
    reads_before, probes_before = graph.reads, graph.probes
    community.PULSE.reset()
    community.PULSE._last_probe = 0.0
    assert pulse_beat.pulse(cfg) is True
    time.sleep(0.5)
    assert graph.probes == probes_before + 1 and graph.reads == reads_before   # the probe only, no report read


def test_a_new_process_compares_its_first_probe_against_the_applied_fingerprint():
    """KI-208 (pure): the cached tier's fingerprint is the baseline for a process with no probe yet."""
    cfg = BlackboxConfig(context_graph_id=GRAPH)
    graph = _Graph([signed_row(THREAT, Reporter("0xa"))])
    current = pulse_module.fingerprint(graph, cfg)
    stale = pulse_module.CommunityPulse(clock=_Clock())
    assert stale.changed(graph, cfg, applied="ThreatReport=0:") is True and stale.baselined_now is False
    fresh = pulse_module.CommunityPulse(clock=_Clock())
    assert fresh.changed(graph, cfg, applied=current) is False and fresh.baselined_now is False
    assert fresh.last_fingerprint == current
    blind = pulse_module.CommunityPulse(clock=_Clock())
    assert blind.changed(graph, cfg, applied="") is False and blind.baselined_now is True   # no cache: baseline as before


def test_a_wedged_beat_does_not_stall_the_pulse_forever(monkeypatch):
    """A node call that never returns must not disable the pulse for the life of the process."""
    cfg = BlackboxConfig(report=True, context_graph_id=VM_GRAPH, community_poll_interval=20)
    monkeypatch.setattr(pulse_beat, "_pulsing", True)
    monkeypatch.setattr(pulse_beat, "_pulsing_since", time.time())
    assert pulse_beat.pulse(cfg) is False                           # a live beat is respected
    community.PULSE._last_probe = 0.0
    monkeypatch.setattr(pulse_beat, "_pulsing_since", time.time() - pulse_beat.STUCK_BEAT_SECONDS - 1)
    started = threading.Event()
    monkeypatch.setattr(pulse_beat, "_background_pulse", lambda config: started.set())
    assert pulse_beat.pulse(cfg) is True                            # a wedged one is replaced
    assert started.wait(2)


def test_the_pulse_is_off_without_a_graph_or_with_interval_zero(monkeypatch):
    called = []
    monkeypatch.setattr(pulse_beat, "DkgClient", lambda *a, **k: called.append(1))
    assert pulse_beat.pulse(BlackboxConfig(context_graph_id="", community_poll_interval=20)) is False
    assert pulse_beat.pulse(BlackboxConfig(context_graph_id=GRAPH, community_poll_interval=0)) is False
    assert called == []


def test_the_pulse_retries_refused_shares_on_its_beat(monkeypatch, tmp_path):
    from plugins.blackbox.community import share_retry
    cfg = BlackboxConfig(report=True, context_graph_id=VM_GRAPH, community_poll_interval=20)
    drained = threading.Event()
    monkeypatch.setattr(pulse_beat, "DkgClient", lambda *a, **k: _Graph())
    monkeypatch.setattr(community, "retry_due_shares", lambda client, cfg, queue=None: drained.set() or 0)
    assert pulse_beat.pulse(cfg) is True
    assert drained.wait(5)


def test_get_runs_the_pulse_instead_of_a_refresh_when_the_cache_is_fresh(monkeypatch):
    cfg = BlackboxConfig(report=True, context_graph_id=VM_GRAPH, community_poll_interval=20, sync_interval=3600)
    rs = compiler.Ruleset(context_graph_id=VM_GRAPH)
    rs.synced_at = time.time()
    refresh_cycle._memory.store(rs)
    pulses = []
    monkeypatch.setattr(pulse_beat, "pulse", lambda config=None: pulses.append(config) or False)
    assert ruleset.get(cfg) is rs
    assert pulses == [cfg]


def test_a_curator_statement_in_shared_memory_changes_the_fingerprint_too():
    """R3-attest: an attestation must reach readers on the pulse, not an hour later."""
    pulse = pulse_module.CommunityPulse(clock=_Clock())
    cfg = BlackboxConfig(context_graph_id=GRAPH)
    graph = _Graph([signed_row(THREAT, Reporter("0xa"))])
    assert pulse.changed(graph, cfg) is False
    graph.statements.append({"r": "urn:guardian:curator:stage-attestation:abc:1"})
    assert pulse.changed(graph, cfg) is True and pulse.report_count == 1
    assert "CuratorStatement=1:" in pulse_module.fingerprint(graph, cfg)


def test_the_beat_runs_membership_so_a_fresh_node_subscribes_without_a_full_refresh(monkeypatch):
    """KI-216 / FIX-0039: on blackbox-main-f the heavy refresh never completed (no
    verified graph), so membership had no caller and the node sat unsubscribed
    for 7+ minutes. The beat always runs, so membership — now the verified graph's
    subscription with its shared memory — runs on the beat."""
    calls = []
    monkeypatch.setattr(pulse_beat, "DkgClient", lambda *a, **k: object())
    monkeypatch.setattr(pulse_beat.community, "ensure_community_subscription",
                        lambda client, cfg: calls.append(cfg.context_graph_id) or (True, "subscribed"))
    monkeypatch.setattr(refresh_cycle, "_retry_shares", lambda client, cfg: None)   # lazy import inside the beat
    monkeypatch.setattr(refresh_cycle, "peek", lambda cfg: compiler.Ruleset())
    monkeypatch.setattr(pulse_beat.community.PULSE, "changed", lambda client, cfg, applied=None: False)
    cfg = BlackboxConfig(context_graph_id=GRAPH)
    pulse_beat._background_pulse(cfg)
    assert calls == [GRAPH]
