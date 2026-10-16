"""The dashboard's verified-sync meter: % of the verified threat graph's REAL size.

Covers the three readings (node backlog from daemon.log, downloaded totals from
one aggregate _meta query, compiled progress), the pure combination into a
state + percentages, and the cached ``GET /api/verified-sync`` route. A number
nobody could read must come back unknown, never zero (LES-011).
"""

from __future__ import annotations

from typing import Any, Dict, List

import pytest

from plugins.blackbox import ruleset
from plugins.blackbox.dashboard import server, sync_meter
from plugins.blackbox.ruleset import graph_queries
from plugins.blackbox.sync import read_recovery_backlog
from plugins.blackbox.sync.progress import RecoveryBacklog

VM_GRAPH = "0x37b1Fdfd134e2b17583bCBdD3034F91504cD9C70/agent-blackbox-vm"
OTHER_GRAPH = "0x00000000000000000000000000000000000000aa/other-vm"


def _reconcile_line(stamp: str, graph: str, pending: int) -> str:
    """A reconcile-pass line in the exact shape DKG 10.0.21 writes (bb-ours, 2026-10-08)."""
    return (f"{stamp} system 7a27ac23 [DKGAgent] VM reconcile pass timing for \"{graph}\": source=periodic "
            f"gapSincePreviousPassMs=50697 scanMs=1603 recoverMs=65128 totalMs=66818 processed=10 "
            f"reconciled=2 pending={pending} continue=1\n")


# --- the node's backlog (daemon.log) ----------------------------------------

def test_the_backlog_is_the_newest_reconcile_pass_for_the_graph(tmp_path):
    (tmp_path / "daemon.log").write_text(
        _reconcile_line("2026-10-08 06:51:39", VM_GRAPH, 429)
        + "2026-10-08 06:52:00 unrelated line pending=1\n"
        + _reconcile_line("2026-10-08 06:53:37", VM_GRAPH, 427)
        + _reconcile_line("2026-10-08 06:54:00", OTHER_GRAPH, 9),
        encoding="utf-8")

    backlog = read_recovery_backlog(str(tmp_path), VM_GRAPH)

    assert backlog == RecoveryBacklog(pending=427, logged_at="2026-10-08 06:53:37")


def test_a_missing_log_is_an_unknown_backlog_not_zero(tmp_path):
    assert read_recovery_backlog(str(tmp_path), VM_GRAPH) is None


def test_a_log_without_a_pass_for_the_graph_is_an_unknown_backlog(tmp_path):
    (tmp_path / "daemon.log").write_text(_reconcile_line("2026-10-08 06:54:00", OTHER_GRAPH, 0), encoding="utf-8")

    assert read_recovery_backlog(str(tmp_path), VM_GRAPH) is None


# --- downloaded totals (one aggregate _meta query) --------------------------

def test_the_totals_query_is_one_owner_pinned_aggregate_over_confirmed_assets():
    query = graph_queries._verified_partition_totals_sparql(VM_GRAPH)

    assert "COUNT(DISTINCT ?ka)" in query and "SUM(?publicTriples)" in query
    assert '"/0x37b1fdfd134e2b17583bcbdd3034f91504cd9c70/"' in query      # KI-106 owner pin
    assert 'STR(?status) = "confirmed"' in query and "_verifiable_memory/" in query


def test_the_totals_query_shares_the_partition_listings_owner_pin():
    pin = graph_queries._owner_pin(VM_GRAPH)

    assert pin and pin in graph_queries._verified_partitions_sparql(VM_GRAPH)
    assert pin in graph_queries._verified_partition_totals_sparql(VM_GRAPH)


class _Client:
    """Answers every query with *rows* and records the call."""

    def __init__(self, rows: list[dict[str, Any]]) -> None:
        self.rows, self.calls = rows, []

    def query(self, sparql: str, cg_id: str, **kwargs: Any) -> list[dict[str, Any]]:
        self.calls.append((sparql, cg_id, kwargs))
        return self.rows


def test_downloaded_totals_are_read_from_the_aggregate_row():
    client = _Client([{"assets": "137", "triples": "1531200"}])

    totals = ruleset.verified_download_totals(client, VM_GRAPH, timeout=5.0)

    assert totals == ruleset.DownloadTotals(assets=137, triples=1531200)
    assert client.calls[0][2]["timeout"] == 5.0


@pytest.mark.parametrize("rows", [[], [{"assets": "lots", "triples": "1"}]])
def test_an_unreadable_aggregate_is_unknown_not_zero(rows):
    assert ruleset.verified_download_totals(_Client(rows), VM_GRAPH) is None


# --- combining the readings ---------------------------------------------------

def _meter(downloaded=ruleset.DownloadTotals(assets=137, triples=1_500_000), pending=427, compiled=124, rules=106_760):
    return sync_meter.build_sync_meter(downloaded=downloaded, pending=pending, compiled_assets=compiled,
                                       verified_rules=rules, checked_at="2026-10-08 06:53:37")


def test_the_meter_measures_both_stages_against_the_real_graph_size():
    meter = _meter()

    assert meter.state == "syncing"
    assert meter.graph_assets == 564
    assert meter.percent_downloaded == 24.3 and meter.percent_compiled == 22.0


def test_a_caught_up_node_with_every_asset_compiled_is_synced():
    meter = _meter(downloaded=ruleset.DownloadTotals(assets=564, triples=6_385_136), pending=0, compiled=564)

    assert meter.state == "synced"
    assert meter.percent_downloaded == 100.0 and meter.percent_compiled == 100.0


def test_new_assets_on_the_graph_move_a_synced_node_back_to_syncing():
    meter = _meter(downloaded=ruleset.DownloadTotals(assets=564, triples=6_385_136), pending=3, compiled=564)

    assert meter.state == "syncing"
    assert meter.graph_assets == 567 and meter.percent_compiled == 99.5


def test_downloaded_but_not_yet_compiled_is_still_syncing():
    meter = _meter(downloaded=ruleset.DownloadTotals(assets=564, triples=6_385_136), pending=0, compiled=560)

    assert meter.state == "syncing" and meter.percent_downloaded == 100.0


def test_rules_never_claim_more_assets_than_the_node_holds():
    meter = _meter(compiled=900)

    assert meter.compiled_assets == 137 and meter.percent_compiled == meter.percent_downloaded


def test_an_unknown_backlog_shows_counts_without_a_percentage():
    meter = _meter(pending=None)

    assert meter.state == "unknown"
    assert meter.graph_assets is None and meter.percent_downloaded is None and meter.percent_compiled is None
    assert meter.downloaded_assets == 137


def test_an_unreadable_node_is_unavailable_not_zero_percent():
    meter = _meter(downloaded=None)

    assert meter.state == "unavailable"
    assert meter.downloaded_assets is None and meter.percent_compiled is None


def test_an_unreachable_node_is_never_queried(monkeypatch, tmp_path):
    def must_not_query(*args, **kwargs):
        raise AssertionError("queried an unreachable node")

    monkeypatch.setattr(ruleset, "verified_download_totals", must_not_query)
    cfg = type("Cfg", (), {"context_graph_id": VM_GRAPH, "dkg_url": "http://127.0.0.1:1", "dkg_home": str(tmp_path)})()

    meter = sync_meter.read_sync_meter(cfg, node_reachable=False, verified_rules=0)

    assert meter.state == "unavailable"


# --- the route ------------------------------------------------------------------

def test_the_route_serves_the_meter_and_reuses_a_reading_within_the_cache_window(monkeypatch, tmp_path):
    fastapi = pytest.importorskip("fastapi")
    from fastapi.testclient import TestClient

    (tmp_path / "daemon.log").write_text(_reconcile_line("2026-10-08 06:53:37", VM_GRAPH, 427), encoding="utf-8")
    monkeypatch.setattr(ruleset, "verified_download_totals",
                        lambda client, graph, timeout=None: ruleset.DownloadTotals(assets=137, triples=1_500_000))
    monkeypatch.setattr(ruleset, "verified_progress", lambda graph: {"assets_compiled": 124})
    cfg = type("Cfg", (), {"context_graph_id": VM_GRAPH, "dkg_url": "http://127.0.0.1:1", "dkg_home": str(tmp_path)})()
    loads: list[int] = []

    def load_config():
        loads.append(1)
        return cfg

    app = fastapi.FastAPI()
    sync_meter.register_sync_meter_routes(app, load_config=load_config, node_reachable=lambda c: True,
                                          verified_rules=lambda c: 106_760)
    with TestClient(app) as client:
        first = client.get("/api/verified-sync").json()
        second = client.get("/api/verified-sync").json()

    assert first == second and len(loads) == 1
    assert first["state"] == "syncing" and first["graph_assets"] == 564
    assert first["verified_rules"] == 106_760 and first["checked_at"] == "2026-10-08 06:53:37"


# --- the graph size is read from one instant (KI-403) ---------------------------------

def _meter_app(monkeypatch, tmp_path, downloads: list[int]):
    """The real route with no cache, serving one live download count from
    *downloads* per poll, against whatever daemon.log *tmp_path* holds."""
    fastapi = pytest.importorskip("fastapi")
    counts = iter(downloads)
    monkeypatch.setattr(sync_meter, "CACHE_SECONDS", 0.0)
    monkeypatch.setattr(ruleset, "verified_download_totals",
                        lambda client, graph, timeout=None: ruleset.DownloadTotals(assets=next(counts), triples=1))
    monkeypatch.setattr(ruleset, "verified_progress", lambda graph: {"assets_compiled": 0})
    cfg = type("Cfg", (), {"context_graph_id": VM_GRAPH, "dkg_url": "http://127.0.0.1:1", "dkg_home": str(tmp_path)})()
    app = fastapi.FastAPI()
    sync_meter.register_sync_meter_routes(app, load_config=lambda: cfg, node_reachable=lambda c: True,
                                          verified_rules=lambda c: 0)
    return app


def test_the_graph_size_holds_steady_while_downloads_outrun_the_last_pass(monkeypatch, tmp_path):
    from fastapi.testclient import TestClient
    # The pass said 312 left when the node held 253; the node then fetched 8 more before the next pass.
    (tmp_path / "daemon.log").write_text(_reconcile_line("2026-10-14 20:21:00", VM_GRAPH, 312), encoding="utf-8")

    with TestClient(_meter_app(monkeypatch, tmp_path, [253, 261])) as client:
        first, later = (client.get("/api/verified-sync").json() for _ in range(2))

    assert first["graph_assets"] == 565 and later["graph_assets"] == 565   # was 573 before KI-403
    assert later["downloaded_assets"] == 261 and later["percent_downloaded"] == 46.2


def test_a_new_pass_re_anchors_the_graph_size(monkeypatch, tmp_path):
    from fastapi.testclient import TestClient
    log = tmp_path / "daemon.log"
    log.write_text(_reconcile_line("2026-10-14 20:21:00", VM_GRAPH, 312), encoding="utf-8")

    with TestClient(_meter_app(monkeypatch, tmp_path, [253, 261, 270])) as client:
        before = [client.get("/api/verified-sync").json()["graph_assets"] for _ in range(2)]
        with log.open("a", encoding="utf-8") as handle:   # the next pass: 295 left, the node now holds 270
            handle.write(_reconcile_line("2026-10-14 20:22:00", VM_GRAPH, 295))
        after = client.get("/api/verified-sync").json()

    assert before == [565, 565]
    assert after["graph_assets"] == 565 and after["checked_at"] == "2026-10-14 20:22:00"


def test_the_graph_size_never_reads_below_what_the_node_holds():
    # Assets published and fetched between two passes: the node already holds more than the pass knew of.
    meter = sync_meter.build_sync_meter(downloaded=ruleset.DownloadTotals(assets=568, triples=1), pending=0,
                                        compiled_assets=565, verified_rules=0, downloaded_at_pass=565)

    assert meter.graph_assets == 568 and meter.percent_downloaded == 100.0


def test_the_anchor_keeps_the_count_seen_when_a_pass_first_appears():
    anchor = sync_meter.GraphSizeAnchor()

    assert anchor.downloaded_at_pass("g@20:21", 253) == 253
    assert anchor.downloaded_at_pass("g@20:21", 261) == 253
    assert anchor.downloaded_at_pass("g@20:22", 261) == 261


def test_the_anchor_re_anchors_when_the_node_holds_fewer_assets_than_it_did():
    anchor = sync_meter.GraphSizeAnchor()
    anchor.downloaded_at_pass("g@20:21", 253)

    assert anchor.downloaded_at_pass("g@20:21", 240) == 240   # rolled back: the old count overstates


def test_an_unreadable_node_leaves_the_anchor_untouched(monkeypatch, tmp_path):
    (tmp_path / "daemon.log").write_text(_reconcile_line("2026-10-14 20:21:00", VM_GRAPH, 312), encoding="utf-8")
    monkeypatch.setattr(ruleset, "verified_download_totals", lambda client, graph, timeout=None: None)
    monkeypatch.setattr(ruleset, "verified_progress", lambda graph: {})
    cfg = type("Cfg", (), {"context_graph_id": VM_GRAPH, "dkg_url": "http://127.0.0.1:1", "dkg_home": str(tmp_path)})()
    anchor = sync_meter.GraphSizeAnchor()

    meter = sync_meter.read_sync_meter(cfg, node_reachable=True, verified_rules=0, anchor=anchor)

    assert meter.state == "unavailable" and meter.graph_assets is None
    assert anchor.downloaded_at_pass("probe", 1) == 1   # nothing was anchored by the failed read


# --- the sync label never says "synced" over a graph still arriving (PR #21 audit) ---

def _cfg(tmp_path):
    return type("Cfg", (), {"context_graph_id": VM_GRAPH, "dkg_home": str(tmp_path)})()


def test_rules_over_a_graph_still_arriving_are_syncing_not_ready():
    assert server._graph_sync_state(490_760, True, "", still_arriving=True) == "syncing"
    assert server._graph_sync_state(490_760, True, "") == "ready"


def test_an_unreachable_node_is_never_called_syncing_on_a_stale_backlog():
    assert server._graph_sync_state(490_760, False, "", still_arriving=True) == "ready"


def test_a_backlog_in_the_nodes_log_means_still_arriving(tmp_path, monkeypatch):
    (tmp_path / "daemon.log").write_text(_reconcile_line("2026-10-08 10:59:34", VM_GRAPH, 55), encoding="utf-8")
    monkeypatch.setattr(ruleset, "verified_progress", lambda graph: None)

    assert sync_meter.verified_graph_still_arriving(_cfg(tmp_path)) is True


def test_rules_behind_what_the_node_holds_mean_still_arriving(tmp_path, monkeypatch):
    (tmp_path / "daemon.log").write_text(_reconcile_line("2026-10-08 11:40:00", VM_GRAPH, 0), encoding="utf-8")
    monkeypatch.setattr(ruleset, "verified_progress", lambda graph: {"assets_compiled": 560, "assets_total": 564})

    assert sync_meter.verified_graph_still_arriving(_cfg(tmp_path)) is True


def test_a_caught_up_graph_is_not_still_arriving(tmp_path, monkeypatch):
    (tmp_path / "daemon.log").write_text(_reconcile_line("2026-10-08 11:40:00", VM_GRAPH, 0), encoding="utf-8")
    monkeypatch.setattr(ruleset, "verified_progress", lambda graph: {"assets_compiled": 564, "assets_total": 564})

    assert sync_meter.verified_graph_still_arriving(_cfg(tmp_path)) is False


def test_no_evidence_is_not_still_arriving(tmp_path, monkeypatch):
    monkeypatch.setattr(ruleset, "verified_progress", lambda graph: None)

    assert sync_meter.verified_graph_still_arriving(_cfg(tmp_path)) is False


@pytest.mark.parametrize("arriving, label", [(True, "VM syncing"), (False, "VM synced")])
def test_the_dashboard_status_says_syncing_until_the_graph_has_arrived(monkeypatch, tmp_path, arriving, label):
    """End to end through GET /api/graph-status on a reachable node holding rules."""
    import time
    from types import SimpleNamespace

    from fastapi.testclient import TestClient

    from plugins.blackbox import audit
    from plugins.blackbox.kernel import config, dkg_client

    cfg = SimpleNamespace(mode="audit", context_graph_id=VM_GRAPH, graph_peer_id="peer", report=False,
                          dkg_url="http://127.0.0.1:9320", dkg_home=str(tmp_path),
                          dkg_bin=str(tmp_path / "dkg"), sync_interval=3600)

    class Rules:
        synced_at = time.time()
        community = {}

        def counts(self):
            return {"ioc": 490_760}

        def source_count(self, source):
            return 490_760 if source == "public" else 0

    monkeypatch.setattr(config, "load_blackbox_config", lambda: cfg)
    monkeypatch.setattr(ruleset, "peek", lambda _cfg=None: Rules())
    monkeypatch.setattr(audit, "count_findings", lambda: 0)
    monkeypatch.setattr(dkg_client.DkgClient, "reachable", lambda self, timeout=None: True)
    monkeypatch.setattr(server, "node_sync_probe",
                        lambda _cfg, reachable: {"node_reachable": True, "catchup": {}, "subscribed": True})
    monkeypatch.setattr(sync_meter, "verified_graph_still_arriving", lambda _cfg: arriving)

    client = TestClient(server.create_app(), base_url="http://127.0.0.1")
    deadline = time.time() + 5
    public = {}
    while time.time() < deadline:   # the node probe is stale-while-revalidate: wait for the first real answer
        public = client.get("/api/graph-status").json()["sync_progress"]["public"]
        if public.get("label") == label:
            break
        time.sleep(0.1)

    assert public["label"] == label
