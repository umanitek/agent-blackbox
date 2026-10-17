"""Release contract: curated public VM only; community SWM is coming soon."""

import time
import pytest
from argparse import Namespace
from pathlib import Path

from fastapi.testclient import TestClient

from plugins.blackbox import cli, detection, ruleset
from plugins.blackbox.community.report_cli import report_command
from plugins.blackbox.sync import command as sync_command
from plugins.blackbox.guard import hooks
from plugins.blackbox.guard import reporting as guard_reporting
from plugins.blackbox.ruleset import disk_cache as ruleset_disk_cache
from plugins.blackbox.ruleset import fetching as ruleset_fetching
from plugins.blackbox.ruleset import refresh_cycle as ruleset_refresh
from plugins.blackbox.kernel import config, constants
from plugins.blackbox.dashboard import server
from _vm_partitions import answer_lane_query, is_lane_query


DASHBOARD_HTML = (
    Path(__file__).resolve().parents[2]
    / "plugins"
    / "blackbox"
    / "dashboard"
    / "static"
    / "index.html"
)
OPENCLAW_DIR = Path(__file__).resolve().parents[2] / "integrations" / "openclaw"


def test_refresh_queries_only_verifiable_memory(monkeypatch, tmp_path):
    queries = []

    class Client:
        def query(self, sparql, _cg, **kwargs):
            queries.append((sparql, kwargs["view"]))
            return []

    monkeypatch.setattr(constants, "blackbox_home", lambda: tmp_path)
    monkeypatch.setattr(ruleset_refresh, "_memory", ruleset_refresh._new_memory())
    cfg = config.BlackboxConfig()
    ruleset.refresh(cfg, Client())

    assert queries
    metadata_query, metadata_view = queries[0]
    assert metadata_view is None
    assert "dkg:assertionGraph" in metadata_query
    assert "/_meta>" in metadata_query
    data_graph = f"did:dkg:context-graph:{cfg.context_graph_id}"
    # The community lives in the same graph's SHARED memory (one graph since 2026-10-16):
    # its tier reads only community statements there; every other read is verified memory.
    community = [query for query, view in queries[1:] if view == constants.VIEW_SHARED_WORKING_MEMORY]
    verified = [(query, view) for query, view in queries[1:] if view != constants.VIEW_SHARED_WORKING_MEMORY]
    assert community and all("ThreatReport" in query for query in community)
    # The small-tier lanes read the confirmed assets' graphs (GRAPH ?g under the VM
    # prefix, through the verified-memory view); the root rows read the data graph.
    assert {view for _query, view in verified} <= {None, "verifiable-memory"}
    vm_prefix = f'"{data_graph}/_verifiable_memory/"'
    assert all(f"GRAPH <{data_graph}>" in query or ("GRAPH ?g {" in query and vm_prefix in query)
               for query, _view in verified)


def test_cached_community_rules_are_discarded():
    cached = {
        "injection": [
            {"identifier": "public", "source": "public", "pattern_src": "safe"},
            {"identifier": "community", "source": "community", "pattern_src": "unsafe"},
        ],
        "graph_threats": [
            {"identifier": "public", "source": "public"},
            {"identifier": "community", "source": "community"},
        ],
    }

    restored = ruleset_disk_cache._deserialize(cached)

    assert [r["identifier"] for r in restored.injection] == ["public"]
    assert [r["identifier"] for r in restored.graph_threats] == ["public"]


@pytest.mark.usefixtures("no_graph")
def test_sharing_stays_dormant_without_a_graph_address(monkeypatch):
    """Contract update (community-graph build B2): the `report` key is LIVE,
    but community sharing remains dormant by construction without a graph
    address (KI-035) — since 2026-10-16 the community lives in the verified
    graph, so that is an install that names no graph at all."""
    monkeypatch.setenv("BLACKBOX_REPORT", "true")
    cfg = config.load_blackbox_config()
    assert cfg.report is True  # the switch is real now
    assert cfg.context_graph_id == ""  # an install that names no graph
    assert cfg.community_enabled is False  # → every community path dormant
    assert cfg.daily_report_limit > 0  # the cap exists the moment sharing can


def test_dashboard_settings_sharing_defaults_off_and_requires_explicit_true():
    """Contract update (community-graph build B7): the sharing toggle is real.
    The fallback default remains OFF, and only an explicit server `true` can
    turn the UI state on — a missing/stale/None value must never opt in."""
    html = DASHBOARD_HTML.read_text(encoding="utf-8")

    assert 'report: false, report_min_severity: "high"' in html  # default OFF
    assert "out.report = data.report === true;" in html  # explicit opt-in only
    assert 'report: true, report_min_severity: "high"' not in html
    assert "out.report = data.report !== false;" not in html  # permissive form banned


def test_openclaw_runtime_reads_vm_only_and_reporting_is_opt_in():
    """The bridge READS only the verified graph (its enforcement tier never comes
    from shared memory). Reporting is OFF by default like the Python plugin
    (opt-in, 2026-10-16), 0 is never "no cap", an opt-in record must stand before
    anything leaves, and what leaves goes into the community sub-graph of the
    verified graph's shared memory — never the graph's root (one graph since 2026-10-16)."""
    ruleset_src = (OPENCLAW_DIR / "src" / "ruleset.ts").read_text(encoding="utf-8")
    config_src = (OPENCLAW_DIR / "src" / "config.ts").read_text(encoding="utf-8")
    client_src = (OPENCLAW_DIR / "src" / "dkgClient.ts").read_text(encoding="utf-8")

    tiers = ruleset_src.split("const TIERS", 1)[1].split("];", 1)[0]
    assert '["verifiable-memory", "public"]' in tiers
    assert "shared-working-memory" not in tiers
    assert 'view: DkgView = "verifiable-memory"' in client_src
    assert "report: false," in config_src                      # opt-in, like the Python plugin
    assert "dailyReportLimit: 0" not in config_src             # 0 was "no cap" (Refine R1)
    assert "effectiveDailyReportLimit(" in config_src
    assert 'COMMUNITY_SUB_GRAPH = "reports"' in client_src
    assert client_src.count("subGraphName: COMMUNITY_SUB_GRAPH") == 2   # the write and the share
    assert 'row.source !== "community"' in ruleset_src


@pytest.mark.usefixtures("no_graph")
def test_report_command_submits_nothing_when_community_dormant(monkeypatch, capsys):
    """Contract update (community-graph build B6): the command is REAL now,
    but with no graph configured it must refuse loudly, submit nothing, and
    never even create a DKG client."""
    monkeypatch.setattr(sync_command, "DkgClient", lambda *a, **k: (_ for _ in ()).throw(
        AssertionError("report must not create a DKG client while dormant")
    ))
    monkeypatch.delenv("BLACKBOX_REPORT", raising=False)

    args = Namespace(status=False, type="ioc", ioc_type="domain", value="evil.example",
                     false_positive=None, severity="high")
    assert report_command.cmd_report(args) == 2
    out = capsys.readouterr().out
    assert "Nothing was submitted" in out
    assert "dormant" in out


def test_detection_audit_never_shares(monkeypatch):
    shared = []

    class Client:
        def share_knowledge_asset(self, *args):
            shared.append(args)

    monkeypatch.setattr(hooks.audit, "recently_reported", lambda _identifier: False)
    monkeypatch.setattr(hooks.audit, "mark_reported", lambda _identifier: None)
    monkeypatch.setattr(hooks.audit, "write_private_audit_ka", lambda *args: None)
    monkeypatch.setattr(guard_reporting, "DkgClient", lambda *args, **kwargs: Client())
    guard_reporting._report_and_audit(
        config.BlackboxConfig(report=True),
        "pre_tool_call",
        [detection.Finding(
            identifier="candidate", category="escalation", severity="critical",
            title="candidate", confirmed=False, source="community",
        )],
        {},
    )

    assert shared == []


def test_dashboard_sync_never_subscribes_or_requests_private_join(monkeypatch):
    events = []

    class Cfg:
        dkg_url = "http://127.0.0.1:9320"
        dkg_home = "/tmp/blackbox"
        context_graph_id = "legacy/private"

    class Client:
        def __init__(self, **_kwargs):
            pass

        def subscribe_context_graph(self, cg_id):
            events.append(("subscribe", cg_id))

        def request_join(self, *_args):
            raise AssertionError("private join must never be requested")

    class Rules:
        @staticmethod
        def refresh(_cfg, _client):
            return ruleset.Ruleset()

    monkeypatch.setattr(server.sync_state, "read", dict)
    result = server._sync_ruleset_once(lambda: Cfg(), Client, Rules)

    assert result == {"total": 0, "public": 0, "community": 0}
    assert events == []


def test_dashboard_does_not_query_rules_while_durable_catchup_runs(monkeypatch):
    class Cfg:
        dkg_url = "http://127.0.0.1:9320"
        dkg_home = "/tmp/blackbox"
        context_graph_id = "public/graph"

    class Client:
        def __init__(self, **_kwargs):
            pass

        def subscribe_context_graph(self, _cg_id):
            raise AssertionError("active catch-up must not be resubscribed")

        def catchup_status(self, _cg_id):
            return {"status": "running", "includeSharedMemory": False}

    cached = ruleset.Ruleset()

    class Rules:
        @staticmethod
        def peek(_cfg):
            return cached

        @staticmethod
        def refresh(_cfg, _client):
            raise AssertionError("VM must not be queried during durable catch-up")

    monkeypatch.setattr(server.sync_state, "read", dict)

    assert server._sync_ruleset_once(lambda: Cfg(), Client, Rules) == {
        "total": 0,
        "public": 0,
        "community": 0,
    }


def test_dashboard_keeps_old_rules_and_advances_verified_count_during_sync(monkeypatch):
    class Cfg:
        dkg_url = "http://127.0.0.1:9320"
        dkg_home = "/tmp/blackbox"
        context_graph_id = "public/replacement"

    class Client:
        def __init__(self, **_kwargs):
            raise AssertionError("active replacement must use the verified cache")

    cached = ruleset.Ruleset(
        dependency={
            "npm:last-good": {
                "identifier": "npm:last-good",
                "source": "public",
            }
        },
        graph_threats=[
            {
                "identifier": "npm:last-good",
                "source": "public",
            }
        ],
        synced_at=time.time() - 60,
    )

    class Rules:
        @staticmethod
        def peek(_cfg):
            return cached

    monkeypatch.setattr(
        server.sync_state,
        "read",
        lambda: {
            "status": "running",
            "context_graph_id": Cfg.context_graph_id,
            "public_entries": 10,
        },
    )

    assert server._sync_ruleset_once(lambda: Cfg(), Client, Rules) == {
        "total": 10,
        "public": 10,
        "community": 0,
    }


def test_dashboard_never_subscribes_when_status_is_unavailable(monkeypatch):
    calls = []

    class Cfg:
        dkg_url = "http://127.0.0.1:9320"
        dkg_home = "/tmp/blackbox"
        context_graph_id = "public/one-shot-subscribe"

    class Client:
        def __init__(self, **_kwargs):
            pass

        def catchup_status(self, _cg_id):
            return {}

        def subscribe_context_graph(self, cg_id):
            calls.append(cg_id)
            return {}

    class Rules:
        @staticmethod
        def refresh(_cfg, _client):
            return ruleset.Ruleset()

    monkeypatch.setattr(server.sync_state, "read", dict)

    server._sync_ruleset_once(lambda: Cfg(), Client, Rules)
    server._sync_ruleset_once(lambda: Cfg(), Client, Rules)

    assert calls == []


def test_dashboard_does_not_resubscribe_terminal_catchup_without_job_id(monkeypatch):
    class Cfg:
        dkg_url = "http://127.0.0.1:9320"
        dkg_home = "/tmp/blackbox"
        context_graph_id = "public/terminal-no-job-id"
        sync_interval = 60

    class Client:
        def __init__(self, **_kwargs):
            pass

        def catchup_status(self, _cg_id):
            return {"status": "done"}

        def subscribe_context_graph(self, _cg_id):
            raise AssertionError("terminal catch-up must not be resubscribed")

    cached = ruleset.Ruleset(
        dependency={
            "npm:ready": {
                "identifier": "npm:ready",
                "source": "public",
            }
        },
        graph_threats=[
            {
                "identifier": "npm:ready",
                "source": "public",
            }
        ],
        synced_at=time.time(),
    )

    class Rules:
        @staticmethod
        def peek(_cfg):
            return cached

        @staticmethod
        def refresh(_cfg, _client):
            raise AssertionError("fresh terminal cache must not be refreshed")

    monkeypatch.setattr(server.sync_state, "read", dict)

    assert server._sync_ruleset_once(lambda: Cfg(), Client, Rules)["public"] == 1


def test_dashboard_reuses_fresh_large_ruleset_without_querying_blazegraph(monkeypatch):
    class Cfg:
        dkg_url = "http://127.0.0.1:9320"
        dkg_home = "/tmp/blackbox"
        context_graph_id = "public/fresh-cache"
        sync_interval = 60

    class Client:
        def __init__(self, **_kwargs):
            pass

        def catchup_status(self, _cg_id):
            return {"status": "done", "jobId": "settled-job"}

        def subscribe_context_graph(self, _cg_id):
            raise AssertionError("settled catch-up must not be resubscribed")

    cached = ruleset.Ruleset(
        dependency={
            "npm:demo": {
                "identifier": "npm:demo",
                "source": "public",
            }
        },
        graph_threats=[
            {
                "identifier": "npm:demo",
                "source": "public",
            }
        ],
        synced_at=time.time(),
    )

    class Rules:
        @staticmethod
        def peek(_cfg):
            return cached

        @staticmethod
        def refresh(_cfg, _client):
            raise AssertionError("fresh cache must not trigger a full VM scan")

    monkeypatch.setattr(server.sync_state, "read", dict)

    assert server._sync_ruleset_once(lambda: Cfg(), Client, Rules) == {
        "total": 1,
        "public": 1,
        "community": 0,
    }


@pytest.mark.usefixtures("no_graph")
def test_dashboard_community_surfaces_live_but_dormant_without_graph(monkeypatch):
    """Contract update (community-graph build B7): the community surfaces are
    LIVE endpoints now. With no graph configured they serve honest empty
    states — never 'coming soon'."""
    monkeypatch.delenv("BLACKBOX_REPORT", raising=False)
    app = server.create_app()
    with TestClient(app, base_url="http://127.0.0.1") as client:
        graph = client.get("/api/graph?tier=community&limit=17&offset=3").json()
        reports = client.get("/api/reports").json()
        threat = client.get("/api/threat?tier=community&identifier=x").json()
        stats = client.get("/api/community-stats").json()

    assert graph["tier"] == "community"
    assert graph["threats"] == []
    assert "coming_soon" not in graph
    assert reports["reports"] == []
    assert reports["sharing_enabled"] is False
    assert "coming_soon" not in reports
    assert threat["found"] is False
    assert "coming_soon" not in threat
    assert stats["configured"] is False
    assert stats["community_threats"] == 0


def test_a_refused_partition_keeps_the_last_good_tier_and_never_reads_the_broad_view(monkeypatch):
    """KI-288: a partition the node refuses (a store deadline) is deferred to the
    next refresh. With nothing cached yet the tier is None, so the caller keeps
    its last-good rules — and nothing falls back to the daemon's broad
    verified-view lanes, which leaked partial lanes and never succeeded under
    load (bench v21, 2026-10-06)."""
    cg = "0xC/agent-blackbox-vm"
    partition = f"did:dkg:context-graph:{cg}/_verifiable_memory/0xc/1"
    queries = []

    class Client:
        def query(self, sparql, _cg, on_error=None, view="unset", **kwargs):
            queries.append(sparql)
            if "dkg:assertionGraph" in sparql:
                return [{"assertionGraph": partition, "status": "confirmed"}]
            return on_error  # every verified read refused

    assert ruleset_fetching.fetch_tier(Client(), cg, constants.VIEW_VERIFIABLE_MEMORY) is None
    assert all("GRAPH" in query for query in queries[1:])   # every verified read names its graphs


def test_small_tiers_are_read_by_graph_scoped_lanes_and_only_confirmed_assets_count(monkeypatch):
    """DKG-lookup B6: the compiled tiers come from typed lanes over ``GRAPH ?g`` under the
    VM prefix (never an unscoped verified-view query, bench v21); a tentative asset's
    rows are dropped; dependency / IOC rows are not compiled at all (looked up live)."""
    cg = "0xC/agent-blackbox-vm"
    data_graph = f"did:dkg:context-graph:{cg}"
    confirmed, tentative = f"{data_graph}/_verifiable_memory/0xc/1", f"{data_graph}/_verifiable_memory/0xc/2"
    rows_by_partition = {
        confirmed: [
            {"threat": "urn:defender:signal:inj", "rdfType": "urn:defender:InjectionSignal", "pattern": "ignore previous"},
            {"threat": "urn:guardian:threat:z", "rdfType": "urn:defender:IocSignal",
             "severity": "high", "category": "domain", "iocValue": "bad.example"},
        ],
        tentative: [{"threat": "urn:defender:signal:tent", "rdfType": "urn:defender:InjectionSignal", "pattern": "x"}],
    }
    asked = []

    class Client:
        def query(self, sparql, _cg, on_error=None, view="unset", **kwargs):
            asked.append((sparql, view))
            if "dkg:assertionGraph" in sparql:
                return [{"assertionGraph": confirmed, "status": "confirmed"},
                        {"assertionGraph": tentative, "status": "tentative"}]
            if is_lane_query(sparql):
                return answer_lane_query(sparql, rows_by_partition)
            return []

    rows = ruleset_fetching.fetch_tier(Client(), cg, constants.VIEW_VERIFIABLE_MEMORY)
    assert [r["threat"] for r in rows] == ["urn:defender:signal:inj"]
    lanes = [(q, v) for q, v in asked if is_lane_query(q)]
    assert lanes and all(v == constants.VIEW_VERIFIABLE_MEMORY and "GRAPH ?g {" in q for q, v in lanes)
    assert not any("GRAPH <" in q for q, v in lanes)   # no per-asset reads


def test_lane_pager_survives_daemon_row_cap(monkeypatch):
    """KI-052: a daemon may cap a response below the requested LIMIT (measured
    on 10.0.19: 5,000 requested -> 1,000 returned). The lane pager — which
    still reads the root data graph — keeps paging until an EMPTY page."""
    cg = "0xC/agent-blackbox-vm"
    all_subjects = [f"urn:guardian:threat:{i:05d}" for i in range(2500)]

    class Client:
        def query(self, sparql, _cg, on_error=None, view="unset", **kwargs):
            if "dkg:assertionGraph" in sparql:
                return []  # no partitions: the root data graph holds the threats
            if "IocSignal" in sparql and "defender:DependencySignal" not in sparql:
                after = ""
                if "FILTER(STR(?threat) >" in sparql:
                    after = sparql.split('FILTER(STR(?threat) > "')[1].split('"')[0]
                remaining = [s for s in all_subjects if s > after]
                return [
                    {"threat": s, "rdfType": "urn:defender:IocSignal", "severity": "high",
                     "category": "ip", "iocValue": f"10.0.{i // 250}.{i % 250}"}
                    for i, s in enumerate(remaining[:1000])  # daemon row cap
                ]
            return []

    rows = ruleset_fetching.fetch_tier(Client(), cg, constants.VIEW_VERIFIABLE_MEMORY)
    assert rows is not None
    got = {r["threat"] for r in rows if "threat" in r}
    assert len(got) == 2500, f"pager truncated at the daemon row cap: {len(got)}"


