"""Release contract: curated public VM only; community SWM is coming soon."""

import time
from argparse import Namespace
from pathlib import Path

from fastapi.testclient import TestClient

from plugins.blackbox import cli, config, constants, detection, hooks, ruleset
from plugins.blackbox.dashboard import server


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
    monkeypatch.setattr(ruleset, "_memory_cache", None)
    cfg = config.BlackboxConfig()
    ruleset.refresh(cfg, Client())

    assert queries
    metadata_query, metadata_view = queries[0]
    assert metadata_view is None
    assert "dkg:assertionGraph" in metadata_query
    assert "/_meta>" in metadata_query
    data_graph = f"did:dkg:context-graph:{cfg.context_graph_id}"
    assert {view for _query, view in queries[1:]} == {None}
    assert all(f"GRAPH <{data_graph}>" in query for query, _view in queries[1:])


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

    restored = ruleset._deserialize(cached)

    assert [r["identifier"] for r in restored.injection] == ["public"]
    assert [r["identifier"] for r in restored.graph_threats] == ["public"]


def test_sharing_stays_dormant_without_a_community_graph_address(monkeypatch):
    """Contract update (community-graph build B2): the `report` key is LIVE,
    but community sharing remains dormant by construction until a community
    graph address exists — the shipped default is empty until Umanitek mints
    the production graph (KI-035). This replaces the old VM-only contract
    where BLACKBOX_REPORT was inert."""
    monkeypatch.setenv("BLACKBOX_REPORT", "true")
    monkeypatch.delenv("BLACKBOX_COMMUNITY_GRAPH_ID", raising=False)
    cfg = config.load_blackbox_config()
    assert cfg.report is True  # the switch is real now
    assert cfg.community_graph_id == ""  # shipped default: no address
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


def test_openclaw_runtime_is_vm_only_and_reporting_cannot_be_reenabled():
    ruleset_src = (OPENCLAW_DIR / "src" / "ruleset.ts").read_text(encoding="utf-8")
    config_src = (OPENCLAW_DIR / "src" / "config.ts").read_text(encoding="utf-8")
    client_src = (OPENCLAW_DIR / "src" / "dkgClient.ts").read_text(encoding="utf-8")

    tiers = ruleset_src.split("const TIERS", 1)[1].split("];", 1)[0]
    assert '["verifiable-memory", "public"]' in tiers
    assert "shared-working-memory" not in tiers
    assert 'view: DkgView = "verifiable-memory"' in client_src
    assert "report: false" in config_src
    assert "dailyReportLimit: 0" in config_src
    assert "report: bool(env.BLACKBOX_REPORT)" not in config_src
    assert 'row.source !== "community"' in ruleset_src


def test_report_command_submits_nothing_when_community_dormant(monkeypatch, capsys):
    """Contract update (community-graph build B6): the command is REAL now,
    but with no community graph configured (the shipped default) it must
    refuse loudly, submit nothing, and never even create a DKG client."""
    monkeypatch.setattr(cli, "DkgClient", lambda *a, **k: (_ for _ in ()).throw(
        AssertionError("report must not create a DKG client while dormant")
    ))
    monkeypatch.delenv("BLACKBOX_COMMUNITY_GRAPH_ID", raising=False)
    monkeypatch.delenv("BLACKBOX_REPORT", raising=False)

    args = Namespace(status=False, type="ioc", ioc_type="domain", value="evil.example",
                     false_positive=None, severity="high")
    assert cli._cmd_report(args) == 2
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
    monkeypatch.setattr(hooks, "DkgClient", lambda *args, **kwargs: Client())
    hooks._report_and_audit(
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

    monkeypatch.setattr(server.sync_state, "read", lambda: {})
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

    monkeypatch.setattr(server.sync_state, "read", lambda: {})

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

    monkeypatch.setattr(server.sync_state, "read", lambda: {})

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

    monkeypatch.setattr(server.sync_state, "read", lambda: {})

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

    monkeypatch.setattr(server.sync_state, "read", lambda: {})

    assert server._sync_ruleset_once(lambda: Cfg(), Client, Rules) == {
        "total": 1,
        "public": 1,
        "community": 0,
    }


def test_dashboard_community_surfaces_live_but_dormant_without_graph(monkeypatch):
    """Contract update (community-graph build B7): the community surfaces are
    LIVE endpoints now. With no community graph configured (the shipped
    default) they serve honest empty states — never 'coming soon'."""
    monkeypatch.delenv("BLACKBOX_COMMUNITY_GRAPH_ID", raising=False)
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
