import subprocess
from pathlib import Path
from types import SimpleNamespace

import pytest
from fastapi.testclient import TestClient

from plugins.blackbox import attach
from plugins.blackbox.dashboard import server


def test_dashboard_public_graph_uses_vm_verified_ruleset_rows(monkeypatch):
    from plugins.blackbox import audit, config, dkg_client, ruleset

    cfg = SimpleNamespace(
        mode="audit",
        context_graph_id="umanitek/blackbox-threats-staging",
        dkg_url="http://127.0.0.1:9320",
        dkg_home="/tmp/blackbox-dkg",
        dkg_bin="/tmp/dkg",
        sync_interval=60,
    )

    class FakeRuleset:
        synced_at = 123.0

        def counts(self):
            return {"injection": 1, "dependency": 2}

        def source_count(self, source):
            return {"public": 2, "community": 1}.get(source, 0)

        def iter_rules(self):
            yield "dependency", {
                "identifier": "dep:npm:verified-one@1.0.0",
                "severity": "critical",
                "name": "Verified one",
                "source": "public",
            }
            yield "dependency", {
                "identifier": "dep:npm:verified-two@2.0.0",
                "severity": "high",
                "name": "Verified two",
                "source": "public",
            }
            yield "injection", {
                "identifier": "injection:community-only",
                "severity": "medium",
                "name": "Community only",
                "source": "community",
            }

    fake_ruleset = FakeRuleset()
    monkeypatch.setattr(config, "load_blackbox_config", lambda: cfg)
    monkeypatch.setattr(ruleset, "peek", lambda _cfg=None: fake_ruleset)
    monkeypatch.setattr(audit, "count_findings", lambda: 0)
    monkeypatch.setattr(dkg_client.DkgClient, "reachable", lambda self, timeout=None: False)
    monkeypatch.setattr(
        dkg_client.DkgClient,
        "query",
        lambda *args, **kwargs: (_ for _ in ()).throw(
            AssertionError("public dashboard rows must not query full threats directly from VM")
        ),
    )

    client = TestClient(server.create_app())

    status = client.get("/api/graph-status").json()
    assert status["curated"] == 2
    assert status["sync_progress"]["public"] == {
        "count": 2,
        "state": "ready",
        "label": "VM synced",
    }

    public = client.get("/api/graph?tier=public&limit=1&offset=1").json()
    assert public == {
        "tier": "public",
        "threats": [{
            "identifier": "dep:npm:verified-two@2.0.0",
            "category": "dependency",
            "severity": "high",
            "name": "Verified two",
        }],
        "total": 2,
        "category_totals": {"dependency": 2},
        "ecosystem_totals": {"npm": 2},
        "offset": 1,
        "limit": 1,
        "partial": False,
    }


def test_dashboard_keeps_partial_vm_count_loading_during_curator_transfer(monkeypatch):
    from plugins.blackbox import audit, config, dkg_client, ruleset, sync_state

    cfg = SimpleNamespace(
        mode="audit",
        context_graph_id="0x37b1/agent-blackbox",
        dkg_url="http://127.0.0.1:9320",
        dkg_home="/tmp/blackbox-dkg",
        dkg_bin="/tmp/dkg",
        sync_interval=60,
    )

    class PartialRuleset:
        synced_at = 123.0

        def counts(self):
            return {"dependency": 246}

        def source_count(self, source):
            return 246 if source == "public" else 0

    state = {
        "status": "running",
        "started_at": 100.0,
        "passes": 2,
        "inserted_triples": 160_000,
        "public_entries": 460,
        "context_graph_id": cfg.context_graph_id,
    }
    monkeypatch.setattr(config, "load_blackbox_config", lambda: cfg)
    monkeypatch.setattr(ruleset, "peek", lambda _cfg=None: PartialRuleset())
    monkeypatch.setattr(audit, "count_findings", lambda: 0)
    monkeypatch.setattr(sync_state, "read", lambda: state)
    monkeypatch.setattr(dkg_client.DkgClient, "reachable", lambda self, timeout=None: True)
    monkeypatch.setattr(
        dkg_client.DkgClient,
        "catchup_status",
        lambda self, cg_id: {"status": "done", "finishedAt": 99},
    )
    monkeypatch.setattr(dkg_client.DkgClient, "query", lambda *args, **kwargs: [])

    status = TestClient(server.create_app()).get("/api/graph-status").json()

    assert status["curated"] == 460
    assert status["sync_progress"]["public"] == {
        "count": 460,
        "state": "syncing",
        "label": "VM syncing",
    }
    assert status["sync_progress"]["catchup"] == {
        "status": "running",
        "started_at": 100.0,
        "finished_at": None,
    }
    assert status["sync_progress"]["authoritative"] == state


def test_running_sync_state_keeps_latest_committed_count(monkeypatch, tmp_path):
    from plugins.blackbox import sync_state

    state_path = tmp_path / "authoritative-sync.json"
    monkeypatch.setattr(sync_state, "_path", lambda: state_path)

    sync_state.write("running", phase="recovering", public_entries=460_000)
    sync_state.write("running", phase="waiting-for-capacity")

    state = sync_state.read()
    assert state["phase"] == "waiting-for-capacity"
    assert state["public_entries"] == 460_000


def test_dashboard_automatic_sync_runs_canonical_verified_cli(monkeypatch):
    cfg = SimpleNamespace(context_graph_id="0x37b1/agent-blackbox")

    class CachedRuleset:
        def counts(self):
            return {"dependency": 7}

        def source_count(self, source):
            return 7 if source == "public" else 0

    class RulesetModule:
        @staticmethod
        def peek(_cfg=None):
            return CachedRuleset()

    calls = []

    def fake_run(argv, **kwargs):
        calls.append((argv, kwargs))
        return subprocess.CompletedProcess(argv, 0, stdout="Ruleset synced", stderr="")

    monkeypatch.setattr(server.subprocess, "run", fake_run)

    result = server._network_sync_once(lambda: cfg, RulesetModule, timeout=123)

    assert result == {
        "ok": True,
        "busy": False,
        "returncode": 0,
        "total": 7,
        "public": 7,
        "community": 0,
    }
    assert calls[0][0] == [
        server.sys.executable,
        "-m",
        "hermes_cli.main",
        "blackbox",
        "sync",
        "--wait",
        "--timeout",
        "123",
        "--require-rules",
    ]
    assert calls[0][1]["timeout"] == 153


def test_dashboard_lists_more_than_five_thousand_vm_threats_with_exact_totals(monkeypatch):
    from plugins.blackbox import config, ruleset

    cfg = SimpleNamespace(
        mode="audit",
        context_graph_id="0x37b1/agent-blackbox",
        dkg_url="http://127.0.0.1:9320",
        dkg_home="/tmp/blackbox-dkg",
        dkg_bin="/tmp/dkg",
        sync_interval=60,
    )

    class LargeThreatGraph:
        synced_at = 123.0

        def iter_rules(self):
            for i in range(6001):
                yield "dependency", {
                    "identifier": f"dep:npm:threat-{i}@1.0.0",
                    "severity": "critical",
                    "name": f"Threat {i}",
                    "source": "public",
                }

    monkeypatch.setattr(config, "load_blackbox_config", lambda: cfg)
    monkeypatch.setattr(ruleset, "peek", lambda _cfg=None: LargeThreatGraph())

    result = TestClient(server.create_app()).get("/api/graph?tier=public&limit=6001").json()

    assert result["total"] == 6001
    assert result["category_totals"] == {"dependency": 6001}
    assert result["ecosystem_totals"] == {"npm": 6001}
    assert len(result["threats"]) == 6001
    assert len({row["identifier"] for row in result["threats"]}) == 6001


def test_dashboard_graph_search_filters_the_full_verified_cache(monkeypatch):
    from plugins.blackbox import config, ruleset

    cfg = SimpleNamespace(
        mode="audit",
        context_graph_id="0x37b1/agent-blackbox",
        dkg_url="http://127.0.0.1:9320",
        dkg_home="/tmp/blackbox-dkg",
        dkg_bin="/tmp/dkg",
        sync_interval=60,
    )

    class SearchableThreats:
        synced_at = 123.0

        def iter_rules(self):
            yield "dependency", {
                "identifier": "dep:npm:quiet-package@1.0.0",
                "severity": "low",
                "name": "Quiet package",
                "source": "public",
            }
            yield "dependency", {
                "identifier": "dep:pypi:needle-package@2.0.0",
                "severity": "critical",
                "name": "Needle package",
                "source": "public",
            }

    monkeypatch.setattr(config, "load_blackbox_config", lambda: cfg)
    monkeypatch.setattr(ruleset, "peek", lambda _cfg=None: SearchableThreats())

    client = TestClient(server.create_app())
    result = client.get(
        "/api/graph?tier=public&limit=100&q=needle"
    ).json()

    assert result["total"] == 1
    assert result["threats"][0]["identifier"] == "dep:pypi:needle-package@2.0.0"

    focused = client.get(
        "/api/graph?tier=public&limit=100&category=dependency&ecosystem=pypi"
    ).json()
    assert focused["total"] == 1
    assert focused["threats"][0]["identifier"] == "dep:pypi:needle-package@2.0.0"


def test_dashboard_graph_front_loads_every_populated_category():
    entries = [
        {"identifier": f"dep:npm:pkg-{i}", "category": "dependency"}
        for i in range(100)
    ] + [
        {"identifier": "injection:one", "category": "injection"},
        {"identifier": "skill:one", "category": "skill"},
        {"identifier": "ioc:one", "category": "ioc"},
    ]

    balanced = server._balanced_graph_entries(entries)

    assert {item["category"] for item in balanced[:4]} == {
        "dependency", "injection", "skill", "ioc"
    }
    assert {item["identifier"] for item in balanced} == {
        item["identifier"] for item in entries
    }


def test_dashboard_graph_expands_explicitly_and_keeps_scene_state():
    html = (
        Path(__file__).resolve().parents[1]
        / "plugins"
        / "blackbox"
        / "dashboard"
        / "static"
        / "index.html"
    ).read_text(encoding="utf-8")

    assert 'id="graph-search"' in html
    assert 'id="graph-load-more"' not in html
    assert 'id="graph-count"' not in html
    assert "if (graphCache[tier]) return Promise.resolve(false);" in html
    assert "return next(nowLoaded);" not in html
    assert ".onZoom(expandGraphForZoom)" not in html
    assert "GRAPH_ZOOM_CAPS" not in html
    assert "GRAPH_CATEGORY_MIN_LEAVES = 12" in html
    assert "loadGraphFocusPage(activeTier, graphFocus[activeTier])" in html
    assert '"&category=" + encodeURIComponent(focus.cat || "")' in html
    assert "priorPositions[node.id]" in html
    assert "graphCanvasSize.width === w && graphCanvasSize.height === h" in html
    assert "var GRAPH_PAGE_SIZE = 20000" in html
    assert "var GRAPH_MAX_VISIBLE_LEAVES = 12000" in html
    assert "compact: { cap: 180, focusCap: 900 }" in html
    assert "explore: { cap: 1200, focusCap: 12000 }" in html
    assert "view.category_totals || {}" in html
    assert 'magnitude.toLocaleString() + " THREAT"' in html


def test_dashboard_explore_mode_adapts_rendered_nodes_to_frame_rate():
    html = (
        Path(__file__).resolve().parents[1]
        / "plugins"
        / "blackbox"
        / "dashboard"
        / "static"
        / "index.html"
    ).read_text(encoding="utf-8")

    assert "var GRAPH_PERFORMANCE_MIN_LEAVES = 600" in html
    assert "var GRAPH_PERFORMANCE_LOW_FPS = 24" in html
    assert "var GRAPH_PERFORMANCE_SUSTAINED_LOW_WINDOWS = 3" in html
    assert "graphAdaptiveLeafCap = { public: null, community: null }" in html
    assert "leafLimit = Math.min(leafLimit, performanceLeafBudget);" in html
    assert "var leafBudget = performanceLeafBudget;" in html
    assert (
        "graphFrameMonitor.lowWindows >= GRAPH_PERFORMANCE_SUSTAINED_LOW_WINDOWS"
        in html
    )
    assert "graphFrameMonitor.healthyWindows >= 3" in html
    assert "Math.floor(current * 0.72)" in html
    assert "Math.floor(cap * 1.3)" in html
    assert '"|perf:" + (graphAdaptiveLeafCap[activeTier] || "auto")' in html
    assert 'id="graph-performance"' in html


def test_dashboard_findings_can_load_more_without_poll_resetting_the_page():
    html = (
        Path(__file__).resolve().parents[1]
        / "plugins"
        / "blackbox"
        / "dashboard"
        / "static"
        / "index.html"
    ).read_text(encoding="utf-8")

    assert 'id="findings-more"' in html
    assert 'id="findings-shown"' in html
    assert "var FINDINGS_PAGE = 10, FINDINGS_MAX = 500" in html
    assert 'getJSON("/api/findings?limit=" + findingsLoaded + "&offset=0")' in html
    assert "findingsLoaded + FINDINGS_PAGE" in html
    assert "requestGeneration !== findingsRequestGeneration" in html
    assert 'findingsMoreBtn.textContent = "Load more threats"' in html


def test_dashboard_prefers_available_vm_data_over_sync_error_panel():
    html = (
        Path(__file__).resolve().parents[1]
        / "plugins"
        / "blackbox"
        / "dashboard"
        / "static"
        / "index.html"
    ).read_text(encoding="utf-8")

    assert 'var hasQueryableVm = Number(graphTotalForTier("public") || 0) > 0' in html
    assert '((status === "failed" || status === "offline") && !hasQueryableVm)' in html


def test_dashboard_does_not_position_private_storage_as_normal_product_behavior():
    html = (
        Path(__file__).resolve().parents[1]
        / "plugins"
        / "blackbox"
        / "dashboard"
        / "static"
        / "index.html"
    ).read_text(encoding="utf-8")

    for unwanted in (
        "Nothing is shared yet",
        "findings and reports stay local",
        "Log findings locally. Nothing is shared.",
        "Changes stay on this machine.",
        "Local only and never shared.",
        "Your findings stay private on this machine.",
    ):
        assert unwanted not in html

    assert "Record findings without blocking agent actions." in html
    assert "Network threat distribution is in development." in html


def test_dashboard_more_node_is_a_display_only_marker():
    html = (
        Path(__file__).resolve().parents[1]
        / "plugins"
        / "blackbox"
        / "dashboard"
        / "static"
        / "index.html"
    ).read_text(encoding="utf-8")

    click_handler = html[html.index("function onNodeClick(node)"):]
    click_handler = click_handler[:click_handler.index("\n  function graphClickableNode")]
    clickable = html[html.index("function graphClickableNode(node)"):]
    clickable = clickable[:clickable.index("\n  function graphPriorityClickNode")]

    assert 'if (node.kind === "more") return;' in click_handler
    assert "openSessionModal(node.session)" not in click_handler
    assert 'node.kind === "more"' not in clickable
    assert "click to see the whole session" not in html


def test_dashboard_refetches_empty_graph_when_first_verified_threats_arrive():
    html = (
        Path(__file__).resolve().parents[1]
        / "plugins"
        / "blackbox"
        / "dashboard"
        / "static"
        / "index.html"
    ).read_text(encoding="utf-8")

    helper = html[html.index("function resetEmptyGraphOnFirstVerifiedThreats"):]
    helper = helper[:helper.index("\n  function graphHasMore")]
    render_status = html[html.index("function renderGraphStatus(data)"):]
    render_status = render_status[:render_status.index("\n  // ---------- Poll loop")]

    assert "if (!cached || graphLoaded(tier) > 0) return false;" in helper
    assert "if (Number(previousTotal) > 0 || !(currentTotal > 0)) return false;" in helper
    assert "graphCache[tier] = null;" in helper
    assert "invalidateGraphTier(tier);" in helper
    assert render_status.index('var previousPublicTotal = graphTotalForTier("public");') < (
        render_status.index("lastStatus = data;")
    )
    assert 'resetEmptyGraphOnFirstVerifiedThreats("public", previousPublicTotal);' in render_status


@pytest.mark.skip(reason="dashboard never joins private graphs")
def test_ruleset_sync_once_uses_official_join_then_subscribe():
    class Cfg:
        dkg_url = "http://127.0.0.1:9320"
        dkg_home = "/tmp/blackbox-dkg"
        context_graph_id = "umanitek/guardian-threats-staging"
        graph_peer_id = "graph-peer"

    events = []
    membership_checks = 0

    class FakeClient:
        def __init__(self, *, url, dkg_home):
            self.url = url
            self.dkg_home = dkg_home
            events.append(("client", url, dkg_home))

        def agent_identity(self):
            return {"agentAddress": "0xabc"}

        def context_graph_has_agent(self, cg_id, agent_address):
            nonlocal membership_checks
            membership_checks += 1
            events.append(("membership", cg_id, agent_address))
            return membership_checks > 1

        def subscribe_context_graph(self, cg_id):
            events.append(("subscribe", cg_id))
            return {"catchup": {"status": "running"}}

        def request_join(self, cg_id, graph_peer_id):
            events.append(("join", cg_id, graph_peer_id))
            return {"delivered": 1}

    class FakeRuleset:
        def counts(self):
            return {"injection": 1, "dependency": 4}

        def source_count(self, source):
            return 0

    class FakeRulesetModule:
        @staticmethod
        def refresh(cfg, client):
            events.append(("refresh", cfg.context_graph_id, client.url, client.dkg_home))
            return FakeRuleset()

    server._join_attempts.clear()
    server._connection_states.clear()
    first = server._sync_ruleset_once(lambda: Cfg(), FakeClient, FakeRulesetModule)
    assert first == {"total": 0, "public": 0, "community": 0}
    assert server._connection_states[Cfg.context_graph_id]["state"] == "joining"
    second = server._sync_ruleset_once(lambda: Cfg(), FakeClient, FakeRulesetModule)
    assert server._connection_states[Cfg.context_graph_id]["state"] == "syncing"

    assert second == {"total": 5, "public": 0, "community": 0}
    assert events == [
        ("client", "http://127.0.0.1:9320", "/tmp/blackbox-dkg"),
        ("membership", "umanitek/guardian-threats-staging", "0xabc"),
        ("join", "umanitek/guardian-threats-staging", "graph-peer"),
        ("client", "http://127.0.0.1:9320", "/tmp/blackbox-dkg"),
        ("membership", "umanitek/guardian-threats-staging", "0xabc"),
        ("subscribe", "umanitek/guardian-threats-staging"),
        ("refresh", "umanitek/guardian-threats-staging", "http://127.0.0.1:9320", "/tmp/blackbox-dkg"),
    ]


@pytest.mark.skip(reason="old SWM count contract is no longer applicable")
def test_ruleset_sync_once_does_not_compete_with_authoritative_sync(monkeypatch):
    class Cfg:
        dkg_url = "http://127.0.0.1:9320"
        dkg_home = "/tmp/blackbox-dkg"
        context_graph_id = "0x37b1/agent-blackbox"
        graph_peer_id = "graph-peer"

    class NoClient:
        def __init__(self, **_kwargs):
            raise AssertionError("dashboard must not start a second DKG sync")

    class NoRuleset:
        @staticmethod
        def refresh(*_args):
            raise AssertionError("dashboard must not query during authoritative sync")

    monkeypatch.setattr(
        server.sync_state,
        "read",
        lambda: {
            "status": "running",
            "public_entries": 1200,
            "community_entries": 300,
        },
    )

    assert server._sync_ruleset_once(lambda: Cfg(), NoClient, NoRuleset) == {
        "total": 1500,
        "public": 1200,
        "community": 300,
    }


def test_dashboard_marks_subscribed_only_after_public_graph_arrives():
    class Cfg:
        dkg_url = "http://127.0.0.1:9320"
        dkg_home = "/tmp/blackbox-dkg"
        context_graph_id = "0x37b1/agent-blackbox"
        graph_peer_id = "graph-peer"

    class FakeClient:
        def __init__(self, *, url, dkg_home):
            pass

        def agent_identity(self):
            return {"agentAddress": "0xabc"}

        def context_graph_has_agent(self, cg_id, agent_address):
            return True

        def subscribe_context_graph(self, cg_id):
            return {"catchup": {"status": "done"}}

        def catchup_status(self, cg_id):
            return {"status": "done"}

    class ReadyRuleset:
        def counts(self):
            return {"dependency": 3}

        def source_count(self, source):
            return 3 if source == "public" else 0

    class FakeRulesetModule:
        @staticmethod
        def refresh(cfg, client):
            return ReadyRuleset()

    server._connection_states.clear()
    result = server._sync_ruleset_once(lambda: Cfg(), FakeClient, FakeRulesetModule)

    assert result == {"total": 3, "public": 3, "community": 0}
    assert server._connection_states[Cfg.context_graph_id]["state"] == "subscribed"


@pytest.mark.skip(reason="covered by the public VM sync contract")
def test_dashboard_restarts_stale_empty_completed_catchup():
    class Cfg:
        dkg_url = "http://127.0.0.1:9320"
        dkg_home = "/tmp/blackbox-dkg"
        context_graph_id = "0x37b1/agent-blackbox"
        graph_peer_id = "graph-peer"

    events = []

    class FakeClient:
        def __init__(self, *, url, dkg_home):
            pass

        def agent_identity(self):
            return {"agentAddress": "0xabc"}

        def context_graph_has_agent(self, cg_id, agent_address):
            return True

        def subscribe_context_graph(self, cg_id):
            events.append(("subscribe", cg_id))
            return {"catchup": {"status": "done"}}

        def restart_context_graph_catchup(self, cg_id):
            events.append(("restart", cg_id))

    class EmptyRuleset:
        def counts(self):
            return {}

        def source_count(self, source):
            return 0

    class FakeRulesetModule:
        @staticmethod
        def refresh(cfg, client):
            return EmptyRuleset()

    server._catchup_restarts.clear()
    result = server._sync_ruleset_once(lambda: Cfg(), FakeClient, FakeRulesetModule)

    assert result == {"total": 0, "public": 0, "community": 0}
    assert events == [
        ("subscribe", "0x37b1/agent-blackbox"),
        ("restart", "0x37b1/agent-blackbox"),
    ]
    assert server._connection_states[Cfg.context_graph_id]["state"] == "syncing"


@pytest.mark.skip(reason="community SWM is not synced")
def test_dashboard_restarts_completed_catchup_when_only_community_synced():
    class Cfg:
        dkg_url = "http://127.0.0.1:9320"
        dkg_home = "/tmp/blackbox-dkg"
        context_graph_id = "0x37b1/agent-blackbox"
        graph_peer_id = "graph-peer"

    events = []

    class FakeClient:
        def __init__(self, *, url, dkg_home):
            pass

        def agent_identity(self):
            return {"agentAddress": "0xabc"}

        def context_graph_has_agent(self, cg_id, agent_address):
            return True

        def subscribe_context_graph(self, cg_id):
            events.append(("subscribe", cg_id))
            return {"catchup": {"status": "done"}}

        def catchup_status(self, cg_id):
            events.append(("status", cg_id))
            return {"status": "done"}

        def restart_context_graph_catchup(self, cg_id):
            events.append(("restart", cg_id))

    class CommunityOnlyRuleset:
        def counts(self):
            return {"dependency": 5}

        def source_count(self, source):
            return 5 if source == "community" else 0

    class FakeRulesetModule:
        @staticmethod
        def refresh(cfg, client):
            return CommunityOnlyRuleset()

    server._catchup_restarts.clear()
    result = server._sync_ruleset_once(lambda: Cfg(), FakeClient, FakeRulesetModule)

    assert result == {"total": 5, "public": 0, "community": 5}
    assert events == [
        ("subscribe", "0x37b1/agent-blackbox"),
        ("status", "0x37b1/agent-blackbox"),
        ("restart", "0x37b1/agent-blackbox"),
    ]
    assert server._connection_states[Cfg.context_graph_id]["state"] == "syncing"


def test_dashboard_clears_stale_pending_approval_once_catchup_is_running():
    class Cfg:
        dkg_url = "http://127.0.0.1:9320"
        dkg_home = "/tmp/blackbox-dkg"
        context_graph_id = "0x37b1/agent-blackbox"
        graph_peer_id = "graph-peer"

    class FakeClient:
        def __init__(self, *, url, dkg_home):
            pass

        def agent_identity(self):
            return {"agentAddress": "0xabc"}

        def context_graph_has_agent(self, cg_id, agent_address):
            return True

        def subscribe_context_graph(self, cg_id):
            return {"catchup": {"status": "running"}}

        def catchup_status(self, cg_id):
            return {"status": "running"}

    class EmptyRuleset:
        def counts(self):
            return {}

        def source_count(self, source):
            return 0

    class FakeRulesetModule:
        @staticmethod
        def refresh(cfg, client):
            return EmptyRuleset()

    server._connection_states.clear()
    server._connection_states[Cfg.context_graph_id] = {
        "state": "pending-approval",
        "updated_at": 1.0,
    }

    result = server._sync_ruleset_once(lambda: Cfg(), FakeClient, FakeRulesetModule)

    assert result == {"total": 0, "public": 0, "community": 0}
    assert server._connection_states[Cfg.context_graph_id]["state"] == "syncing"


@pytest.mark.skip(reason="dashboard never repairs sync through a private join")
def test_dashboard_failed_catchup_with_stale_public_rows_refreshes_join_before_restart():
    class Cfg:
        dkg_url = "http://127.0.0.1:9320"
        dkg_home = "/tmp/blackbox-dkg"
        context_graph_id = "0x37b1/agent-blackbox"
        graph_peer_id = "graph-peer"

    events = []

    class FakeClient:
        def __init__(self, *, url, dkg_home):
            pass

        def agent_identity(self):
            return {"agentAddress": "0xabc"}

        def context_graph_has_agent(self, cg_id, agent_address):
            return True  # stale allowlist entry; the new peer binding is missing

        def subscribe_context_graph(self, cg_id):
            events.append(("subscribe", cg_id))
            return {"catchup": {"status": "failed"}}

        def catchup_status(self, cg_id):
            events.append(("status", cg_id))
            return {"status": "failed"}

        def request_join(self, cg_id, graph_peer_id):
            events.append(("join", cg_id, graph_peer_id))
            return {"alreadyMember": True, "delivered": 1}

        def restart_context_graph_catchup(self, cg_id):
            events.append(("restart", cg_id))

    class StaleRuleset:
        def counts(self):
            return {"dependency": 2}

        def source_count(self, source):
            return 2 if source == "public" else 0

    class FakeRulesetModule:
        @staticmethod
        def refresh(cfg, client):
            events.append(("refresh", cfg.context_graph_id))
            return StaleRuleset()

    server._join_attempts.clear()
    server._connection_states.clear()
    result = server._sync_ruleset_once(lambda: Cfg(), FakeClient, FakeRulesetModule)

    assert result == {"total": 2, "public": 2, "community": 0}
    assert events == [
        ("subscribe", "0x37b1/agent-blackbox"),
        ("refresh", "0x37b1/agent-blackbox"),
        ("status", "0x37b1/agent-blackbox"),
        ("join", "0x37b1/agent-blackbox", "graph-peer"),
        ("restart", "0x37b1/agent-blackbox"),
    ]
    assert server._connection_states[Cfg.context_graph_id]["state"] == "syncing"


def test_dashboard_graph_has_fullscreen_control():
    html = (Path(server.__file__).parent / "static" / "index.html").read_text(
        encoding="utf-8"
    )

    assert 'id="graph-fullscreen"' in html
    assert 'aria-label="View graph fullscreen"' in html
    assert 'stage.requestFullscreen()' in html
    assert 'document.exitFullscreen()' in html
    assert 'document.addEventListener("fullscreenchange", syncGraphFullscreenState)' in html
    assert ".graph-stage:fullscreen" in html
    assert ".graph-fullscreen[hidden] { display: none; }" in html


def test_dashboard_serves_only_allowlisted_brand_fonts():
    client = TestClient(server.create_app())

    font = client.get("/fonts/archivo-latin.woff2")
    assert font.status_code == 200
    assert font.headers["content-type"] == "font/woff2"
    assert font.headers["cache-control"] == "public, max-age=31536000, immutable"
    assert font.content.startswith(b"wOF2")

    assert client.get("/fonts/Archivo-OFL.txt").status_code == 404
    assert client.get("/fonts/not-a-font.woff2").status_code == 404


def test_dashboard_graph_sync_state_tracks_real_dkg_catchup():
    assert server._graph_sync_state(5, True, "running") == "syncing"
    assert server._graph_sync_state(0, False, "running") == "unreachable"
    assert server._graph_sync_state(0, True, "queued") == "syncing"
    assert server._graph_sync_state(0, True, "running") == "syncing"
    assert server._graph_sync_state(0, True, "done") == "empty"


def test_dashboard_retries_empty_ruleset_promptly():
    assert server._RULESET_EMPTY_RETRY_SEC <= 30


def test_blackbox_dashboard_chat_starts_session(monkeypatch):
    calls = []

    def fake_run(argv, **kwargs):
        calls.append(argv)
        return subprocess.CompletedProcess(argv, 0, stdout="hello\n", stderr="\nsession_id: sid-1\n")

    monkeypatch.setattr(server.shutil, "which", lambda name: "/bin/hermes")
    monkeypatch.setattr(server.subprocess, "run", fake_run)
    monkeypatch.setattr(attach, "_repo_root", lambda: Path("/tmp/repo"))

    client = TestClient(server.create_app())
    res = client.post("/api/blackbox-chat", json={"message": "hi"})

    assert res.status_code == 200
    assert res.json() == {"ok": True, "answer": "hello", "session_id": "sid-1"}
    assert calls == [["/bin/hermes", "blackbox", "chat", "--query", "hi", "--quiet", "--pass-session-id"]]


def test_blackbox_dashboard_chat_resumes_session(monkeypatch):
    calls = []

    def fake_run(argv, **kwargs):
        calls.append(argv)
        return subprocess.CompletedProcess(argv, 0, stdout="follow-up\n", stderr="\nsession_id: sid-1\n")

    monkeypatch.setattr(server.shutil, "which", lambda name: "/bin/hermes")
    monkeypatch.setattr(server.subprocess, "run", fake_run)
    monkeypatch.setattr(attach, "_repo_root", lambda: Path("/tmp/repo"))

    client = TestClient(server.create_app())
    res = client.post("/api/blackbox-chat", json={"message": "which of these?", "session_id": "sid-1"})

    assert res.status_code == 200
    assert res.json() == {"ok": True, "answer": "follow-up", "session_id": "sid-1"}
    assert calls == [
        [
            "/bin/hermes",
            "blackbox",
            "chat",
            "--query",
            "which of these?",
            "--quiet",
            "--pass-session-id",
            "--resume",
            "sid-1",
        ]
    ]


def test_attach_targets_include_unavailable_supported_agents(monkeypatch):
    def fake_attach_all(*, hermes=True, openclaw=True, dry_run=False):
        if hermes and not openclaw:
            return {
                "hermes": [
                    {
                        "kind": "hermes",
                        "target": "/tmp/home/.hermes",
                        "already": True,
                    }
                ]
            }
        if openclaw and not hermes:
            return {"openclaw": []}
        return {}

    monkeypatch.setattr(attach, "attach_all", fake_attach_all)

    client = TestClient(server.create_app())
    res = client.get("/api/attach-targets")

    assert res.status_code == 200
    targets = res.json()["targets"]
    hermes = next(t for t in targets if t["kind"] == "hermes")
    openclaw = next(t for t in targets if t["kind"] == "openclaw")
    assert hermes["available"] is True
    assert hermes["protected"] is True
    assert openclaw["available"] is False
    assert "OpenClaw was not detected" in openclaw["disabled_reason"]


def test_attach_targets_do_not_duplicate_errored_supported_agents(monkeypatch):
    def fake_attach_all(*, hermes=True, openclaw=True, dry_run=False):
        if hermes and not openclaw:
            return {"hermes": []}
        if openclaw and not hermes:
            return {
                "openclaw": [
                    {
                        "kind": "openclaw",
                        "target": "/tmp/.openclaw",
                        "error": "cannot read openclaw.json",
                    }
                ]
            }
        return {}

    monkeypatch.setattr(attach, "attach_all", fake_attach_all)

    client = TestClient(server.create_app())
    res = client.get("/api/attach-targets")

    assert res.status_code == 200
    openclaw_rows = [t for t in res.json()["targets"] if t["kind"] == "openclaw"]
    assert len(openclaw_rows) == 1
    assert openclaw_rows[0]["available"] is False
    assert openclaw_rows[0]["disabled_reason"] == "cannot read openclaw.json"


def test_agent_cards_distinguish_attached_from_active(monkeypatch):
    from plugins.blackbox import audit, config, constants, dkg_client

    cfg = SimpleNamespace(
        dkg_url="http://127.0.0.1:9320",
        dkg_home="/tmp/blackbox-dkg",
        context_graph_id="owner/agent-blackbox",
        sync_interval=60,
    )
    monkeypatch.setattr(config, "load_blackbox_config", lambda: cfg)
    monkeypatch.setattr(constants, "hermes_home", lambda: Path("/tmp/.hermes"))
    monkeypatch.setattr(dkg_client.DkgClient, "reachable", lambda self, timeout=None: False)
    monkeypatch.setattr(audit, "local_active_frameworks", lambda: ["hermes"])
    monkeypatch.setattr(
        audit,
        "read_audit",
        lambda limit=1_000_000: [{"framework": "hermes", "workspace": "/tmp/.hermes"}],
    )
    monkeypatch.setattr(audit, "read_findings", lambda limit=100000: [])
    monkeypatch.setattr(
        attach,
        "attach_all",
        lambda **kwargs: {
            "hermes": [{"kind": "hermes", "target": "/tmp/.hermes", "protected": True}],
            "openclaw": [{"kind": "openclaw", "target": "/tmp/.openclaw", "protected": True}],
        },
    )

    agents = TestClient(server.create_app()).get("/api/agents").json()["agents"]
    by_framework = {row["framework"]: row for row in agents}

    assert by_framework["hermes"]["is_active"] is True
    assert by_framework["hermes"]["blackbox_host"] is True
    assert by_framework["openclaw"]["is_active"] is False
    assert by_framework["openclaw"]["blackbox_host"] is False
