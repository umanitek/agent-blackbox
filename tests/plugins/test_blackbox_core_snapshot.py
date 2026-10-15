"""Snapshot jobs keep coverage, usable rules, profile trust and failures distinct."""
import argparse
import json
import threading
from dataclasses import replace
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

import pytest
from _blackbox_loader import load_blackbox

config = load_blackbox("kernel.config")
settings = load_blackbox("kernel.snapshot_config")
core = load_blackbox("sync.core_snapshot")
native = load_blackbox("sync.native")
profile = load_blackbox("sync.node_profile")
direct = load_blackbox("ruleset.direct.client")


def cfg(tmp_path, mode="core-cache"):
    return config.BlackboxConfig(detection_backend="dkg", dkg_home=str(tmp_path),
        snapshot_sync=settings.SnapshotSyncConfig("1", ("configured-core",), mode))


@pytest.fixture
def local_server():
    calls = []
    state = {"terminal": "complete", "current": True}
    class Handler(BaseHTTPRequestHandler):
        def log_message(self, *_):
            pass
        def answer(self):
            body = json.loads(self.rfile.read(int(self.headers.get("Content-Length", "0"))) or b"{}")
            calls.append((self.command, self.path, body))
            if self.path == "/api/context-graph/subscribe":
                reply = {"subscribed": True}
            elif self.path == "/api/query/bounded":
                reply = {"acceptedMode": body.get("chainEvidenceMode"), "chainEvidenceMode": body.get("chainEvidenceMode")}
            elif self.command == "POST":
                state["request"] = body
                reply = {"id": "owned", "state": "running", "request": body}
            elif "request" not in state:
                reply = {"state": "idle"}
            else:
                reply = {"id": "owned", "state": state["terminal"], "request": state["request"],
                         "result": {"mode": state["request"]["mode"], "current": state["current"],
                                    "completeAsOfSnapshot": True, "assets": 12, "committed": 12}}
            data = json.dumps(reply).encode()
            self.send_response(200)
            self.send_header("Content-Length", str(len(data)))
            self.end_headers()
            self.wfile.write(data)
        do_GET = answer
        do_POST = answer
    server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        yield f"http://127.0.0.1:{server.server_port}", calls, state
    finally:
        server.shutdown()
        server.server_close()
        thread.join()


def test_config_requires_operator_trust_and_preserves_unconfigured_profiles():
    assert settings.snapshot_config({}) is None
    parsed = settings.snapshot_config({"detection_backend": "dkg", "snapshot_sync": {
        "on_chain_id": "1", "trusted_core_peers": ["core"]}})
    assert parsed.mode == "core-cache"
    for patch in ({"mode": "auto"}, {"trusted_core_peers": []}, {"on_chain_id": "01"}):
        with pytest.raises(ValueError):
            settings.snapshot_config({"detection_backend": "dkg", "snapshot_sync": {
                "on_chain_id": "1", "trusted_core_peers": ["core"], **patch}})
    with pytest.raises(ValueError, match="detection_backend"):
        settings.snapshot_config({"snapshot_sync": {"on_chain_id": "1", "trusted_core_peers": ["core"]}})


def test_route_and_managed_profile_do_not_start_competing_recovery(tmp_path):
    configured = cfg(tmp_path)
    assert native.route(configured, lambda _: 9) is core.sync
    switches = profile.node_sync_settings(configured)
    assert switches["DKG_VM_RECONCILER_ENABLED"] == "0"
    assert switches["DKG_SYNC_ON_CONNECT_ENABLED"] == "0"
    assert switches["DKG_SYNC_RECONCILER_ENABLED"] == "0"


@pytest.mark.parametrize("terminal,current,expected", [("complete", True, 0), ("complete", False, 2), ("failed", True, 2)])
def test_real_http_job_waits_for_coverage_and_never_upgrades_failed_job(tmp_path, local_server, monkeypatch, terminal, current, expected):
    url, calls, server_state = local_server
    server_state.update(terminal=terminal, current=current)
    configured = replace(cfg(tmp_path), dkg_url=url)
    monkeypatch.setattr(core, "POLL_SECONDS", 0.01)
    monkeypatch.setattr(core.ruleset, "ready_sample", lambda *_, **__: 3)
    result = core.run(core.SnapshotSyncClient(configured), configured,
                      argparse.Namespace(wait=True, require_rules=True, timeout=5))
    assert result == expected
    assert sum(method == "POST" and path == core.PATH for method, path, _ in calls) == 1
    assert not any(path == "/api/context-graph/subscribe" for _, path, _ in calls)
    recorded = core.state.read_for_graph(configured.context_graph_id)
    assert recorded["detection_ready"] is True
    assert recorded["graph_complete"] is (terminal == "complete" and current)
    if terminal == "failed":
        assert recorded["status"] == "failed"


def test_profile_a_b_a_keeps_explicit_query_trust_and_job_state_separate(tmp_path, local_server, monkeypatch):
    url, _, _ = local_server
    import hermes_yaml as yaml
    a, b = tmp_path / "a", tmp_path / "b"
    for home, mode, graph in [(a, "core-cache", "a"), (b, "rpc-only", "b")]:
        home.mkdir()
        (home / "config.yaml").write_text(yaml.safe_dump({"plugins": {"entries": {"blackbox": {
            "detection_backend": "dkg", "context_graph_id": graph, "dkg_url": url,
            "dkg_home": str(home / "dkg"), "snapshot_sync": {"on_chain_id": "1",
            "trusted_core_peers": ["core"], "mode": mode}}}}}))
    for home, mode, graph in [(a, "core-cache", "a"), (b, "rpc-only", "b"), (a, "core-cache", "a")]:
        monkeypatch.setenv("HERMES_HOME", str(home))
        configured = config.load_blackbox_config()
        assert configured.snapshot_sync.mode == mode
        client = direct.LocalGraphClient(configured)
        assert client.request("POST", "/api/query/bounded", {"contextGraphId": graph})["acceptedMode"] == mode
        core.state.write("partial", context_graph_id=graph, chain_evidence_mode=mode)
        assert core.state.read_for_graph(graph)["chain_evidence_mode"] == mode
        assert not core.state.read_for_graph("b" if graph == "a" else "a")
    assert (a / "blackbox" / "authoritative-sync.json").exists()
    assert (b / "blackbox" / "authoritative-sync.json").exists()


def test_matching_running_job_is_observed_without_second_post(tmp_path, local_server, monkeypatch):
    url, calls, server_state = local_server
    configured = replace(cfg(tmp_path), dkg_url=url)
    server_state.update(terminal="running", request={"contextGraphId": configured.context_graph_id,
        "onChainId": "1", "trustedCorePeerIds": ["configured-core"], "mode": "core-cache"})
    monkeypatch.setattr(core.ruleset, "ready_sample", lambda *_, **__: 1)
    args = argparse.Namespace(wait=False, require_rules=True, timeout=1)
    assert core.run(core.SnapshotSyncClient(configured), configured, args) == 0
    assert not any(method == "POST" for method, _, _ in calls)
    server_state["request"]["mode"] = "rpc-only"
    assert core.run(core.SnapshotSyncClient(configured), configured, args) == 2
    assert not any(method == "POST" for method, _, _ in calls)


def test_missing_trust_acknowledgment_is_unavailable(tmp_path, monkeypatch):
    configured = cfg(tmp_path)
    local_http = load_blackbox("kernel.local_http")
    monkeypatch.setattr(local_http, "request", lambda *_, **__: (200, b'{"version":1}'))
    with pytest.raises(direct.GraphReadUnavailable, match="CHAIN_EVIDENCE_MODE_UNACKNOWLEDGED"):
        direct.LocalGraphClient(configured).request("POST", "/api/entities/search", {"contextGraphId": "g"})
