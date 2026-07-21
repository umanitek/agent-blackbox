"""Tests for the stdlib DKG HTTP client (mocked urlopen)."""

import io
import json
import urllib.error

import pytest

from _blackbox_loader import load_blackbox


dkg_client = load_blackbox("dkg_client")


class _FakeResponse:
    def __init__(self, body):
        self._body = body.encode() if isinstance(body, str) else body

    def read(self, n=-1):
        return self._body

    def __enter__(self):
        return self

    def __exit__(self, *a):
        return False


def _capture(monkeypatch, body='{"ok": true}'):
    """Patch urlopen to record the request and return *body*."""
    captured = {}

    def fake_urlopen(req, timeout=None):
        call = {
            "url": req.full_url,
            "method": req.get_method(),
            "headers": dict(req.header_items()),
            "body": req.data.decode() if req.data else None,
            "timeout": timeout,
        }
        captured.setdefault("calls", []).append(call)
        captured.update(call)
        return _FakeResponse(body)

    monkeypatch.setattr(dkg_client.urllib.request, "urlopen", fake_urlopen)
    return captured


def _capture_sequence(monkeypatch, bodies):
    """Patch urlopen to record requests and return one JSON body per call."""
    captured = {"calls": []}
    remaining = list(bodies)

    def fake_urlopen(req, timeout=None):
        if not remaining:
            raise AssertionError(f"unexpected urlopen call: {req.get_method()} {req.full_url}")
        call = {
            "url": req.full_url,
            "method": req.get_method(),
            "headers": dict(req.header_items()),
            "body": req.data.decode() if req.data else None,
            "timeout": timeout,
        }
        captured["calls"].append(call)
        captured.update(call)
        return _FakeResponse(remaining.pop(0))

    monkeypatch.setattr(dkg_client.urllib.request, "urlopen", fake_urlopen)
    return captured


def test_url_and_token_resolution(monkeypatch):
    monkeypatch.setenv("BLACKBOX_DKG_DAEMON_URL", "http://example:9999/")
    monkeypatch.setenv("BLACKBOX_DKG_API_TOKEN", "tok-123")
    client = dkg_client.DkgClient()
    assert client.url == "http://example:9999"  # trailing slash stripped
    assert client.token == "tok-123"


def test_blackbox_dkg_port_sets_default_url(monkeypatch):
    monkeypatch.delenv("BLACKBOX_DKG_DAEMON_URL", raising=False)
    monkeypatch.delenv("BLACKBOX_DKG_URL", raising=False)
    monkeypatch.setenv("BLACKBOX_DKG_PORT", "9331")
    assert dkg_client.load_daemon_url() == "http://127.0.0.1:9331"


def test_generic_dkg_env_does_not_bleed_into_blackbox(monkeypatch, tmp_path):
    blackbox_home = tmp_path / "blackbox-dkg"
    blackbox_home.mkdir()
    (blackbox_home / "auth.token").write_text("# local Blackbox node token\nblackbox-token\n")
    default_dkg_home = tmp_path / "default-dkg"
    default_dkg_home.mkdir()
    (default_dkg_home / "auth.token").write_text("default-token\n")

    monkeypatch.delenv("BLACKBOX_DKG_DAEMON_URL", raising=False)
    monkeypatch.delenv("BLACKBOX_DKG_URL", raising=False)
    monkeypatch.delenv("BLACKBOX_DKG_PORT", raising=False)
    monkeypatch.delenv("BLACKBOX_DKG_API_TOKEN", raising=False)
    monkeypatch.delenv("BLACKBOX_DKG_AUTH_TOKEN", raising=False)
    monkeypatch.setenv("DKG_DAEMON_URL", "http://default-node:9200/")
    monkeypatch.setenv("DKG_API_TOKEN", "default-env-token")
    monkeypatch.setenv("DKG_HOME", str(default_dkg_home))

    client = dkg_client.DkgClient(dkg_home=str(blackbox_home))
    assert client.url == dkg_client.constants.DEFAULT_DKG_URL
    assert client.token == "blackbox-token"


def test_share_knowledge_asset_payload(monkeypatch):
    cap = _capture_sequence(
        monkeypatch,
        [
            '{"ok": true}',
            '{"jobId":"share-job-1","state":"queued"}',
            '{"jobId":"share-job-1","state":"succeeded","entitiesPromoted":1}',
        ],
    )
    client = dkg_client.DkgClient(url="http://node", token="tok")
    quads = [{"subject": "s", "predicate": "p", "object": '"o"'}]
    result = client.share_knowledge_asset("cg", "notes", quads)
    assert result["state"] == "succeeded"
    assert cap["calls"][0]["url"] == "http://node/api/knowledge-assets"
    assert cap["calls"][0]["method"] == "POST"
    body = json.loads(cap["calls"][0]["body"])
    assert body["contextGraphId"] == "cg"
    assert body["name"] == "notes"
    assert body["quads"] == quads
    assert body["alsoShareSwm"] is False
    assert cap["calls"][1]["url"] == "http://node/api/knowledge-assets/notes/swm/share-async"
    assert json.loads(cap["calls"][1]["body"]) == {"contextGraphId": "cg", "entities": "all"}
    assert cap["calls"][2]["url"] == "http://node/api/knowledge-assets/swm/share-jobs/share-job-1"
    assert cap["calls"][2]["method"] == "GET"
    # Auth header present.
    assert any(v == "Bearer tok" for v in cap["headers"].values())
    # Shares that also write to SWM use the longer store timeout, not the read one.
    assert cap["timeout"] == dkg_client._STORE_TIMEOUT


def test_share_rejects_oversized_literal_before_http(monkeypatch):
    def fail_urlopen(req, timeout=None):
        raise AssertionError("urlopen should not be called")

    monkeypatch.setattr(dkg_client.urllib.request, "urlopen", fail_urlopen)
    client = dkg_client.DkgClient(url="http://node", token="tok")
    rows = [{
        "subject": "urn:test:s",
        "predicate": "urn:test:p",
        "object": '"' + ("x" * 50001) + '"',
    }]
    with pytest.raises(dkg_client.DkgError, match="exceeds Blackbox cap"):
        client.share_knowledge_asset("cg", "notes", rows)


def test_catchup_status_encodes_context_graph_id(monkeypatch):
    cap = _capture(monkeypatch, '{"status":"running"}')
    client = dkg_client.DkgClient(url="http://node", token="tok")

    result = client.catchup_status("umanitek/blackbox threats")

    assert result == {"status": "running"}
    assert cap["method"] == "GET"
    assert cap["url"] == (
        "http://node/api/sync/catchup-status?"
        "contextGraphId=umanitek%2Fblackbox%20threats"
    )


def test_catchup_status_can_pin_exact_job_id(monkeypatch):
    cap = _capture(monkeypatch, '{"jobId":"fresh","status":"done"}')
    client = dkg_client.DkgClient(url="http://node", token="tok")

    result = client.catchup_status("owner/graph", job_id="fresh job/1")

    assert result == {"jobId": "fresh", "status": "done"}
    assert cap["method"] == "GET"
    assert cap["url"] == (
        "http://node/api/sync/catchup-status?jobId=fresh%20job%2F1"
    )


def test_connect_peer_uses_dkg_peer_resolution(monkeypatch):
    cap = _capture(monkeypatch)
    client = dkg_client.DkgClient(url="http://node", token="tok")

    client.connect_peer("publisher-peer")

    assert cap["method"] == "POST"
    assert cap["url"] == "http://node/api/connect"
    assert json.loads(cap["body"]) == {"peerId": "publisher-peer"}
    assert cap["timeout"] == 15.0


def test_authoritative_catchup_pins_publisher_for_durable_vm_recovery(monkeypatch):
    cap = _capture(monkeypatch, '{"ok":true,"totalDurableInsertedTriples":23}')
    client = dkg_client.DkgClient(url="http://node", token="tok")

    result = client.catchup_from_peer("owner/private", "curator-peer", budget_ms=9_999_999)

    assert result == {"ok": True, "totalDurableInsertedTriples": 23}
    assert cap["method"] == "POST"
    assert cap["url"] == "http://node/api/shared-memory/catchup"
    assert json.loads(cap["body"]) == {
        "contextGraphId": "owner/private",
        "peerId": "curator-peer",
        "includeSharedMemory": False,
        "includeDurable": True,
        "hostCatchupFallback": False,
        "perPeerDurableBudgetMs": 300_000,
    }
    assert cap["timeout"] == dkg_client.constants.GRAPH_SYNC_SETTLEMENT_TIMEOUT_S


def test_context_graph_has_agent_uses_local_participants_metadata(monkeypatch):
    cap = _capture(
        monkeypatch,
        '{"allowedAgents":["0xAbC0000000000000000000000000000000000000"]}',
    )
    client = dkg_client.DkgClient(url="http://node", token="tok")

    assert client.context_graph_has_agent(
        "owner/private graph",
        "0xabc0000000000000000000000000000000000000",
    ) is True
    assert cap["url"] == (
        "http://node/api/context-graph/owner%2Fprivate%20graph/participants"
    )


def test_request_join_publishes_encryption_profile_before_signing(monkeypatch):
    cap = _capture_sequence(
        monkeypatch,
        [
            '{"ok":true}',
            '{"delegation":{"agentAddress":"0xabc","signature":"sig"}}',
            '{"delivered":1}',
        ],
    )
    client = dkg_client.DkgClient(url="http://node", token="tok")

    result = client.request_join("owner/private graph", "curator-peer")

    assert result == {"delivered": 1}
    assert [call["url"] for call in cap["calls"]] == [
        "http://node/api/agent/publish-profile",
        "http://node/api/context-graph/owner%2Fprivate%20graph/sign-join",
        "http://node/api/context-graph/owner%2Fprivate%20graph/request-join",
    ]
    assert json.loads(cap["calls"][0]["body"]) == {}
    assert json.loads(cap["calls"][2]["body"]) == {
        "delegation": {"agentAddress": "0xabc", "signature": "sig"},
        "curatorPeerId": "curator-peer",
        "agentName": "agent-blackbox",
    }


def test_request_join_tolerates_older_daemon_without_profile_endpoint(monkeypatch, caplog):
    calls = []

    def fake_urlopen(req, timeout=None):
        calls.append(req.full_url)
        if req.full_url.endswith("/api/agent/publish-profile"):
            raise urllib.error.HTTPError(
                req.full_url,
                404,
                "not found",
                {},
                io.BytesIO(b'{"error":"not found"}'),
            )
        if req.full_url.endswith("/sign-join"):
            return _FakeResponse('{"delegation":{"agentAddress":"0xabc"}}')
        return _FakeResponse('{"delivered":1}')

    monkeypatch.setattr(dkg_client.urllib.request, "urlopen", fake_urlopen)
    client = dkg_client.DkgClient(url="http://node", token="tok")

    assert client.request_join("cg", "peer") == {"delivered": 1}
    assert len(calls) == 3
    assert "Could not publish DKG agent profile before join" in caplog.text


def test_restart_context_graph_catchup_uses_official_unsubscribe_then_subscribe(monkeypatch):
    cap = _capture_sequence(
        monkeypatch,
        ['{"unsubscribed":"cg"}', '{"catchup":{"status":"queued"}}'],
    )
    client = dkg_client.DkgClient(url="http://node", token="tok")

    result = client.restart_context_graph_catchup("cg")

    assert result == {"catchup": {"status": "queued"}}
    assert [call["url"] for call in cap["calls"]] == [
        "http://node/api/context-graph/unsubscribe",
        "http://node/api/context-graph/subscribe",
    ]
    assert [json.loads(call["body"]) for call in cap["calls"]] == [
        {"contextGraphId": "cg"},
        {"contextGraphId": "cg", "includeSharedMemory": False},
    ]


def test_unsubscribe_context_graph_preserves_the_official_data_safe_operation(monkeypatch):
    cap = _capture(monkeypatch, body='{"unsubscribed":"cg","subscribed":false}')
    client = dkg_client.DkgClient(url="http://node", token="tok")

    result = client.unsubscribe_context_graph("cg")

    assert result == {"unsubscribed": "cg", "subscribed": False}
    assert cap["method"] == "POST"
    assert cap["url"] == "http://node/api/context-graph/unsubscribe"
    assert json.loads(cap["body"]) == {"contextGraphId": "cg"}


def test_query_normalizes_bindings(monkeypatch):
    body = json.dumps({"bindings": [{"identifier": '"dep:npm:x@1"'}]})
    cap = _capture(monkeypatch, body=body)
    client = dkg_client.DkgClient(url="http://node", token="t")
    rows = client.query("SELECT * WHERE {?s ?p ?o}", "cg")
    assert rows == [{"identifier": '"dep:npm:x@1"'}]
    assert json.loads(cap["body"])["view"] == "verifiable-memory"


def test_scoped_graph_query_can_omit_the_memory_view(monkeypatch):
    cap = _capture(monkeypatch, '{"bindings": []}')
    client = dkg_client.DkgClient(url="http://node", token="t")

    client.query(
        "SELECT * WHERE { GRAPH ?g { ?s ?p ?o } }",
        "cg",
        view=None,
    )

    assert json.loads(cap["body"]) == {
        "sparql": "SELECT * WHERE { GRAPH ?g { ?s ?p ?o } }",
        "contextGraphId": "cg",
    }


def test_threat_count_uses_one_verifiable_memory_query(monkeypatch):
    cap = _capture(
        monkeypatch,
        '{"bindings":[{"n":"\\\"123\\\"^^<http://www.w3.org/2001/XMLSchema#integer>"}]}',
    )
    client = dkg_client.DkgClient(url="http://node", token="tok")

    assert client.threat_count("owner/agent-blackbox-vm") == 123
    body = json.loads(cap["body"])
    assert body["contextGraphId"] == "owner/agent-blackbox-vm"
    assert body["view"] == dkg_client.constants.VIEW_VERIFIABLE_MEMORY
    assert "COUNT(DISTINCT ?threat)" in body["sparql"]
    assert "VALUES ?type" in body["sparql"]
    assert "UNION" not in body["sparql"]


def test_working_memory_query_sends_agent_address(monkeypatch):
    cap = _capture(monkeypatch, '{"bindings": []}')
    client = dkg_client.DkgClient(url="http://node", token="t")

    client.query(
        "SELECT * WHERE {?s ?p ?o}",
        "cg",
        view="working-memory",
        agent_address="0xabc",
    )

    assert json.loads(cap["body"]) == {
        "sparql": "SELECT * WHERE {?s ?p ?o}",
        "contextGraphId": "cg",
        "view": "working-memory",
        "agentAddress": "0xabc",
    }


def test_query_fails_open_on_http_error(monkeypatch):
    def raise_http(req, timeout=None):
        raise urllib.error.HTTPError(req.full_url, 500, "err", {}, io.BytesIO(b"boom"))

    monkeypatch.setattr(dkg_client.urllib.request, "urlopen", raise_http)
    client = dkg_client.DkgClient(url="http://node", token="t")
    # query() swallows DkgError and returns [] (read paths fail open).
    assert client.query("SELECT * WHERE {?s ?p ?o}", "cg") == []


def test_write_path_raises_dkg_error_on_http_error(monkeypatch):
    def raise_http(req, timeout=None):
        raise urllib.error.HTTPError(req.full_url, 403, "forbidden", {}, io.BytesIO(b"nope"))

    monkeypatch.setattr(dkg_client.urllib.request, "urlopen", raise_http)
    client = dkg_client.DkgClient(url="http://node", token="t")
    with pytest.raises(dkg_client.DkgError) as exc_info:
        client.share_knowledge_asset("cg", "n", [])
    assert exc_info.value.status_code == 403


def test_share_is_idempotent_on_already_finalized(monkeypatch):
    # Re-sharing a threat whose deterministic KA name already exists sealed must
    # be treated as success, not a 500 (verified live against a v10 node).
    body = b'{"error":"assertion ... is already finalized"}'

    def raise_finalized(req, timeout=None):
        raise urllib.error.HTTPError(req.full_url, 500, "err", {}, io.BytesIO(body))

    monkeypatch.setattr(dkg_client.urllib.request, "urlopen", raise_finalized)
    client = dkg_client.DkgClient(url="http://node", token="t")
    res = client.share_knowledge_asset("cg", "threat-abc", [])
    assert res.get("idempotent") is True


def test_share_repairs_wm_merkle_conflict(monkeypatch):
    conflict = (
        '{"jobId":"share-job-1","state":"failed",'
        '"lastError":{"code":"WM_DRAFT_CONFLICT","message":"draft conflict: '
        'different merkleRoot"}}'
    )
    cap = _capture_sequence(
        monkeypatch,
        [
            '{"jobId":"share-job-1","state":"queued"}',
            conflict,
            '{"seededFrom":{"layer":"swm"}}',
            '{"jobId":"share-job-2","state":"queued"}',
            '{"jobId":"share-job-2","state":"succeeded","entitiesPromoted":1}',
        ],
    )
    client = dkg_client.DkgClient(url="http://node", token="t")
    res = client.share_finalized_knowledge_asset("cg", "threat-abc")
    assert res["jobId"] == "share-job-2"
    assert res["state"] == "succeeded"
    assert cap["calls"][2]["url"].endswith("/api/knowledge-assets/threat-abc/wm/pull-from")
    assert json.loads(cap["calls"][2]["body"]) == {
        "contextGraphId": "cg",
        "layer": "swm",
        "onConflict": "replace",
    }


def test_share_async_wait_raises_failed_job(monkeypatch):
    _capture_sequence(
        monkeypatch,
        [
            '{"jobId":"share-job-1","state":"queued"}',
            '{"jobId":"share-job-1","state":"failed","lastError":{"message":"not-agent-gated"}}',
        ],
    )
    client = dkg_client.DkgClient(url="http://node", token="t")
    with pytest.raises(dkg_client.DkgError, match="not-agent-gated"):
        client.share_async_and_wait("cg", "n", timeout_s=1, poll_s=1)


def test_extract_binding_shapes():
    assert dkg_client.extract_binding({"value": "foo"}) == "foo"
    assert dkg_client.extract_binding('"literal"') == "literal"
    assert dkg_client.extract_binding('"5"^^<http://www.w3.org/2001/XMLSchema#integer>') == "5"
    assert dkg_client.extract_binding("urn:guardian:threat:x") == "urn:guardian:threat:x"
    assert dkg_client.extract_binding(None) == ""


def test_normalize_bindings_nested_shape():
    result = {"results": {"bindings": [{"n": {"value": "3"}}]}}
    assert dkg_client.normalize_bindings(result) == [{"n": {"value": "3"}}]
