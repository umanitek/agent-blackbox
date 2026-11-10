"""The local-store read client: three outcomes, loopback only (DKG-lookup build B1)."""

from __future__ import annotations

import json
import socket
import urllib.error

import pytest

from plugins.blackbox.kernel import store


class _Response:
    def __init__(self, body: bytes) -> None:
        self._body = body

    def read(self) -> bytes:
        return self._body

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        return False


def _results(*rows):
    bindings = [{name: {"type": "literal", "value": value} for name, value in row.items()} for row in rows]
    return json.dumps({"head": {"vars": []}, "results": {"bindings": bindings}}).encode()


@pytest.fixture
def urlopen(monkeypatch):
    """Patch urlopen; the test sets ``calls.answer`` to bytes or an exception."""
    calls = type("Calls", (), {"answer": b"", "requests": []})()

    def fake(request, timeout=None):
        calls.requests.append((request, timeout))
        if isinstance(calls.answer, BaseException):
            raise calls.answer
        return _Response(calls.answer)

    monkeypatch.setattr(store.client.local_http, "open_direct", fake)
    return calls


def test_rows_come_back_in_the_node_api_term_shape(urlopen):
    """IRIs bare, literals quoted + escaped (what ``extract_binding`` decodes), so a
    value that starts with a quote survives exactly as the partition reader's do."""
    urlopen.answer = json.dumps({"results": {"bindings": [{
        "t": {"type": "uri", "value": "urn:defender:signal:1"},
        "sev": {"type": "literal", "value": "high"},
        "odd": {"type": "literal", "value": '"quoted" back\\slash\nline'},
        "n": {"type": "literal", "value": "3", "datatype": "http://www.w3.org/2001/XMLSchema#integer"},
        "name": {"type": "literal", "value": "x", "xml:lang": "en"},
        "b": {"type": "bnode", "value": "b0"},
    }]}}).encode()
    answer = store.StoreClient("http://127.0.0.1:7878/query").select("SELECT ?t WHERE {}")
    assert answer.known and answer.rows == [{
        "t": "urn:defender:signal:1", "sev": '"high"',
        "odd": '"\\"quoted\\" back\\\\slash\\nline"',
        "n": '"3"^^<http://www.w3.org/2001/XMLSchema#integer>', "name": '"x"@en', "b": "_:b0",
    }]
    from plugins.blackbox.kernel.sparql_text import extract_binding
    assert extract_binding(answer.rows[0]["odd"]) == '"quoted" back\\slash\nline'
    assert extract_binding(answer.rows[0]["sev"]) == "high"


def test_no_matching_rows_is_a_known_empty_answer(urlopen):
    urlopen.answer = _results()
    answer = store.StoreClient("http://127.0.0.1:7878/query").select("SELECT ?t WHERE {}")
    assert answer.known and answer.rows == []


def test_the_query_goes_as_a_form_post_with_the_results_json_accept_header(urlopen):
    urlopen.answer = _results()
    store.StoreClient("http://127.0.0.1:7878/query", timeout=0.5).select('SELECT ?t WHERE { ?t ?p "x" }')
    request, timeout = urlopen.requests[0]
    assert request.get_method() == "POST" and timeout == 0.5
    assert request.data == b"query=SELECT+%3Ft+WHERE+%7B+%3Ft+%3Fp+%22x%22+%7D"
    assert request.get_header("Accept") == "application/sparql-results+json"


@pytest.mark.parametrize("failure, reason", [
    (urllib.error.URLError(TimeoutError("timed out")), "timeout"),
    (TimeoutError("timed out"), "timeout"),
    (urllib.error.HTTPError("u", 500, "boom", {}, None), "http 500"),
    (ConnectionRefusedError(111, "refused"), "transport"),
])
def test_a_failure_is_could_not_tell_never_an_empty_answer(urlopen, failure, reason):
    urlopen.answer = failure
    answer = store.StoreClient("http://127.0.0.1:7878/query").select("SELECT ?t WHERE {}")
    assert not answer.known and answer.rows is None and answer.reason.startswith(reason)


@pytest.mark.parametrize("body", [b"not json", b"{}", b'{"results": {"bindings": "x"}}'])
def test_a_malformed_body_is_could_not_tell(urlopen, body):
    urlopen.answer = body
    answer = store.StoreClient("http://127.0.0.1:7878/query").select("SELECT ?t WHERE {}")
    assert not answer.known and answer.reason == "malformed results"


def test_an_empty_endpoint_is_could_not_tell_without_a_network_call(urlopen):
    answer = store.StoreClient("").select("SELECT ?t WHERE {}")
    assert not answer.known and answer.reason == "no store endpoint" and urlopen.requests == []


@pytest.mark.parametrize("status, expected", [
    ({"storeUrl": "http://127.0.0.1:7878/query"}, "http://127.0.0.1:7878/query"),
    ({"storeUrl": "http://localhost:9999/blazegraph/sparql"}, "http://localhost:9999/blazegraph/sparql"),
    ({"storeUrl": "http://[::1]:7878/query"}, "http://[::1]:7878/query"),
    ({"storeUrl": "http://10.116.0.6:7878/query"}, ""),
    ({"storeUrl": "http://store.example.com/query"}, ""),
    ({"storeUrl": "file:///tmp/x"}, ""),
    ({}, ""),
    ({"storeUrl": None}, ""),
])
def test_only_a_loopback_store_endpoint_is_accepted(status, expected):
    assert store.loopback_store_url(status) == expected
