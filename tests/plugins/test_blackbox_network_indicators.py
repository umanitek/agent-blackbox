"""Network Shield's verified lists: every malicious domain and IP of the verified graph, read
with the live lookup's scope (plugins/blackbox/ruleset/live/network_lists.py).

The contract: only rows from confirmed, owner-pinned assets count; curator corrections and
revocations take a row out; values carry the guard's own spelling; an unreadable store answers
None (the caller keeps its last list), never an empty list.
"""

from __future__ import annotations

from plugins.blackbox.ruleset.live import network_lists as ni
from plugins.blackbox.ruleset.live.scope import VerifiedScope

CG = "0x37b1fdfd134e2b17583bcbdd3034f91504cd9c70/agent-blackbox-vm"
VM = f"did:dkg:context-graph:{CG}/_verifiable_memory/"
GOOD, OTHER = VM + "asset-1", VM + "asset-2"


def _row(threat, ioc_type, value, graph=GOOD):
    return {"threat": {"value": threat}, "category": {"value": ioc_type}, "iocValue": {"value": value}, "g": {"value": graph}}


def _scope(**overrides):
    values = dict(context_graph_id=CG, store_url="http://127.0.0.1:7879", assertion_graphs=frozenset({GOOD}))
    values.update(overrides)
    return VerifiedScope(**values)


class _FakeLanes:
    """The pager's query shape: one page of rows, then an empty page."""

    def __init__(self, rows):
        self.pages = [rows, []]
        self.queries = []

    def query(self, sparql, _cg, **_):
        self.queries.append(sparql)
        return self.pages.pop(0) if self.pages else []


def test_only_confirmed_uncorrected_unrevoked_domains_and_ips_are_kept():
    rows = [
        _row("urn:t:1", "domain", "Evil.Example."),
        _row("urn:t:2", "ip", "45.130.148.102"),
        _row("urn:t:3", "domain", "tentative.example", graph=OTHER),   # not a confirmed asset
        _row("urn:t:4", "domain", "corrected.example"),                # withdrawn by a correction
        _row("urn:t:5", "ip", "203.0.113.9"),                          # revoked by the curator
        _row("urn:t:6", "url", "http://x.example/a"),                  # not a network-layer type
    ]
    scope = _scope(suppressed_subjects=frozenset({"urn:t:4"}), revoked_identifiers=frozenset({"ioc:ip:203.0.113.9"}))
    found = ni.indicators_from_rows(rows, scope)
    assert found.domains == frozenset({"evil.example"})
    assert found.ips == frozenset({"45.130.148.102"})
    assert found.assets == 1


def test_the_lane_reads_ioc_signals_under_the_verified_memory_prefix_and_is_cached():
    ni.forget()
    lanes = _FakeLanes([_row("urn:t:1", "domain", "evil.example")])
    scope = _scope()
    first = ni.network_indicators(scope, store_factory=lambda _url: lanes)
    assert first is not None and first.domains == frozenset({"evil.example"})
    assert "defender:IocSignal" in lanes.queries[0] and VM in lanes.queries[0]
    asked = len(lanes.queries)
    again = ni.network_indicators(scope, store_factory=lambda _url: lanes)
    assert again is first and len(lanes.queries) == asked, "same scope: no second read"


def test_no_scope_or_a_failed_read_is_none_never_an_empty_list():
    ni.forget()
    assert ni.network_indicators(None) is None
    assert ni.network_indicators(_scope(assertion_graphs=frozenset())) is None

    class _Broken:
        def query(self, *_args, on_error=None, **_kwargs):
            return on_error

    assert ni.network_indicators(_scope(), store_factory=lambda _url: _Broken()) is None
