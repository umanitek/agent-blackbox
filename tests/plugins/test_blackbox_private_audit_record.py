"""The private working-memory audit record is actually written (FIX-0017).

Every other test stubs ``audit.write_private_audit_ka`` out, and the function
is best-effort (it swallows its own failures) — so when the restructure broke
its lazy import, the record silently stopped being written and the suite
stayed green. These tests call the real function with a recording client.
"""

from __future__ import annotations

from _blackbox_loader import load_blackbox

audit = load_blackbox("audit")
constants = load_blackbox("kernel.constants")
# Loaded with the module, so conftest's autouse fixture finds the guard's report queue and runs
# the follow-up inline (the guard package's entry is lazy since L-W4: nothing loads it for us).
load_blackbox("guard.report_queue")


class _RecordingClient:
    """Captures private-KA writes instead of talking to a DKG node."""

    def __init__(self) -> None:
        self.writes: list[tuple[str, str, list[dict[str, str]]]] = []

    def write_private_knowledge_asset(self, cg_id: str, name: str, quads: list[dict[str, str]]) -> None:
        self.writes.append((cg_id, name, quads))


def test_private_audit_record_is_written_with_redacted_evidence():
    client = _RecordingClient()
    finding = {"identifier": "dep:npm:evil@1.0.0", "severity": "high", "evidence": "npm install evil@1.0.0"}

    audit.write_private_audit_ka(client, "graph-1", "pre_tool_call", finding)

    assert len(client.writes) == 1, "the private audit record was not written"
    cg_id, _name, quads = client.writes[0]
    assert cg_id == "graph-1"
    predicates = {q["predicate"] for q in quads}
    assert constants.IDENTIFIER_PRED in predicates
    assert constants.SCHEMA_DESCRIPTION_PRED in predicates


def test_private_audit_record_subject_is_an_audit_urn():
    client = _RecordingClient()

    audit.write_private_audit_ka(client, "graph-1", "pre_tool_call", {"identifier": "x"})

    _cg, _name, quads = client.writes[0]
    assert all(q["subject"].startswith("urn:guardian:audit:") for q in quads)


def test_private_audit_record_is_never_written_to_a_remote_node():
    """KI-223: the record carries redacted command/prompt text; a remote dkg_url (a shared
    bench node, a cloud node) would carry that text off this machine."""
    remote = _RecordingClient()
    remote.url = "http://203.0.113.9:9200"
    audit.write_private_audit_ka(remote, "graph-1", "pre_tool_call",
                                 {"identifier": "dep:npm:evil@1.0.0", "severity": "high", "evidence": "npm install evil"})
    assert remote.writes == []
    local = _RecordingClient()
    local.url = "http://127.0.0.1:9320"
    audit.write_private_audit_ka(local, "graph-1", "pre_tool_call",
                                 {"identifier": "dep:npm:evil@1.0.0", "severity": "high", "evidence": "npm install evil"})
    assert len(local.writes) == 1
    assert audit.node_is_local("") and audit.node_is_local("http://localhost:9320") and not audit.node_is_local("http://node.example:9200")


# ------------------------------------------------------------- this node's own private graph (2026-10-10)


class _Node:
    """A node that knows who it is and answers graph creation (409 once it exists)."""

    def __init__(self, address="0xABC", *, refuse=None):
        self.address, self.refuse, self.created = address, refuse, []

    def agent_identity(self):
        return {"agentAddress": self.address}

    def request(self, method, path, body=None, timeout=None):
        if self.refuse is not None:
            raise self.refuse
        if body["id"] in self.created:
            raise _Status(409)
        self.created.append(body["id"])
        return {"created": body["id"]}


class _Status(Exception):
    def __init__(self, code):
        super().__init__(f"status {code}")
        self.status_code = code


def test_the_local_graph_is_this_nodes_own_and_created_once(tmp_path, monkeypatch):
    """DKG 10.0.23 refuses a write into Umanitek's verified graph (CONTEXT_GRAPH_NOT_FOUND);
    the record lives in `<agent address>/blackbox-local`, created on first use."""
    monkeypatch.setattr(constants, "blackbox_home", lambda: tmp_path)
    node = _Node()
    assert audit.local_audit_graph(node) == "0xABC/blackbox-local" and node.created == ["0xABC/blackbox-local"]
    other = _Node()                                   # a fresh process: the cache answers, nothing is created
    assert audit.local_audit_graph(other) == "0xABC/blackbox-local" and other.created == []


def test_an_existing_local_graph_is_fine(tmp_path, monkeypatch):
    monkeypatch.setattr(constants, "blackbox_home", lambda: tmp_path)
    node = _Node()
    node.created.append("0xABC/blackbox-local")       # created by an earlier install
    assert audit.local_audit_graph(node) == "0xABC/blackbox-local"


def test_a_refused_or_anonymous_node_gives_no_local_graph(tmp_path, monkeypatch):
    monkeypatch.setattr(constants, "blackbox_home", lambda: tmp_path)
    assert audit.local_audit_graph(_Node(refuse=_Status(500))) == ""
    assert audit.local_audit_graph(_Node(address="")) == ""
    assert not (tmp_path / "local_audit_graph.json").exists()


def test_the_hook_writes_its_private_record_into_the_local_graph(tmp_path, monkeypatch):
    reporting = load_blackbox("guard.reporting")
    config = load_blackbox("kernel.config")
    monkeypatch.setattr(constants, "blackbox_home", lambda: tmp_path)
    writes = []
    monkeypatch.setattr(reporting.audit, "local_audit_graph", lambda client: "0xABC/blackbox-local")
    monkeypatch.setattr(reporting.audit, "write_private_audit_ka", lambda client, graph, event, finding: writes.append(graph))
    monkeypatch.setattr(reporting.audit, "record", lambda **kw: None)
    monkeypatch.setattr(reporting.audit, "recently_reported", lambda identifier: False)
    monkeypatch.setattr(reporting.audit, "mark_reported", lambda identifier: None)
    monkeypatch.setattr(reporting.identity, "reporter_address", lambda client: None)
    detection = load_blackbox("detection")
    finding = detection.Finding(identifier="dep:npm:evil@1.0.0", category="dependency", severity="critical",
                                title="t", tool_name="terminal", matched="m", evidence="e", confirmed=True, source="public")
    reporting._report_and_audit(config.BlackboxConfig(), "pre_tool_call", [finding], {})
    assert writes == ["0xABC/blackbox-local"]


def test_the_local_tier_reads_only_the_identifier_lane_of_the_nodes_own_graph():
    """Bench A 2026-10-10: the defender-signal lanes over working memory ran > 30 s and the
    node restarted its store; the private graph holds audit records only."""
    fetching = load_blackbox("ruleset.fetching")
    asked = []

    class Node:
        def query(self, sparql, cg, view=None, on_error=None, agent_address=None, **kw):
            asked.append((sparql, cg, view, agent_address))
            if "FILTER(STR(?threat) >" in sparql:
                return []
            return [{"threat": "urn:guardian:audit:1", "identifier": '"ioc:ip:203.0.113.9"',
                     "rdfType": "http://umanitek.ai/ontology/guardian/AuditRecord", "severity": '"high"'}]

    rows = fetching.fetch_local_records(Node(), "0xABC/blackbox-local", "0xABC")
    assert [r["threat"] for r in rows] == ["urn:guardian:audit:1"]
    assert all("defender:" not in q and cg == "0xABC/blackbox-local" and view == "working-memory" and who == "0xABC"
               for q, cg, view, who in asked)
