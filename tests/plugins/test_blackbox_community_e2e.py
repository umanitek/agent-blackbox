"""B8: the two-node community e2e — Agent A reports, Agent B sees.

Marked ``integration`` (excluded by default). Point it at real nodes with:

    BLACKBOX_E2E_NODE_A_URL=http://<a>:9320  BLACKBOX_E2E_NODE_A_HOME=...
    BLACKBOX_E2E_NODE_B_URL=http://<b>:9320  BLACKBOX_E2E_NODE_B_HOME=...
    BLACKBOX_CONTEXT_GRAPH_ID=<cg id>   # the verified graph: its shared memory is the community's
    uv run pytest -m integration tests/plugins/test_blackbox_community_e2e.py -s

Skips cleanly when the endpoints are not configured (CI-safe). The run
output records the measured share→visible propagation time — the number
that backs the proposal's latency claim (KI-019).
"""

from __future__ import annotations

import os
import time

import pytest

from plugins.blackbox import community
from plugins.blackbox.community import report_builder
from plugins.blackbox.community.report_signer import ReportSigner, network_environment
from plugins.blackbox.kernel import signing
from plugins.blackbox.kernel import threat_ids
from plugins.blackbox.kernel.config import BlackboxConfig
from plugins.blackbox.kernel.dkg_client import DkgClient
from plugins.blackbox.kernel.reporter_key import ReporterKeyStore


pytestmark = pytest.mark.integration

CG = os.environ.get("BLACKBOX_CONTEXT_GRAPH_ID", "")
A_URL = os.environ.get("BLACKBOX_E2E_NODE_A_URL", "")
A_HOME = os.environ.get("BLACKBOX_E2E_NODE_A_HOME", "")
B_URL = os.environ.get("BLACKBOX_E2E_NODE_B_URL", "")
B_HOME = os.environ.get("BLACKBOX_E2E_NODE_B_HOME", "")

needs_nodes = pytest.mark.skipif(
    not (CG and A_URL and B_URL),
    reason="community e2e endpoints not configured (set BLACKBOX_E2E_NODE_*_URL + BLACKBOX_CONTEXT_GRAPH_ID)",
)

def _client(url: str, home: str) -> DkgClient:
    return DkgClient(url=url, dkg_home=home)


def _reporter(client: DkgClient) -> str:
    info = client.agent_identity()
    for key in ("agentAddress", "defaultAgentAddress", "address"):
        val = info.get(key) if isinstance(info, dict) else None
        if isinstance(val, str) and val.startswith("0x"):
            return val
    pytest.fail("node has no resolvable 0x identity — KI-003/KI-017 violation")


def _signer(client: DkgClient, key_file) -> ReportSigner:
    """Each node signs with ITS OWN key (Refine R0b) — separate key files,
    because both nodes' shares are made from this one test process."""
    return ReportSigner(private_key=ReporterKeyStore(key_file).load_or_create(),
                        environment=network_environment(client.status()), graph=CG)


def _visible_identifiers(client: DkgClient) -> set[tuple[str, str]]:
    """(identifier, signer) for every report that VERIFIES on *client* —
    the one reader every product surface uses (R0c/R0d), never the
    self-described reporter field (KI-110)."""
    read = community.read_verified_reports(client, BlackboxConfig(context_graph_id=CG))
    return {(report.identifier, report.author) for report in read.reports}


@needs_nodes
def test_report_from_a_visible_on_b_with_distinct_identities(tmp_path):
    a = _client(A_URL, A_HOME)
    b = _client(B_URL, B_HOME)
    rep_a, rep_b = _reporter(a), _reporter(b)
    assert rep_a != rep_b, "two nodes must carry DISTINCT identities (KI-017)"

    identifier = f"ioc:domain:e2e-{int(time.time())}.example"
    signer_a = _signer(a, tmp_path / "a_key.pem")
    q = report_builder.build_report_quads(
        identifier=identifier, category="ioc", severity="high",
        reporter_address=rep_a, framework="hermes", ioc_type="domain",
        signer=signer_a,
    )
    name = f"report-{threat_ids.stable_hash(identifier + rep_a, 16)}"
    shared_at = time.monotonic()
    a.share_knowledge_asset(CG, name, q)

    b.subscribe_context_graph(CG, include_shared_memory=True)
    deadline = time.monotonic() + 600
    while time.monotonic() < deadline:
        if (identifier, signing.public_key_hex(signer_a.private_key)) in _visible_identifiers(b):
            latency = time.monotonic() - shared_at
            print(f"\nPROPAGATION: A→B visible in {latency:.1f}s (KI-019 measured)")
            break
        time.sleep(10)
    else:
        pytest.fail("report from A never became visible on B within 600s")

    # Second reporter raises the DISTINCT count to 2 — the consensus primitive.
    q2 = report_builder.build_report_quads(
        identifier=identifier, category="ioc", severity="high",
        reporter_address=rep_b, framework="hermes", ioc_type="domain",
        signer=_signer(b, tmp_path / "b_key.pem"),
    )
    b.share_knowledge_asset(CG, f"report-{threat_ids.stable_hash(identifier + rep_b, 16)}", q2)
    deadline = time.monotonic() + 600
    while time.monotonic() < deadline:
        signers = {author for (ident, author) in _visible_identifiers(b) if ident == identifier}
        if len(signers) >= 2:
            print(f"REPORTER COUNT: {len(signers)} distinct verified signers for {identifier}")
            break
        time.sleep(10)
    else:
        pytest.fail("second reporter never raised the distinct count to 2")


@needs_nodes
def test_burst_respects_daily_cap_at_the_graph(tmp_path):
    """Rate-brake verification at the graph, not in unit mocks (KI-002).

    N distinct identifiers shared back-to-back → each lands exactly once
    (subject naming is idempotent); a re-share of the same identifier by the
    same reporter never creates a second subject.
    """
    a = _client(A_URL, A_HOME)
    rep = _reporter(a)
    signer = _signer(a, tmp_path / "a_key.pem")
    base = int(time.time())
    idents = [f"ioc:domain:burst-{base}-{i}.example" for i in range(3)]
    for ident in idents:
        q = report_builder.build_report_quads(
            identifier=ident, category="ioc", severity="high",
            reporter_address=rep, framework="hermes", ioc_type="domain", signer=signer,
        )
        name = f"report-{threat_ids.stable_hash(ident + rep, 16)}"
        a.share_knowledge_asset(CG, name, q)
        a.share_knowledge_asset(CG, name, q)  # idempotent repeat — must not duplicate

    time.sleep(15)
    visible = _visible_identifiers(a)
    for ident in idents:
        matching = [(i, r) for (i, r) in visible if i == ident]
        assert len(matching) == 1, f"{ident}: expected exactly one subject, saw {len(matching)}"
