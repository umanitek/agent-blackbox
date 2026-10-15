"""Sampling failures remain distinct from an empty, readable confirmed graph."""
import argparse
from dataclasses import replace

import pytest
from rdflib import URIRef
from test_blackbox_core_snapshot import cfg, local_server, core, direct
from test_blackbox_direct_graph import GraphNode, CG, PART, BASE, D, DP, config, load_blackbox


@pytest.mark.parametrize("recovery", ["transient", "persistent", "empty"])
def test_complete_snapshot_waits_for_fresh_read_and_preserves_read_failure(tmp_path, request, monkeypatch, recovery):
    url, calls, _ = request.getfixturevalue("local_server")
    configured = replace(cfg(tmp_path), dkg_url=url)
    samples = 0

    def sample(*_, **kwargs):
        nonlocal samples
        samples += 1
        # A positive sample before completion cannot conceal a later read failure.
        if samples == 1:
            return 3
        if recovery == "persistent" or (recovery == "transient" and samples == 2):
            raise direct.GraphReadUnavailable("QUERY_DEADLINE_EXCEEDED")
        kwargs["cursor"]["exhausted"] = True
        return 3 if recovery == "transient" else 0

    monkeypatch.setattr(core.ruleset, "ready_sample", sample)
    monkeypatch.setattr(core, "POLL_SECONDS", .01)
    result = core.run(core.SnapshotSyncClient(configured), configured,
                      argparse.Namespace(wait=True, require_rules=True, timeout=.15))
    recorded = core.state.read_for_graph(configured.context_graph_id)
    assert result == (0 if recovery == "transient" else 2)
    assert recorded["graph_complete"] is True
    assert recorded["detection_ready"] is (recovery == "transient")
    assert recorded["readiness_state"] == {"transient": "ready", "persistent": "unavailable", "empty": "empty"}[recovery]
    if recovery == "persistent":
        assert recorded["readiness_error"] == "QUERY_DEADLINE_EXCEEDED"
        assert recorded["public_entries"] is None
    else:
        assert recorded["readiness_error"] == ""
        assert recorded["public_entries"] == (3 if recovery == "transient" else 0)
    assert sum(method == "POST" for method, _, _ in calls) == 1


def test_partition_sample_keeps_corrections_owner_scope_and_observes_withdrawal():
    view = load_blackbox("ruleset.direct.view")
    node = GraphNode()
    other = BASE + "/_verifiable_memory/1/2"
    node.partition(other)
    node.add("urn:signal:suppressed", "urn:defender:IocSignal", {DP+"iocType":"domain", DP+"value":"suppressed.example"})
    node.add("urn:correction", "urn:defender:CorrectionSignal", {DP+"targetSubject":"urn:signal:suppressed", DP+"action":"suppress"}, other)
    node.add("urn:observation", "urn:blackbox:SourceObservation", {
        "urn:blackbox:p:canonicalType":"domain", "urn:blackbox:p:normalizedValue":"active.example",
        "urn:blackbox:p:lifecycleStatus":"active"}, other)
    pending = BASE + "/_verifiable_memory/0/0"
    node.partition(pending, "tentative")
    node.add("urn:pending", "urn:defender:IocSignal", {DP+"iocType":"domain", DP+"value":"pending.example"}, pending)
    foreign = BASE + "/_verifiable_memory/0/1"
    node.partition(foreign)
    meta = node.store.graph(URIRef(BASE+"/_meta"))
    meta.set((URIRef(foreign+"/ka"), URIRef(D+"kaUal"), URIRef("did:dkg:evm:1/0x2222222222222222222222222222222222222222/1")))
    node.add("urn:foreign", "urn:defender:IocSignal", {DP+"iocType":"domain", DP+"value":"foreign.example"}, foreign)
    configured = config.BlackboxConfig(detection_backend="dkg", context_graph_id=CG, community_graph_id='', report=False)
    sample = view.sample_rules(configured, client=node, category="ioc")
    assert set(sample.ioc) == {"ioc:domain:active.example"}
    node.store.graph(URIRef(other)).remove((URIRef("urn:observation"), None, None))
    assert view.ready_sample(configured, client=node) == 0
