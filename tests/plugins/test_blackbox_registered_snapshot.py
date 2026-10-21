"""Registered-core policy stays explicit and cannot bypass daemon or job fences."""
import argparse
from dataclasses import replace

import pytest
from _blackbox_loader import load_blackbox
from tests.plugins.test_blackbox_snapshot_request import replies

config = load_blackbox("kernel.config")
settings = load_blackbox("kernel.snapshot_config")
core = load_blackbox("sync.core_snapshot")
POLICY = settings.REGISTERED_BASE_CORES


def configuration(tmp_path, policy=POLICY):
    parsed = settings.snapshot_config({"detection_backend": "dkg", "snapshot_sync": {
        "on_chain_id": "14", "trusted_core_peers": [], "source_policy": policy}})
    return config.BlackboxConfig(detection_backend="dkg", dkg_home=str(tmp_path), snapshot_sync=parsed)


@pytest.mark.parametrize("policy", [POLICY, "DKG_Core_chain_cache"])
@pytest.mark.parametrize("capabilities", [None, {}, {"sourcePolicies": []}, {"sourcePolicies": POLICY}])
def test_older_or_malformed_daemon_never_starts_an_automatic_job(tmp_path, capabilities, policy):
    cfg = configuration(tmp_path, policy)
    with replies([{"state": "idle", "capabilities": capabilities}]) as (url, calls):
        assert core.run(core.SnapshotSyncClient(replace(cfg, dkg_url=url)), cfg,
                        argparse.Namespace(wait=False, timeout=5)) == 2
    assert len(calls) == 1 and calls[0][0] == "GET"
    assert core.state.read_for_graph(cfg.context_graph_id)["error"] == "DKG_UPGRADE_REQUIRED"


@pytest.mark.parametrize("change", [None, "policy", "source", "missing"])
def test_registered_sources_complete_only_with_matching_owned_policy_and_proven_sources(tmp_path, monkeypatch, change):
    cfg = configuration(tmp_path)
    payload = {"contextGraphId": cfg.context_graph_id, "onChainId": "14", "mode": "core-cache",
               "trustedCorePeerIds": [], "sourcePolicy": POLICY}
    job = {"id": "owned", "state": "running", "request": {**payload, "transport": "exact"}}
    result = {"mode": "core-cache", "completeAsOfSnapshot": True, "current": True,
              "assets": 12, "committed": 12, "sourcePolicy": POLICY,
              "selectedCorePeerIds": ["registered-core"], "sourceCore": "registered-core",
              "coverageSourceCore": "registered-core"}
    complete = {**job, "state": "complete", "result": result}
    if change == "policy":
        complete["request"] = {**job["request"], "sourcePolicy": "advertised-cores"}
    elif change == "source":
        result["coverageSourceCore"] = "unselected-peer"
    elif change == "missing":
        del result["selectedCorePeerIds"]
    sequence = [{"state": "idle", "capabilities": {"sourcePolicies": [POLICY]}}, job, complete]
    monkeypatch.setattr(core, "POLL_SECONDS", .001)
    monkeypatch.setattr(core.ruleset, "ready_sample", lambda *_, **__: 2)
    with replies(sequence) as (url, calls):
        assert core.run(core.SnapshotSyncClient(replace(cfg, dkg_url=url)), cfg,
                        argparse.Namespace(wait=True, require_rules=True, timeout=5)) == (0 if change is None else 2)
    assert [body for method, _, body in calls if method == "POST"] == [payload]
    assert core.state.read_for_graph(cfg.context_graph_id)["graph_complete"] is (change is None)
