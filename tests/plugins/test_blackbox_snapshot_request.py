"""Resolved transports are additive at admission, immutable during observation."""
import argparse
from copy import deepcopy
from dataclasses import replace

import pytest
from _blackbox_loader import load_blackbox
from tests.plugins.blackbox_sync_fixtures import replies

config = load_blackbox("kernel.config")
settings = load_blackbox("kernel.snapshot_config")
core = load_blackbox("sync.core_snapshot")


def configuration(tmp_path):
    return config.BlackboxConfig(detection_backend="dkg", dkg_home=str(tmp_path),
        snapshot_sync=settings.SnapshotSyncConfig("1", ("configured-core",), "core-cache"))


def request_for(cfg):
    return {"contextGraphId": cfg.context_graph_id, "onChainId": "1",
            "trustedCorePeerIds": ["configured-core"], "mode": "core-cache"}


@pytest.mark.parametrize("transport", [None, "exact", "bulk"])
@pytest.mark.parametrize("rejoin", [False, True])
def test_transport_selection_preserves_one_owned_job(tmp_path, monkeypatch, transport, rejoin):
    cfg = configuration(tmp_path)
    payload = request_for(cfg)
    resolved = dict(payload, **({"transport": transport} if transport else {}))
    running = {"id": "owned", "state": "running", "request": resolved}
    complete = {**running, "state": "complete", "result": {
        "mode": "core-cache", "completeAsOfSnapshot": True, "current": True,
        "assets": 12, "committed": 12}}
    sequence = ([{"state": "idle"}] if not rejoin else []) + [running, complete]
    monkeypatch.setattr(core, "POLL_SECONDS", .001)
    monkeypatch.setattr(core.ruleset, "ready_sample", lambda *_, **__: 3)
    with replies(sequence) as (url, calls):
        cfg = replace(cfg, dkg_url=url)
        assert core.run(core.SnapshotSyncClient(cfg), cfg,
                        argparse.Namespace(wait=True, require_rules=True, timeout=5)) == 0
    posts = [body for method, path, body in calls if method == "POST" and path == core.PATH]
    assert posts == ([] if rejoin else [payload])
    assert not sequence
    observed = core.state.read_for_graph(cfg.context_graph_id)
    assert observed["job_id"] == "owned" and observed["graph_complete"] is True


CHANGES = [
    {"request": {"contextGraphId": "different-graph"}},
    {"request": {"onChainId": "2"}},
    {"request": {"mode": "rpc-only"}},
    {"request": {"trustedCorePeerIds": ["other-core"]}},
    {"request": {"unexpected": True}},
    {"request": {"transport": "unknown"}},
    {"request": {"transport": None}},
    {"request": {"transport": {"invalid": True}}},
    {"request": None},
    {"drop": "mode"},
    {"drop": "transport", "poll_only": True},
    {"request": {"transport": "exact"}, "poll_only": True},
    {"id": "replacement", "poll_only": True},
]


@pytest.mark.parametrize("stage,change", [(stage, change) for stage in ("post", "rejoin", "poll")
    for change in CHANGES if not change.get("poll_only") or stage == "poll"])
def test_request_and_job_fences_survive_transport_compatibility(tmp_path, monkeypatch, stage, change):
    cfg = configuration(tmp_path)
    running = {"id": "owned", "state": "running", "request": {**request_for(cfg), "transport": "bulk"}}
    changed = deepcopy(running)
    if "request" in change:
        if change["request"] is None:
            changed["request"] = None
        else:
            changed["request"].update(change["request"])
    if "drop" in change:
        del changed["request"][change["drop"]]
    if "id" in change:
        changed["id"] = change["id"]
    sequence = {"post": [{"state": "idle"}, changed], "rejoin": [changed],
                "poll": [{"state": "idle"}, running, changed]}[stage]
    monkeypatch.setattr(core, "POLL_SECONDS", .001)
    monkeypatch.setattr(core.ruleset, "ready_sample", lambda *_, **__: 3)
    with replies(sequence) as (url, calls):
        cfg = replace(cfg, dkg_url=url)
        assert core.run(core.SnapshotSyncClient(cfg), cfg,
                        argparse.Namespace(wait=True, require_rules=True, timeout=5)) == 2
    assert not sequence
    assert sum(method == "POST" for method, _, _ in calls) == (stage != "rejoin")
    observed = core.state.read_for_graph(cfg.context_graph_id)
    assert observed["error"] == ("ANOTHER_SNAPSHOT_JOB_IS_RUNNING" if stage == "rejoin" else "SNAPSHOT_JOB_CHANGED")
    assert observed["graph_complete"] is False
