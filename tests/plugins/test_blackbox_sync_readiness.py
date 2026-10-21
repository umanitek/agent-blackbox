"""Defaults require real local capability and recent authenticated source evidence."""
import argparse
from copy import deepcopy

import pytest
from _blackbox_loader import load_blackbox
from tests.plugins.blackbox_sync_fixtures import replies, completed_job, QUERY_CAPABILITIES

ready = load_blackbox("sync.snapshot_readiness")
profile = load_blackbox("setup.sync_profile")
yaml_files = load_blackbox("kernel.yaml_files")
config = load_blackbox("kernel.config")


@pytest.mark.parametrize("path,value", [
    (("id",), None), (("capabilities",), {}),
    *(( ("state",), value) for value in ("idle", "running", "failed")),
    *(( ("finishedAt",), value) for value in (0, 10**16, 10**400, "now", float("inf"), float("nan"))),
    (("request", "contextGraphId"), "other/graph"), (("request", "sourcePolicy"), "advertised-core"),
    (("result", "coverageSourceCore"), "unselected-core"), (("result", "current"), False),
    (("result", "committed"), 11), (("result", "assets"), 0), (("result", "assets"), True),
])
def test_no_default_from_unsupported_unavailable_or_unproven_sources(tmp_path, path, value):
    job = completed_job()
    target = job
    for key in path[:-1]:
        target = target[key]
    target[path[-1]] = value
    with replies([job]) as (url, calls):
        entry = {"dkg_url": url, "dkg_home": str(tmp_path), "community_graph_id": ""}
        assert ready.defaults(entry) == {}
    assert [method for method, _, _ in calls] == ["GET"]


@pytest.mark.parametrize("community", [None, "owner/community"])
def test_community_never_disabled_even_if_sharing_is_off(tmp_path, community, monkeypatch):
    monkeypatch.setenv("BLACKBOX_COMMUNITY_GRAPH_ID", "")  # Empty env does not override saved/default community.
    with replies([completed_job()]) as (url, calls):
        entry = {"dkg_url": url, "dkg_home": str(tmp_path), "report": False}
        if community is not None:
            entry["community_graph_id"] = community
        before = deepcopy(entry)
        assert ready.defaults(entry) == {} and entry == before
    assert not calls


@pytest.mark.parametrize("transport", [None, "exact", "bulk"])
def test_compatible_public_only_profile_can_adopt_verified_default_without_starting_a_job(tmp_path, transport):
    job = completed_job()
    if transport:
        job["request"]["transport"] = transport
    with replies([job, QUERY_CAPABILITIES]) as (url, calls):
        entry = {"community_graph_id": "", "dkg_url": url, "dkg_home": str(tmp_path)}
        selected = ready.defaults(entry)
        cfg = config.load_blackbox_config(entry={**entry, **selected})
    assert cfg.detection_backend == "dkg" and cfg.community_graph_id == ""
    assert cfg.snapshot_sync.source_policy == "DKG_Core_chain_cache"
    assert [(method, path) for method, path, _ in calls] == [("GET", ready.PATH), ("GET", "/api/query/bounded")]


@pytest.mark.parametrize("capabilities", [{}, {"version": 2, "chainEvidenceModes": ["core-cache"]},
    {"version": 1, "chainEvidenceModes": ["rpc-only"]}, {"version": True, "chainEvidenceModes": ["core-cache"]}])
def test_snapshot_support_without_matching_bounded_queries_keeps_ordinary_sync(tmp_path, capabilities):
    with replies([completed_job(), capabilities]) as (url, calls):
        assert ready.defaults({"community_graph_id": "", "dkg_url": url, "dkg_home": str(tmp_path)}) == {}
    assert all(method == "GET" for method, _, _ in calls)


def test_explicit_setup_refuses_community_loss_without_mutating_config(tmp_path, monkeypatch):
    monkeypatch.setenv("HERMES_HOME", str(tmp_path))
    path = tmp_path / "config.yaml"
    yaml_files.dump_yaml(path, {"plugins": {"entries": {"blackbox": {"report": False, "community_shadow": True}}}})
    before = path.read_bytes()
    with pytest.raises(ValueError, match="DIRECT_COMMUNITY_MIGRATION_REQUIRED"):
        profile.configure(argparse.Namespace(dkg_core_chain_cache=True))
    assert path.read_bytes() == before


def test_existing_explicit_profile_is_never_automatically_replaced(tmp_path, monkeypatch):
    monkeypatch.setenv("HERMES_HOME", str(tmp_path))
    path = tmp_path / "config.yaml"
    value = {"community_graph_id": "", **ready.requested_profile()}
    yaml_files.dump_yaml(path, {"plugins": {"entries": {"blackbox": value}}})
    before = path.read_bytes()
    profile.configure(argparse.Namespace())
    assert path.read_bytes() == before


@pytest.mark.parametrize("address", ["http://127.0.0.1:1", "https://remote.invalid:9320"])
def test_unreachable_or_nonlocal_daemon_cannot_enable_default(tmp_path, address):
    assert ready.defaults({"community_graph_id": "", "dkg_url": address, "dkg_home": str(tmp_path)}) == {}
