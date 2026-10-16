"""The DKG 10.0.21 native route for Umanitek's default graph (KI-282).

On 10.0.21 a fresh node recovers the default graph by itself in about 35
minutes when its exact-batch stream and recovery prefetch are on, but both are
off by default and the older durable catch-up job got 0 batches in an hour.
These tests pin: which graphs take the native route, the node profile it
needs (and that an operator's own value wins), what is written to the node's
config.json, the service-manager rule that keeps the hourly-restart loop
(KI-059/KI-065) from coming back, and the observer's outcomes.
"""

import argparse
import json

import pytest
from _blackbox_loader import load_blackbox

config_mod = load_blackbox("kernel.config")
constants = load_blackbox("kernel.constants")
dkg_client = load_blackbox("kernel.dkg_client")
managed_node = load_blackbox("sync.managed_node")
native = load_blackbox("sync.native")
sync_command = load_blackbox("sync.command")

CUSTOM_GRAPH = "0x0000000000000000000000000000000000000001/someone-elses-graph"


def _cfg(dkg_home, **overrides):
    return config_mod.BlackboxConfig(dkg_home=str(dkg_home), **overrides)


@pytest.fixture
def dkg_home(tmp_path):
    (tmp_path / "config.json").write_text(json.dumps({"name": "agent-blackbox"}), encoding="utf-8")
    return tmp_path


@pytest.fixture(autouse=True)
def no_operator_switches(monkeypatch):
    """Each test starts with no operator override of the recovery speed-ups."""
    for name in managed_node._DKG_RECOVERY_SPEEDUPS:
        monkeypatch.delenv(name, raising=False)


# ------------------------------------------------------------------ which graphs


def test_the_default_graph_and_source_take_the_native_route(dkg_home):
    assert native.handles(_cfg(dkg_home))


def test_a_graph_the_operator_chose_keeps_the_older_route(dkg_home):
    assert not native.handles(_cfg(dkg_home, context_graph_id=CUSTOM_GRAPH))
    assert not native.handles(_cfg(dkg_home, graph_peer_id="12D3KooWsomeoneElse"))


# ------------------------------------------------------------------ the node profile


def test_the_default_graph_gets_the_native_profile_and_both_speedups(dkg_home):
    settings = managed_node.node_sync_settings(_cfg(dkg_home))

    assert settings["DKG_SYNC_RECONCILER_ENABLED"] == "0"
    assert settings["DKG_VM_RECONCILER_ENABLED"] == "1"
    assert settings["DKG_SYNC_ON_CONNECT_ENABLED"] == "1"   # KI-044: authority reaches subscribers
    assert settings["DKG_EXACT_BATCH_STREAM_ENABLED"] == "1"
    assert settings["DKG_VM_RECOVERY_PREFETCH_ENABLED"] == "1"


def test_another_graph_keeps_the_steady_profile_without_speedups(dkg_home):
    settings = managed_node.node_sync_settings(_cfg(dkg_home, context_graph_id=CUSTOM_GRAPH))

    assert settings == managed_node._DKG_STEADY_SYNC_SETTINGS


def test_an_operators_own_value_for_a_speedup_wins(dkg_home, monkeypatch):
    monkeypatch.setenv("DKG_EXACT_BATCH_STREAM_ENABLED", "0")

    settings = managed_node.node_sync_settings(_cfg(dkg_home))

    assert settings["DKG_EXACT_BATCH_STREAM_ENABLED"] == "0"
    assert settings["DKG_VM_RECOVERY_PREFETCH_ENABLED"] == "1"


def test_the_launch_environment_carries_the_speedups(dkg_home, monkeypatch):
    monkeypatch.setattr(managed_node, "_managed_dkg_node_executable", lambda _cfg: None)

    env = managed_node._dkg_sync_environment(_cfg(dkg_home))

    assert env["DKG_EXACT_BATCH_STREAM_ENABLED"] == "1"
    assert env["DKG_VM_RECOVERY_PREFETCH_ENABLED"] == "1"
    assert env["DKG_SYNC_RECONCILER_ENABLED"] == "0"


# ------------------------------------------------------------------ config.json


def test_the_native_profile_is_written_to_the_nodes_own_config(dkg_home):
    assert managed_node._set_persisted_dkg_sync_state(_cfg(dkg_home)) is True

    data = json.loads((dkg_home / "config.json").read_text(encoding="utf-8"))
    assert data["syncReconcilerEnabled"] is False
    assert data["vmReconcilerEnabled"] is True
    assert data["vmRecoveryPrefetchEnabled"] is True
    assert data["syncOnConnectEnabled"] is True
    assert data["syncGlobalMaxInflight"] == 1 and data["syncGlobalQueueLimit"] == 4
    assert data["name"] == "agent-blackbox"                       # unrelated keys survive


def test_an_environment_only_switch_never_lands_in_config(dkg_home):
    managed_node._set_persisted_dkg_sync_state(_cfg(dkg_home))

    text = (dkg_home / "config.json").read_text(encoding="utf-8")
    assert "xactBatchStream" not in text     # DKG has no config key for it


def test_writing_the_same_profile_twice_reports_no_change(dkg_home):
    cfg = _cfg(dkg_home)
    managed_node._set_persisted_dkg_sync_state(cfg)

    assert managed_node._set_persisted_dkg_sync_state(cfg) is False


def test_another_graph_writes_the_steady_profile(dkg_home):
    managed_node._set_persisted_dkg_sync_state(_cfg(dkg_home, context_graph_id=CUSTOM_GRAPH))

    data = json.loads((dkg_home / "config.json").read_text(encoding="utf-8"))
    assert data["syncReconcilerEnabled"] is True
    assert "vmRecoveryPrefetchEnabled" not in data


# ------------------------------------------------------------------ the restart rule


def test_a_node_blackbox_launched_must_carry_every_switch(dkg_home, monkeypatch):
    monkeypatch.setattr(managed_node, "_daemon_pid", lambda _cfg: 4242)
    monkeypatch.setattr(managed_node, "_systemd_unit_of", lambda _pid: None)

    expected = managed_node.expected_node_settings(_cfg(dkg_home))

    assert expected["DKG_EXACT_BATCH_STREAM_ENABLED"] == "1"


def test_a_service_supervised_node_is_not_restarted_for_an_env_only_switch(dkg_home, monkeypatch, caplog):
    """KI-059/KI-065 must not come back: a restart through the unit cannot add
    the stream switch, so counting it would restart the node every hour."""
    monkeypatch.setattr(managed_node, "_daemon_pid", lambda _cfg: 4242)
    monkeypatch.setattr(managed_node, "_systemd_unit_of", lambda _pid: "blackbox-dkg.service")

    with caplog.at_level("WARNING"):
        expected = managed_node.expected_node_settings(_cfg(dkg_home))

    assert "DKG_EXACT_BATCH_STREAM_ENABLED" not in expected
    assert expected["DKG_VM_RECOVERY_PREFETCH_ENABLED"] == "1"     # config-backed: still counted
    assert "re-run the Blackbox installer" in caplog.text


# ------------------------------------------------------------------ the observer


class _Rules:
    def __init__(self, count):
        self.count = count

    def source_count(self, source):
        return self.count if source == "public" else 0


class _Node:
    """A node double: answers subscribe, and records what the observer asked."""

    def __init__(self, subscribe_error=None):
        self.subscribe_error = subscribe_error
        self.subscribes = 0

    def subscribe_context_graph(self, cg_id, **_kw):
        self.subscribes += 1
        if self.subscribe_error is not None:
            raise self.subscribe_error
        return {"subscribed": cg_id}


@pytest.fixture
def states(monkeypatch):
    seen = []
    monkeypatch.setattr(native.sync_state, "write", lambda status, **d: seen.append((status, d)))
    monkeypatch.setattr(native.time, "sleep", lambda _s: None)
    return seen


def _args(**kw):
    return argparse.Namespace(**{"wait": True, "require_rules": True, "timeout": 60, **kw})


def test_the_observer_returns_once_verified_rules_are_usable(dkg_home, monkeypatch, states, capsys):
    counts = iter([0, 0, 1234])
    monkeypatch.setattr(native.ruleset, "refresh", lambda *_a, **_k: _Rules(next(counts)))
    node = _Node()

    assert native.run(node, _cfg(dkg_home), _args()) == 0

    assert node.subscribes == 1                               # subscribed once, then only observed
    assert "Loaded 1,234 verified detection rules" in capsys.readouterr().out
    status, details = states[-1]
    assert status == "partial" and details["public_entries"] == 1234
    assert details["detection_ready"] is True and details["graph_complete"] is False


def test_no_rules_by_the_deadline_fails_a_required_wait(dkg_home, monkeypatch, states):
    clock = iter(range(0, 10_000, 30))
    monkeypatch.setattr(native.time, "monotonic", lambda: float(next(clock)))
    monkeypatch.setattr(native.ruleset, "refresh", lambda *_a, **_k: _Rules(0))

    assert native.run(_Node(), _cfg(dkg_home), _args(timeout=90)) == 2
    assert states[-1][0] == "failed"


def test_without_wait_the_observer_reports_and_returns_zero(dkg_home, monkeypatch, states):
    monkeypatch.setattr(native.ruleset, "refresh", lambda *_a, **_k: _Rules(0))

    assert native.run(_Node(), _cfg(dkg_home), _args(wait=False, require_rules=False)) == 0
    assert states[-1][0] == "partial"


def test_a_permanent_refusal_stops_the_observer_at_once(dkg_home, monkeypatch, states):
    refusal = dkg_client.DkgError("forbidden", status_code=403)
    monkeypatch.setattr(native.ruleset, "refresh", lambda *_a, **_k: _Rules(0))
    node = _Node(subscribe_error=refusal)

    assert native.run(node, _cfg(dkg_home), _args()) == 2
    assert node.subscribes == 1
    assert "DKG subscription unavailable" in states[-1][1]["error"]


def test_a_temporary_node_error_is_retried(dkg_home, monkeypatch, states):
    calls = {"n": 0}

    class Flaky(_Node):
        def subscribe_context_graph(self, cg_id, **_kw):
            calls["n"] += 1
            if calls["n"] == 1:
                raise dkg_client.DkgError("node starting", status_code=503)
            return {"subscribed": cg_id}

    counts = iter([0, 7])
    monkeypatch.setattr(native.ruleset, "refresh", lambda *_a, **_k: _Rules(next(counts)))

    assert native.run(Flaky(), _cfg(dkg_home), _args()) == 0
    assert calls["n"] == 2


def test_a_compile_error_keeps_observing_instead_of_failing(dkg_home, monkeypatch, states):
    outcomes = iter([native.ruleset.RulesetRefreshUnavailable("store busy"), _Rules(5)])

    def refresh(*_a, **_k):
        outcome = next(outcomes)
        if isinstance(outcome, Exception):
            raise outcome
        return outcome

    monkeypatch.setattr(native.ruleset, "refresh", refresh)

    assert native.run(_Node(), _cfg(dkg_home), _args()) == 0


# ------------------------------------------------------------------ the dispatcher


def test_a_plain_sync_of_the_default_graph_is_observed_natively(dkg_home, monkeypatch):
    routes = []
    monkeypatch.setattr(sync_command, "load_blackbox_config", lambda: _cfg(dkg_home))
    monkeypatch.setattr(sync_command.managed_node, "_uses_managed_dkg", lambda *_a: False)
    monkeypatch.setattr(native, "sync", lambda _args: routes.append("native") or 0)
    monkeypatch.setattr(sync_command, "_cmd_sync_impl", lambda _args: routes.append("catch-up") or 0)

    sync_command.cmd_sync(argparse.Namespace(wait=False, require_rules=False, timeout=60))

    assert routes == ["native"]


def test_a_plain_sync_of_another_graph_keeps_the_catch_up_route(dkg_home, monkeypatch):
    routes = []
    monkeypatch.setattr(sync_command, "load_blackbox_config", lambda: _cfg(dkg_home, context_graph_id=CUSTOM_GRAPH))
    monkeypatch.setattr(sync_command.managed_node, "_uses_managed_dkg", lambda *_a: False)
    monkeypatch.setattr(native, "sync", lambda _args: routes.append("native") or 0)
    monkeypatch.setattr(sync_command, "_cmd_sync_impl", lambda _args: routes.append("catch-up") or 0)

    sync_command.cmd_sync(argparse.Namespace(wait=False, require_rules=False, timeout=60))

    assert routes == ["catch-up"]
