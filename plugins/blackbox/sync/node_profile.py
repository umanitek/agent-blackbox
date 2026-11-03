"""The managed DKG node's sync profile: which sync settings it should run with.

Holds the settings tables (environment-variable name → value, and → the
node's config.json key), reads what the node has persisted, writes the
profile into config.json, and checks whether a live node runs it. The
process side — starting, restarting, waiting — stays in :mod:`.managed_node`.
"""

from __future__ import annotations

import json
import os
import psutil
from pathlib import Path

from ..kernel.config import BlackboxConfig
from . import process_limits
from ..kernel.bounded_files import atomic_write

#: The node's own sync limits (DKG 10.0.25 defaults: 10 transfers at once, a queue of 20),
#: so the verified download and the graph's shared memory (the community) sync side by
#: side. Blackbox ran the node with ONE slot and no queue until 2026-10-22; under one graph
#: the community catch-ups then starved the verified download (30 of 565 assets after 40
#: minutes). Bench with 10 slots and the community on from the start: the whole graph in
#: about 30 minutes, no deferred fetch, no store recovery, ~4.4 GB of 8 GB in use.
#: Existing installs move to these values at their next sync (one node restart).
_DKG_STEADY_SYNC_SETTINGS = {
    "DKG_SYNC_ON_CONNECT_ENABLED": "1",
    "DKG_SYNC_RECONCILER_ENABLED": "1",
    "DKG_DURABLE_SYNC_ENABLED": "1",
    "DKG_SYNC_GLOBAL_MAX_INFLIGHT": "10",
    "DKG_SYNC_GLOBAL_QUEUE_LIMIT": "20",
}

#: The native profile for Umanitek's default graph on DKG 10.0.21+ (KI-282):
#: the node's own VM reconciler recovers the graph, and the older periodic sync
#: reconciler is off so it does not compete with that recovery for sync slots.
#: Connection-time sync stays on (KI-044). See :mod:`.native`.
_DKG_NATIVE_SYNC_SETTINGS = {
    **_DKG_STEADY_SYNC_SETTINGS,
    "DKG_SYNC_RECONCILER_ENABLED": "0",
    "DKG_VM_RECONCILER_ENABLED": "1",
}

#: The 10.0.21 recovery speed-ups, both OFF by default in the node: the exact
#: batch stream (a core streams verified batches instead of one asset per
#: request) and preparing the next batch while the current one transfers.
#: An operator's own value in the environment always wins.
_DKG_RECOVERY_SPEEDUPS = {
    "DKG_EXACT_BATCH_STREAM_ENABLED": "1",
    "DKG_VM_RECOVERY_PREFETCH_ENABLED": "1",
}

#: Switches the node reads ONLY from its environment (no config.json key in
#: DKG 10.0.21, dkg-agent sync/backpressure.js resolveExactBatchStreamEnabled).
#: Whoever launches the node must pass them.
_DKG_ENV_ONLY_SETTINGS = frozenset({"DKG_EXACT_BATCH_STREAM_ENABLED"})

_DKG_CONFIG_SYNC_SETTINGS = {
    "DKG_SYNC_ON_CONNECT_ENABLED": "syncOnConnectEnabled",
    "DKG_SYNC_RECONCILER_ENABLED": "syncReconcilerEnabled",
    "DKG_VM_RECONCILER_ENABLED": "vmReconcilerEnabled",
    "DKG_VM_RECOVERY_PREFETCH_ENABLED": "vmRecoveryPrefetchEnabled",
    "DKG_DURABLE_SYNC_ENABLED": "durableSyncEnabled",
    "DKG_SYNC_GLOBAL_MAX_INFLIGHT": "syncGlobalMaxInflight",
    "DKG_SYNC_GLOBAL_QUEUE_LIMIT": "syncGlobalQueueLimit",
}

#: config.json keys DKG reads as integers; every other mapped key is a boolean.
_INTEGER_CONFIG_KEYS = frozenset({"syncGlobalMaxInflight", "syncGlobalQueueLimit"})


def node_sync_settings(cfg: BlackboxConfig) -> dict[str, str]:
    """The node settings this configuration needs, keyed by DKG env-var name.

    Umanitek's default graph gets the native profile plus the recovery
    speed-ups (an operator's explicit environment value wins); any other
    graph keeps the steady profile, unchanged.

    Usage::

        env.update(node_sync_settings(cfg))
    """
    from . import native   # sibling module; lazy so the two never import-cycle

    inflight, queue = process_limits.sync_slots()
    if cfg.snapshot_sync is not None:
        # The VM reconciler stays ON beside the snapshot download: its pass line
        # (``pending=N`` in daemon.log) is the only place the node states the graph's
        # size mid-sync, and the dashboard's progress bar reads it (Amos, 2026-10-28:
        # keep the percentage). Its cost to the snapshot's speed is measured on a bench.
        return {**_DKG_NATIVE_SYNC_SETTINGS,
                "DKG_SYNC_GLOBAL_MAX_INFLIGHT": str(inflight), "DKG_SYNC_GLOBAL_QUEUE_LIMIT": str(queue),
                "DKG_SYNC_ON_CONNECT_ENABLED": "0",
                "DKG_EXACT_BATCH_STREAM_ENABLED": "1", "DKG_VM_RECOVERY_PREFETCH_ENABLED": "0"}
    settings = dict(_DKG_NATIVE_SYNC_SETTINGS if native.handles(cfg) else _DKG_STEADY_SYNC_SETTINGS)
    # The tables carry the ≥ 8 GB values; a smaller machine runs fewer transfers at once.
    settings["DKG_SYNC_GLOBAL_MAX_INFLIGHT"], settings["DKG_SYNC_GLOBAL_QUEUE_LIMIT"] = str(inflight), str(queue)
    if native.handles(cfg):
        for name, default in _DKG_RECOVERY_SPEEDUPS.items():
            settings[name] = os.environ.get(name, default)
    return settings


def _persisted_dkg_sync_settings(cfg: BlackboxConfig) -> dict[str, str]:
    """Return the node's persisted sync settings, keyed by DKG env-var name.

    Values come from ``<dkg_home>/config.json`` (normalized to the env string
    form: booleans as ``"1"``/``"0"``, integers as decimal strings). A setting
    absent from the file is omitted, so callers can tell "not persisted" from
    "persisted as X".
    """
    try:
        persisted = json.loads(
            (Path(cfg.dkg_home) / "config.json").read_text(encoding="utf-8-sig")
        )
    except (OSError, ValueError, TypeError):
        return {}
    settings: dict[str, str] = {}
    if isinstance(persisted, dict):
        for env_name, config_name in _DKG_CONFIG_SYNC_SETTINGS.items():
            value = persisted.get(config_name)
            if isinstance(value, bool):
                settings[env_name] = "1" if value else "0"
            elif isinstance(value, int):
                settings[env_name] = str(value)
    return settings


def _managed_dkg_sync_mode_matches(
    cfg: BlackboxConfig,
    expected: dict[str, str],
) -> bool:
    """Return whether the live worker's EFFECTIVE sync settings equal *expected*.

    DKG resolves each sync setting as environment variable, else
    ``config.json``, else its built-in default (dkg-agent
    ``sync/backpressure.js`` ``resolveBooleanSwitch`` /
    ``resolveSyncGlobalBackpressure``). So a worker launched WITHOUT the
    variables — e.g. by a systemd unit running ``dkg start --foreground`` —
    still runs the persisted values. Comparing only the launch environment
    (the pre-2026-09-26 behavior) misread every service-managed node as stale
    and restarted it on every hourly sync (KI-059/KI-065): the source of the
    "hourly self-exit". A variable that IS set still overrides config, so a
    worker launched with a stale bootstrap override is still detected.
    """
    from .node_process import managed_daemon_pid   # lazy: node_profile stays importable alone

    pid = managed_daemon_pid(cfg)   # never a stale daemon.pid (KI-312)
    if pid is None:
        return False
    try:
        process_env = psutil.Process(pid).environ()
    except (OSError, psutil.Error):
        return False
    persisted = _persisted_dkg_sync_settings(cfg)
    for name, value in expected.items():
        effective = process_env.get(name) or persisted.get(name)
        if effective != value:
            return False
    return True


def _set_persisted_dkg_sync_state(cfg: BlackboxConfig) -> bool:
    """Persist this configuration's node profile in config.json; report whether it changed.

    Writing the profile into the node's own config (not only the launch
    environment) is what makes it hold whoever starts the node: Blackbox, the
    installer, a systemd unit, or ``dkg start`` by hand (on 2026-10-04 a node
    started by ``dkg hermes setup`` ran without the switches). Older releases
    also left nodes in a bootstrap-only mode after an interrupted sync; every
    sync repairs that here without touching DKG's durable checkpoints.
    """
    path = Path(cfg.dkg_home) / "config.json"
    data = json.loads(path.read_text(encoding="utf-8-sig"))
    original = json.dumps(data, sort_keys=True)
    for env_name, value in node_sync_settings(cfg).items():
        key = _DKG_CONFIG_SYNC_SETTINGS.get(env_name)
        if key is None:
            continue   # an environment-only switch: see _DKG_ENV_ONLY_SETTINGS
        data[key] = int(value) if key in _INTEGER_CONFIG_KEYS else value == "1"
    # One graph (2026-10-16): the community's reports live in the verified graph's
    # shared memory, and reports written while this node was offline come back only
    # through the shared-memory step of sync-on-connect.
    data["syncSharedMemoryOnConnect"] = True
    if original == json.dumps(data, sort_keys=True):
        return False
    atomic_write(path, json.dumps(data, indent=2) + "\n")
    return True
