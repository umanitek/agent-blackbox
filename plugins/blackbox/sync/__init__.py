"""Sync — keeping this node's copy of the verified threat graph current.

Owns the local DKG node's catch-up of Umanitek's verified graph and the
bookkeeping around it:

* :mod:`.state` — the last-sync record other surfaces read (status, dashboard).
* :mod:`.progress` — parses the node's durable catch-up progress (resume bookmark);
  :func:`read_durable_progress` and :func:`read_recovery_backlog` (how many
  verified assets the node still has to download) are re-exported for the dashboard.

* :func:`cmd_sync` — the ``blackbox sync`` command (internals: :mod:`.command`
  for the catch-up orchestration, :mod:`.managed_node` for the node process).

Usage: ``from ..sync import state as sync_state`` · ``from ..sync.progress import read_durable_progress``.
"""

from __future__ import annotations

import argparse

from pathlib import Path

from . import node_service, progress, state
from ..kernel import health
from ..kernel.config import load_blackbox_config
from ..kernel.dkg_client import DkgClient
from .command import cmd_sync as _sync_with_node
from .progress import read_durable_progress, read_recovery_backlog
from .snapshot_readiness import defaults as snapshot_defaults, validate_requested_profile as validate_snapshot_profile

__all__ = ["cmd_sync", "progress", "read_durable_progress", "read_recovery_backlog",
           "snapshot_defaults", "state", "validate_snapshot_profile"]


def cmd_sync(args: argparse.Namespace) -> int:
    """``blackbox sync``. On a machine with no DKG node for Blackbox — a Hermes plugin-catalog
    install brings the plugin only — it says how to install one instead of waiting on a node that
    is not there (exit 2 with ``--wait``); otherwise :func:`.command.cmd_sync`."""
    cfg = load_blackbox_config()
    if not health.node_installed(cfg, DkgClient(url=cfg.dkg_url, dkg_home=cfg.dkg_home).reachable()):
        print("Blackbox setup has not run, so there is no DKG node and no threat graph to sync. "
              f"To {health.NODE_INSTALL_HINT}.")
        return 2 if getattr(args, "wait", False) else 0
    node_service.trim_error_log(Path(cfg.dkg_home))   # every sync, the dashboard's included
    return _sync_with_node(args)
