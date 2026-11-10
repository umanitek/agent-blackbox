"""Validate direct graph mode before any sync side effect."""
from .. import ruleset
from ..kernel.dkg_client import DkgError
from . import native


def valid(cfg):
    if getattr(cfg, "snapshot_sync_error", ""):
        # The operator asked for snapshot sync and the block cannot be used: never fall
        # back to another sync mode on our own.
        print(f"snapshot_sync in config.yaml is invalid: {cfg.snapshot_sync_error}. "
              "Correct or remove that block, then run sync again.")
        return False
    if getattr(cfg, "detection_backend", "legacy-cache") != "dkg":
        return True
    try:
        ruleset.validate_config(cfg)
        if native.handles(cfg) or cfg.snapshot_sync is not None:
            return True
        print("Direct graph sync currently requires the default native recovery route.")
    except DkgError as exc:
        print(f"Direct graph configuration unavailable: {exc}")
    return False
