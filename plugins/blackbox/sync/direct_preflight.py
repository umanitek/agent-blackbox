"""Validate direct graph mode before any sync side effect."""
from .. import ruleset
from ..kernel.dkg_client import DkgError
from . import native


def valid(cfg):
    if getattr(cfg, "detection_backend", "legacy-cache") != "dkg":
        return True
    try:
        ruleset.validate_config(cfg)
        if native.handles(cfg):
            return True
        print("Direct graph sync currently requires the default native recovery route.")
    except DkgError as exc:
        print(f"Direct graph configuration unavailable: {exc}")
    return False
