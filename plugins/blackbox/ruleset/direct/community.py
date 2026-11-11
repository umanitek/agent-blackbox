"""Persist only the existing community read model beside action-scoped public reads.

The same signed reader, daily budgets, revocations, 90-day retention and
identifier-only materialization apply in both detection backends. No public
snapshot is exported into this file. Profile-local paths are resolved per call.
"""
from copy import deepcopy
import json
import time

from ...kernel import constants, yaml_files
from ...kernel.dkg_client import DkgClient
from .. import community_tier, disk_cache, locks
from ..compiler import Ruleset


def _path():
    return constants.blackbox_home() / "community-read-model.json"


def read(cfg):
    try:
        raw = json.loads(_path().read_text(encoding="utf-8-sig"))
        if raw.get("context_graph_id") != cfg.context_graph_id:
            return None
        return disk_cache._deserialize(raw)
    except FileNotFoundError:
        # Switching backends must keep first-seen/retention history. Only the
        # community model is carried over; public rules never enter this file.
        prior = disk_cache._read_cache()
        return prior if prior is not None and prior.context_graph_id == cfg.context_graph_id else None
    except (OSError, ValueError, TypeError, AttributeError):
        return None


def attach(rules, cfg):
    prior = read(cfg)
    if prior is None:
        return False
    rules.community = deepcopy(prior.community)
    rules.community_paused = prior.community_paused
    rules.community_empty_since = prior.community_empty_since
    rules.community_fingerprint = prior.community_fingerprint
    community_tier.materialize_community_rules(rules)
    return True


def refresh(cfg, client=None):
    with locks._ruleset_refresh_lock(blocking=False) as acquired:
        if not acquired:
            return False
        client = client or DkgClient.for_config(cfg)
        prior = read(cfg)
        rules = Ruleset(context_graph_id=cfg.context_graph_id)
        community_tier.apply_community_tier(rules, client, cfg, prior)
        if getattr(rules, "community_read_unavailable", False):
            return False  # keep the previous persisted generation intact
        rules.synced_at = time.time()
        yaml_files.atomic_write(_path(), json.dumps(disk_cache._serialize(rules)))
        return True
