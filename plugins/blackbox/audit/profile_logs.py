"""Fold the logs a Hermes profile kept in its own Blackbox folder into the shared ones (2026-11-19).

Until 2026-11-19 every named Hermes profile — Blackbox's own assistant included — kept a
private ``<profile>/blackbox/`` folder: its own logs (the dashboard never read them), no compiled
rules, settings copied once. Now one folder serves every profile (``constants.hermes_root``).
This moves what the old folders recorded into the shared logs, in time order, and renames each
old folder ``blackbox.folded-<time>`` so it is folded once and nothing is deleted.

Usage::

    fold_profile_logs()          # at dashboard start; returns how many records joined
"""

from __future__ import annotations

import json
import logging
import time
from pathlib import Path
from typing import Optional

from ..kernel import constants
from ..kernel.bounded_files import atomic_write
from . import log_store

logger = logging.getLogger(__name__)

#: The logs a profile's Blackbox wrote (the same names as in the shared folder).
LOG_NAMES = ("findings.jsonl", "audit.jsonl", "file_access.jsonl", "dependencies.jsonl")


def _time_of(line: str) -> float:
    try:
        value = json.loads(line).get("ts")
        return float(value) if value is not None else 0.0
    except (ValueError, TypeError, AttributeError):
        return 0.0


def _merge(old: Path, shared: Path) -> int:
    """Merge *old* into *shared* by record time under the logs lock; how many records joined."""
    joining = [line for line in old.read_text(encoding="utf-8-sig", errors="replace").splitlines() if line.strip()]
    if not joining:
        return 0
    shared.parent.mkdir(parents=True, exist_ok=True)
    with log_store._logs_lock(shared):
        current = shared.read_text(encoding="utf-8-sig", errors="replace").splitlines() if shared.exists() else []
        merged = sorted([line for line in current if line.strip()] + joining, key=_time_of)   # stable: equal times keep order
        atomic_write(shared, "\n".join(merged) + "\n")
    return len(joining)


def fold_profile_logs(root: Optional[Path] = None) -> int:
    """Fold every named profile's old ``blackbox/`` logs under *root* (the main Hermes home) into
    the shared Blackbox folder. Fail-open: a folder that cannot be read or renamed is left as it
    is (and said so) — the dashboard still starts."""
    root = Path(root) if root is not None else constants.hermes_root()
    shared = constants.blackbox_home()
    joined = 0
    for old in sorted((root / "profiles").glob("*/blackbox")):
        try:
            if not old.is_dir() or old.resolve() == shared.resolve():
                continue
            for name in LOG_NAMES:
                if (old / name).is_file():
                    joined += _merge(old / name, shared / name)
            old.rename(old.with_name(f"blackbox.folded-{time.strftime('%Y%m%dT%H%M%S')}"))
        except OSError as exc:
            logger.warning("blackbox: could not fold %s into the shared logs (%s); it stays where it is", old, exc)
    if joined:
        logger.info("blackbox: %d records from Hermes profiles joined the shared logs", joined)
    return joined
