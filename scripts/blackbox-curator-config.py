#!/usr/bin/env python3
"""Keep operator-owned Blackbox curator settings present across restarts."""

from __future__ import annotations

import argparse
import json
import os
import stat
import tempfile
from pathlib import Path


def _atomic_write_text(path: Path, text: str) -> None:
    """Replace ``path`` without changing its permissions."""
    original_mode = stat.S_IMODE(path.stat().st_mode)
    fd, temporary_name = tempfile.mkstemp(
        prefix=f".{path.name}.", suffix=".tmp", dir=path.parent
    )
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as handle:
            handle.write(text)
            handle.flush()
            os.fsync(handle.fileno())
        os.chmod(temporary_name, original_mode)
        os.replace(temporary_name, path)
    finally:
        try:
            os.unlink(temporary_name)
        except FileNotFoundError:
            pass


def ensure_graph_auto_approval(config_path: Path, graph_id: str) -> bool:
    """Ensure ``graph_id`` is configured and auto-approved; preserve all else."""
    with config_path.open(encoding="utf-8") as handle:
        config = json.load(handle)
    if not isinstance(config, dict):
        raise ValueError(f"DKG config must be a JSON object: {config_path}")

    changed = False
    for key in ("contextGraphs", "autoApproveJoinRequests"):
        current = config.get(key)
        if current is None:
            current = []
        if not isinstance(current, list) or not all(isinstance(item, str) for item in current):
            raise ValueError(f"DKG config field {key!r} must be a string array")
        if graph_id not in current:
            config[key] = [*current, graph_id]
            changed = True

    desired = {
        "syncOnConnectEnabled": False,
        "syncReconcilerEnabled": False,
    }
    for key, value in desired.items():
        if config.get(key) != value:
            config[key] = value
            changed = True

    promote_queue = config.get("promoteQueue")
    if promote_queue is None:
        promote_queue = {}
    if not isinstance(promote_queue, dict):
        raise ValueError("DKG config field 'promoteQueue' must be an object")
    updated_queue = {**promote_queue, "workerConcurrency": 1, "pollIntervalMs": 1000}
    if promote_queue != updated_queue:
        config["promoteQueue"] = updated_queue
        changed = True

    if not changed:
        return False

    _atomic_write_text(config_path, json.dumps(config, indent=2) + "\n")
    return True


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Ensure a curator keeps graph-scoped DKG join auto-approval enabled."
    )
    parser.add_argument("--config", type=Path, required=True)
    parser.add_argument("--graph", required=True)
    args = parser.parse_args()
    if not args.graph.strip():
        parser.error("--graph must not be empty")
    changed = ensure_graph_auto_approval(args.config, args.graph)
    print("updated" if changed else "already configured")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
