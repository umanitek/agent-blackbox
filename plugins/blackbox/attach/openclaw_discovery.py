"""Finding OpenClaw workspaces and reading their config and version."""

from __future__ import annotations

import json
import os
import re
from pathlib import Path
from typing import Any, Optional
from . import openclaw_json5

_OPENCLAW_MIN_VERSION = (2026, 6, 11)
_OPENCLAW_MIN_VERSION_TEXT = ".".join(str(part) for part in _OPENCLAW_MIN_VERSION)


def _openclaw_config_path(target: Path) -> Path:
    """Return the config file represented by an OpenClaw attach *target*.

    Standard targets are state directories containing ``openclaw.json``.  An
    explicit ``$OPENCLAW_CONFIG_PATH`` may point at any filename, so discovery
    returns that file directly and this helper keeps both forms supported.
    """
    try:
        if target.is_file() or target.suffix.lower() in {".json", ".json5"}:
            return target
    except OSError:
        pass
    return target / "openclaw.json"


def discover_openclaw_workspaces() -> list[Path]:
    """Return existing local OpenClaw config targets.

    Candidate roots come from ``$OPENCLAW_CONFIG_PATH``,
    ``$OPENCLAW_STATE_DIR``, ``$OPENCLAW_HOME/.openclaw``, and any
    ``~/.openclaw*`` profile directory.  Standard configs are represented by
    their state directory for stable dashboard labels; a custom config filename
    is represented by the file itself.  Results are de-duplicated by config
    path, preserving order.
    """
    candidates: list[Path] = []

    def _add(path: Optional[Path]) -> None:
        if path is None:
            return
        try:
            resolved = path.expanduser()
        except Exception:
            return
        if resolved not in candidates:
            candidates.append(resolved)

    def _add_config(path: Path) -> None:
        try:
            expanded = path.expanduser()
        except Exception:
            return
        # Keep the long-standing state-directory target shape for the normal
        # filename; only a true custom filename needs to travel as a file.
        _add(expanded.parent if expanded.name == "openclaw.json" else expanded)

    config_path = os.environ.get("OPENCLAW_CONFIG_PATH")
    if config_path and config_path.strip():
        _add_config(Path(config_path.strip()))

    state_dir = os.environ.get("OPENCLAW_STATE_DIR")
    if state_dir and state_dir.strip():
        _add(Path(state_dir.strip()))
    openclaw_home = os.environ.get("OPENCLAW_HOME")
    if openclaw_home and openclaw_home.strip():
        _add(Path(openclaw_home.strip()) / ".openclaw")

    # Glob every ``~/.openclaw*`` profile so any --profile/--dev workspace
    # created after the dashboard started still gets auto-attached.
    try:
        home = Path.home()
        for candidate in sorted(home.glob(".openclaw*")):
            if candidate.is_dir():
                _add(candidate)
    except Exception:  # pragma: no cover - defensive
        pass

    out: list[Path] = []
    seen_configs: set = set()
    for candidate in candidates:
        config = _openclaw_config_path(candidate)
        try:
            if not config.is_file():
                continue
            key = str(config.resolve())
        except OSError:
            continue
        if key in seen_configs:
            continue
        seen_configs.add(key)
        out.append(candidate)
    return out


def _load_openclaw_config(path: Path) -> dict[str, Any]:
    """Load an OpenClaw JSON/JSON5 config or raise without modifying it."""
    text = path.read_text(encoding="utf-8-sig")
    try:
        data = json.loads(text)
    except json.JSONDecodeError:
        data = json.loads(openclaw_json5._json5_to_json(text))
    if not isinstance(data, dict):
        raise ValueError("OpenClaw config root must be an object")
    return data


def _calendar_version(value: Any) -> Optional[tuple]:
    match = re.search(r"(\d{4})\.(\d{1,2})\.(\d{1,2})", str(value or ""))
    if not match:
        return None
    return tuple(int(part) for part in match.groups())


def _openclaw_version(data: dict[str, Any]) -> Optional[tuple]:
    meta = data.get("meta")
    return _calendar_version(meta.get("lastTouchedVersion")) if isinstance(meta, dict) else None
