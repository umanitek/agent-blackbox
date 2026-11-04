"""YAML config files (Hermes ``config.yaml`` and friends), read and written safely.

:func:`load_yaml` never raises (unreadable -> ``{}``); :func:`dump_yaml` writes
through :func:`atomic_write` (temp file + rename) so a concurrent reader never
sees a torn file. ``yaml`` is None only if PyYAML is somehow absent.

A ``config.yaml`` is the user's own file: Hermes Desktop writes a 2,400-line one,
almost all of it comments that document every setting. Where Hermes ships its
comment-preserving editor (``hermes_yaml.roundtrip_yaml``, Hermes 0.21.7+),
:func:`load_yaml` reads through it and :func:`dump_yaml` writes what it read back
the same way, so a load -> change -> dump keeps every comment and quote and
changes only the keys Blackbox set (2026-11-03: setup dropped all 2,147 comment
lines of Hermes Desktop's config). Data that did not come from :func:`load_yaml`
(a new file) and older Hermes (PyYAML) keep the plain safe_dump.
"""

from __future__ import annotations

import io
import logging
import os
from pathlib import Path
from typing import Any, Dict
from .bounded_files import atomic_write   # the kernel's one torn-free write (re-exported for yaml callers)

logger = logging.getLogger(__name__)

# Hermes 0.21.7 removed PyYAML and reads YAML through its own ruamel-backed ``hermes_yaml``
# (same safe_load / safe_dump calls); older Hermes ships PyYAML. Without either, every config
# read would come back empty and Blackbox would silently run on defaults — so say so loudly.
try:
    import hermes_yaml as yaml  # type: ignore[import-not-found]
except ImportError:
    try:
        import yaml  # type: ignore[no-redef]
    except ImportError:  # pragma: no cover - no YAML library at all
        yaml = None  # type: ignore[assignment]
        logger.warning("blackbox: no YAML library (hermes_yaml or PyYAML) — config.yaml cannot be read; "
                       "Blackbox is running on its defaults")


# ---------------------------------------------------------------------------
# YAML helpers (idempotent, preserve unrelated keys)
# ---------------------------------------------------------------------------


def _roundtrip_editor() -> Any:
    """Hermes's comment-preserving YAML editor, or None (older Hermes, PyYAML)."""
    factory = getattr(yaml, "roundtrip_yaml", None)
    return factory() if callable(factory) else None


def _keeps_comments(data: Any) -> bool:
    """Whether *data* was read by the round-trip editor (ruamel's CommentedMap carries ``.ca``)."""
    return hasattr(data, "ca")


def load_yaml(path: Path) -> dict[str, Any]:
    if yaml is None or not path.exists():
        return {}
    try:
        text = path.read_text(encoding="utf-8-sig")
        editor = _roundtrip_editor()
        data = editor.load(text) if editor is not None else yaml.safe_load(text)
    except Exception as exc:
        logger.debug("blackbox.attach: could not parse %s (%s)", path, exc)
        return {}
    return data if isinstance(data, dict) else {}


def dump_yaml(path: Path, data: dict[str, Any]) -> None:
    editor = _roundtrip_editor() if _keeps_comments(data) else None
    if editor is not None:
        buffer = io.StringIO()
        editor.dump(data, buffer)
        atomic_write(path, buffer.getvalue())
        return
    atomic_write(path, yaml.safe_dump(data, default_flow_style=False, sort_keys=False))
