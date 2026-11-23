"""The visibility trail of a Hermes tool call: what the agent touched, flagged or not.

Moved out of :mod:`.hooks` (2026-11-23, a move only) when that file reached the size alarm.
Visibility, not detection: every file a tool reads or writes, every read, download and
dependency install a shell command names, is logged (``audit.record_file_access`` /
``audit.record_dependency``), whatever the checks found. Fail-open: a logging fault is swallowed.

Usage::

    record_activity("terminal", {"command": "npm install left-pad"})
"""

from __future__ import annotations

import logging
from typing import Any

from .. import audit, detection

logger = logging.getLogger(__name__)


def record_activity(tool_name: str, args: Any) -> None:
    """Log what the agent touched to the visibility trail (fail-open).

    Covers both the dedicated file tools and the shell channel (parsing reads,
    downloads, and dependency installs out of commands). Visibility, not
    detection: everything is logged regardless of whether it flags.
    """
    try:
        access = detection.file_access_arg(tool_name, args)
        if access:
            audit.record_file_access(access["tool"], access["path"], access["mode"])
            return
        if (tool_name or "").strip().lower() not in detection.SHELL_TOOLS:
            return
        command = detection.command_from_args(tool_name, args)
        if not command:
            return
        for path in detection.parse_shell_reads(command):
            audit.record_file_access("shell", path, "read")
        for url in detection.parse_downloads(command):
            audit.record_file_access("shell", url, "download")
        for dep in detection.parse_dependency_installs(command):
            audit.record_dependency(dep["ecosystem"], dep["name"], dep.get("version", ""), "shell")
    except Exception as exc:  # pragma: no cover - fail open
        logger.debug("blackbox: activity visibility log failed: %s", exc)
