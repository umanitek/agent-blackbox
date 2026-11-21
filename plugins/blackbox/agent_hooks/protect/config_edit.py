"""Blackbox's entries in an agent's JSON hook config — added and removed without touching the user's.

Every entry Blackbox writes runs the runner (its command contains :data:`MARK`), so Blackbox's
entries are found by that mark alone: install removes the old ones and adds the current ones
(idempotent, and a moved runner or Python is corrected); uninstall removes them and nothing else.
The first time Blackbox changes a file it keeps the original beside it (``<file>.blackbox-backup``).
A file that is not plain JSON (comments, a syntax error) is never rewritten: the agent is reported
as not hooked, with the reason.

Usage::

    result = install(host, home, commands)   # commands: {agent event: command line}
    result.ok, result.error, result.path
    uninstall(host, home)

**Undo:** every edit is a Blackbox-marked entry beside the user's own hooks, with the original
config backed up once; removing protection takes out exactly the marked entries.
"""

from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Optional

from ...kernel.bounded_files import atomic_write
from ..hosts import Host

#: In every command Blackbox writes, and in nothing a user writes.
MARK = "agent-hooks/runner.py"
BACKUP_SUFFIX = ".blackbox-backup"
#: Seconds an agent waits for a hook (the runner itself gives up after 2.5 s).
HOOK_TIMEOUT = 10
#: The largest config read (an agent's settings file).
MAX_CONFIG_BYTES = 2 * 1024 * 1024


@dataclass(frozen=True)
class EditResult:
    ok: bool
    path: str
    error: str = ""


def _read(path: Path) -> tuple[Optional[dict[str, Any]], str]:
    if not path.exists():
        return {}, ""
    try:
        if path.stat().st_size > MAX_CONFIG_BYTES:
            return None, "the config file is too large to edit safely"
        data = json.loads(path.read_text(encoding="utf-8-sig") or "{}")
    except (OSError, ValueError, RecursionError):
        return None, "the config file is not plain JSON, so Blackbox left it untouched"
    return (data, "") if isinstance(data, dict) else (None, "the config file is not a JSON object")


def _write(path: Path, data: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    backup = path.with_name(path.name + BACKUP_SUFFIX)
    if path.exists() and not backup.exists():
        atomic_write(backup, path.read_bytes())
    atomic_write(path, json.dumps(data, indent=2) + "\n")


def _ours(entry: Any) -> bool:
    return isinstance(entry, dict) and MARK in str(entry.get("command") or "")


def _strip(hooks: dict[str, Any], style: str) -> dict[str, Any]:
    """*hooks* without Blackbox's entries; an event left empty is dropped."""
    out: dict[str, Any] = {}
    for event, entries in hooks.items():
        if not isinstance(entries, list):
            out[event] = entries
            continue
        if style == "nested":
            kept = []
            for group in entries:
                if isinstance(group, dict) and isinstance(group.get("hooks"), list):
                    inner = [hook for hook in group["hooks"] if not _ours(hook)]
                    if inner:
                        kept.append({**group, "hooks": inner})
                elif not _ours(group):
                    kept.append(group)
        else:
            kept = [entry for entry in entries if not _ours(entry)]
        if kept:
            out[event] = kept
    return out


def _entry(host: Host, command: str) -> dict[str, Any]:
    if host.style == "nested":
        group: dict[str, Any] = {"hooks": [{"type": "command", "command": command, "timeout": HOOK_TIMEOUT}]}
        if host.matcher:
            group = {"matcher": host.matcher, **group}
        return group
    if host.id == "windsurf":
        return {"command": command, "show_output": False}
    return {"command": command}


def install(host: Host, home: Path, commands: dict[str, str]) -> EditResult:
    """Blackbox's entries for every event in *commands*, beside the user's own."""
    path = host.config_path(home)
    data, error = _read(path)
    if data is None:
        return EditResult(False, str(path), error)
    hooks = data.get("hooks") if isinstance(data.get("hooks"), dict) else {}
    hooks = _strip(hooks, host.style)
    for event, command in commands.items():
        hooks.setdefault(event, []).append(_entry(host, command))
    data["hooks"] = hooks
    for key, value in host.extra.items():
        data.setdefault(key, value)
    try:
        _write(path, data)
    except OSError as exc:
        return EditResult(False, str(path), f"could not write the config: {exc.strerror or exc}")
    return EditResult(True, str(path))


def uninstall(host: Host, home: Path) -> EditResult:
    """The config without Blackbox's entries (the user's own stay exactly as they are)."""
    path = host.config_path(home)
    data, error = _read(path)
    if data is None:
        return EditResult(False, str(path), error)
    if not isinstance(data.get("hooks"), dict):
        return EditResult(True, str(path))
    hooks = _strip(data["hooks"], host.style)
    if hooks:
        data["hooks"] = hooks
    else:
        data.pop("hooks")
    try:
        _write(path, data)
    except OSError as exc:
        return EditResult(False, str(path), f"could not write the config: {exc.strerror or exc}")
    return EditResult(True, str(path))


def installed_commands(host: Host, home: Path) -> list[str]:
    """Blackbox's commands now in the agent's config (empty when none, or unreadable)."""
    data, _error = _read(host.config_path(home))
    hooks = (data or {}).get("hooks")
    if not isinstance(hooks, dict):
        return []
    found = []
    for entries in hooks.values():
        for entry in entries if isinstance(entries, list) else []:
            inner = entry.get("hooks") if isinstance(entry, dict) and isinstance(entry.get("hooks"), list) else [entry]
            found.extend(str(hook.get("command")) for hook in inner if _ours(hook))
    return found
