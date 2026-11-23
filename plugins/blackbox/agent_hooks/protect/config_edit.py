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
    invalid_entries(host, home)              # why the AGENT would not run Blackbox's entries ([] = fine)

**Undo:** every edit is a Blackbox-marked entry beside the user's own hooks, with the original
config backed up once; removing protection takes out exactly the marked entries.
"""

from __future__ import annotations

import json
import re
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Optional

from ...kernel.bounded_files import atomic_write
from ...kernel.agent_hosts import TOOL_KINDS, Host

#: In every command Blackbox writes, and in nothing a user writes.
MARK = "agent-hooks/runner.py"
BACKUP_SUFFIX = ".blackbox-backup"
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


def _entry(host: Host, command: str, kind: str = "pre_tool", event: str = "") -> dict[str, Any]:
    if host.style == "nested":
        hook: dict[str, Any] = {"type": "command", "command": command}
        if host.hook_timeout is not None:   # in the agent's OWN unit (Gemini: ms) — KI-570
            hook[host.hook_timeout.key] = host.hook_timeout.value(event)
        group: dict[str, Any] = {"hooks": [hook]}
        if host.matcher and kind in TOOL_KINDS:   # a lifecycle group carries no tool matcher
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
        hooks.setdefault(event, []).append(_entry(host, command, host.events.get(event, ""), event))
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
        _put_back(path, data)
    except OSError as exc:
        return EditResult(False, str(path), f"could not write the config: {exc.strerror or exc}")
    return EditResult(True, str(path))


def _put_back(path: Path, data: dict[str, Any]) -> None:
    """Writes the config without Blackbox's entries and takes Blackbox's backup of it away. When
    that config is the one the backup kept (the person changed nothing since), the backup's own
    BYTES go back — their formatting too (uninstall leaves the person's files byte-identical)."""
    backup = path.with_name(path.name + BACKUP_SUFFIX)
    original = backup.read_bytes() if backup.is_file() and not backup.is_symlink() else None
    try:
        same = original is not None and json.loads(original.decode("utf-8-sig") or "{}") == data
    except (ValueError, RecursionError):
        same = False
    atomic_write(path, original if same and original is not None else json.dumps(data, indent=2) + "\n")
    if original is not None:
        backup.unlink()


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


def _our_hooks(data: dict[str, Any]) -> list[tuple[str, dict[str, Any], dict[str, Any]]]:
    """Every Blackbox hook in *data*: ``(event, its group, the hook)``."""
    hooks = data.get("hooks")
    out = []
    for event, entries in (hooks.items() if isinstance(hooks, dict) else ()):
        for group in entries if isinstance(entries, list) else []:
            inner = group.get("hooks") if isinstance(group, dict) and isinstance(group.get("hooks"), list) else [group]
            out.extend((event, group, hook) for hook in inner if _ours(hook))
    return out


def _hook_problem(host: Host, event: str, group: dict[str, Any], hook: dict[str, Any]) -> str:
    """Why *host* would not run (or would cut short) this one Blackbox hook; "" when it is fine.
    Mirrors the agent's documented hook schema — what its own loader checks."""
    if host.style == "nested" and hook.get("type") != "command":
        return f"{event}: the hook has no \"type\": \"command\", so {host.name} skips it"
    matcher = group.get("matcher") if group is not hook else None
    if isinstance(matcher, str) and matcher not in ("", "*"):
        try:
            re.compile(matcher)
        except re.error:
            return f"{event}: the matcher {matcher!r} is not a valid pattern, so {host.name} never runs it"
    limit = host.hook_timeout
    if limit is None or limit.key not in hook:
        return ""
    seconds = limit.seconds(hook.get(limit.key))
    if seconds is None:
        return f"{event}: {limit.key} is not a number"
    if seconds < limit.floor(event):
        unit = "milliseconds" if limit.per_second == 1000 else "seconds"
        return (f"{event}: {limit.key} is {hook.get(limit.key)} — {host.name} reads it in {unit}, so the hook is cut off "
                f"after {seconds:g} s, before Blackbox can answer")
    return ""


def invalid_entries(host: Host, home: Path) -> list[str]:
    """Why *host*'s own loader would not run Blackbox's hooks in its config ([] = they will run).

    Checks every Blackbox entry against the agent's documented schema — the time limit in the
    agent's own unit (Gemini CLI: milliseconds), the entry type, the matcher — and the agent's
    per-hook off-list (Gemini CLI's ``hooksConfig.disabled`` names hook commands). A hook that is
    merely WRITTEN proves nothing: the sweep rewrites an entry that fails here, and the profile
    shows the reason (KI-570)."""
    data, _error = _read(host.config_path(home))
    if not data:
        return []
    problems = [problem for event, group, hook in _our_hooks(data) if (problem := _hook_problem(host, event, group, hook))]
    off_list = (data.get("hooksConfig") or {}).get("disabled") if isinstance(data.get("hooksConfig"), dict) else None
    if isinstance(off_list, list) and any(MARK in str(name) for name in off_list):
        problems.append(f"hooksConfig.disabled lists Blackbox's hook, so {host.name} skips it")
    return problems
