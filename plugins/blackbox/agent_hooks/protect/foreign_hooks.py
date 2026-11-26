"""Every program an agent loads from its hook and plugin folders, watched — not only Blackbox's own.

Private security finding ``2026-11-25-linux-hook-watch-puts-blackbox-s-hook-ba`` (Linux round L5,
Medium; the same on macOS): the hook watch (:mod:`.hook_watch`) put Blackbox's own OpenCode plugin
back and called it done while a planted ``plugin/x.js`` stayed loaded; a lone foreign plugin, or an
extra Cline hook beside Blackbox's, raised nothing at all. Every file in an agent's code folders
(``Host.code_folders``: Cline's ``Hooks`` and ``Plugins``, OpenCode's ``plugin`` and ``plugins``)
runs inside that agent the next time it starts — also when the person starts it outside the sandbox.

What this does, per look (:func:`look`): the files there that are not Blackbox's are fingerprinted
(SHA-256, bounded) against what was there when Blackbox installed (:func:`remember`; an install
older than this watch is adopted at its first look — the person's own plugins); after that a
NEW or CHANGED one is one HIGH finding, naming the agent that wrote it when Blackbox's records show
an allowed tool call naming the file while it was written (else "writer unknown").

What it never does: delete or move such a file. The person's own plugins must keep working, and a
file is moved aside only where it took the place of Blackbox's own hook (:func:`.hook_watch.quarantine`).
Whether a file an agent was SEEN writing should be moved aside too is the owner's decision (fix wave
W12); the safe default is to alert and keep.

Usage::

    findings = look(host, home)          # [] when nothing new; each a finding dict to record
    still_loaded(host, home)             # the foreign files there now (names), for the restore's words
"""

from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
from typing import Any, Mapping, Optional

from ...kernel.agent_hosts import Host
from ...kernel.bounded_files import read_json_object, write_json_object
from . import hook_watch

#: The finding a new or changed foreign hook or plugin is recorded as; never shared (``custom``).
FOREIGN_HOOK_ID = "self-protection:agent-hook-added"
TITLE = "A new program was added where an AI agent loads its hooks or plugins"
#: Bounds: files looked at per agent, bytes hashed per file, audit rows read for the writer.
MAX_FILES = 200
MAX_BYTES = 512 * 1024
AUDIT_ROWS = 2000
#: How long before a file's write an agent's call naming it is looked at, and the clock slack.
WINDOW_SECONDS = 600
SLACK_SECONDS = 5


def _baseline_path() -> Path:
    return hook_watch._folder() / "foreign-hooks.json"


def _files(host: Host, home: Path) -> list[Path]:
    """The files in *host*'s code folders (and one folder below: OpenCode 2's ``plugins/<name>/``)."""
    out: list[Path] = []
    for relative in host.code_folders:
        folder = home / relative
        if not folder.is_dir() or folder.is_symlink():
            continue
        for entry in sorted(folder.iterdir())[:MAX_FILES]:
            if entry.is_dir() and not entry.is_symlink():
                out += [child for child in sorted(entry.iterdir())[:MAX_FILES] if child.is_file()]
            elif entry.is_file() or entry.is_symlink():
                out.append(entry)
    return out[:MAX_FILES]


def _sha(path: Path) -> str:
    try:
        if path.is_symlink():
            return "link:" + os.readlink(path)
        with open(path, "rb") as handle:
            return hashlib.sha256(handle.read(MAX_BYTES)).hexdigest()
    except OSError:
        return ""


def foreign(host: Host, home: Path) -> dict[str, str]:
    """``{path: sha256}`` of every file in *host*'s code folders that is not Blackbox's own."""
    own = {str(path) for path in hook_watch.own_paths(host, home)}
    return {str(path): sha for path in _files(host, home)
            if str(path) not in own and not (path.is_file() and hook_watch._ours(path)) and (sha := _sha(path))}


def still_loaded(host: Host, home: Path) -> list[str]:
    """The names of the foreign files in *host*'s code folders now."""
    return [os.path.basename(path) for path in foreign(host, home)]


def _writer(path: str, written: float, rows: list[Mapping[str, Any]]) -> str:
    """The agent whose ALLOWED tool call named *path* while it was written ("" when not known)."""
    home = os.path.expanduser("~").rstrip("/")
    forms = [path] + (["~" + path[len(home):], "$HOME" + path[len(home):]] if path.startswith(home + "/") else [])
    for row in rows:
        detail = row.get("detail") if isinstance(row.get("detail"), Mapping) else {}
        when = float(row.get("ts") or 0)
        if row.get("event") != "pre_tool_call" or str(detail.get("decision") or "") == "block":
            continue
        if not written - WINDOW_SECONDS <= when <= written + SLACK_SECONDS:
            continue
        text = json.dumps(detail.get("args"), ensure_ascii=False) if detail.get("args") is not None else ""
        if any(form in text for form in forms):
            return str(row.get("framework") or "hermes")
    return ""


def _finding(host: Host, path: str, change: str, writer: str) -> dict[str, Any]:
    by = f"written by {writer}" if writer else "writer unknown"
    return {"identifier": FOREIGN_HOOK_ID, "category": "self-protection", "severity": "high", "title": TITLE,
            "tool_name": "", "evidence": f"{host.name}: {change} {path} ({by}) — it runs inside {host.name} the next time it "
                                         "starts; kept, not removed: check it is yours"[:400],
            "confirmed": False, "source": "custom",
            "fields": {"agent": host.id, "path": path[:400], "change": change, "writer": writer}}


def remember(host: Host, home: Path) -> None:
    """Record what is in *host*'s code folders now as known — called right after Blackbox's own
    install, so a file planted later is new, and the person's plugins there before are not."""
    data = read_json_object(_baseline_path()) or {}
    data[f"{host.id}:{home}"] = foreign(host, home)
    write_json_object(_baseline_path(), data, what="the agents' hook folders")


def look(host: Host, home: Path, audit_rows: Optional[list[Mapping[str, Any]]] = None) -> list[dict[str, Any]]:
    """One look at *host*'s code folders: a finding for each foreign file new or changed since the
    last look (the first look adopts what is there). *audit_rows*: newest audit rows (read lazily)."""
    key = f"{host.id}:{home}"
    data = read_json_object(_baseline_path()) or {}
    now = foreign(host, home)
    known = data.get(key)
    if not isinstance(known, dict):
        if now or host.code_folders:
            data[key] = now
            write_json_object(_baseline_path(), data, what="the agents' hook folders")
        return []
    fresh = [path for path, sha in now.items() if known.get(path) != sha]
    if fresh or set(known) - set(now):
        data[key] = now
        write_json_object(_baseline_path(), data, what="the agents' hook folders")
    if not fresh:
        return []
    if audit_rows is None:
        from ... import audit   # late: only a look that found something reads the trail
        audit_rows = audit.read_audit(limit=AUDIT_ROWS)
    out = []
    for path in fresh:
        try:
            written = os.lstat(path).st_mtime
        except OSError:
            written = 0.0
        out.append(_finding(host, path, "changed" if path in known else "added", _writer(path, written, audit_rows)))
    return out


__all__ = ["FOREIGN_HOOK_ID", "TITLE", "foreign", "look", "remember", "still_loaded"]
