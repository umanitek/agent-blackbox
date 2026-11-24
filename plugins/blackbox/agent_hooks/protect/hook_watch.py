"""Blackbox's own hooks, watched: a hook of Blackbox's that disappears or changes OUTSIDE a Blackbox
install is a HIGH finding, and it is put back where that is safe.

WHY (security finding 2026-11-24, Linux round L4): a sandboxed agent moved ``~/Documents/Cline``
and ``~/.config/opencode`` away (only the hook folders themselves were pinned), planted its own
``~/Documents/Cline/Hooks/TaskStart`` and took Blackbox's OpenCode plugin with it. 90 s later
nothing was put back and nobody was told. The sandbox now pins every folder above every hook place
(``shields.files.sandbox.policy``); this watch is the layer for every other route (an agent outside
the sandbox, a program the person ran, an editor).

What is compared, per agent and per config home (:func:`fingerprint`): for the hook FILES that are
Blackbox's own (Cline's scripts and SDK plugin, OpenCode's plugins, Copilot CLI's hooks file) the
SHA-256 of each; for an agent config Blackbox only adds entries to (Claude Code's settings.json …)
the SHA-256 of Blackbox's commands in it — the person's own edits there change nothing here.
:func:`remember` stores the fingerprint right after Blackbox itself installed (``agent_hooks.install``),
so an upgrade is never taken for tampering; :func:`changed` answers what differs since.

Put back only on a SAFE path (:func:`safe`): every folder from the home down to the file is a real
folder of this user (no link that would send Blackbox's write elsewhere). A file that is not
Blackbox's where Blackbox's was is moved into Blackbox's own folder first (:func:`quarantine`), out
of the agent's load path and kept for the person to look at — never deleted.

Usage::

    remember(key, fingerprint(host, home))      # after Blackbox's own install
    lost = changed(key, fingerprint(host, home))  # paths gone or changed since ([] = intact)
    finding(host.name, lost, restored=True)     # the HIGH finding the notifications show
"""

from __future__ import annotations

import hashlib
import os
import shutil
import time
from pathlib import Path
from typing import Any, Mapping

from ...kernel import constants
from ...kernel.agent_hosts import Host
from ...kernel.bounded_files import read_json_object, write_json_object
from .config_edit import MARK

#: The finding every restoration (or failed one) is recorded as; never shared (source ``custom``).
HOOK_CHANGED_ID = "self-protection:agent-hook-changed"
TITLE = "Blackbox's hook in an AI agent was removed or changed outside Blackbox"
#: The fingerprint key of an agent config Blackbox only adds entries to.
COMMANDS_KEY = "commands"
#: The most bytes of one hook file hashed (Blackbox's own are a few KB).
MAX_HOOK_BYTES = 512 * 1024


def _folder() -> Path:
    return constants.blackbox_home() / "agent-hooks"


def _baseline_path() -> Path:
    return _folder() / "hook-baseline.json"


def _sha(path: Path) -> str:
    """The SHA-256 of *path*'s first :data:`MAX_HOOK_BYTES` ("" when it is not a readable file)."""
    try:
        if path.is_symlink() or not path.is_file():
            return ""
        with open(path, "rb") as handle:
            return hashlib.sha256(handle.read(MAX_HOOK_BYTES)).hexdigest()
    except OSError:
        return ""


def _ours(path: Path) -> bool:
    try:
        with open(path, encoding="utf-8-sig", errors="replace") as handle:
            return MARK in handle.read(4096)
    except OSError:
        return False


def own_paths(host: Host, home: Path) -> list[Path]:
    """Every file *host* takes hooks from that Blackbox writes as its own (none for a config
    Blackbox only adds entries to)."""
    target = host.config_path(home)
    if host.style == "scripts":
        files = [target / event for event in host.events]
    elif host.style in ("plugin", "own-json"):
        files = [target]
    else:
        files = []
    return files + list(host.companion_paths(home))


def fingerprint(host: Host, home: Path, commands: list[str]) -> dict[str, str]:
    """``{path: sha256}`` of each of Blackbox's own hook files that is there now (only Blackbox's —
    a person's own script for an event is not watched), plus ``{"commands": sha256}`` of
    *commands* (Blackbox's entries in the agent's config, ``installed_commands``) for an agent
    config Blackbox only adds to. {} when nothing of Blackbox's is installed."""
    found = {str(path): _sha(path) for path in own_paths(host, home) if _ours(path) and not path.is_symlink()}
    if host.style not in ("scripts", "plugin", "own-json") and commands:
        found[COMMANDS_KEY] = hashlib.sha256("\n".join(sorted(commands)).encode("utf-8")).hexdigest()
    return {path: sha for path, sha in found.items() if sha}


def _read() -> dict[str, dict[str, str]]:
    data = read_json_object(_baseline_path()) or {}
    return {key: dict(value) for key, value in data.items() if isinstance(value, dict)}


def remember(key: str, prints: Mapping[str, str]) -> None:
    """Stores *prints* as what Blackbox installed for *key* (``<agent id>:<config path>``); empty
    *prints* forgets the key (Blackbox removed its hooks)."""
    data = _read()
    if prints:
        data[key] = dict(prints)
    else:
        data.pop(key, None)
    write_json_object(_baseline_path(), data, what="the agent hooks baseline")


def known(key: str) -> dict[str, str]:
    """What Blackbox last installed for *key* ({} when nothing is remembered)."""
    return _read().get(key, {})


def changed(key: str, now: Mapping[str, str]) -> list[str]:
    """The remembered paths (or ``commands``) of *key* that are gone or differ in *now*."""
    return [path for path, sha in known(key).items() if now.get(path) != sha]


def safe(home: Path, paths: list[str]) -> bool:
    """True when Blackbox may write each of *paths* again: every folder that exists from *home*
    down to it is a real folder (not a link) of this user, and the path itself is not a link."""
    uid = getattr(os, "getuid", lambda: -1)()
    for raw in paths:
        if raw == COMMANDS_KEY:
            continue
        path = Path(raw)
        if path.is_symlink() or home not in path.parents:
            return False
        folder = path.parent
        while folder != home.parent:
            if folder.is_symlink():
                return False
            if folder.exists():
                facts = folder.stat()
                if not folder.is_dir() or (uid >= 0 and facts.st_uid != uid):
                    return False
            folder = folder.parent
    return True


def quarantine(paths: list[str]) -> list[str]:
    """Moves each of *paths* that holds a file that is NOT Blackbox's into Blackbox's own folder
    (``agent-hooks/replaced/``, mode 0600: never run, never loaded, kept for the person). Answers
    where each one went."""
    moved = []
    for raw in paths:
        path = Path(raw)
        if raw == COMMANDS_KEY or not path.is_file() or path.is_symlink() or _ours(path):
            continue
        target = _folder() / "replaced" / f"{int(time.time())}-{path.parent.name}-{path.name}"
        target.parent.mkdir(parents=True, exist_ok=True)
        shutil.move(str(path), str(target))
        target.chmod(0o600)
        moved.append(str(target))
    return moved


def finding(agent: str, lost: list[str], restored: bool, moved: list[str]) -> dict[str, Any]:
    """The HIGH finding for *agent*'s changed hook (*lost*: the paths, ``commands`` for config entries)."""
    names = [os.path.basename(path) if path != COMMANDS_KEY else "its config's Blackbox entries" for path in lost]
    outcome = "Blackbox put its hook back" if restored else "Blackbox could not put it back safely: protect the agent again"
    return {"identifier": HOOK_CHANGED_ID, "category": "self-protection", "severity": "high", "title": TITLE,
            "tool_name": "", "evidence": f"{agent}: {', '.join(names)[:200]} — {outcome}", "confirmed": False,
            "source": "custom", "fields": {"agent": agent, "restored": restored, "moved_aside": len(moved)}}


__all__ = ["COMMANDS_KEY", "HOOK_CHANGED_ID", "TITLE", "changed", "finding", "fingerprint", "known", "own_paths",
           "quarantine", "remember", "safe"]
