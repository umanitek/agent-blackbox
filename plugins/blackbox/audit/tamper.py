"""Tamper counts: how often something tried to switch Blackbox off or get around it, and was refused.

Every refusal by the protection that guards Blackbox itself is counted, on every machine, in every
mode: a refused attempt the person never sees invites the next one, and a rising count is the
signal. The counts are kept per category, survive restarts, and are never reset by an agent: they
live in ``<BLACKBOX_HOME>/tamper-counts.json``, a place self-protection guards, so an agent's attempt
to edit or delete them is itself refused and counted.

================================  ===============================================================
category                          counted when
================================  ===============================================================
``self-protection``               the guard refused an agent changing, stopping or switching off
                                  Blackbox (its settings, files, hooks, service, control API)
``self-protection-kernel``        the operating system's agent sandbox refused a write to
                                  Blackbox's own places
``startup-item``                  the guard refused an agent writing a place something starts from
                                  by itself (login items, services, schedules)
================================  ===============================================================

Counted at the one place every refusal is recorded, :func:`note`, called by the audit log for each
record: the Hermes hook, every other agent's hooks and the sandbox all record their findings
through it. A finding counts when the record says it was blocked (``detail["blocked"]``) or when the
record is a kernel refusal (``sandbox_deny``); a flagged finding never counts.

Usage::

    tamper.tamper_counts()   # {"self-protection": {"count": 3, "last_at": 1795…, "last_agent": "codex"}, …}
"""

from __future__ import annotations

import time
from pathlib import Path
from typing import Any, Optional, TypedDict

from ..kernel import constants, threat_ids
from ..kernel.bounded_files import file_lock, read_json_object, write_json_object
from ..kernel.persistence_places import STARTUP_ITEM

#: The record of a refusal the operating system's sandbox made (its findings are refusals by nature).
KERNEL_REFUSAL_EVENT = "sandbox_deny"
SELF_PROTECTION, SELF_PROTECTION_KERNEL, STARTUP = "self-protection", "self-protection-kernel", "startup-item"
CATEGORIES = (SELF_PROTECTION, SELF_PROTECTION_KERNEL, STARTUP)
#: How long a writer waits for another process counting at the same moment.
LOCK_TIMEOUT_S = 2.0


class TamperCount(TypedDict):
    """One category: how many refusals, when the last one was (Unix seconds) and which agent made it."""

    count: int
    last_at: float
    last_agent: str


def _path() -> Path:
    return constants.blackbox_home() / "tamper-counts.json"


def category(finding: dict[str, Any], event: str) -> Optional[str]:
    """The tamper category of a REFUSED *finding* in a record of *event*, or None for any other."""
    identifier, matched = str(finding.get("identifier") or ""), str(finding.get("matched") or "")
    if matched == STARTUP_ITEM:
        return STARTUP
    if matched == threat_ids.SELF_PROTECTION or threat_ids.is_self_protection(identifier):
        return SELF_PROTECTION_KERNEL if event == KERNEL_REFUSAL_EVENT else SELF_PROTECTION
    return None


def note(event: str, findings: Optional[list[dict[str, Any]]], detail: Optional[dict[str, Any]],
         agent: str) -> None:
    """Count every refused tamper finding of one audit record (the audit log calls this for each)."""
    blocked = set((detail or {}).get("blocked") or ())
    refused = [f for f in findings or () if event == KERNEL_REFUSAL_EVENT or f.get("identifier") in blocked]
    hits = [c for c in (category(f, event) for f in refused) if c]
    if not hits:
        return
    with file_lock(_path().with_suffix(".lock"), timeout_s=LOCK_TIMEOUT_S):
        counts = _read()
        now = time.time()
        for name in hits:
            entry = counts.get(name) or {"count": 0, "last_at": 0.0, "last_agent": ""}
            counts[name] = {"count": int(entry["count"]) + 1, "last_at": now, "last_agent": agent or "hermes"}
        write_json_object(_path(), counts, what="Blackbox's tamper counts")


def _read() -> dict[str, TamperCount]:
    data = read_json_object(_path()) or {}
    out: dict[str, TamperCount] = {}
    for name in CATEGORIES:
        entry = data.get(name)
        if isinstance(entry, dict) and isinstance(entry.get("count"), int) and entry["count"] >= 0:
            out[name] = {"count": entry["count"], "last_at": float(entry.get("last_at") or 0.0),
                         "last_agent": str(entry.get("last_agent") or "")[:64]}
    return out


def tamper_counts() -> dict[str, TamperCount]:
    """Every category that has counted at least one refusal (read-only)."""
    return _read()
