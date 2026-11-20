"""Which agents on this machine Blackbox protects, and which new ones it just protected (2026-11-19).

Amos: "every new profile and every new instance, automatically, always protected moving forward".
With ``auto_attach`` on (the one yes the installers and Desktop's setup ask for), the dashboard's
sweep protects each new Hermes profile or OpenClaw workspace within a minute; this module is the
step that does it (:func:`protect_automatically`, called by that sweep) and remembers what it
protected, so the dashboard can say "New agent protected: Hermes · coder". :func:`coverage` is
what the dashboard shows next to its agents: the switch, every agent still unprotected (never one
the operator switched off — that was a choice), and the recent automatic protections.

Pattern: a small Observer-style log owned by one object with one lock (:class:`AutoProtected`);
everything else is plain functions over the discoverers. Memory only: a restart forgets the
"recent" list, never any protection (that lives in each agent's own config).

Usage::

    rows = protect_automatically(targets)       # the sweep: [{kind, target, already, error?}, ...]
    view = coverage()   # {"auto_attach": bool, "unprotected": [Agent], "recent": [Agent + seq + at]}
"""

from __future__ import annotations

import collections
import itertools
import logging
import threading
import time
from pathlib import Path
from typing import Any, Iterable, TypedDict

from ..kernel.config import load_blackbox_config
from . import declined, hermes_homes, openclaw_discovery
from .sweep import Target, is_attached, set_protection

logger = logging.getLogger(__name__)

#: How many automatic protections the dashboard can still be told about.
RECENT_LIMIT = 50
#: The Hermes profile Blackbox's own assistant runs in (``blackbox chat``).
ASSISTANT_PROFILE = "agent-blackbox"


class Agent(TypedDict):
    """One agent as the dashboard names it: its kind, its folder and a label for people."""

    kind: str
    target: str
    label: str


class RecentAgent(Agent):
    """An agent the sweep protected by itself: *seq* rises by one each time, *at* is epoch seconds."""

    seq: int
    at: float


def agent_label(kind: str, target: str | Path) -> str:
    """"Hermes · coder", "Hermes (main)", "Blackbox assistant", "OpenClaw" (its default
    profile, ``~/.openclaw``) or "OpenClaw · work" (``~/.openclaw-work``)."""
    path = Path(str(target))
    if kind == "openclaw":
        profile = path.name.removeprefix(".openclaw").lstrip("-")
        return f"OpenClaw · {profile}" if profile else "OpenClaw"
    if path.parent.name == "profiles":
        return "Blackbox assistant" if path.name == ASSISTANT_PROFILE else f"Hermes · {path.name}"
    return "Hermes (main)"


def _agent(kind: str, target: str) -> Agent:
    return Agent(kind=kind, target=target, label=agent_label(kind, target))


class AutoProtected:
    """The recent automatic protections, newest last (see the module doc)."""

    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._seq = itertools.count(1)
        self._recent: collections.deque[RecentAgent] = collections.deque(maxlen=RECENT_LIMIT)

    def note(self, kind: str, target: str) -> None:
        with self._lock:
            self._recent.append(RecentAgent(**_agent(kind, target), seq=next(self._seq), at=time.time()))

    def recent(self) -> list[RecentAgent]:
        with self._lock:
            return list(self._recent)


RECENT = AutoProtected()


def protect_automatically(targets: Iterable[Target]) -> list[dict[str, Any]]:
    """Protect each of *targets* (the sweep's choice from :func:`~.sweep.automatic_targets`) and
    note every one that was not protected before. Fail-open per target: one broken agent config
    never stops the others. Returns each target's attach row."""
    rows: list[dict[str, Any]] = []
    for kind, target in sorted(targets):
        # Asked BEFORE attaching: "not already" in the attach row also means "its entry was
        # rewritten" (OpenClaw rewrites its own config; the entry is then put back), and an
        # agent that was protected all along must not be announced as newly protected.
        was_protected = is_attached(kind, target)
        try:
            row = dict(set_protection(kind, target, True) or {})
        except Exception as exc:   # health: allow BLE001 -- one agent's broken config never stops the sweep
            logger.warning("blackbox rescan: attach %s %s raised: %s", kind, target, exc)
            continue
        rows.append(row)
        if row.get("error"):
            logger.warning("blackbox rescan: attach %s %s failed: %s", kind, target, row["error"])
        elif not row.get("already"):
            logger.info("blackbox rescan: %s %s at %s", "refreshed" if was_protected else "auto-attached", kind, target)
            if not was_protected:
                RECENT.note(kind, target)
    return rows


def _discovered() -> list[Target]:
    found = [("hermes", str(home)) for home in hermes_homes.discover_hermes_homes()]
    return found + [("openclaw", str(ws)) for ws in openclaw_discovery.discover_openclaw_workspaces()]


def coverage() -> dict[str, Any]:
    """``{"auto_attach", "unprotected", "recent"}`` — the switch, every discovered agent Blackbox
    does not protect that the operator did NOT switch off, and the recent automatic protections."""
    unprotected = [_agent(kind, target) for kind, target in _discovered()
                   if not is_attached(kind, target) and not declined.is_declined(kind, target)]
    return {"auto_attach": load_blackbox_config().auto_attach, "unprotected": unprotected, "recent": RECENT.recent()}
