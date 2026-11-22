"""Where notices come from: three things Blackbox already records, read and compared each tick.

* every engaged shield's alerts (``shields.alerts`` — File Shield's hits and changes, Network
  Shield's system events), in the shield's own lock-screen-safe words;
* the audit findings (``audit.read_findings``): an agent stopped or flagged, an agent asking for
  root, a program an agent started running as root — except a finding a shield alert already
  speaks for;
* the agent instances (``agent_hooks.tracking.live``): an agent or sub-agent started, ended or
  waits for the person; a session's one-line digest; an agent running without Blackbox; a
  setting that switches Blackbox's hooks off.

Pattern: **Observer by polling** — a :class:`Collector` remembers what it has seen and answers
only what is NEW. Its first reading only learns (a dashboard start is not news); a source that
fails costs only its own notices that tick.
"""

from __future__ import annotations

import logging
import time
from typing import Any, Callable, Iterable, Mapping, Optional

from .. import audit, shields
from ..agent_hooks import owners, tracking
from . import wording
from .model import CATEGORIES, Notice

logger = logging.getLogger(__name__)

FINDINGS_READ = 200
MAX_REMEMBERED = 5000
_LEVELS = {"critical": "critical", "high": "warning", "medium": "warning"}


def _shield_notice(alert: shields.ShieldAlert) -> Notice:
    category = alert.category if alert.category in CATEGORIES else "security"
    return Notice(id=f"shield:{alert.key}", ts=alert.ts, category=category, kind=f"shield:{alert.kind}",
                  level=_LEVELS.get(alert.severity, "info"), title=alert.title, body=alert.text, detail=alert.detail[:400],
                  agent=alert.agent, agent_name=wording.agent_name(alert.agent) if alert.agent else "")


def _attributed(row: Mapping[str, Any], owner_of: Optional[Callable[[Mapping[str, Any]], Optional[owners.Owner]]]) -> Mapping[str, Any]:
    """An OS-sandbox refusal (recorded as ``agent-sandbox``: the kernel's log names a program, not
    an agent) as the agent instance it was attributed to — KI-586: the notice said "Blackbox
    stopped agent-sandbox" while the instance row named the Claude Code session."""
    if owner_of is None or row.get("framework") != audit.SANDBOX_RECORDER:
        return row
    owner = owner_of(row)
    if owner is None:
        return row
    return {**row, "framework": owner.agent, "session_id": owner.instance, "workspace": owner.folder}


class Collector:
    """Reads the three sources and answers the notices not seen before.

    *read_alerts*, *read_findings* and *read_live* are injected (the defaults are the real
    sources), so tests drive it without a node, an agent or a shield."""

    def __init__(self, read_alerts: Optional[Callable[[], Iterable[shields.ShieldAlert]]] = None,
                 read_findings: Optional[Callable[[], Iterable[Mapping[str, Any]]]] = None,
                 read_live: Optional[Callable[[], Mapping[str, Any]]] = None,
                 read_owners: Optional[Callable[[], Callable[[Mapping[str, Any]], Optional[owners.Owner]]]] = None) -> None:
        self._read_alerts = read_alerts or (lambda: shields.alerts(limit=100))
        self._read_findings = read_findings or (lambda: audit.read_findings(limit=FINDINGS_READ))
        self._read_live = read_live or tracking.live
        self._read_owners = read_owners or owners.finding_owners
        self._primed = False
        self._seen: dict[str, float] = {}                    # notice id → when first seen
        self._covered: set[str] = set()                      # finding identifiers a shield alert speaks for
        self._instances: dict[str, tuple[str, str]] = {}     # instance key → (status, waiting)
        self._digest_at: dict[str, float] = {}

    def _new(self, notices: Iterable[Optional[Notice]]) -> list[Notice]:
        fresh = []
        for notice in notices:
            if notice is None or notice.id in self._seen:
                continue
            self._seen[notice.id] = time.monotonic()
            fresh.append(notice)
        if len(self._seen) > MAX_REMEMBERED:
            for old in sorted(self._seen, key=self._seen.get)[:len(self._seen) - MAX_REMEMBERED]:   # type: ignore[arg-type]
                self._seen.pop(old)
        return fresh

    def _from_shields(self) -> list[Notice]:
        alerts = list(self._read_alerts())
        self._covered.update(alert.finding for alert in alerts if alert.finding)
        return self._new(_shield_notice(alert) for alert in alerts)

    def _from_findings(self) -> list[Notice]:
        rows = [row for row in self._read_findings() if str(row.get("identifier") or "") not in self._covered]
        owner_of = self._read_owners() if any(row.get("framework") == audit.SANDBOX_RECORDER for row in rows) else None
        return self._new(wording.finding(_attributed(row, owner_of)) for row in rows)

    def _from_instances(self, now: float, digest_minutes: int) -> list[Notice]:
        tree = self._read_live()
        notices: list[Notice] = []
        current: dict[str, tuple[str, str]] = {}
        for product in tree.get("products") or []:
            for profile in product.get("profiles") or []:
                for session in profile.get("instances") or []:
                    notices += self._instance(session, None, now, current)
                    for sub in session.get("sub_agents") or []:
                        notices += self._instance(sub, session, now, current)
                    if digest_minutes and session.get("status") != "ended":
                        last = self._digest_at.setdefault(str(session.get("key")), now)
                        if now - last >= digest_minutes * 60:
                            self._digest_at[str(session.get("key"))] = now
                            notices.append(wording.digest(session, now, final=False))
        self._instances = current
        notices += [wording.unprotected(row, now) for row in tree.get("unprotected") or []]
        for profile in tree.get("profiles") or []:
            notices += [wording.hooks_off(problem, str(profile.get("agent") or ""), now) for problem in profile.get("problems") or []
                        if problem.get("kind") in ("hooks-off", "managed-only", "hooks-missing")]
        return self._new(notices)

    def _instance(self, row: Mapping[str, Any], parent: Optional[Mapping[str, Any]], now: float,
                  current: dict[str, tuple[str, str]]) -> list[Notice]:
        key, status, waiting = str(row.get("key")), str(row.get("status")), str(row.get("waiting") or "")
        before = self._instances.get(key)
        current[key] = (status, waiting)
        out: list[Notice] = []
        if before is None and status != "ended":
            out.append(wording.lifecycle("started", row, parent, now))
        if status == "ended" and (before is None or before[0] != "ended"):
            out.append(wording.lifecycle("ended", row, parent, now))
            if parent is None:
                out.append(wording.digest(row, now, final=True))
                self._digest_at.pop(key, None)
        if parent is None and waiting and status == "waiting" and (before is None or before[1] != waiting):
            out.append(wording.lifecycle("waiting", row, None, now))
        return out

    def collect(self, now: Optional[float] = None, digest_minutes: int = 0) -> list[Notice]:
        """The notices that are new since the last call, oldest first ([] on the first call)."""
        now = time.time() if now is None else now
        found: list[Notice] = []
        for name, read in (("shields", self._from_shields), ("findings", self._from_findings),
                           ("instances", lambda: self._from_instances(now, digest_minutes))):
            try:
                found += read()
            except Exception:   # health: allow BLE001 -- one source's fault costs only its notices this tick
                logger.debug("blackbox notify: reading %s failed", name, exc_info=True)
        if not self._primed:
            self._primed = True
            return []
        return sorted(found, key=lambda notice: notice.ts)
