"""Turning protection DOWN needs the person's confirmation: anything that would switch Blackbox
off always requires the person's permission.

A change that weakens protection (:mod:`.weakening`) — Audit instead of Block, a shield or a
detection off, an agent no longer protected, a protected path removed, remote access unlocked —
is held (:mod:`.store`) until the person answers a paired companion app's native dialog, which
proves the answer with its own key — or, without one, until the person passes the system's password
prompt from the dashboard page (:mod:`.system_prompt`); the gate is ``dashboard/approval_routes``. Strengthening
changes apply at once.

Usage::

    approvals.reasons("/api/settings", {"mode": "audit"}, approvals.Current.read())
    approvals.STORE.hold(route, body, reasons)
"""

from __future__ import annotations

from . import system_prompt
from .store import Approvals, Held, answer_message, pair_message, sign
from .weakening import SECTION_JUDGES, Current, gated, reasons

#: The one store for this dashboard run.
STORE = Approvals()


__all__ = ["SECTION_JUDGES", "STORE", "Approvals", "Current", "Held", "answer_message", "gated", "pair_message", "reasons", "sign", "system_prompt"]
