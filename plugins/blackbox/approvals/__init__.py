"""Turning protection DOWN needs the person's confirmation in Blackbox Desktop (Amos, 2026-11-21:
"anything that would switch off Blackbox must always require Blackbox permission").

A change that weakens protection (:mod:`.weakening`) — Audit instead of Block, a shield or a
detection off, an agent no longer protected, a protected path removed, remote access unlocked —
is held (:mod:`.store`) until the person answers a native dialog in the Desktop app, which proves
the answer with its own key — or, without Desktop, until the person passes the system's password
prompt from the dashboard page (:mod:`.system_prompt`); the gate is ``dashboard/approval_routes``. Strengthening
changes apply at once. Blackbox Desktop's docs/security/approvals.md has the threat model.

Usage::

    approvals.reasons("/api/settings", {"mode": "audit"}, approvals.Current.read())
    approvals.STORE.hold(route, body, reasons)
"""

from __future__ import annotations

from . import system_prompt
from .store import Approvals, Held, answer_message, pair_message, sign
from .weakening import Current, gated, reasons

#: The one store for this dashboard run.
STORE = Approvals()


__all__ = ["STORE", "Approvals", "Current", "Held", "answer_message", "gated", "pair_message", "reasons", "sign", "system_prompt"]
