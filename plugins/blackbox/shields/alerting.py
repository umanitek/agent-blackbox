"""Every engaged shield's alerts in one list — what ``notify`` turns into notifications.

A shield offers ``Shield.alerts`` (its own lock-screen-safe wording); this module asks each
ENABLED shield and merges the answers newest first. A shield whose ``alerts`` raises costs only
its own alerts (the others are still shown).

Usage::

    from .. import shields
    for alert in shields.alerts(limit=50): ...      # [ShieldAlert]
"""

from __future__ import annotations

import logging

from .contract import ShieldAlert

logger = logging.getLogger(__name__)
MAX_ALERTS = 200


def alerts(limit: int = 50) -> list[ShieldAlert]:
    """The alerts of every enabled shield that offers some, newest first (at most *limit*)."""
    from .. import shields   # the registry is this package's entry; read when asked (it imports this module)
    found: list[ShieldAlert] = []
    for shield, mode in shields.snapshot().entries:
        if not mode.enabled or shield.alerts is None:
            continue
        try:
            found.extend(item for item in shield.alerts() if isinstance(item, ShieldAlert))
        except Exception:   # health: allow BLE001 -- one shield's fault costs only its own alerts
            logger.debug("blackbox: shield %s alerts failed", shield.id, exc_info=True)
    return sorted(found, key=lambda item: -item.ts)[:max(0, min(limit, MAX_ALERTS))]
