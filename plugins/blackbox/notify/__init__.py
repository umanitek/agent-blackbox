"""Native notifications: Blackbox tells the person what their AI agents are doing — which agent,
what it did in plain words, and whether Blackbox allowed, flagged or stopped it (Amos,
2026-11-22: the PLUGIN itself connects to the system's notifications from install; Blackbox
Desktop only shows the same feed).

* :mod:`.sources` reads what Blackbox already records (shield alerts, findings — an agent asking
  for root or running as root among them —, agent instances) and answers what is new;
* :mod:`.wording` words each notice safe for a lock screen; :mod:`.policy` is what the person
  wants told (security ON; lifecycle and digest opt-in; per-agent mute, quiet hours, a
  per-minute cap; turning security notices off waits for the person's approval);
* :mod:`.feed` is the ONE notifications feed (and the history); :mod:`.deliver` hands it to ONE
  deliverer — Blackbox Desktop while it holds the lease, else the plugin's own notifier
  (:mod:`.platform`: per operating system; macOS has Blackbox's own notifier app).

Nothing here is on an agent's path: the pump runs on the dashboard's own thread, and a notifier
that fails only costs a notification (fail-open). No prompt or command text is in a notice.

Usage::

    from .. import notify
    notify.PUMP.start()                       # the dashboard, at startup
    notify.rows(since=41)                     # the feed after seq 41, as JSON rows
    notify.claim("desktop", 30)               # Blackbox Desktop delivers for the next 30 s
"""

from __future__ import annotations

from dataclasses import asdict
from pathlib import Path
from typing import Any, Optional

from ..kernel import settings
from . import deliver, feed, platform, policy
from .deliver import Pump, claim, holder
from .model import CATEGORIES, Delivery, Notice, NotifierStatus
from .policy import Policy

__all__ = ["CATEGORIES", "PUMP", "Delivery", "Notice", "NotifierStatus", "Policy", "Pump", "claim", "delivered", "history", "holder",
           "install_notifier", "mark_delivered", "notifier_status", "open_notification_settings", "policy_weakening", "read_policy",
           "remove_notifier", "request_permission", "rows", "send_test", "top", "wait"]

#: The saved ``notifications`` section is validated by this package (the settings writer asks it).
settings.SECTION_VALIDATORS[policy.SECTION] = policy.validate

#: The one pump of this dashboard run.
PUMP = Pump()


def read_policy() -> Policy:
    return policy.read()


def policy_weakening(proposed: Any) -> list[str]:
    """Why saving *proposed* (a ``notifications`` section) would tell the person less about
    threats — the approval gate holds such a change (empty: apply it)."""
    return policy.weakening(proposed, policy.read())


def rows(since: int = 0, limit: int = 100) -> list[dict[str, Any]]:
    """The feed after *since*, oldest first."""
    return [asdict(notice) for notice in feed.since(since, limit)]


def history(limit: int = 100, before: int = 0) -> list[dict[str, Any]]:
    """The newest notices first (a page of the history)."""
    return [asdict(notice) for notice in feed.latest(limit, before)]


def top() -> int:
    return feed.top()


def delivered() -> int:
    return feed.delivered()


def mark_delivered(seq: int) -> int:
    return feed.mark_delivered(seq)


def wait(seq: int, seconds: float) -> int:
    return feed.wait(seq, seconds)


def notifier_status() -> NotifierStatus:
    return platform.status()


def install_notifier(source: Optional[Path] = None, sha256: str = "") -> NotifierStatus:
    """Put the plugin's own notifier in place (see ``platform``); raises ValueError for an
    archive that does not match its checksum."""
    return platform.install(source, sha256)


def remove_notifier() -> None:
    platform.remove()


def request_permission() -> NotifierStatus:
    """Ask the person now whether Blackbox may notify them — only from their click, and macOS
    asks only someone at the desktop (``platform.request``)."""
    return platform.request()


def open_notification_settings() -> bool:
    """Open the system's notification settings for Blackbox (the person's click)."""
    return platform.open_settings()


def send_test() -> Delivery:
    """Hand one harmless notification to the system now and say what became of it (the person's
    "is it working?") — "delivered to Notification Center", or why it was not shown."""
    return platform.send("Blackbox notifications are on", "This is what Blackbox shows when an AI agent needs your attention.",
                         "info", "blackbox-test")
