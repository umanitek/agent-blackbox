"""One notification, as Blackbox words it for the person.

``title`` and ``body`` are LOCK-SCREEN SAFE: they say which agent, what it did in plain words and
Blackbox's verdict — never a path, a command, a prompt, an address or a user name. ``detail`` is
what the person may choose to add (``notifications.details``): the finding's own already-redacted
title and evidence. ``agent`` / ``instance`` let a click open the instance it is about.
"""

from __future__ import annotations

from dataclasses import dataclass

#: ``security`` — something was stopped or needs a look (on by default); ``lifecycle`` — an agent
#: or sub-agent started, ended or waits for the person; ``digest`` — what a session did, in one line;
#: ``watched`` — a new file arrived in a folder the person watches (on by default: a companion app
#: told it before the core did, and an update keeps what the person saw).
CATEGORIES = ("security", "lifecycle", "digest", "watched")
LEVELS = ("info", "warning", "critical")


@dataclass(frozen=True)
class Notice:
    """*id*: stable for the thing it reports (a second sighting of the same thing is not news).
    *seq*: its place in the feed (0 until published). *deliver*: False when the policy holds it
    back from the screen (quiet hours, a muted agent, the per-minute cap) — it still is in the
    history."""

    id: str
    ts: float
    category: str
    kind: str
    level: str
    title: str
    body: str
    detail: str = ""
    agent: str = ""          # the agent's id (claude-code…), "" when no agent is involved
    agent_name: str = ""
    instance: str = ""       # the instance key a click opens
    project: str = ""        # the project folder's name
    seq: int = 0
    deliver: bool = True
    held: str = ""           # why it is not shown: "quiet-hours" | "muted" | "rate" | ""
    delivery: str = ""       # what the plugin's notifier made of it (OUTCOMES); "" = not handed to it (held, a companion app showed it, not yet)


@dataclass(frozen=True)
class NotifierStatus:
    """The plugin's own native notifier on this machine. *kind*: ``app`` (Blackbox's notifier app:
    notifications carry Blackbox's name), ``fallback`` (the system's script notifier: they carry
    its name), ``none``. *permission*: ``authorized`` | ``denied`` | ``not-determined`` |
    ``unknown``. *detail*: one plain sentence for the person.

    *settings* / *settings_label*: the link that opens the system's notification settings for
    Blackbox and its button's words (both "" when there is nothing to change there) — the
    dashboard, ``blackbox notifications status`` and a companion app offer it while permission
    is off or not asked yet. *can_ask*: the system has not asked the person yet and Blackbox may
    ask now (``POST /api/notifications/allow`` from a click; never from an installer outside the
    person's desktop session). *screen_hidden*: the screen is shared or mirrored, when the system
    hides banners by default — a notification then waits in Notification Center."""

    kind: str
    available: bool
    permission: str
    detail: str
    settings: str = ""
    settings_label: str = ""
    can_ask: bool = False
    screen_hidden: bool = False


#: What became of one notification: ``delivered`` — the system took it into its notification
#: centre under Blackbox's name; ``fallback`` — Blackbox's own notifier could not show it, so it
#: went through the system's script notifier (labelled "Blackbox"); ``not-shown`` — nothing
#: showed it (permission off, or no notifier at all).
OUTCOMES = ("delivered", "fallback", "not-shown")


@dataclass(frozen=True)
class Delivery:
    """The honest answer of one ``send``: *outcome* (one of :data:`OUTCOMES`) and *detail*, one
    plain sentence for the person ("Delivered to Notification Center." — never "shown" when the
    system did not take it)."""

    outcome: str
    detail: str

    @property
    def reached_system(self) -> bool:
        """True when the system's notification centre took it (directly or through the fallback)."""
        return self.outcome != "not-shown"
