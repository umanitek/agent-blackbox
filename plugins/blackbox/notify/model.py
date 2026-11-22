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
#: ``watched`` — a new file arrived in a folder the person watches (on by default: Blackbox Desktop
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


@dataclass(frozen=True)
class NotifierStatus:
    """The plugin's own native notifier on this machine. *kind*: ``app`` (Blackbox's notifier app:
    notifications carry Blackbox's name), ``fallback`` (the system's script notifier: they carry
    its name), ``none``. *permission*: ``authorized`` | ``denied`` | ``not-determined`` |
    ``unknown``. *detail*: one plain sentence for the person."""

    kind: str
    available: bool
    permission: str
    detail: str
