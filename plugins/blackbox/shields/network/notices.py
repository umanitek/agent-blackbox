"""Network Shield's alerts as the notifier may show them: a fixed, LOCK-SCREEN-SAFE sentence per
kind of alert — never the address, the user name or the file a notification on a locked Mac would
give away. The full sentence (``api.alerts``'s own text) travels as the alert's ``detail``, for
inside the app and for a person who chose "show details in notifications".

One wording for the dashboard's notifier and Blackbox Desktop (which used to keep its own copy).

Usage::

    notices.shield_alerts()      # [ShieldAlert] — what ``Shield.alerts`` answers
"""

from __future__ import annotations

import hashlib

from ..contract import ShieldAlert
from . import api
from .monitor import system_report

TITLE = "Network Shield"
SEE = "Open Blackbox to see the details."
#: kind → (what happened, what to do), both safe on a lock screen.
WORDS: dict[str, tuple[str, str]] = {
    "ssh-session-new": ("Someone signed in remotely", "A new SSH session started on this Mac. Open Blackbox to see who."),
    "remote-session-new": ("Someone connected remotely", "A new remote session started on this Mac. Open Blackbox to see who."),
    "ssh-session-ended": ("A remote session ended", SEE),
    "remote-session-ended": ("A remote session ended", SEE),
    "remote-auth-failed": ("Failed sign-in attempt", "Someone failed to sign in remotely. Open Blackbox to see from where."),
    "remote-auto-blocked": ("Password guessing blocked", "Blackbox blocked an address that kept failing to sign in. " + SEE),
    "remote-service-changed": ("Remote access setting changed", SEE),
    "remote-login-changed": ("Remote Login switched", SEE),
    "remote-end-refused": ("A remote session could not be ended", SEE),
    "file-changed": ("A login file changed", "A file that controls who can sign in to this Mac changed. " + SEE),
    "connection-cut": ("Malicious connection cut", "Blackbox ended a connection to an address on the threat list. " + SEE),
    "listener-new": ("A program is accepting connections", "A program started listening for connections from the network. " + SEE),
    "listener-closed": ("A program stopped accepting connections", SEE),
    "persistence-new": ("New startup item", "Something set itself to run when this Mac starts. " + SEE),
    "persistence-changed": ("A startup item changed", SEE),
    "persistence-removed": ("A startup item was removed", SEE),
    "dns-changed": ("DNS settings changed", SEE),
    "proxy-set": ("A proxy was set", "Your traffic may be going through a proxy. " + SEE),
    "proxy-removed": ("A proxy was removed", SEE),
    "vpn-added": ("A VPN was added", SEE),
    "firewall-changed": ("The macOS firewall changed", SEE),
    "helper-modified": ("Blackbox's helper was changed", "Something changed Blackbox's network helper. " + SEE),
}


def _standing() -> list[ShieldAlert]:
    """What is true NOW and worth one notice (its key never changes, so it is told once)."""
    snapshot = system_report.snapshot()
    if not snapshot or (snapshot.get("posture") or {}).get("passwordless_sudo") != "yes":
        return []
    return [ShieldAlert(key="network:passwordless-sudo", kind="passwordless-sudo", ts=float(snapshot.get("at") or 0), severity="high",
                        title=f"{TITLE} · sudo needs no password",
                        text="Any program on this Mac — an AI agent included — can become root without asking you. " + SEE,
                        detail="A sudo rule on this Mac lets commands run without a password.")]


def shield_alerts() -> list[ShieldAlert]:
    """Network Shield's latest alerts, each with its lock-screen-safe title and text."""
    found = _standing()
    for row in api.alerts():
        kind, full = str(row.get("kind") or ""), str(row.get("text") or "")
        what, then = WORDS.get(kind, ("Network Shield alert", SEE))
        ts = float(row.get("ts") or 0)
        key = f"network:{kind}:{ts:.3f}:{hashlib.sha256(full.encode('utf-8')).hexdigest()[:10]}"
        found.append(ShieldAlert(key=key, kind=kind, ts=ts, severity=str(row.get("severity") or "info"),
                                 title=f"{TITLE} · {what}", text=then, detail=full))
    return found
