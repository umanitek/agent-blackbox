"""The security posture check: the helper's raw facts (``netd/observe/posture.rs``) turned into
checks a person understands, and a score.

Each check: ``id``, ``title``, ``status`` (``ok`` / ``warn`` / ``bad`` / ``unknown``), ``why`` it
matters in one line, and how to fix it — ``fix`` names a safe one-click fix the helper can make
(``network/protect/posture_fix.py``, asked first, with Undo), ``settings`` a System Settings deep
link for the rest. The score is the weighted share of known checks that pass. Observing only.
"""

from __future__ import annotations

from typing import Any, Mapping, Optional

_SETTINGS = "x-apple.systempreferences:"
PANES = {
    "security": _SETTINGS + "com.apple.preference.security",
    "filevault": _SETTINGS + "com.apple.preference.security?FileVault",
    "firewall": _SETTINGS + "com.apple.preference.security?Firewall",
    "updates": _SETTINGS + "com.apple.preferences.softwareupdate",
    "sharing": _SETTINGS + "com.apple.preferences.sharing",
    "airdrop": _SETTINGS + "com.apple.AirDrop-Handoff-Settings.extension",
    "lock": _SETTINGS + "com.apple.Lock-Screen-Settings.extension",
    "users": _SETTINGS + "com.apple.preferences.users",
}
WEIGHTS = {"filevault": 15, "firewall": 12, "stealth": 4, "gatekeeper": 10, "sip": 10, "updates": 8, "remote-login": 8,
           "screen-sharing": 8, "remote-management": 6, "file-sharing": 5, "airdrop": 5, "screen-lock": 6, "guest": 3,
           "passwordless-sudo": 8, "blackbox": 10}


def _check(check_id: str, title: str, status: str, why: str, fix: str = "", settings: str = "", detail: str = "") -> dict[str, Any]:
    return {"id": check_id, "title": title, "status": status, "why": why, "fix": fix, "settings": settings, "detail": detail,
            "weight": WEIGHTS[check_id]}


def _onoff(value: str, good: str = "on") -> str:
    return "unknown" if value not in ("on", "off", "block-all") else ("ok" if value == good or (good == "on" and value == "block-all") else "bad")


def _updates(updates: Mapping[str, str]) -> str:
    values = [updates.get(key, "") for key in ("check", "security")]
    if any(v == "0" for v in values):
        return "bad"
    return "ok"   # unset keys mean macOS's default: on


def checks(facts: Mapping[str, Any], blackbox: Mapping[str, Any]) -> list[dict[str, Any]]:
    """Every check for *facts*; *blackbox*: ``running``, ``dns_active``, ``firewall_active``,
    ``remote_locked`` (Remote Login allowed only through Blackbox's lock)."""
    remote_locked = bool(blackbox.get("remote_locked"))
    airdrop_everyone = [entry["user"] for entry in facts.get("airdrop", []) if str(entry.get("mode", "")).lower().startswith("everyone")]
    lock = str(facts.get("screen_lock", "unknown"))
    guest = str(facts.get("guest", ""))
    protections = blackbox.get("running") and blackbox.get("dns_active") and blackbox.get("firewall_active")
    return [
        _check("filevault", "FileVault disk encryption", _onoff(facts.get("filevault", "unknown")),
               "Encrypts your disk, so a lost or stolen Mac cannot be read.", settings=PANES["filevault"]),
        _check("firewall", "macOS firewall", _onoff(facts.get("firewall", "unknown")),
               "Refuses incoming connections to apps you have not allowed.", fix="firewall-on", settings=PANES["firewall"]),
        _check("stealth", "Firewall stealth mode", "warn" if facts.get("stealth") == "off" else _onoff(facts.get("stealth", "unknown")),
               "Makes this Mac invisible to network scans (no answer to probes).", fix="stealth-on", settings=PANES["firewall"]),
        _check("gatekeeper", "Gatekeeper", _onoff(facts.get("gatekeeper", "unknown")),
               "Only opens apps that are signed and checked by Apple.", settings=PANES["security"]),
        _check("sip", "System Integrity Protection", _onoff(facts.get("sip", "unknown")),
               "Stops anything — even with admin rights — from changing macOS itself.",
               detail="Can only be switched on from macOS Recovery."),
        _check("updates", "Automatic security updates", _updates(facts.get("updates") or {}),
               "Security fixes arrive without waiting for you.", settings=PANES["updates"]),
        _check("remote-login", "Remote Login (SSH)", "ok" if not facts.get("remote_login") else ("warn" if remote_locked else "bad"),
               "Lets anyone with a password or key log in to this Mac over the network.", fix="remote-login-off", settings=PANES["sharing"],
               detail="On, but only allowed sources can reach it (Blackbox's lock)." if facts.get("remote_login") and remote_locked else ""),
        _check("screen-sharing", "Screen Sharing", "bad" if facts.get("screen_sharing") else "ok",
               "Lets someone see and control your screen from another machine.", fix="screen-sharing-off", settings=PANES["sharing"]),
        _check("remote-management", "Remote Management (ARD)", "bad" if facts.get("remote_management") else "ok",
               "Lets an administrator control this Mac remotely.", fix="remote-management-off", settings=PANES["sharing"]),
        _check("file-sharing", "File Sharing", "warn" if facts.get("file_sharing") else "ok",
               "Shares folders with other machines on the network.", fix="file-sharing-off", settings=PANES["sharing"]),
        _check("airdrop", "AirDrop not open to everyone", "warn" if airdrop_everyone else "ok",
               "AirDrop set to Everyone lets strangers nearby send you files.", settings=PANES["airdrop"],
               detail=("Set to Everyone for: " + ", ".join(airdrop_everyone)) if airdrop_everyone else ""),
        _check("screen-lock", "Password right after sleep", "unknown" if lock == "unknown" else ("ok" if lock == "immediate" else ("bad" if lock == "off" else "warn")),
               "Locks the Mac the moment it sleeps, so nobody walks up to an open session.", settings=PANES["lock"],
               detail="" if lock in ("unknown", "immediate") else f"Now: {lock}."),
        _check("guest", "Guest account off", "bad" if guest == "1" else "ok",
               "A guest account lets anyone log in without a password.", fix="guest-off", settings=PANES["users"]),
        _check("passwordless-sudo", "A password is needed to become root", {"yes": "bad", "no": "ok"}.get(str(facts.get("passwordless_sudo")), "unknown"),
               "Without a password, any program on this Mac — an AI agent included — becomes root without asking you.",
               settings=PANES["users"],
               detail="A rule in /etc/sudoers or /etc/sudoers.d says NOPASSWD. Remove it to be asked again."
               if facts.get("passwordless_sudo") == "yes" else ""),
        _check("blackbox", "Blackbox protections on", "ok" if protections else "warn",
               "DNS Shield and the Threat Firewall stop known malicious sites and addresses for every app."),
    ]


def score(items: list[Mapping[str, Any]]) -> Optional[int]:
    """The weighted share of known checks that pass (a warning counts half); None when none is known."""
    known = [c for c in items if c["status"] != "unknown"]
    total = sum(c["weight"] for c in known)
    if not total:
        return None
    earned = sum(c["weight"] * (1.0 if c["status"] == "ok" else 0.5 if c["status"] == "warn" else 0.0) for c in known)
    return round(100 * earned / total)
