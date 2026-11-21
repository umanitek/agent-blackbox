"""Exposure and startup items, for a person: every service the network can reach and everything
that starts by itself, each with who signed its program and how worried to be.

Built from the helper's latest system report (:mod:`.system_report`). A program's signature comes
from :mod:`.intel.signature` (cached; an unknown one is checked in the background, a few per read,
so a page never waits on ``codesign``). Observing only.

Risk levels, worst first: ``critical`` (a startup item signed by no one), ``high`` (unsigned,
ad-hoc or test-signed, or run from a temporary / Downloads folder), ``medium`` (signed by a known
developer — check you know it; configuration profiles, kernel extensions, scheduled jobs),
``low`` (part of macOS), ``checking`` (signature not read yet).
"""

from __future__ import annotations

import re
import threading
from typing import Any, Mapping, Optional

from . import system_report
from . import signature

CHECKS_PER_READ = 8
SERVICES = {22: "SSH (Remote Login)", 88: "Kerberos", 445: "File Sharing (SMB)", 548: "File Sharing (AFP)",
            631: "Printer Sharing", 3031: "Remote Apple Events", 3283: "Remote Management", 5000: "AirPlay Receiver",
            5353: "Bonjour", 5900: "Screen Sharing", 7000: "AirPlay Receiver"}
ITEM_NAMES = {"launch-agent": "Launch agent (all users)", "launch-daemon": "Launch daemon (system)", "user-agent": "Launch agent (your account)",
              "cron": "Scheduled job (cron)", "periodic": "Scheduled job (periodic)", "login-item": "Login / background item",
              "profile": "Configuration profile", "system-extension": "System extension", "kernel-extension": "Kernel extension"}
# no-tmp: ok — a program RUN from a temporary folder is a risk signal here, not scratch space
_RISKY_PLACES = re.compile(r"^(/tmp/|/private/tmp/|/private/var/folders/|/var/folders/|/Users/[^/]+/Downloads/)")
_ORDER = {"critical": 0, "high": 1, "medium": 2, "checking": 3, "low": 4}
_checking: set[str] = set()
_lock = threading.Lock()


def _check_later(paths: list[str]) -> None:
    """Reads a few unknown signatures in the background (each path once at a time)."""
    with _lock:
        todo = [p for p in paths if p not in _checking][:CHECKS_PER_READ]
        _checking.update(todo)

    def work() -> None:
        for path in todo:
            try:
                signature.check(path)
            finally:
                with _lock:
                    _checking.discard(path)
    if todo:
        threading.Thread(target=work, name="blackbox-exposure-signatures", daemon=True).start()


def judge(program: str, startup: bool = False) -> tuple[str, str, Optional[dict[str, Any]]]:
    """(risk, why, signature) for *program*. *startup*: an unsigned startup item is critical."""
    if not program:
        return "medium", "The program could not be identified.", None
    if _RISKY_PLACES.match(program):
        return ("critical" if startup else "high"), "Runs from a temporary or Downloads folder.", None
    found = signature.lookup(program)
    if found is None:
        return "checking", "Reading who signed it…", None
    sig = found.as_json()
    if found.kind == "apple":
        return "low", "Part of macOS (signed by Apple).", sig
    if found.kind == "app_store":
        return "medium", "From the Mac App Store.", sig
    if found.kind == "developer_id":
        notarised = ", notarised by Apple" if found.notarised else ""
        return "medium", f"Signed by {found.signer or 'a known developer'}{notarised}. Check you know it.", sig
    if found.kind == "development":
        return "high", "A developer's test build — not meant to run on your Mac.", sig
    if found.kind == "invalid":   # claims a signer it cannot prove (review 2026-11-21, finding 3)
        return ("critical" if startup else "high"), (f"Its signature does not verify — it claims to be signed by "
                                                     f"{found.signer or 'someone'}, but it was changed or the certificate is not real."), sig
    if found.kind == "unknown":   # unreadable, or a signer Apple does not vouch for: as cautious as unsigned
        return ("critical" if startup else "high"), "Its signature could not be checked, or names a signer Apple does not vouch for.", sig
    kind = "Signed by no one (ad hoc)." if found.kind == "adhoc" else "Not signed at all."
    return ("critical" if startup else "high"), kind, sig


def listeners(snapshot: Mapping[str, Any]) -> list[dict[str, Any]]:
    rows, unknown = [], []
    for item in snapshot.get("exposure", []):
        risk, why, sig = judge(item["program"])
        if risk == "checking":
            unknown.append(item["program"])
        rows.append({**item, "service": SERVICES.get(item["port"], ""), "risk": risk, "why": why, "signature": sig,
                     "first_seen": system_report.first_seen(item) or item.get("since")})
    _check_later(unknown)
    return sorted(rows, key=lambda r: (_ORDER.get(r["risk"], 9), -(r["first_seen"] or 0)))


def startup_items(snapshot: Mapping[str, Any]) -> list[dict[str, Any]]:
    rows, unknown = [], []
    for item in snapshot.get("persistence", []):
        kind = item["kind"]
        if kind in ("profile", "kernel-extension", "cron", "periodic") and not item["program"]:
            risk = "high" if kind == "kernel-extension" else "medium"
            why = {"profile": "Can change system settings and certificates.", "kernel-extension": "Runs inside the macOS kernel."}.get(kind, "Runs on a schedule.")
            sig = None
        else:
            risk, why, sig = judge(item["program"], startup=True)
            if risk == "checking":
                unknown.append(item["program"])
        rows.append({**item, "kind_name": ITEM_NAMES.get(kind, kind), "risk": risk, "why": why, "signature": sig,
                     "added_at": system_report.first_seen(item)})
    _check_later(unknown)
    return sorted(rows, key=lambda r: (_ORDER.get(r["risk"], 9), -(r["added_at"] or 0)))


def view(now: Optional[float] = None) -> dict[str, Any]:
    """The ``exposure`` read: listeners, startup items and the raw tamper look (the feature adds
    whether DNS Shield is on). *watching* is False until the helper's report is fresh."""
    snapshot = system_report.snapshot(now)
    if snapshot is None:
        return {"watching": False, "listeners": [], "startup": [], "tamper": None}
    return {"watching": True, "updated_at": snapshot.get("at"), "listeners": listeners(snapshot),
            "startup": startup_items(snapshot), "tamper": snapshot.get("tamper")}
