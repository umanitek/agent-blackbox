"""Exposure and startup items, for a person: every service the network can reach and everything
that starts by itself, each with who signed its program and how worried to be.

Built from the helper's latest system report (:mod:`.system_report`). A program's signature comes
from :mod:`.intel.signature` (cached; an unknown one is checked in the background, a few per read,
so a page never waits on ``codesign``). Observing only.

Risk levels, worst first: ``critical`` (a startup item signed by no one), ``high`` (unsigned,
ad-hoc or test-signed, or run from a temporary / Downloads folder), ``medium`` (signed by a known
developer — check you know it; configuration profiles, kernel extensions, scheduled jobs),
``low`` (part of macOS, or Blackbox itself), ``checking`` (signature not read yet).

Blackbox's own items are recognised only from facts nothing in the person's account can forge
(independent review 2026-11-26, finding 9: a LaunchAgent planted with an ``ai.umanitek.blackbox.*``
label and a program under Blackbox's data folder — both the person's, so an agent's, to write —
rated "Blackbox, low"; so did any process whose pid was written into the node's pid file):

* a startup item is Blackbox's (``own``, low) when the root helper reports it from a place only
  root writes (a system launch daemon / agent, a system systemd unit), with one of Blackbox's
  labels, and its program is root's own file inside the root-only helper folder;
* a listener is Blackbox's when its process is this dashboard (the helper reports the pid; the
  dashboard knows its own).

An item in the person's own account that LOOKS like Blackbox's (its label and a program in
Blackbox's folders, or the node's pid file) is rated like any program and marked
``claims_own`` with a sentence saying so — Blackbox can not vouch for what the person's account
can change. Anything else named "Blackbox" is judged like any program.
"""

from __future__ import annotations

import os
import re
import threading
from typing import Any, Mapping, Optional

from ....kernel import config, constants, system_helper
from ....kernel.bounded_files import read_small_text
from . import system_report
from . import signature

CHECKS_PER_READ = 8
SERVICES = {22: "SSH (Remote Login)", 88: "Kerberos", 445: "File Sharing (SMB)", 548: "File Sharing (AFP)",
            631: "Printer Sharing", 3031: "Remote Apple Events", 3283: "Remote Management", 5000: "AirPlay Receiver",
            5353: "Bonjour", 5900: "Screen Sharing", 7000: "AirPlay Receiver"}
ITEM_NAMES = {"launch-agent": "Launch agent (all users)", "launch-daemon": "Launch daemon (system)", "user-agent": "Launch agent (your account)",
              "cron": "Scheduled job (cron)", "periodic": "Scheduled job (periodic)", "login-item": "Login / background item",
              "profile": "Configuration profile", "system-extension": "System extension", "kernel-extension": "Kernel extension",
              # Linux's
              "systemd-unit": "systemd service (system)", "user-unit": "systemd service (your account)",
              "autostart": "Desktop autostart entry", "dbus-service": "D-Bus service (starts on demand)",
              "session-start": "Session start file", "root-config": "System configuration (root)"}
# no-tmp: ok — a program RUN from a temporary folder is a risk signal here, not scratch space
_RISKY_PLACES = re.compile(r"^(/tmp/|/private/tmp/|/private/var/folders/|/var/folders/|/Users/[^/]+/Downloads/)")
_ORDER = {"critical": 0, "high": 1, "medium": 2, "checking": 3, "low": 4}
#: Blackbox's launchd labels all start so (dashboard, node, system protection helper, curator…).
OWN_LABEL_PREFIX = "ai.umanitek.blackbox"
OWN_NAME = "Blackbox (this protection)"
#: Startup kinds the helper reads from places only root writes.
ROOT_HELD_KINDS = frozenset({"launch-daemon", "launch-agent", "systemd-unit"})
NODE_CLAIM = (" Blackbox's DKG node file names this process; its peer-to-peer port is how it receives the threat "
              "graph — but that file is yours to change, so check it is Blackbox's node.")
CLAIMED_WHY = (" It says it is Blackbox's, but it sits where any program you run could change it, "
               "so Blackbox can not vouch for it.")
_NODE_PID_FILE = "daemon.pid"
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
        # A program named without a folder, or one that is not there, has no signature to read
        # and is never cached: answer it now, never "checking" forever (E2E B8).
        if not os.path.isabs(program):
            return "medium", f"Started by name ({program[:64]}) — Blackbox cannot tell which file that runs. Check you know it.", None
        if not os.path.isfile(program):
            return "medium", "Its program is not on this Mac, or Blackbox cannot read it.", None
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


def _own_folders() -> tuple[str, ...]:
    return tuple(os.path.realpath(str(folder)) + os.sep for folder in
                 (constants.blackbox_home(), config.dkg_home(), system_helper.HOME))


def _root_file(path: str) -> bool:
    try:
        return os.lstat(path).st_uid == 0
    except OSError:
        return False


def is_own_startup_item(item: Mapping[str, Any]) -> bool:
    """Blackbox's own helper, proven: a root-held kind (the helper's report), one of Blackbox's
    labels, and a root-owned program inside the root-only helper folder."""
    program = os.path.realpath(str(item.get("program") or ""))
    return (item.get("kind") in ROOT_HELD_KINDS and str(item.get("label") or "").startswith(OWN_LABEL_PREFIX)
            and program.startswith(os.path.realpath(str(system_helper.HOME)) + os.sep) and _root_file(program))


def claims_own_startup_item(item: Mapping[str, Any]) -> bool:
    """Looks like Blackbox's (its label and a program in Blackbox's folders) but is not proven."""
    program = os.path.realpath(str(item.get("program") or ""))
    return str(item.get("label") or "").startswith(OWN_LABEL_PREFIX) and program.startswith(_own_folders())


def _node_pid() -> int:
    """The pid Blackbox's DKG node's pid file names (the person's file: a claim, never proof)."""
    text = read_small_text(str(config.dkg_home() / _NODE_PID_FILE), 64)
    return int(text.strip()) if text and text.strip().isdigit() else 0


def listeners(snapshot: Mapping[str, Any]) -> list[dict[str, Any]]:
    rows, unknown = [], []
    node = _node_pid()
    for item in snapshot.get("exposure", []):
        if item.get("pid") == os.getpid():
            rows.append({**item, "service": OWN_NAME, "risk": "low", "why": "Blackbox's dashboard.", "signature": None, "own": True,
                         "first_seen": system_report.first_seen(item) or item.get("since")})
            continue
        risk, why, sig = judge(item["program"])
        if risk == "checking":
            unknown.append(item["program"])
        claimed = {"claims_own": True, "why": why + NODE_CLAIM} if node and item.get("pid") == node else {}
        rows.append({**item, "service": SERVICES.get(item["port"], ""), "risk": risk, "why": why, "signature": sig,
                     "first_seen": system_report.first_seen(item) or item.get("since"), **claimed})
    _check_later(unknown)
    return sorted(rows, key=lambda r: (_ORDER.get(r["risk"], 9), -(r["first_seen"] or 0)))


def startup_items(snapshot: Mapping[str, Any]) -> list[dict[str, Any]]:
    rows, unknown, seen = [], [], set()
    for item in snapshot.get("persistence", []):
        kind = item["kind"]
        # One row per thing that starts: macOS lists a LaunchAgent both as a file and as a
        # background item, which showed every item twice (E2E 2026-11-21).
        key = (item.get("label") or item.get("id"), item.get("program"))
        if key in seen:
            continue
        seen.add(key)
        original = item   # first-seen times are kept under the item as the helper reported it
        if not item.get("label") or item.get("label") == "(null)":
            item = {**item, "label": os.path.basename(str(item.get("program") or "")) or "Unnamed item"}
        if is_own_startup_item(item):
            rows.append({**item, "kind_name": ITEM_NAMES.get(kind, kind), "risk": "low", "own": True,
                         "why": f"{OWN_NAME}.", "signature": None, "added_at": system_report.first_seen(original)})
            continue
        if kind in ("profile", "kernel-extension", "cron", "periodic") and not item["program"]:
            risk = "high" if kind == "kernel-extension" else "medium"
            why = {"profile": "Can change system settings and certificates.", "kernel-extension": "Runs inside the macOS kernel."}.get(kind, "Runs on a schedule.")
            sig = None
        else:
            risk, why, sig = judge(item["program"], startup=True)
            if risk == "checking":
                unknown.append(item["program"])
        claimed = {"claims_own": True, "why": why + CLAIMED_WHY} if claims_own_startup_item(item) else {}
        rows.append({**item, "kind_name": ITEM_NAMES.get(kind, kind), "risk": risk, "why": why, "signature": sig,
                     "added_at": system_report.first_seen(original), **claimed})
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
