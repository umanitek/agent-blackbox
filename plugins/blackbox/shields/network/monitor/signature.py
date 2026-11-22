"""Who signed a program, and which app it belongs to — read from the program itself.

``codesign -dv --verbose=2 <path>`` (it writes to stderr) names the signer chain:

* ``Authority=macOS Software Signing`` / ``Software Signing`` (+ ``Platform identifier``) — Apple's own;
* ``Authority=Apple Mac OS Application Signing`` — from the Mac App Store;
* ``Authority=Developer ID Application: Brave Software, Inc. (KL8N8XSYF4)`` — a known developer,
  with ``Notarization Ticket=stapled`` when Apple notarised it;
* ``Authority=Apple Development: …`` — a developer's own test build;
* ``Signature=adhoc`` — signed by no one (anybody can make one);
* ``code object is not signed at all`` — unsigned.

An executable inside ``Something.app/Contents/MacOS/`` also gets the app's own name, identifier
and version from its ``Info.plist`` (read with a size cap, never anything else in the bundle).

A claimed signer is only believed once it VERIFIES (:mod:`...signing` — the signature is intact,
the chain ends at Apple with the right kind of leaf, and a Developer ID program's notarisation is
asked of Gatekeeper): ``codesign -dv`` alone only displays what a binary says about itself, which a
self-signed certificate or a changed binary can fake. A claim that does not verify is the kind
``invalid`` (its own state, never safe); one that could not be checked is ``unknown``.

Results are cached by path + modification time + size (a program changes only when it is
replaced), bounded; :func:`lookup` never runs ``codesign`` (a page never waits) and :func:`check`
does.

Usage::

    found = check("/Applications/Safari.app/Contents/MacOS/Safari")   # runs codesign once
    found = lookup(path)          # the cached answer, or None when not checked yet
    found.kind                    # "apple" | "app_store" | "developer_id" | "development" | "adhoc" | "unsigned"
                                  # | "invalid" (claims a signer that does not verify) | "unknown"
    found.claimed                 # for "invalid": the kind it claimed
"""

from __future__ import annotations

import os
import plistlib
import subprocess
import threading
from dataclasses import dataclass
from typing import Optional

from . import platform
from ...json_records import JsonValue, _record_json
from ....kernel import code_signing as signing

MAX_CACHED = 4000
MAX_PLIST_BYTES = 1024 * 1024


@dataclass(frozen=True)
class Signature:
    """Who signed a program (*kind*, the *signer* as it names itself, its *team* id), whether
    Apple *notarised* it, and the app it belongs to (*bundle_id*, *app_name*, *version*).
    *claimed*: for kind ``invalid``, the kind the program claimed (its *signer* is the claimed name)."""

    kind: str
    signer: str = ""
    team: str = ""
    notarised: bool = False
    bundle_id: str = ""
    app_name: str = ""
    version: str = ""
    claimed: str = ""

    def as_json(self) -> dict[str, JsonValue]:
        return _record_json(self)


def parse(text: str) -> Signature:
    """The signature ``codesign -dv --verbose=2`` describes in *text* (read by the kernel's
    ``code_signing.parse_display``, which other packages share)."""
    claim = signing.parse_display(text)
    return Signature(kind=claim.kind, signer=claim.signer, team=claim.team, notarised=claim.notarised)


def bundle_of(path: str) -> tuple[str, str, str]:
    """``(identifier, name, version)`` of the app bundle *path* runs from ("" each when none)."""
    if ".app/Contents/MacOS/" not in path:
        return "", "", ""
    plist = path.split("/Contents/MacOS/", 1)[0] + "/Contents/Info.plist"
    try:
        if os.path.getsize(plist) > MAX_PLIST_BYTES:
            return "", "", ""
        with open(plist, "rb") as handle:
            info = plistlib.load(handle)
    except (OSError, ValueError, plistlib.InvalidFileException):
        return "", "", ""
    if not isinstance(info, dict):
        return "", "", ""
    text = lambda key: str(info.get(key) or "")[:200]
    return text("CFBundleIdentifier"), text("CFBundleDisplayName") or text("CFBundleName"), text("CFBundleShortVersionString")


_lock = threading.Lock()
_cache: dict[tuple[str, float, int], Signature] = {}
#: Kinds that name a signer and so must verify before they are believed.
CLAIMS = frozenset(signing.REQUIREMENTS)


def _key(path: str) -> Optional[tuple[str, float, int]]:
    try:
        status = os.stat(path)
    except OSError:
        return None
    return path, status.st_mtime, status.st_size


def verified(path: str, found: Signature, run: signing.Runner = signing._run) -> Signature:
    """*found* (what ``codesign -dv`` displayed) held to what it claims: unchanged when it
    verifies (notarisation from Gatekeeper for Developer ID), ``invalid`` when it does not,
    ``unknown`` when it could not be checked."""
    if found.kind not in CLAIMS:
        return found   # ad hoc / unsigned / unknown claim nothing to verify
    check_result = signing.verify(path, found.kind, run)
    if check_result.valid is None:
        return Signature(kind="unknown", signer=found.signer, team=found.team)
    if not check_result.valid:
        return Signature(kind="invalid", signer=found.signer, team=found.team, claimed=found.kind)
    notarised = check_result.notarised if found.kind == "developer_id" else found.notarised
    return Signature(**{**found.__dict__, "notarised": notarised})


def lookup(path: str) -> Optional[Signature]:
    """The cached signature of *path*, or None when not checked yet (or the file is gone)."""
    key = _key(path)
    with _lock:
        return _cache.get(key) if key else None


def check(path: str) -> Signature:
    """Checks *path* (runs ``codesign`` once per program version) and caches the answer."""
    key = _key(path)
    if key is None:
        return Signature(kind="unknown")
    with _lock:
        if key in _cache:
            return _cache[key]
    displayed = platform.code_signature(path)
    try:
        found = Signature(kind="unknown") if displayed is None else verified(path, parse(displayed))
    except (OSError, subprocess.TimeoutExpired):
        found = Signature(kind="unknown")
    bundle_id, app_name, version = bundle_of(path)
    found = Signature(**{**found.__dict__, "bundle_id": bundle_id, "app_name": app_name, "version": version})
    with _lock:
        if len(_cache) >= MAX_CACHED:
            _cache.pop(next(iter(_cache)))
        _cache[key] = found
    return found


def forget() -> None:
    """Drops every cached signature and verification (tests)."""
    with _lock:
        _cache.clear()
    signing.forget()
