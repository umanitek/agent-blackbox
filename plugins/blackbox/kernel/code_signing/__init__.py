"""Whether a program's code signature is REAL — verified, not just displayed (read-only).

``codesign -dv`` only prints what a binary claims about itself: a self-signed certificate named
"Software Signing" or "Developer ID Application: …", or a binary changed after signing, would show
the same text as the real thing (independent review, 2026-11-21, finding 3). So every claimed
signer is checked three ways before Blackbox believes it:

1. ``codesign --verify --strict <path>`` — the signature is intact (the code is what was signed);
2. ``codesign --verify -R=<requirement> <path>`` — the certificate chain really ends at Apple and
   has the kind of leaf the claim names (:data:`REQUIREMENTS`: Apple's own, Mac App Store,
   Developer ID, Apple Development);
3. for a Developer ID claim, ``spctl --assess --type execute`` — whether Apple notarised it.

:func:`verify` answers a :class:`Verification`; ``valid`` False means "the signature does not
verify" (its own state — never safe), None means it could not be checked (a tool failed or timed
out — never safe either). Results are cached by path + modification time + size.

Used by ``network.monitor.intel.signature`` (processes, listeners, startup items) and
``files.monitor.inspect`` (File Shield). Imports nothing else in the add-on.

What a program CLAIMS is read by :func:`parse_display` (the text of ``codesign -dv
--verbose=2``) into a :class:`Claim`.

Usage::

    claim = parse_display(displayed_text)      # Claim(kind="developer_id", signer="Brave Software, Inc.", …)
    found = verify("/Applications/Safari.app/Contents/MacOS/Safari", claimed="apple")
    found.valid, found.notarised
"""

from __future__ import annotations

import os
import subprocess
import threading
from dataclasses import dataclass
from typing import Callable, Optional

CODESIGN = "/usr/bin/codesign"
SPCTL = "/usr/sbin/spctl"
TIMEOUT_SECONDS = 5.0
MAX_CACHED = 4000

#: The code requirement each claimed signer must satisfy (Apple's certificate extension OIDs:
#: 6.1.9 Mac App Store leaf, 6.1.13 Developer ID Application leaf, 6.2.6 Developer ID intermediate,
#: 6.1.12 Apple Development leaf).
REQUIREMENTS = {
    "apple": "anchor apple",
    "app_store": "anchor apple generic and certificate leaf[field.1.2.840.113635.100.6.1.9] exists",
    "developer_id": ("anchor apple generic and certificate 1[field.1.2.840.113635.100.6.2.6] exists "
                     "and certificate leaf[field.1.2.840.113635.100.6.1.13] exists"),
    "development": "anchor apple generic and certificate leaf[field.1.2.840.113635.100.6.1.12] exists",
}

#: ``(command) -> (exit status, stdout + stderr)``, or None when it could not run in time.
Runner = Callable[[list[str]], Optional[tuple[int, str]]]


@dataclass(frozen=True)
class Verification:
    """*valid*: True (intact and the claimed signer holds), False (does not verify), None (could
    not be checked). *notarised*: Apple notarised it (Developer ID only; False otherwise)."""

    valid: Optional[bool]
    notarised: bool = False


#: The signers ``codesign -dv`` names for Apple's own programs, and for Mac App Store apps.
APPLE_AUTHORITIES = frozenset({"Software Signing", "macOS Software Signing", "Apple iPhone OS Application Signing"})
APP_STORE_AUTHORITY = "Apple Mac OS Application Signing"


@dataclass(frozen=True)
class Claim:
    """What a program SAYS about its signer (``codesign -dv`` only displays it — see the module
    doc): *kind* is ``apple`` / ``app_store`` / ``developer_id`` / ``development`` / ``adhoc`` /
    ``unsigned`` / ``unknown``; *notarised* is the stapled-ticket claim."""

    kind: str
    signer: str = ""
    team: str = ""
    notarised: bool = False


def parse_display(text: str) -> Claim:
    """The signer ``codesign -dv --verbose=2`` describes in *text*."""
    if "code object is not signed at all" in text:
        return Claim(kind="unsigned")
    fields: dict[str, list[str]] = {}
    for line in text.splitlines():
        key, sep, value = line.partition("=")
        if sep:
            fields.setdefault(key.strip(), []).append(value.strip())
    authorities = fields.get("Authority", [])
    team = next((t for t in fields.get("TeamIdentifier", []) if t != "not set"), "")
    notarised = "stapled" in fields.get("Notarization Ticket", [])
    first = authorities[0] if authorities else ""
    if "adhoc" in fields.get("Signature", []) or not authorities and "adhoc" in text:
        return Claim(kind="adhoc")
    if first in APPLE_AUTHORITIES:
        return Claim(kind="apple", signer="Apple", team=team, notarised=True)
    if first == APP_STORE_AUTHORITY:
        return Claim(kind="app_store", signer="Mac App Store", team=team, notarised=True)
    if first.startswith("Developer ID Application:"):
        return Claim(kind="developer_id", signer=first.split(":", 1)[1].strip(), team=team, notarised=notarised)
    if first.startswith("Apple Development:"):
        return Claim(kind="development", signer=first.split(":", 1)[1].strip(), team=team)
    return Claim(kind="unknown", signer=first, team=team)


def _run(command: list[str]) -> Optional[tuple[int, str]]:
    try:
        done = subprocess.run(command, capture_output=True, text=True, encoding="utf-8", errors="replace",
                              timeout=TIMEOUT_SECONDS, stdin=subprocess.DEVNULL, check=False)
    except (OSError, subprocess.SubprocessError):
        return None
    return done.returncode, (done.stdout or "") + (done.stderr or "")


def bundle_of(path: str) -> str:
    """The ``.app`` bundle *path* runs from (Gatekeeper assesses bundles), else *path* itself."""
    return path.split("/Contents/MacOS/", 1)[0] if ".app/Contents/MacOS/" in path else path


def assess(path: str, claimed: str, run: Runner = _run) -> Verification:
    """Verifies *path* against the signer it *claims* (a key of :data:`REQUIREMENTS`) — no cache."""
    requirement = REQUIREMENTS.get(claimed)
    if requirement is None:
        return Verification(valid=False)   # a claim we cannot hold to a requirement is not believed
    intact = run([CODESIGN, "--verify", "--strict", path])
    if intact is None:
        return Verification(valid=None)
    if intact[0] != 0:
        return Verification(valid=False)
    holds = run([CODESIGN, "--verify", f"-R={requirement}", path])
    if holds is None:
        return Verification(valid=None)
    if holds[0] != 0:
        return Verification(valid=False)
    notarised = False
    if claimed == "developer_id":
        verdict = run([SPCTL, "--assess", "--type", "execute", "-vv", bundle_of(path)])
        notarised = bool(verdict and verdict[0] == 0 and "Notarized Developer ID" in verdict[1])
    return Verification(valid=True, notarised=notarised or claimed in ("apple", "app_store"))


_lock = threading.Lock()
_cache: dict[tuple[str, float, int, str], Verification] = {}


def verify(path: str, claimed: str, run: Runner = _run) -> Verification:
    """:func:`assess`, cached per program version (path + modification time + size + claim)."""
    try:
        status = os.stat(path)
    except OSError:
        return Verification(valid=None)
    key = (path, status.st_mtime, status.st_size, claimed)
    with _lock:
        if key in _cache:
            return _cache[key]
    found = assess(path, claimed, run)
    if found.valid is not None:   # a timeout is retried next time, an answer is kept
        with _lock:
            if len(_cache) >= MAX_CACHED:
                _cache.pop(next(iter(_cache)))
            _cache[key] = found
    return found


def forget() -> None:
    """Drops every cached verification (tests)."""
    with _lock:
        _cache.clear()
