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
    describe("/opt/homebrew/bin/claude")       # Signer(kind, signer, team, verified, notarised) — links followed
    described("/opt/homebrew/bin/claude")      # the kept answer, or None — never runs a tool
    describe_soon("/opt/homebrew/bin/claude")  # the kept answer, or None while a background check runs
    found = verify("/Applications/Safari.app/Contents/MacOS/Safari", claimed="apple")
    found.valid, found.notarised
"""

from __future__ import annotations

import os
import subprocess
import threading
import time
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


@dataclass(frozen=True)
class Signer:
    """Who signed a program, HELD to what it claims: *kind* as in :class:`Claim`, plus
    ``invalid`` (it names a signer that does not verify) and ``script`` (a text file an
    interpreter runs — nothing to sign); *verified* True only when the claim verified, None when
    it could not be checked or there is nothing to verify."""

    kind: str
    signer: str = ""
    team: str = ""
    verified: Optional[bool] = None
    notarised: bool = False


#: How long an answer that could not be checked (a tool timed out: Gatekeeper's ``spctl`` takes
#: seconds on a loaded Mac) is reused before it is asked again — WHY (KI-584): uncached, every
#: open of an agent's profile waited the full timeout again.
UNKNOWN_RETRY_SECONDS = 600.0
_described: dict[tuple[str, float, int], tuple[Signer, float]] = {}


def _version(real: str) -> Optional[tuple[str, float, int]]:
    try:
        status = os.stat(real)
    except OSError:
        return None
    return real, status.st_mtime, status.st_size


def described(path: str) -> Optional[Signer]:
    """:func:`describe`'s kept answer for *path*'s current version, or None when it has not been
    checked yet — never runs a tool (a page that must not wait asks this first)."""
    key = _version(os.path.realpath(path))
    with _lock:
        found = _described.get(key) if key else None
    return found[0] if found else None


_checking: dict[str, tuple[threading.Thread, list[Signer]]] = {}
#: How long :func:`describe_soon` waits for a check before it answers "not yet" (most finish in
#: well under this; Gatekeeper on a loaded Mac takes seconds).
SOON_SECONDS = 0.5


def describe_soon(path: str, run: Runner = _run, wait: float = SOON_SECONDS) -> Optional[Signer]:
    """The answer for *path* when it is kept or comes within *wait* seconds; else None, with
    :func:`describe` left running in a background thread (one per path at a time; its answer is
    kept by :func:`describe`) — for a page that must not wait for Gatekeeper (KI-584: an agent's
    profile was blank for the whole check). Ask again later for the answer."""
    found = described(path)
    if found is not None:
        return found
    real = os.path.realpath(path)
    with _lock:
        running = _checking.get(real)
        if running is None:
            answer: list[Signer] = []

            def check() -> None:
                try:
                    answer.append(describe(real) if run is _run else describe(real, run))
                finally:
                    with _lock:
                        _checking.pop(real, None)

            running = _checking[real] = (threading.Thread(target=check, name="blackbox-code-signing", daemon=True), answer)
            running[0].start()
    worker, answer = running
    worker.join(max(0.0, wait))
    return answer[0] if answer else described(path)


def entitlements(path: str, run: Runner = _run) -> Optional[str]:
    """The entitlements *path* is signed with, as plist XML ("" when it has none); None when
    ``codesign`` cannot say (unsigned, gone, timed out)."""
    shown = run([CODESIGN, "-d", "--entitlements", "-", "--xml", path])
    return None if shown is None or shown[0] != 0 else _xml_part(shown[1])


def _xml_part(text: str) -> str:
    """The plist in ``codesign``'s answer (it writes the XML; a note may come with it)."""
    start = text.find("<?xml")
    return text[start:] if start >= 0 else ""


def describe(path: str, run: Runner = _run) -> Signer:
    """The signer of the program at *path* (links followed), verified — for showing a person
    what a program is. A file that starts with ``#!`` is a script. Kept per program version (path
    + modification time + size); an answer that could not be checked is asked again after
    :data:`UNKNOWN_RETRY_SECONDS`."""
    real = os.path.realpath(path)
    key = _version(real)
    if key is None:
        return Signer(kind="unknown")
    with _lock:
        kept = _described.get(key)
    if kept is not None and (kept[0].kind != "unknown" or time.monotonic() - kept[1] < UNKNOWN_RETRY_SECONDS):
        return kept[0]
    found = _describe(real, run)
    with _lock:
        if len(_described) >= MAX_CACHED:
            _described.pop(next(iter(_described)))
        _described[key] = (found, time.monotonic())
    return found


def _describe(real: str, run: Runner) -> Signer:
    try:
        with open(real, "rb") as handle:
            if handle.read(2) == b"#!":
                return Signer(kind="script")
    except OSError:
        return Signer(kind="unknown")
    shown = run([CODESIGN, "-dv", "--verbose=2", real])
    if shown is None:
        return Signer(kind="unknown")
    claim = parse_display(shown[1])
    if claim.kind not in REQUIREMENTS:
        return Signer(kind=claim.kind, signer=claim.signer, team=claim.team)
    held = verify(real, claim.kind, run)
    if held.valid is None:
        return Signer(kind="unknown", signer=claim.signer, team=claim.team)
    if not held.valid:
        return Signer(kind="invalid", signer=claim.signer, team=claim.team, verified=False)
    return Signer(kind=claim.kind, signer=claim.signer, team=claim.team, verified=True,
                  notarised=held.notarised if claim.kind == "developer_id" else claim.notarised)


def forget() -> None:
    """Drops every cached verification (tests)."""
    with _lock:
        _cache.clear()
        _described.clear()
