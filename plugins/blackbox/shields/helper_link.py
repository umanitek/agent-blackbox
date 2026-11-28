"""The plugin's side of the system protection helper's authentication (helper/PLAN.md).

The helper obeys only plans signed with the key made when it was installed, and reports only to
a server that proved that key (security wave 2, finding 1 — a process that grabs the dashboard's
port first cannot steer a root daemon). ``blackbox-netd install`` writes the key for the person
who installed it to :func:`key_path` (ONE place per person, so Blackbox's installer and a
companion app both drive the same helper). This module reads it and:

* signs each plan answer: ``X-Blackbox-Signature = hex(HMAC-SHA256(key, nonce + "\\n" + body))``
  over the exact bytes sent, with the ``nonce`` the helper put in the request (:func:`signed`);
* checks each report (:func:`require_signed_report`): ``X-Blackbox-Helper-Signature =
  hex(HMAC-SHA256(key, "blackbox-helper-report-v2\n" + ts + "\n" + nonce + "\n" + body))`` over the
  exact bytes received, with ``ts`` (``X-Blackbox-Helper-Timestamp``, unix seconds, decimal ASCII)
  within :data:`REPORT_FRESH_SECONDS` of now and ``nonce`` (``X-Blackbox-Helper-Nonce``, 32
  lower-case hex) not seen before in that window — so a report a squatter caught can not be
  replayed later (independent review 2026-11-26, finding 7; the helper's ``link.rs`` signs the
  same bytes, one test vector on both sides). Refused with 401 when wrong, stale, replayed or missing.

A MISSING key file is "not paired" and a key file that is there but wrong (a link, the wrong size)
is BROKEN: either way every report is refused and plans go out unsigned (the helper refuses them);
the card says so, with the fix (:func:`pairing`). WHY (external review, 2026-11-28): with no key file
an unsigned report was accepted, so any local program could write the helper's status; every
published helper has a key since 2026-11-21.

Upgrade window (DEPRECATED, one release): a helper from before 1.6.3 signs only the body. Its
report is accepted until this Mac's helper has sent one v2 report (then :func:`_v2_seen` stays
true for good, and a body-only signature — a replayable one — is refused).

Usage::

    from .helper_link import signed, require_signed_report
    return signed(plan_dict, params)           # in a plan read
    require_signed_report(context)             # first thing in a report write
"""

from __future__ import annotations

import hashlib
import hmac
import json
import os
import re
import stat
import threading
import time
from pathlib import Path
from typing import Any, Callable, Mapping, Optional

from ..kernel import constants, system_helper
from ..kernel.bounded_files import atomic_write
from .shield_api import RawAnswer, ShieldApiError, ShieldContext

#: The plan's signature header (answers) and the helper's (reports).
SIGNATURE_HEADER = "X-Blackbox-Signature"
HELPER_SIGNATURE_HEADER = "X-Blackbox-Helper-Signature"
#: A report's signed time and nonce (helper/src/link.rs: HELPER_TIMESTAMP_HEADER, HELPER_NONCE_HEADER).
HELPER_TIMESTAMP_HEADER = "X-Blackbox-Helper-Timestamp"
HELPER_NONCE_HEADER = "X-Blackbox-Helper-Nonce"
#: The first line of a report's signed material (a plan signature can never pass for a report's).
REPORT_SIGNING_CONTEXT = b"blackbox-helper-report-v2\n"
#: How far a report's time may be from now, either way (the helper's VERIFIED_FOR is 120 s too).
REPORT_FRESH_SECONDS = 120
REPORT_NONCE = re.compile(r"[0-9a-f]{32}")
REPORT_TIME = re.compile(r"[0-9]{1,12}")
#: Report nonces remembered (a helper reports every few seconds; the window is two minutes).
MAX_SEEN_NONCES = 4096
#: The key's exact size (the helper refuses any other — "auth": "broken").
KEY_BYTES = 32
#: A nonce as the helper sends it (16 random bytes, hex); a little room either way.
NONCE = re.compile(r"[0-9a-f]{16,64}")

NOT_PAIRED = "not-paired"
PAIRED = "paired"
BROKEN = "broken"


def key_path() -> Path:
    """Where the person's copy of the helper key lives (macOS; the helper writes it at install)."""
    return system_helper.user_key_folder() / system_helper.KEY_FILE_NAME


def read_key() -> Optional[bytes]:
    """The key, or None when there is none or it is not a plain file of exactly KEY_BYTES."""
    path = key_path()
    try:
        info = path.lstat()
        if not stat.S_ISREG(info.st_mode) or info.st_size != KEY_BYTES:
            return None
        fd = os.open(path, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0))
        try:
            data = os.read(fd, KEY_BYTES + 1)
        finally:
            os.close(fd)
    except OSError:
        return None
    return data if len(data) == KEY_BYTES else None


def pairing() -> str:
    """``paired`` (a usable key), ``broken`` (a key file of the wrong kind) or ``not-paired``."""
    if read_key() is not None:
        return PAIRED
    try:
        return BROKEN if key_path().lstat() else NOT_PAIRED
    except OSError:
        return NOT_PAIRED


def sign_plan(key: bytes, nonce: str, body: bytes) -> str:
    """hex(HMAC-SHA256(key, nonce + "\\n" + body))."""
    return hmac.new(key, nonce.encode("ascii") + b"\n" + body, hashlib.sha256).hexdigest()


def sign_report(key: bytes, stamp: int, nonce: str, body: bytes) -> str:
    """hex(HMAC-SHA256(key, "blackbox-helper-report-v2\n" + stamp + "\n" + nonce + "\n" + body)) —
    what the helper puts on a report (*stamp* in decimal ASCII, *nonce* as sent)."""
    material = REPORT_SIGNING_CONTEXT + str(stamp).encode("ascii") + b"\n" + nonce.encode("ascii") + b"\n" + body
    return hmac.new(key, material, hashlib.sha256).hexdigest()


def sign_legacy_report(key: bytes, body: bytes) -> str:
    """hex(HMAC-SHA256(key, body)) — a helper from before 1.6.3 (DEPRECATED, see the module doc)."""
    return hmac.new(key, body, hashlib.sha256).hexdigest()


def signed(payload: Any, params: Mapping[str, str]) -> Any:
    """*payload* as the helper must receive it: with a key and a valid ``nonce`` in *params*, the
    exact JSON bytes plus their signature; otherwise the plain value (a helper without a key —
    or a page — reads it as before; a keyed helper refuses it)."""
    key = read_key()
    nonce = str(params.get("nonce") or "")
    if key is None or not NONCE.fullmatch(nonce):
        return payload
    body = json.dumps(payload, separators=(",", ":"), sort_keys=True).encode("utf-8")
    return RawAnswer(body=body, headers={SIGNATURE_HEADER: sign_plan(key, nonce, body)})


_seen_lock = threading.Lock()
#: nonce -> the report time it came with (memory only: a restart forgets, the time window still holds).
_seen_nonces: dict[str, int] = {}


def _v2_mark() -> Path:
    return constants.blackbox_home() / "network-shield" / "helper-report-v2"


def _v2_seen() -> bool:
    """True once this Mac's helper has sent a v2 report (from then on a body-only one is refused)."""
    return _v2_mark().is_file()


def _refuse(why: str) -> None:
    raise ShieldApiError(401, f"this report is not signed by this Mac's system protection helper ({why})")


def _remember(nonce: str, stamp: int, now: int) -> bool:
    """Keeps *nonce*; False when it was seen already (a replay). Forgets the ones out of the window."""
    with _seen_lock:
        if nonce in _seen_nonces:
            return False
        if len(_seen_nonces) >= MAX_SEEN_NONCES:
            for old in [key for key, seen in _seen_nonces.items() if abs(now - seen) > REPORT_FRESH_SECONDS]:
                del _seen_nonces[old]
            if len(_seen_nonces) >= MAX_SEEN_NONCES:
                return False   # flooded within the window: refuse rather than forget a live nonce
        _seen_nonces[nonce] = stamp
        return True


def _check_v2(key: bytes, headers: Mapping[str, str], body: bytes, now: int) -> None:
    given = headers.get(HELPER_SIGNATURE_HEADER.lower(), "").strip()
    stamp_text = headers.get(HELPER_TIMESTAMP_HEADER.lower(), "").strip()
    nonce = headers.get(HELPER_NONCE_HEADER.lower(), "").strip()
    if not REPORT_TIME.fullmatch(stamp_text) or not REPORT_NONCE.fullmatch(nonce):
        _refuse("a malformed time or nonce")
    stamp = int(stamp_text)
    if not given or not hmac.compare_digest(given, sign_report(key, stamp, nonce, body)):
        _refuse("a wrong signature")
    if abs(now - stamp) > REPORT_FRESH_SECONDS:
        _refuse("an old report")
    if not _remember(nonce, stamp, now):
        _refuse("a report already received")
    if not _v2_seen():
        _v2_mark().parent.mkdir(parents=True, exist_ok=True)
        atomic_write(_v2_mark(), "1\n", mode=0o600)


def require_signed_report(context: ShieldContext, clock: Callable[[], float] = time.time) -> None:
    """Refuses (401) a report that is not signed with the key, fresh and new (see the module doc),
    and every report while this Mac has no usable key."""
    key = read_key()
    if key is None:
        if pairing() == NOT_PAIRED:
            _refuse("this Mac has no helper key; reinstall the system protection helper to pair it")
        _refuse("the helper key on this Mac is broken; reinstall the system protection helper")
    headers = {str(name).lower(): str(value) for name, value in (context.request_headers or {}).items()}
    if HELPER_TIMESTAMP_HEADER.lower() in headers or HELPER_NONCE_HEADER.lower() in headers or _v2_seen():
        _check_v2(key, headers, context.request_body, int(clock()))
        return
    given = headers.get(HELPER_SIGNATURE_HEADER.lower(), "").strip()   # DEPRECATED body-only form
    if not given or not hmac.compare_digest(given, sign_legacy_report(key, context.request_body)):
        _refuse("a wrong or missing signature")
