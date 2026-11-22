"""The plugin's side of the system protection helper's authentication (helper/PLAN.md).

The helper obeys only plans signed with the key made when it was installed, and reports only to
a server that proved that key (security wave 2, finding 1 — a process that grabs the dashboard's
port first cannot steer a root daemon). ``blackbox-netd install`` writes the key for the person
who installed it to :func:`key_path` (ONE place per person, so Blackbox's installer and a
companion app both drive the same helper). This module reads it and:

* signs each plan answer: ``X-Blackbox-Signature = hex(HMAC-SHA256(key, nonce + "\\n" + body))``
  over the exact bytes sent, with the ``nonce`` the helper put in the request (:func:`signed`);
* checks each report: ``X-Blackbox-Helper-Signature = hex(HMAC-SHA256(key, body))`` over the
  exact bytes received (:func:`require_signed_report`) — refused with 401 when wrong or missing
  once a key exists.

No key (a helper installed before keys, or none yet) → plans go out unsigned: a keyed helper
refuses them and the card says the helper is not paired (:func:`pairing`).

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
from pathlib import Path
from typing import Any, Mapping, Optional

from ..kernel import system_helper
from .shield_api import RawAnswer, ShieldApiError, ShieldContext

#: The plan's signature header (answers) and the helper's (reports).
SIGNATURE_HEADER = "X-Blackbox-Signature"
HELPER_SIGNATURE_HEADER = "X-Blackbox-Helper-Signature"
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


def sign_report(key: bytes, body: bytes) -> str:
    """hex(HMAC-SHA256(key, body)) — what the helper puts on a report."""
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


def require_signed_report(context: ShieldContext) -> None:
    """Refuses (401) a report that is not signed with the key, once a key exists."""
    key = read_key()
    if key is None:
        return   # not paired: a helper from before keys reports unsigned ("auth": "legacy")
    given = str((context.request_headers or {}).get(HELPER_SIGNATURE_HEADER.lower(), "")).strip()
    if not given or not hmac.compare_digest(given, sign_report(key, context.request_body)):
        raise ShieldApiError(401, "this report is not signed by this Mac's system protection helper")
