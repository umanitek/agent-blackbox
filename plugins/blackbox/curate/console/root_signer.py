"""Sign ONE prepared manifest with root A, then discard the key (trust-and-threat-lab C1, §03.2).

Pattern: Command. :meth:`RootSigner.sign` is one self-contained request:
verify the phone-held second factor, decrypt root A from the
:class:`.root_store.EncryptedRootStore` with the passphrase typed for THIS
signature, sign the manifest through the signing choke point
(``CurateContext.sign(ManifestDraft)``, so the ``SigningLog`` records it) and
drop the key before returning. No object — the signer, the store, the factor,
the context — holds the decrypted root between requests, so there is no idle
window for a local process to read it (Python cannot zero key bytes; the next
best thing is that no reference outlives the request).

The second factor is a Strategy (:class:`SecondFactor`); the one built is
:class:`TotpSecondFactor` — RFC 6238 TOTP whose secret is enrolled once into
the phone's authenticator app. The node keeps the TOTP SECRET (never the
root key) and the last accepted time step, so a code works at most once: a
second ``sign()`` needs a fresh passphrase AND a fresh code. The factor is
checked first and consumed even when the passphrase then turns out wrong
(fail closed: a failed attempt costs the attacker the code).

Usage::

    signer = RootSigner(ctx, EncryptedRootStore(), TotpSecondFactor())
    envelope = signer.sign(prepared_manifest, passphrase, "123456")   # RootSignerError when refused
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import json
import os
import secrets
import struct
import threading
import time
from contextlib import contextmanager
from pathlib import Path
from typing import Callable, Iterator, Optional, Protocol

from ...kernel import signing
from ...kernel.bounded_files import atomic_write, file_lock
from ...kernel.signing import KeyManifest
from .. import keys
from ..context import CurateContext, ManifestDraft
from .root_store import EncryptedRootStore, RootStoreError

TOTP_FILE = "root_a.totp.json"
TOTP_STEP_SECONDS = 30
TOTP_DIGITS = 6
#: Steps either side of now a code may come from (phone clock drift).
TOTP_DRIFT_STEPS = 1
_SECRET_BYTES = 20          # 160 bits, RFC 4226's recommended length for HMAC-SHA1
_FILE_MODE = 0o600


class RootSignerError(RuntimeError):
    """A root signature was refused (second factor, passphrase, or the manifest
    itself). Nothing was signed and nothing was logged."""


class SecondFactor(Protocol):
    """A phone-held second factor. ``consume(code)`` is True at most ONCE per
    valid code; a reused, stale or wrong code is False."""

    def consume(self, code: str) -> bool: ...


class TotpSecondFactor:
    """RFC 6238 TOTP (HMAC-SHA1, 6 digits, 30 s) with replay refusal.

    State lives in ``<curate home>/root_a.totp.json`` (0600): the base32
    secret and the last accepted time step. Read-check-write runs under a
    thread lock AND an ``flock`` on ``root_a.totp.json.lock``, so two factor
    objects or two processes on one state file still accept a code once.
    :meth:`enroll` creates it once; :meth:`consume` accepts only a step newer
    than the last accepted one.
    *clock* returns Unix seconds (injectable for tests).
    """

    def __init__(self, path: Optional[Path] = None, clock: Callable[[], float] = time.time) -> None:
        self._path = path or (keys.curate_home() / TOTP_FILE)
        self._clock = clock
        self._lock = threading.Lock()

    def enroll(self) -> str:
        """Create the secret (once) and return the ``otpauth://`` URI for the
        phone's authenticator. Refuses (``RootSignerError``) when already enrolled."""
        secret = base64.b32encode(secrets.token_bytes(_SECRET_BYTES)).decode("ascii")
        with self._lock:
            self._path.parent.mkdir(parents=True, exist_ok=True)
            try:
                fd = os.open(self._path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, _FILE_MODE)
            except FileExistsError:
                raise RootSignerError("the root second factor is already enrolled") from None
            with os.fdopen(fd, "w", encoding="utf-8") as handle:
                json.dump({"secret": secret, "last_step": -1}, handle)
        return f"otpauth://totp/Blackbox:root-a?secret={secret}&issuer=Blackbox&digits={TOTP_DIGITS}"

    def consume(self, code: str) -> bool:
        if not (len(code) == TOTP_DIGITS and code.isdigit()):
            return False
        with self._exclusive():
            state = self._read()
            if state is None:
                return False
            secret, last_step = state
            now = int(self._clock()) // TOTP_STEP_SECONDS
            for step in range(now - TOTP_DRIFT_STEPS, now + TOTP_DRIFT_STEPS + 1):
                if step > last_step and hmac.compare_digest(totp_code(secret, step), code):
                    self._write(secret, step)
                    return True
            return False

    @contextmanager
    def _exclusive(self) -> Iterator[None]:
        """Hold this object's thread lock and the cross-process lock (kernel ``file_lock`` on the
        same ``.lock`` file as before — the same flock, so mixed versions still exclude each
        other). A lock that cannot be had raises: a code check never runs unlocked."""
        with self._lock, file_lock(self._path.with_name(self._path.name + ".lock")) as held:
            if not held:
                raise OSError("the authenticator state is locked by another process")
            yield

    def _read(self) -> Optional[tuple[bytes, int]]:
        """(secret bytes, last step), or None when not enrolled or damaged (fail closed)."""
        try:
            state = json.loads(self._path.read_text(encoding="utf-8-sig"))
            return base64.b32decode(state["secret"]), int(state["last_step"])
        except (OSError, ValueError, KeyError, TypeError):
            return None

    def _write(self, secret: bytes, last_step: int) -> None:
        state = {"secret": base64.b32encode(secret).decode("ascii"), "last_step": last_step}
        atomic_write(self._path, json.dumps(state), mode=_FILE_MODE, durable=True)


def totp_code(secret: bytes, step: int) -> str:
    """The RFC 6238 / RFC 4226 code for *secret* at time *step*."""
    digest = hmac.new(secret, struct.pack(">Q", step), hashlib.sha1).digest()
    offset = digest[-1] & 0x0F
    value = struct.unpack(">I", digest[offset:offset + 4])[0] & 0x7FFFFFFF
    return str(value % 10 ** TOTP_DIGITS).zfill(TOTP_DIGITS)


class RootSigner:
    """Signs one prepared manifest per call with root A (see the module doc).

    Holds the context (the choke point), the encrypted store and the second
    factor — never a key.
    """

    def __init__(self, ctx: CurateContext, store: EncryptedRootStore, factor: SecondFactor) -> None:
        self._ctx = ctx
        self._store = store
        self._factor = factor

    def sign(self, prepared_manifest: KeyManifest, passphrase: str, second_factor: str) -> signing.SignedEnvelope:
        """The root-A-signed envelope of *prepared_manifest*, recorded in the
        signing log. Raises :class:`RootSignerError` (nothing signed) on a
        wrong or reused second factor, a wrong passphrase, or a manifest the
        choke point refuses."""
        if not self._factor.consume(second_factor):
            raise RootSignerError("second factor refused")
        try:
            key = self._store.open(passphrase)
        except RootStoreError as exc:
            raise RootSignerError(str(exc)) from None
        failure: Optional[str] = None
        try:
            envelope = self._ctx.sign(ManifestDraft(prepared_manifest), key)
        except Exception as exc:
            # Keep only the message: a live traceback would hold the frames that hold the key
            # (an OSError from the signing log included). Nothing escapes unlogged either way.
            failure = f"{type(exc).__name__}: {exc}"
        finally:
            del key
        if failure is not None:
            raise RootSignerError(f"the manifest was not signed: {failure}")
        return envelope
