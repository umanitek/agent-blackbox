"""Login sessions for the key console (trust-and-threat-lab C2, §03.1 gate 2).

Gate 1 (the ``Tailscale-User-Login`` header) is not authentication on a
shared host: any local process can reach 127.0.0.1 and forge it. So the
console also asks for its own login passphrase and remembers the answer in a
session — memory only, one lock, gone when the process stops.

A session starts PENDING (``begin()``, issued with the login form) so that
even the login POST carries a per-session CSRF token; a correct passphrase
replaces it with a fresh AUTHENTICATED session (a new id, so a session id
planted before login is worthless after it). Every session expires after
:data:`IDLE_SECONDS` without a request, or at logout.

The passphrase is never stored: settings hold a salted scrypt hash made by
:func:`hash_login_passphrase`, and :meth:`ConsoleSessions.login` compares in
constant time. After :data:`MAX_FAILED_LOGINS` wrong passphrases in a row,
logins are refused for :data:`LOCKOUT_SECONDS` (scrypt alone makes guessing
slow; the lockout makes it pointless).

Usage::

    sessions = ConsoleSessions(settings.login_passphrase_hash)
    pending_id, csrf = sessions.begin()
    session_id = sessions.login(pending_id, passphrase)   # None when refused
    sessions.is_authenticated(session_id)                 # True, and the idle clock restarts
    sessions.csrf_token(session_id)                       # the token every change must carry
    sessions.logout(session_id)
"""

from __future__ import annotations

import base64
import hashlib
import secrets
import threading
import time
from dataclasses import dataclass
from typing import Callable, Optional

IDLE_SECONDS = 15 * 60
#: Live sessions (pending + authenticated) kept at once; the oldest pending one is
#: dropped first, so a local process minting login forms cannot grow memory without bound.
MAX_SESSIONS = 64
MAX_FAILED_LOGINS = 5
LOCKOUT_SECONDS = 5 * 60

_SCRYPT_N, _SCRYPT_R, _SCRYPT_P = 2 ** 14, 8, 1
_SCRYPT_LENGTH = 32
_HASH_SCHEME = "scrypt"


def hash_login_passphrase(passphrase: str) -> str:
    """The stored form of a console login passphrase: ``scrypt$<salt b64>$<hash b64>``."""
    if not passphrase:
        raise ValueError("the console login passphrase must not be empty")
    salt = secrets.token_bytes(16)
    digest = _scrypt(passphrase, salt)
    return "$".join((_HASH_SCHEME, _b64(salt), _b64(digest)))


def _scrypt(passphrase: str, salt: bytes) -> bytes:
    return hashlib.scrypt(passphrase.encode("utf-8"), salt=salt, n=_SCRYPT_N, r=_SCRYPT_R,
                          p=_SCRYPT_P, dklen=_SCRYPT_LENGTH)


def _b64(raw: bytes) -> str:
    return base64.urlsafe_b64encode(raw).decode("ascii")


def _parse_hash(stored: str) -> tuple[bytes, bytes]:
    """``(salt, digest)`` from a :func:`hash_login_passphrase` string; ValueError otherwise."""
    scheme, salt, digest = stored.split("$")
    if scheme != _HASH_SCHEME:
        raise ValueError(f"unknown passphrase hash scheme {scheme!r}")
    return base64.urlsafe_b64decode(salt), base64.urlsafe_b64decode(digest)


@dataclass
class _Session:
    csrf: str
    authenticated: bool
    last_seen: float


class ConsoleSessions:
    """The console's login sessions: memory only, one lock.

    *passphrase_hash* — from :func:`hash_login_passphrase` (checked at
    construction, so a malformed setting fails at start-up, not at login).
    *clock* — monotonic seconds (injectable for tests).
    """

    def __init__(self, passphrase_hash: str, clock: Callable[[], float] = time.monotonic) -> None:
        self._salt, self._digest = _parse_hash(passphrase_hash)
        self._clock = clock
        self._lock = threading.Lock()
        self._sessions: dict[str, _Session] = {}
        self._failed_logins = 0
        self._locked_until = 0.0

    def begin(self) -> tuple[str, str]:
        """A new PENDING session for the login form: ``(session id, csrf token)``."""
        with self._lock:
            return self._create(authenticated=False)

    def login(self, pending_id: str, passphrase: str) -> Optional[str]:
        """Swap a live pending session for an authenticated one when *passphrase*
        is right; the new session id, or None (wrong passphrase, unknown or
        expired session, or logins locked out after repeated failures)."""
        with self._lock:
            now = self._clock()
            pending = self._live(pending_id, now)
            if now < self._locked_until or pending is None or pending.authenticated:
                return None
            if not secrets.compare_digest(_scrypt(passphrase, self._salt), self._digest):
                self._failed_logins += 1
                if self._failed_logins >= MAX_FAILED_LOGINS:
                    self._failed_logins = 0
                    self._locked_until = now + LOCKOUT_SECONDS
                return None
            self._failed_logins = 0
            del self._sessions[pending_id]
            session_id, _csrf = self._create(authenticated=True)
            return session_id

    def is_authenticated(self, session_id: str) -> bool:
        """True for a live authenticated session; restarts its idle clock."""
        with self._lock:
            now = self._clock()
            session = self._live(session_id, now)
            if session is None or not session.authenticated:
                return False
            session.last_seen = now
            return True

    def csrf_token(self, session_id: str) -> Optional[str]:
        """The CSRF token bound to a live session (pending or authenticated), else None."""
        with self._lock:
            session = self._live(session_id, self._clock())
            return session.csrf if session is not None else None

    def logout(self, session_id: str) -> None:
        """End a session now (unknown ids are ignored)."""
        with self._lock:
            self._sessions.pop(session_id, None)

    def _live(self, session_id: str, now: float) -> Optional[_Session]:
        """The session when it exists and has not idled out; an expired one is dropped."""
        session = self._sessions.get(session_id or "")
        if session is not None and now - session.last_seen >= IDLE_SECONDS:
            del self._sessions[session_id]
            return None
        return session

    def _create(self, *, authenticated: bool) -> tuple[str, str]:
        now = self._clock()
        for stale in [sid for sid, s in self._sessions.items() if now - s.last_seen >= IDLE_SECONDS]:
            del self._sessions[stale]
        while len(self._sessions) >= MAX_SESSIONS:
            # Pending sessions go first: a flood of login forms must not log the operator out.
            pending = [sid for sid, s in self._sessions.items() if not s.authenticated]
            oldest = min(pending or self._sessions, key=lambda sid: self._sessions[sid].last_seen)
            del self._sessions[oldest]
        session_id, csrf = secrets.token_urlsafe(32), secrets.token_urlsafe(32)
        self._sessions[session_id] = _Session(csrf=csrf, authenticated=authenticated, last_seen=now)
        return session_id, csrf


__all__ = [
    "IDLE_SECONDS",
    "LOCKOUT_SECONDS",
    "MAX_FAILED_LOGINS",
    "MAX_SESSIONS",
    "ConsoleSessions",
    "hash_login_passphrase",
]
