"""Pending approvals of changes that turn protection DOWN, and the paired companion app's key.

A change that weakens protection is not applied when it is asked for: it is HELD here and a
paired companion app asks the person in a native dialog. The app proves the answer with a
key only it holds — an HMAC-SHA256 over the answer, the request id, the route and the exact body
— so a program that can call the dashboard (an agent that got hold of its token) cannot approve
its own request. An approved request is applied when the same body is sent again to the same
route, once, within :data:`USE_WINDOW_SECONDS`.

The key is paired once per dashboard run: the first ``pair`` is accepted; a later one (the app
relaunched with a fresh per-launch key) only with a proof made with the key held now — and the
requests already waiting keep waiting for the new app to show them. The app
keeps its current key where only it can read it.

Pattern: **State** — each held request is ``pending`` → ``approved`` → used (gone), or denied /
expired (gone).

Usage::

    store = Approvals()
    store.pair(key_hex)                                   # the app, at launch
    held = store.hold("/api/settings", body, ["Switch from Block to Audit mode"])
    store.answer(held.id, approve=True, proof=sign(key, answer_message("approve", held)))
    store.consume("/api/settings", body)                  # True once: the change may be applied
"""

from __future__ import annotations

import hashlib
import hmac
import secrets
import threading
import time
from collections import OrderedDict
from dataclasses import dataclass
from typing import Callable, Optional

#: How long a held request waits for the person's answer.
APPROVAL_TTL_SECONDS = 300
#: How long an approved request may take to be sent again and applied.
USE_WINDOW_SECONDS = 120
#: Held requests kept at once (an agent repeating a request cannot grow this).
MAX_HELD = 20
#: The companion app's key length, in bytes.
KEY_BYTES = 32


def body_digest(body: bytes) -> str:
    return hashlib.sha256(body).hexdigest()


def sign(key: bytes, message: str) -> str:
    """The proof the companion app sends: HMAC-SHA256 of *message* with its key, as hex."""
    return hmac.new(key, message.encode("utf-8"), hashlib.sha256).hexdigest()


@dataclass
class Held:
    """One change waiting for the person: what it is (``reasons``, shown in the dialog) and the
    exact request it was (route + body digest), so only THAT change can be applied with it."""

    id: str
    route: str
    body_sha256: str
    reasons: tuple[str, ...]
    created: float
    approved_at: Optional[float] = None

    def as_json(self) -> dict[str, object]:
        return {"id": self.id, "route": self.route, "body_sha256": self.body_sha256,
                "reasons": list(self.reasons), "created": self.created, "approved": self.approved_at is not None}


def answer_message(verb: str, held: Held) -> str:
    """What the app signs to answer *held*: ``<approve|deny>:<id>:<route>:<body sha256>``."""
    return f"{verb}:{held.id}:{held.route}:{held.body_sha256}"


def pair_message(new_key_hex: str) -> str:
    return f"pair:{new_key_hex}"


class Approvals:
    """The held requests and the paired key, for one dashboard run (memory only, thread-safe)."""

    def __init__(self, clock: Callable[[], float] = time.time) -> None:
        self._clock = clock
        self._lock = threading.Lock()
        self._key: Optional[bytes] = None
        self._held: OrderedDict[str, Held] = OrderedDict()
        self._prompted: set[str] = set()   # requests that already raised the system prompt

    # ------------------------------------------------------------------ pairing

    def paired(self) -> bool:
        return self._key is not None

    def pair(self, key_hex: str, proof: str = "") -> bool:
        """Accept *key_hex* as the app's key: the first one, or a new one signed with the current
        key (``sign(current, pair_message(key_hex))``). Held requests KEEP waiting across a new key:
        the app relaunched (a fresh per-launch key, proven by the old one) shows them again and its
        answers are checked against the new key. WHY: dropping them (until 2026-11-21) silently
        cancelled a weakening request the person had not yet answered whenever the app restarted
        while the dashboard kept running — the requester was never told. An APPROVED request also
        stays usable within its window: the person's answer was already given."""
        try:
            key = bytes.fromhex(key_hex)
        except (TypeError, ValueError):
            return False
        if len(key) != KEY_BYTES:
            return False
        with self._lock:
            if self._key is not None and not hmac.compare_digest(str(proof), sign(self._key, pair_message(key_hex))):
                return False
            self._key = key
            self._prompted.clear()   # the new app may raise each request's prompt again
            return True

    # ------------------------------------------------------------------ requests

    def hold(self, route: str, body: bytes, reasons: list[str]) -> Held:
        """Hold the change (the same route + body already waiting is the same request)."""
        digest = body_digest(body)
        with self._lock:
            self._expire()
            for held in self._held.values():
                if held.route == route and held.body_sha256 == digest and held.approved_at is None:
                    return held
            held = Held(secrets.token_hex(12), route, digest, tuple(reasons), self._clock())
            self._held[held.id] = held
            while len(self._held) > MAX_HELD:
                self._held.popitem(last=False)
            return held

    def waiting(self) -> list[Held]:
        """The requests still waiting for an answer, oldest first."""
        with self._lock:
            self._expire()
            return [held for held in self._held.values() if held.approved_at is None]

    def answer(self, request_id: str, approve: bool, proof: str) -> bool:
        """The person's answer, as signed by the app. False for an unknown, expired or
        already-answered request, an unpaired store, or a proof that does not match."""
        with self._lock:
            self._expire()
            held = self._held.get(str(request_id))
            if held is None or held.approved_at is not None or self._key is None:
                return False
            expected = sign(self._key, answer_message("approve" if approve else "deny", held))
            if not hmac.compare_digest(str(proof), expected):
                return False
            if approve:
                held.approved_at = self._clock()
            else:
                del self._held[held.id]
            return True

    def approve_confirmed(self, request_id: str) -> bool:
        """Approve *request_id* after the system's password prompt was passed (:mod:`.system_prompt`;
        claim the prompt first with :meth:`mark_prompted`). False for an unknown, expired or
        already-approved request."""
        with self._lock:
            self._expire()
            held = self._held.get(str(request_id))
            if held is None or held.approved_at is not None:
                return False
            held.approved_at = self._clock()
            return True

    def mark_prompted(self, request_id: str) -> bool:
        """Claim the one system prompt *request_id* may raise (False: already asked, or unknown)."""
        with self._lock:
            self._expire()
            if str(request_id) not in self._held or str(request_id) in self._prompted:
                return False
            self._prompted.add(str(request_id))
            return True

    def consume(self, route: str, body: bytes) -> bool:
        """True ONCE for an approved request with this route and exact body (then it is gone)."""
        digest = body_digest(body)
        with self._lock:
            self._expire()
            for held in list(self._held.values()):
                if held.approved_at is not None and held.route == route and held.body_sha256 == digest:
                    del self._held[held.id]
                    return True
            return False

    def _expire(self) -> None:
        now = self._clock()
        for held in list(self._held.values()):
            limit = held.approved_at + USE_WINDOW_SECONDS if held.approved_at is not None else held.created + APPROVAL_TTL_SECONDS
            if now > limit:
                del self._held[held.id]
        self._prompted &= set(self._held)
