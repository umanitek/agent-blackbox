"""Consent for outward curator writes, made mechanical (Refine R6, plan §09).

Every write to a shared graph is a legal act under the curator's key, so it
needs consent BOUND TO ITS CONTENT: the CLI shows what will be published and
the operator types the first 8 hex characters of the content hash. A ``--yes``
flag is accepted only in the SANDBOX (no pinned curator root for the network);
on a network with a pinned root it is refused. A shown code is single-use and
expires 10 minutes after it was shown; when the write it allowed did not
succeed the consent is RELEASED, so the same content can be consented to again
(KI-249: a failed write must not leave the operator unable to retry). Every decision lands in an append-only
local ledger — never shared (plan §11: the consent ledger is local only).

The hardware-key touch ("the key-B touch IS the consent") arrives with the
pilot gate (R7b): this module is the typed half.

Usage::

    ledger = ConsentLedger()
    code = ledger.show(envelope_text, summary)        # print the summary + code to the operator
    ok, why = ledger.consent(envelope_text, typed=code_from_operator, sandbox=is_sandbox, yes=False)
"""

from __future__ import annotations

import contextlib
import hashlib
import json
import threading
import time
from pathlib import Path
from typing import Iterator, Optional

from ...kernel.bounded_files import append_line, file_lock, read_jsonl
from .. import keys

#: Operators type this many hex characters of the content hash.
CODE_CHARS = 8
#: A shown code is good for this long (plan §09: single-use, 10-minute expiry).
CODE_TTL_SECONDS = 600
_LEDGER_FILE = "consent.jsonl"


def confirmation_code(content: str) -> str:
    """The first 8 hex of sha256(*content*): what the operator types."""
    return hashlib.sha256(content.encode("utf-8")).hexdigest()[:CODE_CHARS]


class ConsentLedger:
    """Append-only record of codes shown and consents given or refused."""

    def __init__(self, path: Optional[Path] = None, clock=time.time) -> None:
        self._path = path or (keys.curate_home() / _LEDGER_FILE)
        self._clock = clock
        self._lock = threading.Lock()

    def show(self, content: str, summary: str) -> str:
        """Record that *content* was shown (with *summary*) and return its code."""
        code = confirmation_code(content)
        self._append({"event": "shown", "code": code, "summary": summary[:400]})
        return code

    def consent(self, content: str, *, typed: Optional[str], sandbox: bool, yes: bool) -> tuple[bool, str]:
        """Whether the write may proceed, and why not.

        * ``yes`` without typing: sandbox only; refused on a network with a
          pinned root ("no --yes on mainnet").
        * otherwise *typed* must equal the code, the code must have been shown
          within :data:`CODE_TTL_SECONDS`, and not consumed before.
        """
        code = confirmation_code(content)
        # One step under the ledger's cross-process lock: "unused?" and "now used" cannot interleave
        # between two publishes of one code (each caller builds its own ConsentLedger).
        with self._exclusive():
            if yes and not typed:
                verdict = (True, "sandbox: consent by --yes") if sandbox else (False, "--yes is refused outside the sandbox")
            elif (typed or "").strip().lower() != code:
                verdict = (False, "the typed code does not match this content")
            else:
                verdict = self._fresh_and_unused(code)
            self._append({"event": "consent" if verdict[0] else "refused", "code": code, "why": verdict[1]})
        return verdict

    def standing(self, content: str, why: str) -> tuple[bool, str]:
        """Record a write made under the operator's STANDING consent to the
        automation policy (the curator service; plan §07) — no code is typed.
        The caller has checked the policy and its acceptance; *why* is the
        policy's reason and lands in the ledger with the content's code."""
        verdict = (True, f"standing consent: {why[:200]}")
        self._append({"event": "consent", "code": confirmation_code(content), "why": verdict[1]})
        return verdict

    def release(self, content: str, why: str) -> None:
        """The write *content*'s consent allowed did NOT succeed: the consent is
        given back, so the operator can consent to the same content again."""
        self._append({"event": "released", "code": confirmation_code(content), "why": why[:200]})

    def _fresh_and_unused(self, code: str) -> tuple[bool, str]:
        shown_at: Optional[float] = None
        spent = False
        for entry in self._entries():
            if entry.get("code") != code:
                continue
            if entry.get("event") == "shown":
                shown_at = _timestamp(entry.get("ts"), shown_at)
            elif entry.get("event") == "consent":
                spent = True
            elif entry.get("event") == "released":
                spent = False
        if spent:
            return False, "this code was already used (single-use)"
        if shown_at is None:
            return False, "this code was never shown"
        if self._clock() - shown_at > CODE_TTL_SECONDS:
            return False, "this code expired (10 minutes); show it again"
        return True, "consent by typed code"

    def _entries(self) -> list[dict]:
        return read_jsonl(self._path)

    @contextlib.contextmanager
    def _exclusive(self) -> Iterator[None]:
        """This process's lock and the ledger's file lock, held together (a waiting
        consent blocks rather than proceeding unlocked)."""
        with self._lock, file_lock(self._path.with_name(self._path.name + ".lock")):
            yield

    def _append(self, entry: dict) -> None:
        entry = {"ts": self._clock(), **entry}
        append_line(self._path, json.dumps(entry, sort_keys=True), mode=0o600)


def _timestamp(value: object, previous: Optional[float]) -> Optional[float]:
    """A "shown" line's ``ts`` (0, long expired, when missing). A ``ts`` that is not a number is
    a damaged line: it is skipped (*previous* stands) — it never breaks every later consent."""
    try:
        return float(value or 0)
    except (TypeError, ValueError):
        return previous
