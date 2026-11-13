"""The errors the publishing step raises when it refuses, and the curator CLI's one boundary."""

from __future__ import annotations

import argparse
import functools
from typing import Callable

from ...kernel import display_safety


class VerbError(ValueError):
    """A verb refused; the message says why (printed, never a traceback)."""


class PublishLedgerError(ValueError):
    """The publish ledger refused: an illegal state transition, a record
    missing a field its state requires, or an unreadable ledger file. Never
    caught to "carry on" — a ledger that cannot be trusted stops the publisher
    (fail closed: a wrong guess here can pay to mint the same batch twice)."""


def guarded(verb: Callable[[argparse.Namespace], int]) -> Callable[[argparse.Namespace], int]:
    """The CLI boundary every curate command has (Decorator): a refusal (:class:`VerbError`) is
    "Refused: …" and exit 2; any other failure is one readable line and exit 1 — never a
    traceback. Usage: ``parser.set_defaults(func=guarded(cmd_correct))``."""
    @functools.wraps(verb)
    def run(args: argparse.Namespace) -> int:
        try:
            return verb(args)
        except VerbError as exc:
            print(f"Refused: {exc}")
            return 2
        except Exception as exc:  # health: allow BLE001 -- the outermost CLI boundary: a readable line, never a traceback
            print(f"curate {getattr(args, 'verb', '')} failed: {display_safety.term_safe(str(exc), 200)}")
            return 1
    return run
