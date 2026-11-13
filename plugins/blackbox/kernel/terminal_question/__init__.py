"""Asking the operator a question at their terminal — the one way every Blackbox command does it.

Under ``curl … | bash`` (how the installer runs) stdin is the pipe the script came down, not
the person: reading it would take the script's own next line as their answer. So when stdin is
not a terminal the question goes to the controlling terminal directly (POSIX ``/dev/tty``), and
when there is none the answer is None — the caller then does nothing it would need a yes for.

Usage::

    from ..kernel.terminal_question import ask
    answer = ask("Remove Blackbox? [y/N] ")
    if answer is None: ...                       # nobody to ask: refuse, say how (--yes)
    elif answer.strip().lower() in ("y", "yes"): ...
"""

from __future__ import annotations

import os
import sys
from typing import Optional


def ask(prompt: str) -> Optional[str]:
    """The operator's answer to *prompt* (the line as typed), or None when no terminal can be asked."""
    if sys.stdin is not None and sys.stdin.isatty():
        try:
            return input(prompt)
        except EOFError:
            return None
    if os.name == "nt":
        return None
    try:
        with open("/dev/tty", "r+", encoding="utf-8") as tty:
            tty.write(prompt)
            tty.flush()
            return tty.readline()
    except OSError:
        return None

__all__ = ["ask"]   # the surface other modules may import
