"""Every form a token approval is written in — the parsing half of :mod:`.approvals`.

:func:`approvals_in` reads a tool call's text and returns each approval it would
send as an :class:`~.approval_calls.Approval`: who may spend, whether the amount is
unlimited, and which kind. Pure: no I/O, no ruleset; :mod:`.approvals` decides what
a found approval means. Each form has its own parser:

* :mod:`.cast_forms` — Foundry ``cast`` and ``spl-token`` command lines;
* :mod:`.calldata` — raw ABI calldata, however its hex is written;
* :mod:`.script_forms` — ethers / web3.py / viem code, variables followed;
* :mod:`.permits` — EIP-712 permit signatures (EIP-2612 and Permit2).

Usage::

    approvals_in("cast send 0xA0b8… 'approve(address,uint256)' 0xdead… 1157920…935")
    # -> [Approval(spender="0x…dead", unlimited=True, kind="approve")]
"""

from __future__ import annotations

import re
import shlex

from . import calldata, cast_forms, permits, script_forms
from .approval_calls import CALLS_BY_NAME, Approval

__all__ = ["Approval", "approvals_in"]

_CONTINUATION = re.compile(r"\\\r?\n")


def _shell_words(text: str) -> list[str]:
    """The call's shell words (quotes and ``\\``-newline continuations resolved)."""
    text = _CONTINUATION.sub(" ", text)   # shlex would keep the escaped newline inside a word
    try:
        return shlex.split(text, posix=True)
    except ValueError:
        return text.split()


#: Characters a shell removes from a word: quotes and backslashes may sit inside a name.
_SHELL_QUOTING = re.compile(r"""['"\\]""")
#: What every command-line approval contains once the quoting is gone: ``spl-token``, or the
#: name of an approval call followed by its opening parenthesis.
_COMMAND_APPROVAL = re.compile(rf"spl-token|(?:{'|'.join(map(re.escape, CALLS_BY_NAME))})\s*\(", re.IGNORECASE)


def _may_hold_command_approval(text: str) -> bool:
    """Whether *text* could hold a command-line approval at all. WHY: splitting a text into
    shell words costs seconds on a large file with few spaces, and this runs on every tool
    call; a text without these words has nothing for :mod:`.cast_forms` to find. Never False
    for a text the word reader would find an approval in (a test checks every call name)."""
    return bool(_COMMAND_APPROVAL.search(_SHELL_QUOTING.sub("", text)))


def approvals_in(text: str) -> list[Approval]:
    """Every token approval *text* would send (see the module doc), each once."""
    if not text:
        return []
    words = _shell_words(text) if _may_hold_command_approval(text) else []
    found = (cast_forms.from_words(words) + calldata.from_text(text)
             + script_forms.from_text(text) + permits.from_text(text))
    return list(dict.fromkeys(found))
