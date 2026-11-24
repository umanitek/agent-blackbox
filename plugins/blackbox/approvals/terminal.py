"""Confirming a held change from the person's OWN terminal, where the system draws no password
dialog — a Linux server without pkexec (design decision F9; KI-659, Linux round L1: on Ubuntu
24.04 server `POST /api/approvals/confirm` answered "not confirmed" in 66 ms with no prompt at all,
so a person could never turn protection down from the dashboard).

The proof is root's, not the page's: ``blackbox approve`` (run by the person at their terminal,
never through an agent — self-protection refuses an agent's ``blackbox approve``) asks the
dashboard for a one-time challenge for the held request, then runs ``sudo -k`` (so sudo asks for
the password again) and ``sudo`` to write that challenge into :data:`ROOT_FOLDER` — a file only
root can create there. The dashboard approves the request only when that file is root's, a
plain file, in a root-owned folder nobody else can write, and holds exactly its challenge
(:func:`proved`). Afterwards the command removes the file and runs ``sudo -k`` again.

Limit: with passwordless sudo, sudo asks nothing — the person's own configuration; an agent's
own sudo write into Blackbox's root folder is still refused (``detection.privileged_writes``).

Usage::

    if terminal.needed(): ...                        # the page says: run `blackbox approve`
    nonce = store.challenge(held.id)                 # the dashboard, per request, once
    terminal.proved(terminal.ROOT_FOLDER, held.id, nonce)
"""

from __future__ import annotations

import hmac
import os
import platform
import re
import stat
from pathlib import Path

from . import system_prompt

#: Where ``sudo`` writes the proof (root-owned; the Linux helper's folder's parent).
ROOT_FOLDER = Path("/var/lib/blackbox/approvals")
#: A held request's id, as the store makes them (never a path).
REQUEST_ID = re.compile(r"[A-Za-z0-9_-]{1,64}")
#: The shell sudo runs: make the folder (0755, root's) and write the challenge (0644).
WRITE_PROOF = 'umask 022 && mkdir -p "$1" && chmod 755 "$1" && printf %s "$3" > "$1/$2"'
MAX_PROOF_BYTES = 256
#: What the person reads on a machine that needs it.
HOW = "run `blackbox approve` in your own terminal (sudo asks for your password)"


def needed() -> bool:
    """True on a Linux machine where the system draws no password dialog (no pkexec)."""
    return platform.system() == "Linux" and not system_prompt.available()


def proved(folder: Path, request_id: str, nonce: str) -> bool:
    """True when root wrote *nonce* as *request_id*'s proof in *folder* (see the module doc)."""
    if not REQUEST_ID.fullmatch(str(request_id)) or not nonce:
        return False
    try:
        place = os.lstat(folder)
        proof = os.lstat(folder / request_id)
        if not stat.S_ISDIR(place.st_mode) or place.st_uid != 0 or place.st_mode & 0o022:
            return False
        if not stat.S_ISREG(proof.st_mode) or proof.st_uid != 0 or proof.st_nlink != 1 or proof.st_size > MAX_PROOF_BYTES:
            return False
        with open(folder / request_id, "rb") as handle:
            written = handle.read(MAX_PROOF_BYTES).decode("ascii", "replace")
    except OSError:
        return False
    return hmac.compare_digest(written, nonce)
