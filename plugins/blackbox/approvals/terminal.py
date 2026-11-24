"""Confirming a held change from the person's OWN terminal, where the system draws no password
dialog — a Linux server without pkexec (design decision F9; KI-659, Linux round L1: on Ubuntu
24.04 server `POST /api/approvals/confirm` answered "not confirmed" in 66 ms with no prompt at all,
so a person could never turn protection down from the dashboard).

The proof is root's, not the page's: ``blackbox approve`` (run by the person at their terminal,
never through an agent — self-protection refuses an agent's ``blackbox approve``) asks the
dashboard for a one-time challenge for the held request, then runs ``sudo -k`` (so sudo asks for
the password again) and ``sudo`` to write that challenge as a file only root can create
(:data:`WRITE_PROOF`). The dashboard approves the request only when that file is root's, a plain
file, in root-owned folders nobody else can write, and holds exactly its challenge
(:func:`proved`). Afterwards the command removes the file (and the folders, when empty) and runs
``sudo -k`` again.

**The installed layout** (KI-678, Linux round L3 — LES-155: the dashboard runs as the person, so
every folder above the proof must let the person PASS, never write)::

    /var/lib/blackbox                 root 0711  the helper's folder (its netd/ stays 0700)
    /var/lib/blackbox/approvals       root 0711
    /var/lib/blackbox/approvals/<uid> root 0711  one per person: sudo's own SUDO_UID, never a name the caller picks
    …/<uid>/<request id>              root 0644  the challenge; single-use (the dashboard's nonce is popped on
                                                 the first confirm, and the command removes the file)

0711 (traverse, no listing): the person's dashboard reaches the one name it knows, nobody lists
another person's waiting requests. WHY not a folder the person owns: their own processes — the
agents — could then write the proof, and the password would prove nothing. The threat model stays
"only root writes it", so only someone who typed the sudo password approves. The helper's install
keeps ``/var/lib/blackbox`` at 0711 (it was 0700, so the dashboard could not reach the proof and
every confirmation failed), and its uninstall removes ``approvals/``.

Limit: with passwordless sudo, sudo asks nothing — the person's own configuration; an agent's
own sudo write into Blackbox's root folder is still refused (``detection.privileged_writes``).

Usage::

    if terminal.needed(): ...                        # the page says: run `blackbox approve`
    nonce = store.challenge(held.id)                 # the dashboard, per request, once
    terminal.proved(terminal.ROOT_FOLDER, held.id, nonce)   # reads ROOT_FOLDER/<this uid>/<id>
"""

from __future__ import annotations

import hmac
import logging
import os
import platform
import re
import stat
from pathlib import Path

from . import system_prompt

logger = logging.getLogger(__name__)

#: Blackbox's root-owned folder (the Linux helper's ``install::LIB``) and where ``sudo`` writes proofs.
LIB = Path("/var/lib/blackbox")
ROOT_FOLDER = LIB / "approvals"
#: Every folder on the proof's path: root's, traverse only (see the module doc).
FOLDER_MODE = 0o711
#: A held request's id, as the store makes them (never a path).
REQUEST_ID = re.compile(r"[A-Za-z0-9_-]{1,64}")
#: The shell sudo runs with ``sh <base> <id> <nonce>``: the person's folder named by sudo's own
#: SUDO_UID (digits only), every folder on the path 0711, the challenge written 0644 beside and
#: renamed into place (never seen half-written).
WRITE_PROOF = ('set -e; case "$SUDO_UID" in ""|*[!0-9]*) exit 1;; esac; umask 077; d="$1/$SUDO_UID"; mkdir -p "$d"; '
               'chmod 711 "${1%/*}" "$1" "$d"; printf %s "$3" > "$d/.$2"; chmod 644 "$d/.$2"; mv -f "$d/.$2" "$d/$2"')
#: The shell sudo runs afterwards with ``sh <base> <id>``: the proof goes, and each folder too when
#: empty (a machine without the helper keeps nothing; KI-682).
REMOVE_PROOF = ('case "$SUDO_UID" in ""|*[!0-9]*) exit 1;; esac; rm -f "$1/$SUDO_UID/$2"; '
                'rmdir "$1/$SUDO_UID" 2>/dev/null; rmdir "$1" 2>/dev/null; rmdir "${1%/*}" 2>/dev/null; exit 0')
MAX_PROOF_BYTES = 256
#: What the person reads on a machine that needs it.
HOW = "run `blackbox approve` in your own terminal (sudo asks for your password)"


def needed() -> bool:
    """True on a Linux machine where the system draws no password dialog (no pkexec)."""
    return platform.system() == "Linux" and not system_prompt.available()


def _root_folder(path: Path) -> bool:
    place = os.lstat(path)
    return stat.S_ISDIR(place.st_mode) and place.st_uid == 0 and not place.st_mode & 0o022


def proved(base: Path, request_id: str, nonce: str, uid: int | None = None) -> bool:
    """True when root wrote *nonce* as *request_id*'s proof in *base*/<*uid*> (this process's uid
    when not given): the file root's, plain, one link, small; its folder, *base* and *base*'s
    parent root's and writable by nobody else (see the module doc)."""
    # Windows has no uid (and no sudo): no proof can exist there.
    person = uid if uid is not None else (os.getuid() if hasattr(os, "getuid") else None)
    if not REQUEST_ID.fullmatch(str(request_id)) or not nonce or person is None:
        return False
    folder = base / str(person)
    try:
        if not all(_root_folder(place) for place in (folder, base, base.parent)):
            return False
        proof = os.lstat(folder / request_id)
        if not stat.S_ISREG(proof.st_mode) or proof.st_uid != 0 or proof.st_nlink != 1 or proof.st_size > MAX_PROOF_BYTES:
            return False
        with open(folder / request_id, "rb") as handle:
            written = handle.read(MAX_PROOF_BYTES).decode("ascii", "replace")
    except PermissionError as refused:
        # The layout is wrong (a folder above the proof is not 0711): say where, or the person only
        # ever reads "not confirmed" (KI-678).
        logger.warning("blackbox approve: the proof can not be read (%s); every folder on its path must be root's, mode 0711", refused)
        return False
    except OSError:
        return False
    return hmac.compare_digest(written, nonce)
