"""Blackbox's own keys: protected paths built in, refused in every mode (Blackbox's protection).

The rest of self-protection (:mod:`.guard_settings`) lets an agent read Blackbox and refuses only
a change. Some of what Blackbox keeps is a key, and reading it is the harm: the key that signs the
system protection helper's plans and reports, Blackbox's reporter and curator keys, and its DKG
node's keystore, wallets and API token. An agent holding one can make Blackbox's records say
what it likes.

These are protected paths like the person's own list, judged by the same one mechanism
(:func:`.protected.touches`: every tool, every shell reader, copier and archiver, code, other
tools' arguments, and every spelling resolved to the canonical path) — with two differences:
they are built in (the person cannot drop them from a list) and a finding refuses in every mode.

* :func:`builtin_patterns` — the helper's key folder (``kernel.system_helper.user_key_folder``)
  and the key files in Blackbox's data folders (:data:`KEY_FILES`). Blackbox's records beside
  them (findings, audit) stay readable.
* :func:`reads_a_secret` — the evidence when a call reaches one, else ``""``.

A whole-folder read of a folder holding one (``tar czf x.tgz ~/.hermes``, ``grep -r BEGIN ~``) is
a read of the key; a ``find -name '*.md' -exec …`` is not.

Usage::

    reads_a_secret("terminal", {"command": "xxd ~/Library/Application\\\\ Support/Blackbox/helper/plan.key"})
    # -> "a read of Blackbox's keys"
"""

from __future__ import annotations

import os
import re
from typing import Any

from ...kernel import constants, system_helper
from . import guard_places, protected, shell_files

EVIDENCE = "a read of Blackbox's keys"
#: The refusal's title and what the agent can do instead. WHY (2026-11-21): a whole-folder read
#: (``tar czf x.tgz ~/.hermes``, ``grep -rn mode ~/.hermes/``) was refused as "Change to Blackbox's
#: own settings" — true of nothing it did — and the agent could not tell what to leave out.
#: DECISION: the advice names only forms the guard allows. An ``--exclude`` is NOT honoured: tar,
#: grep, rsync and zip each read exclude patterns differently, and one mis-read pattern would hand a
#: key over — so a folder that holds a key is never read whole, whatever is excluded.
TITLE = "Would read Blackbox's key files"
ADVICE = ("Blackbox's key files sign its records and the system protection helper's plans, so no agent may read "
          "them, even inside a whole-folder archive or search. Name only the files you need instead "
          "(e.g. ~/.hermes/config.yaml), or archive/search a folder that does not hold Blackbox's keys.")
#: The key files in Blackbox's data folders: the reporter and curator keys (``.pem``), and the
#: node's keystore, wallets and API token (the names setup/uninstall backs up as NODE_KEY_FILES).
KEY_FILES = ("*.pem", "*.key", "*.p12", "agent-keystore.json", "wallets.json", "wallets.key", "auth.token")
#: Code that names one of the keys in pieces (``"Application Support", "Blackbox", "helper"``) —
#: the paths code builds piece by piece are not seen by the path reading.
_IN_PIECES = re.compile(r"plan\.key|Blackbox\W{1,8}helper|(?:reporter|curator)_key\.pem|agent-keystore\.json|wallets\.key",
                        re.IGNORECASE)


def builtin_patterns() -> tuple[str, ...]:
    """The built-in protected paths, as patterns :func:`.protected.touches` reads (worked out again
    when the home folders change, at most every few seconds — the rule runs on every tool call)."""
    return _PATTERNS.get(guard_places._machine())


def _read_patterns() -> tuple[str, ...]:
    """Only folders that exist: a Mac with no helper has no key to keep, and archiving its
    ``Application Support`` must not be refused for a key that is not there."""
    key_folder = str(system_helper.user_key_folder())
    folders = (str(constants.blackbox_home()), str(constants.blackbox_dkg_home()))
    return (*([key_folder] if os.path.isdir(key_folder) else []),
            *(os.path.join(folder, name) for folder in dict.fromkeys(folders) if os.path.isdir(folder) for name in KEY_FILES))


_PATTERNS = guard_places.Kept(_read_patterns)


def _code_of(tool: str, args: Any) -> list[str]:
    """The code a call runs: a code tool's code, and the code a shell hands to an interpreter."""
    if not isinstance(args, dict):
        return []
    if tool in protected.CODE_TOOLS and isinstance(args.get("code"), str):
        return [args["code"]]
    command = next((value for key, value in args.items() if key in ("command", "cmd") and isinstance(value, str)), "")
    from .guard_settings import _inline_code   # the one reader of ``-c`` code on a command line
    heredocs = [found.group("body") for found in shell_files._HEREDOC.finditer(command)] if "<<" in command else []
    return [*(_inline_code(command) if command else []), *heredocs]


def reads_a_secret(tool_name: str, args: Any) -> str:
    """The evidence when an agent's call would read one of Blackbox's keys — whatever the tool —
    else ``""``."""
    tool = (tool_name or "").strip().lower()
    if protected.touches(tool_name, args, builtin_patterns(), whole=True, first_only=True):
        return EVIDENCE
    return EVIDENCE if any(_IN_PIECES.search(code) for code in _code_of(tool, args)) else ""
