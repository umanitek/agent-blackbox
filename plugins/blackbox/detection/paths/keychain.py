"""The macOS keychain: saved passwords and the browsers' master keys.

The keychain holds every password macOS saved, and the "Safe Storage" key each
Chromium browser uses to encrypt its saved passwords and cookies — including the
cookies of the trader's exchange sessions. macOS stealers take it two ways, and
both are covered:

* the files — ``~/Library/Keychains/login.keychain-db`` (copied, archived, read),
  through file tools and the terminal, or a folder holding them copied whole
  (``tar czf x.tgz ~/Library``);
* the ``security`` tool, which prints a password or dumps the keychain without
  naming a file (``security find-generic-password -wa Chrome``). Options checked
  against ``security <verb> -h`` on macOS 15.2; only ``security`` run as a command
  counts (``echo security …`` merely mentions it).

A built-in Trader Shield rule, not an entry in the operator's protected-path list:
Settings saves that list in full the first time it is saved, so a default added to
it later never reaches an install whose settings were ever saved (found on the
trader bench, 2026-10-13). Gated by the mode like the wallet rules; local-only.

Usage::

    detect_keychain_access("terminal", {"command": "security find-generic-password -wa Chrome"})
    # -> [Finding(identifier="fileaccess:terminal:macos-keychain", severity="critical", ...)]
"""

from __future__ import annotations

import re
from typing import Any

from .. import shell_shapes
from ..finding import Finding
from ...kernel import threat_ids
from .protected import _accesses, _folder_holds, _protected_path_match
import itertools

#: The file category these findings carry (a closed name, never a path).
KEYCHAIN_CATEGORY = "macos-keychain"

#: ``security`` verbs that reveal secrets, with the options that make them do it
#: (empty: the verb always does). ``export`` reveals keys unless limited to certificates.
_KEYCHAIN_SECRET_VERBS = {
    "find-generic-password": ("-w", "-g"),
    "find-internet-password": ("-w", "-g"),
    "dump-keychain": ("-d", "-r"),
    "export": (),
}
_EXPORT_HARMLESS_TYPES = {"certs", "pubkeys"}
#: Words after which the next word is a command being run (not an argument).
_COMMAND_POSITION = frozenset({";", "&&", "||", "|", "&", "sudo", "exec", "command", "nohup", "time", "env"})
#: ``NAME=`` before a command (``K=$(security …)`` after the substitution is opened up).
_ASSIGNMENT = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*=")
#: Where macOS keeps keychains: the user's (login.keychain-db and the local-items folder)
#: and the system's. Checked on macOS 15.2: every file under ~/Library/Keychains matches.
KEYCHAIN_PLACES = ("~/Library/Keychains/*", "/Library/Keychains/*")


def _reads_keychain(command: str) -> bool:
    """True when *command* runs ``security`` in a way that prints keychain secrets."""
    words = command.replace(";", " ; ").replace("$(", " ").replace("`", " ").split()
    for index, word in enumerate(words):
        if word.rsplit("/", 1)[-1] != "security" or index + 1 >= len(words):
            continue
        before = words[index - 1] if index else ";"
        if before not in _COMMAND_POSITION and not _ASSIGNMENT.match(before):   # "echo security …" only mentions it
            continue
        verb, options = words[index + 1], words[index + 2:]
        if verb not in _KEYCHAIN_SECRET_VERBS:
            continue
        if verb == "export":
            types = [value.lower() for flag, value in itertools.pairwise(options) if flag == "-t"]
            if not types or not set(types) <= _EXPORT_HARMLESS_TYPES:
                return True
            continue
        wanted = {flag.lstrip("-") for flag in _KEYCHAIN_SECRET_VERBS[verb]}
        if any(option.startswith("-") and not option.startswith("--") and wanted & set(option.lstrip("-"))
               for option in options):
            return True
    return False


def detect_keychain_access(tool_name: str, args: Any) -> list[Finding]:
    """One finding when this call reads the macOS keychain (see the module doc)."""
    tool = (tool_name or "").strip().lower()
    reached = [(access_tool, mode) for access_tool, path, mode in _accesses(tool_name, args)
               if any(_protected_path_match(path, place) or (mode == "copy" and _folder_holds(path, place))
                      for place in KEYCHAIN_PLACES)]
    if not reached and tool in shell_shapes.SHELL_TOOLS and _reads_keychain(shell_shapes.command_from_args(tool_name, args)):
        reached = [(tool, "read")]
    if not reached:
        return []
    access_tool, mode = reached[0]
    return [Finding(
        identifier=threat_ids.fileaccess_identifier(access_tool, KEYCHAIN_CATEGORY),
        category="fileaccess",
        severity="critical",
        title="Read of the macOS keychain",
        tool_name=access_tool,
        matched=KEYCHAIN_CATEGORY,
        evidence=f"{mode} {KEYCHAIN_CATEGORY}",
        confirmed=False,
        source="secret",   # built-in, local-only, blockable — never shared
        fields={"tool_name": access_tool, "file_category": KEYCHAIN_CATEGORY},
    )]
