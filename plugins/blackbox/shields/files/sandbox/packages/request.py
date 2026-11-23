"""What a sandboxed agent may ask Blackbox to install with Homebrew: one validated request.

The agent's ``brew install …`` reaches Blackbox as its argv, and nothing else. This module turns
that argv into a :class:`BrewRequest`, or refuses it with a sentence (:class:`Refused`). It is
the whole of what the agent controls, so it is strict:

* a verb from :data:`VERBS` (install, upgrade, reinstall, uninstall);
* package NAMES only, each matching :data:`NAME` (``wget``, ``python@3.12``, ``node+x``). A name may
  carry an official tap (``homebrew/core/wget``, ``homebrew/cask/firefox``), which is dropped. Any
  other tap, a URL, a local path or a file is refused;
* only the flags in :data:`FLAGS` (``--cask``, ``--formula``, ``--quiet``, ``--verbose``). No
  ``--HEAD``, ``--build-from-source`` / ``-s``, ``--force``, ``--appdir=…``, ``--debug``,
  ``--interactive``, nor any flag with a value;
* at most :data:`MAX_NAMES` names, each at most :data:`MAX_NAME_CHARS` characters.

The agent's environment never travels: the request carries the argv alone, and the broker runs
brew with a clean environment of its own (``jobs.clean_environment``). Pure: reads nothing.

Usage::

    parse(["install", "tree"])          # BrewRequest(verb="install", names=("tree",), kind="")
    parse(["install", "--HEAD", "x"])   # raises Refused("… --HEAD …")
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Sequence

#: The verbs Blackbox runs for an agent, outside the sandbox (each changes what is installed).
VERBS = frozenset({"install", "upgrade", "reinstall", "uninstall"})
#: Homebrew's own spellings of those verbs.
ALIASES = {"remove": "uninstall", "rm": "uninstall"}
#: A package name as Homebrew writes one (lower case; ``@`` for a version, ``+`` and ``.`` allowed).
NAME = re.compile(r"^[a-z0-9][a-z0-9+_.@-]*$")
#: The official taps a name may be written under (the tap part is dropped).
OFFICIAL_TAPS = ("homebrew/core/", "homebrew/cask/")
#: The flags an agent may pass. Every other flag is refused (no build options, no locations).
FLAGS = frozenset({"--cask", "--formula", "--quiet", "-q", "--verbose", "-v"})
MAX_NAMES = 20
MAX_NAME_CHARS = 100
#: Homebrew's own words for a package it left as it was (KI-639): ``Warning: tree 2.3.2 is already
#: installed`` (``… and up-to-date.``, ``…, it's just not linked``), ``Warning: tree 2.3.2 already
#: installed`` (upgrade), ``Warning: Cask 'firefox' is already installed.``, ``Warning: Not upgrading
#: firefox, the latest version is already installed``. Homebrew's output is not translated.
UNCHANGED = (re.compile(r"^Warning: (?:Cask ')?([a-z0-9][a-z0-9+_.@-]*)'?(?: \S+)? (?:is )?already installed\b"),
             re.compile(r"^Warning: Not upgrading ([a-z0-9][a-z0-9+_.@-]*), the latest version is already installed\b"))
#: The verbs whose run may leave a package as it was (reinstall and uninstall always change it).
MAY_LEAVE = frozenset({"install", "upgrade"})


class Refused(ValueError):
    """The request is not one Blackbox runs; ``str(error)`` says why, for the agent."""


@dataclass(frozen=True)
class BrewRequest:
    """One validated request: *verb* (:data:`VERBS`), *names* (validated, tap dropped), *kind*
    (``--cask``, ``--formula`` or ""), *quiet* / *verbose* (the two output flags)."""

    verb: str
    names: tuple[str, ...]
    kind: str = ""
    quiet: bool = False
    verbose: bool = False

    def words(self) -> list[str]:
        """The words after ``brew``, exactly as Blackbox runs them."""
        return [self.verb, *([self.kind] if self.kind else []), *(["--quiet"] if self.quiet else []),
                *(["--verbose"] if self.verbose else []), *self.names]

    def shown(self) -> str:
        """The request as the person reads it: ``brew install tree wget``."""
        return " ".join(["brew", *self.words()])

    @property
    def tool(self) -> str:
        return "Homebrew"

    def check_command(self, name: str) -> str:
        """What *name* is threat-checked as (the guard's package rules)."""
        return f"brew install {self.kind + ' ' if self.kind else ''}{name}"

    def unchanged(self, line: str) -> str:
        """The asked-for name an output *line* says Homebrew left as it was (:data:`UNCHANGED`), or ""."""
        if self.verb not in MAY_LEAVE:
            return ""
        for pattern in UNCHANGED:
            found = pattern.match(line)
            if found and found.group(1) in self.names:
                return found.group(1)
        return ""


def brokered(argv: Sequence[str]) -> bool:
    """True when ``brew <argv>`` changes what is installed (Blackbox runs it); else it is a read."""
    verb = str(argv[0]) if argv else ""
    return ALIASES.get(verb, verb) in VERBS


def _name(word: str) -> str:
    for tap in OFFICIAL_TAPS:
        if word.startswith(tap):
            word = word[len(tap):]
            break
    if "/" in word or ":" in word:
        raise Refused(f"{word!r} names a tap, a web address or a file; Blackbox installs only packages "
                      "from Homebrew's official taps, by name")
    if len(word) > MAX_NAME_CHARS or not NAME.match(word):
        raise Refused(f"{word!r} is not a Homebrew package name")
    return word


def parse(argv: Sequence[str]) -> BrewRequest:
    """The :class:`BrewRequest` for ``brew <argv>``; raises :class:`Refused` with the reason."""
    words = [str(word) for word in argv] if isinstance(argv, (list, tuple)) else []
    if not words or ALIASES.get(words[0], words[0]) not in VERBS:
        raise Refused("only brew install, upgrade, reinstall and uninstall are run by Blackbox")
    verb, names, flags = ALIASES.get(words[0], words[0]), [], set()
    for word in words[1:]:
        if word.startswith("-"):
            if word not in FLAGS:
                raise Refused(f"the option {word} is not allowed (Blackbox runs only: {', '.join(sorted(FLAGS))})")
            flags.add(word)
        else:
            names.append(_name(word))
    if {"--cask", "--formula"} <= flags:
        raise Refused("--cask and --formula together")
    if not names and verb != "upgrade":
        raise Refused(f"name the package to {verb}")
    if len(names) > MAX_NAMES:
        raise Refused(f"at most {MAX_NAMES} packages at a time")
    kind = "--cask" if "--cask" in flags else "--formula" if "--formula" in flags else ""
    return BrewRequest(verb, tuple(dict.fromkeys(names)), kind, bool(flags & {"--quiet", "-q"}), bool(flags & {"--verbose", "-v"}))
