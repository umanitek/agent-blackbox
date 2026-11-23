"""What of Blackbox an agent may not change — the places, and whether a word names one.

Blackbox is only worth something while the agent it watches cannot switch it off. The red-team
pass of 2026-11-20 (164 ways an agent might try) showed the old list was too short: it knew
Hermes' config and Blackbox's two folders, and missed OpenClaw's config, the plugin file OpenClaw
loads, the live source checkout an install copies from, the service definitions, the ``blackbox``
command, and every wildcard, parent folder or pieced-together spelling of all of them.

* :func:`guarded_places` — every place, as absolute patterns (``*`` allowed).
* :func:`reaches` — does this word, as a shell or a script would read it, name a guarded place,
  a wildcard that matches one, or a folder that holds one (``rm -rf ~/.hermes``)?
* :func:`holds` — is it only a folder ABOVE one (the caller decides whether the command can
  reach below it)?
* :func:`names_in_pieces` — does this text spell a guarded place piece by piece
  (``homedir() + '/.hermes/config.yaml'``, ``Path.home() / '.hermes' / 'config.yaml'``)?
* :func:`judging` — which places are "guarded" while a check runs: Blackbox's own (:data:`OWN`,
  the default), the places something starts from by itself (:data:`STARTS`) or Homebrew's program
  folders (:data:`PROGRAMS`) — both read from ``kernel.persistence_places``, the one list the agent
  sandbox's profile reads too (private security finding
  ``2026-11-23-hooks-only-an-agent-appends-an-ssh-key-t``). Pattern: **Context Object** (a
  ``ContextVar``, per thread and task), so the one reading of a command line serves every place set.

Usage::

    reaches("~/.her*/config.yaml")              # True: a wildcard that matches Hermes' config
    reaches("$HOME/.openclaw/openclaw.json")    # True
    reaches("~/projects/app/config.yaml")       # False
"""

from __future__ import annotations

import contextvars
import fnmatch
import glob
import os
import re
import threading
import time
from contextlib import contextmanager
from pathlib import Path
from typing import Callable, Generic, Hashable, Iterator, TypeVar

from ...kernel import addons as guarded_extra, agent_hosts, constants, persistence_places, shell_path, system_helper
from .shell_words import _home_as_tilde

#: The plugin folder this code runs from: an installed copy, or a source checkout.
_PLUGIN_DIR = Path(__file__).resolve().parents[2]
#: The file an installed copy keeps to say which checkout it was copied from.
_SOURCE_ROOT_MARKER = ".blackbox-source-root"
#: At most this many real files a guarded pattern is expanded to when a wildcard is compared.
_MAX_EXPANDED = 200
_GLOB_CHARS = "*?["
#: Text that spells a guarded place in pieces: Hermes' folder with its config, plugins or Blackbox
#: folder; OpenClaw's config file; Blackbox's service label.
_IN_PIECES = re.compile(
    r"\.hermes\b[^\n]{0,80}?(?:config\.yaml|\.env\b|blackbox|plugins)"
    r"|\.openclaw[\w-]*\b[^\n]{0,40}?openclaw\.json|ai\.umanitek\.blackbox|integrations\W{1,6}openclaw", re.IGNORECASE)
#: Text that spells a place something starts from, in pieces (``Path.home() / '.ssh' / 'authorized_keys'``).
_STARTS_IN_PIECES = re.compile(
    r"\.ssh\b[^\n]{0,60}?(?:authorized_keys|\benvironment\b|['\"/]rc\b)|Launch(?:Agents|Daemons)\b|com\.apple\.loginitems"
    r"|backgroundtaskmanagement", re.IGNORECASE)

#: The place sets a check can judge against (see :func:`judging`).
OWN, STARTS, PROGRAMS = "own", "starts", "programs"
_SCOPE: contextvars.ContextVar[str] = contextvars.ContextVar("blackbox_guard_scope", default=OWN)


@contextmanager
def judging(scope: str) -> Iterator[None]:
    """Within the block, :func:`reaches`, :func:`holds`, :func:`inside` and :func:`guarded_places`
    answer for the place set *scope* (:data:`OWN`, :data:`STARTS` or :data:`PROGRAMS`)."""
    token = _SCOPE.set(scope)
    try:
        yield
    finally:
        _SCOPE.reset(token)


def scope() -> str:
    """The place set the running check judges against (:func:`judging`)."""
    return _SCOPE.get()


Value = TypeVar("Value")
#: How long a reading of the machine (the places, the real files, the ports) is kept.
_KEEP_SECONDS = 5.0


class Kept(Generic[Value]):
    """A value worked out from the machine, kept for a few seconds per key (one lock).

    The rule runs on every tool call and reads many words per call; listing folders and reading
    the config for each word made an ordinary command cost milliseconds. ``Kept(read).get(key)``
    calls ``read()`` at most once per :data:`_KEEP_SECONDS` while *key* stays the same."""

    def __init__(self, read: Callable[[], Value]) -> None:
        self._read = read
        self._lock = threading.Lock()
        self._key: Hashable = None
        self._until = 0.0
        self._value: Value | None = None

    def get(self, key: Hashable) -> Value:
        with self._lock:
            now = time.monotonic()
            if self._value is None or key != self._key or now >= self._until:
                self._value, self._key, self._until = self._read(), key, now + _KEEP_SECONDS
            return self._value

    def put(self, key: Hashable, value: Value) -> None:
        """Keep *value* for *key* now — a caller that already holds a fresh reading (the hook's
        own config) saves the read :meth:`get` would make."""
        with self._lock:
            self._value, self._key, self._until = value, key, time.monotonic() + _KEEP_SECONDS


def _source_roots() -> list[Path]:
    """The checkouts whose files an install loads or copies from: the one this plugin folder sits
    in, and the one an installed copy says it came from."""
    roots = []
    if (_PLUGIN_DIR.parents[1] / "integrations" / "openclaw").is_dir():
        roots.append(_PLUGIN_DIR.parents[1])
    try:
        marked = (_PLUGIN_DIR / _SOURCE_ROOT_MARKER).read_text(encoding="utf-8-sig").strip()
        if marked:
            roots.append(Path(marked))
    except OSError:
        pass
    return roots


def _machine() -> tuple[object, ...]:
    """What the guarded places depend on: when one of these changes, they are worked out again
    (including a place an add-on declares, :mod:`...kernel.addons`)."""
    return (*(os.environ.get(name, "") for name in ("HOME", "HERMES_HOME", "BLACKBOX_HOME", "OPENCLAW_CONFIG_PATH")),
            guarded_extra.version())


def guarded_places() -> tuple[str, ...]:
    """Every place an agent may not change, as absolute patterns (see :func:`_read_places`), in
    the place set being judged (:func:`judging`)."""
    return _current()[0]


def _current() -> tuple[tuple[str, ...], tuple[str, ...], re.Pattern[str]]:
    return _PLACES[_SCOPE.get()].get(_machine())


def _starts_places() -> tuple[str, ...]:
    return persistence_places.hook_places(os.path.expanduser("~")).starts


def _program_places() -> tuple[str, ...]:
    return persistence_places.hook_places(os.path.expanduser("~"), persistence_places.HOMEBREW_PREFIXES).programs


def _read_places(places: tuple[str, ...]) -> tuple[tuple[str, ...], tuple[str, ...], re.Pattern[str]]:
    """The guarded patterns, the real files they stand for on this machine, and ONE expression
    that matches a path which is a guarded place or lies inside one."""
    within = "|".join(fnmatch.translate(pattern) for place in places for pattern in (place, place.rstrip(os.sep) + os.sep + "*"))
    # An empty set (no Homebrew on this machine) matches nothing: "" would match every path.
    return places, tuple(dict.fromkeys(real for place in places for real in _real(place))), re.compile(within or "(?!)")


def _all_places() -> tuple[str, ...]:
    """Every place an agent may not change, as absolute patterns.

    Hermes' config and ``.env`` (the main home and every profile), Blackbox's plugin and data
    folders, OpenClaw's config in every profile, the plugin files a running install loads (this
    plugin folder, its OpenClaw plugin, the checkout they are copied from), the node's folder,
    the service definitions, the ``blackbox`` command, each coding agent's hook config that
    Blackbox writes into (``kernel.agent_hosts``), every add-on's folder
    (the folders that carry ``kernel.addons.MANIFEST``), the places an installed add-on declared, and a shell startup
    file that holds the agent sandbox's PATH block (KI-535)."""
    hermes = str(constants.hermes_root())
    home = os.path.expanduser("~")
    places = [
        os.path.join(hermes, "config.yaml"), os.path.join(hermes, ".env"),
        os.path.join(hermes, "profiles", "*", "config.yaml"), os.path.join(hermes, "profiles", "*", ".env"),
        os.path.join(hermes, "plugins", "blackbox"), os.path.join(hermes, "profiles", "*", "plugins", "blackbox"),
        os.path.join(hermes, "desktop-plugins", "blackbox"),
        str(constants.blackbox_home()), str(constants.blackbox_dkg_home()), str(_PLUGIN_DIR),
        os.path.join(home, ".openclaw*", "openclaw.json"), os.path.join(home, ".openclaw*", "extensions", "blackbox*"),
        os.path.join(home, "Library", "LaunchAgents", "ai.umanitek.blackbox*"),
        os.path.join(home, ".config", "systemd", "user", "blackbox-*"),
        os.path.join(home, ".local", "bin", "blackbox"),
        str(system_helper.user_key_folder()),   # the helper's key: moved or deleted, the helper stops obeying
    ]
    # Each coding agent's hook config: removing Blackbox's hook there switches that agent's protection
    # off. A shared settings file stays editable except for Blackbox's part (guard_settings).
    places += [str(host.config_path(Path(home))) for host in agent_hosts.HOSTS]
    # The second form some agents take hooks in (Cline's SDK plugin, OpenCode 2's plugin).
    places += [str(path) for host in agent_hosts.HOSTS for path in host.companion_paths(Path(home))]
    # A shell startup file holding the agent sandbox's PATH block (kernel.shell_path): without the
    # block later agents start outside the sandbox. The person's own lines stay editable (guard_settings).
    places += [str(path) for path in shell_path.holding(Path(home))]
    # Each add-on's folder beside the plugin, in every Hermes home: deleting it removes protection.
    # The manifest name is guarded too, so an agent can neither plant an add-on nor unmake one.
    plugin_dirs = (os.path.join(hermes, "plugins"), os.path.join(hermes, "profiles", "*", "plugins"),
                   os.path.join(hermes, "desktop-plugins"), str(_PLUGIN_DIR.parent))
    for plugin_dir in plugin_dirs:
        places += [guarded_extra.manifest_pattern(plugin_dir), *guarded_extra.folders(plugin_dir)]
    places += list(guarded_extra.places())   # places an installed add-on declared for itself
    for root in _source_roots():
        places += [str(root / "plugins" / "blackbox"), str(root / "integrations" / "openclaw"), str(root / ".dkg")]
    custom_openclaw = os.environ.get("OPENCLAW_CONFIG_PATH", "").strip()
    if custom_openclaw:
        places.append(os.path.expanduser(custom_openclaw))
    return tuple(dict.fromkeys(places))


def _expanded(word: str) -> str:
    """*word* as an absolute path, or "" when it is not one (``~``, ``$HOME`` and variables expanded)."""
    path = os.path.expanduser(os.path.expandvars(_home_as_tilde(str(word or "").strip())))
    return os.path.normpath(path) if os.path.isabs(path) else ""


def _real(place: str) -> list[str]:
    """The files a guarded pattern stands for on this machine (the pattern itself when it has no wildcard)."""
    if not any(char in place for char in _GLOB_CHARS):
        return [place]
    try:
        return [match for _, match in zip(range(_MAX_EXPANDED), glob.iglob(place, include_hidden=True))]
    except (OSError, ValueError):
        return []


def reaches(word: str) -> bool:
    """True when *word* names a guarded place, is a wildcard that matches one, or is a folder
    that holds one. A relative word is not judged here — the caller joins it onto a folder first."""
    path = _expanded(word)
    if not path:
        return False
    _, real_files, within = _current()
    if within.match(path):
        return True
    parent, wildcard = path.rstrip(os.sep) + os.sep, any(char in path for char in _GLOB_CHARS)
    for real in real_files:
        if real.startswith(parent):                                    # a parent folder of it
            return True
        if wildcard and (fnmatch.fnmatch(real, path) or fnmatch.fnmatch(real, parent + "*") or fnmatch.fnmatch(path, real)):
            return True
    return False


_PLACES = {OWN: Kept(lambda: _read_places(_all_places())), STARTS: Kept(lambda: _read_places(_starts_places())),
           PROGRAMS: Kept(lambda: _read_places(_program_places()))}


def holds(word: str) -> bool:
    """True when *word* is a folder that only HOLDS a guarded place (``~``, ``/``, ``~/Documents``
    above Cline's hooks): written without a wildcard, not a guarded place itself, not inside one.

    WHY (KI-591): :func:`reaches` answers True for such a folder too, which ``rm -rf ~`` needs —
    but a command that only reads a folder or only adds a new one to it (``df -h /``,
    ``mkdir -p ~/Documents``) cannot reach what lies below; the caller judges the command."""
    path = _expanded(word)
    if not path or any(char in path for char in _GLOB_CHARS):
        return False
    return reaches(word) and not _current()[2].match(path)


def inside(folder: str) -> bool:
    """True when *folder* is a guarded place or lies inside one (never for a mere parent of one:
    the home folder holds Blackbox, and working there is ordinary)."""
    path = _expanded(folder)
    return bool(path) and bool(_current()[2].match(path))


def is_source_checkout(folder: str) -> bool:
    """True when *folder* is, or lies inside, a checkout whose files a running install loads or
    copies from — where a ``git`` command that rewrites the working tree rewrites Blackbox."""
    if _SCOPE.get() != OWN:
        return False
    path = _expanded(folder)
    return bool(path) and any(path == str(root) or path.startswith(str(root) + os.sep) for root in _source_roots())


def names_in_pieces(text: str) -> bool:
    """True when *text* spells a guarded place in pieces a path check cannot join."""
    pieces = {OWN: _IN_PIECES, STARTS: _STARTS_IN_PIECES}.get(_SCOPE.get())
    return bool(pieces and pieces.search(text or ""))
