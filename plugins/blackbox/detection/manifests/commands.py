"""Which installs a shell command runs, and in which folder (KI-595).

``npm install express`` names its package and is checked by its words
(:func:`..action_parsing.parse_dependency_installs`). ``npm install``, ``npm ci``, ``uv sync``,
``pip install -r requirements.txt`` or ``bundle install`` name none: what they install is in a
manifest or lockfile in the folder they run in. :func:`install_sites` finds every install in a
command — the named ones too, whose lockfile the after-install check reads — with the folder
each runs in: the tool call's own working-folder argument, else the folder the caller set
(``kernel.action_context``), moved by every ``cd`` / ``pushd`` before it and by the manager's own
folder option (``npm --prefix``, ``pnpm -C``, ``yarn --cwd``, ``uv --project``, ``poetry -C``,
``cargo --manifest-path``, ``bundle --gemfile``).

Usage::

    for site in install_sites("cd app && npm ci", folder="/home/me"):
        site.manager, site.folder, site.named    # "npm", "/home/me/app", ()
"""

from __future__ import annotations

import os
import re
import shlex
from dataclasses import dataclass
from typing import Iterator, Optional

#: The cheap gate: no manager word, no parse.
_MANAGERS = re.compile(r"\b(?:npm|pnpm|yarn|bun|pip3?|uv|poetry|pipenv|cargo|bundle)\b")
_SEPARATORS = frozenset({";", "&&", "||", "|", "&", "(", ")"})
_PREFIX_WORDS = frozenset({"sudo", "env", "time", "nohup", "exec", "command", "builtin"})
_ASSIGNMENT = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*=")
#: Options whose next word is their value, not a package (per manager family).
_VALUE_OPTIONS = frozenset({"--prefix", "-C", "--dir", "--cwd", "--registry", "--tag", "--project", "--directory",
                            "--manifest-path", "--gemfile", "--index-url", "-i", "--extra-index-url", "-f",
                            "--find-links", "--python", "-p", "--target", "-t", "--root", "--path", "--with",
                            "--without", "--only", "-E", "--extras", "--group", "-G", "--workspace", "-w",
                            "--filter", "-F", "--features", "--package"})
_FOLDER_OPTIONS = {"--prefix": "npm", "-C": "pnpm|poetry", "--dir": "pnpm", "--cwd": "yarn|bun",
                   "--project": "uv", "--directory": "uv|poetry"}
_REQUIREMENT_OPTIONS = frozenset({"-r", "--requirement", "-c", "--constraint"})


@dataclass(frozen=True)
class InstallSite:
    """One install a command runs. *manager* is the tool ("npm", "pnpm", "yarn", "bun", "pip",
    "uv", "poetry", "pipenv", "cargo", "bundle"); *folder* the absolute folder it runs in ("" when
    nobody said); *named* the package words it names (empty for a manifest install); *files* the
    requirements files it names, absolute; *project* True for ``pip install .`` (the folder's
    pyproject.toml); *strict* True for ``npm ci`` (the lockfile only, never package.json)."""

    manager: str
    folder: str
    named: tuple[str, ...] = ()
    files: tuple[str, ...] = ()
    project: bool = False
    strict: bool = False

    @property
    def from_files(self) -> bool:
        """True when what it installs is read from files (a manifest install)."""
        return not self.named or bool(self.files) or self.project


def _words(command: str) -> list[str]:
    lexer = shlex.shlex(command, posix=True, punctuation_chars=";&|()")
    lexer.whitespace_split = True
    lexer.commenters = ""
    try:
        return list(lexer)
    except ValueError:   # an unclosed quote: read it as plain words, as the shell would refuse it
        return command.split()


def _segments(command: str) -> Iterator[list[str]]:
    """Each simple command's words, in order (a newline, ``;``, ``&&``, ``||`` and ``|`` end one)."""
    for line in command.splitlines():
        current: list[str] = []
        for word in _words(line):
            if word in _SEPARATORS or set(word) <= set(";&|"):
                if current:
                    yield current
                current = []
            else:
                current.append(word)
        if current:
            yield current


def _within(folder: str, target: str) -> str:
    """*target* (absolute, ``~``-relative or relative to *folder*) as an absolute path ("" = unknown)."""
    target = os.path.expanduser(target)
    if os.path.isabs(target):
        return os.path.normpath(target)
    return os.path.normpath(os.path.join(folder, target)) if folder else ""


def _strip_prefix(words: list[str]) -> list[str]:
    start = 0
    while start < len(words) and (words[start] in _PREFIX_WORDS or _ASSIGNMENT.match(words[start])
                                  or (words[start].startswith("-") and start and words[start - 1] in _PREFIX_WORDS)):
        start += 1
    rest = words[start:]
    if len(rest) >= 3 and re.fullmatch(r"python(?:3(?:\.\d+)?)?", rest[0]) and rest[1] == "-m":
        return rest[2:]   # python -m pip …
    return rest


def _scan(words: list[str]) -> tuple[list[str], dict[str, str]]:
    """``(positional words, {option: value})`` of a manager's words after its name."""
    positional: list[str] = []
    options: dict[str, str] = {}
    index = 0
    while index < len(words):
        word = words[index]
        name, _, inline = word.partition("=") if word.startswith("--") else (word, "", "")
        if name in _VALUE_OPTIONS or name in _REQUIREMENT_OPTIONS:
            value = inline or (words[index + 1] if index + 1 < len(words) and not inline else "")
            options.setdefault(name, value)
            if name in _REQUIREMENT_OPTIONS:
                options[f"{name}#{index}"] = value   # every -r counts, not only the first
            index += 1 if inline else 2
            continue
        if word in ("-e", "--editable") and index + 1 < len(words):
            positional.append(words[index + 1])
            index += 2
            continue
        if not word.startswith("-"):
            positional.append(word)
        index += 1
    return positional, options


def _folder(manager: str, folder: str, options: dict[str, str]) -> str:
    for option, managers in _FOLDER_OPTIONS.items():
        if options.get(option) and manager in managers.split("|"):
            return _within(folder, options[option])
    for option in ("--manifest-path", "--gemfile"):
        if options.get(option):
            return os.path.dirname(_within(folder, options[option]))
    return folder


_SUBCOMMANDS = {
    "npm": {"install": "any", "i": "any", "add": "named", "ci": "files", "isntall": "any", "in": "any"},
    "pnpm": {"install": "any", "i": "any", "add": "named"},
    "yarn": {"": "files", "install": "files", "add": "named"},
    "bun": {"install": "any", "i": "any", "add": "named"},
    "uv": {"sync": "files", "add": "named"},
    "poetry": {"install": "files", "add": "named", "sync": "files"},
    "pipenv": {"install": "any", "sync": "files"},
    "cargo": {"build": "files", "fetch": "files", "b": "files", "add": "named", "install": "path"},
    "bundle": {"": "files", "install": "files", "add": "named"},
}


def _site(words: list[str], folder: str) -> Optional[InstallSite]:
    manager = "pip" if words[0] == "pip3" else words[0]
    positional, options = _scan(words[1:])
    sub = positional[0] if positional else ""
    if manager == "pip":
        return _pip_site("pip", positional[1:], options, folder) if sub == "install" else None
    if manager == "uv" and sub == "pip":
        action = positional[1] if len(positional) > 1 else ""
        return _pip_site("uv-pip", positional[2:], options, folder, sync=action == "sync") \
            if action in ("install", "sync") else None
    kind = _SUBCOMMANDS.get(manager, {}).get(sub)
    if kind is None:
        return None
    where = _folder(manager, folder, options)
    names = tuple(positional[1:])
    if kind == "path":   # cargo install --path X builds X with its lock; cargo install NAME is not a project install
        return InstallSite(manager, _within(folder, options["--path"])) if options.get("--path") else None
    if kind == "files" or (kind == "any" and not names):
        return InstallSite(manager, where, strict=sub == "ci")
    return InstallSite(manager, where, names)


def _pip_site(manager: str, words: list[str], options: dict[str, str], folder: str,
              sync: bool = False) -> Optional[InstallSite]:
    """pip install / uv pip install / uv pip sync: requirements files, a project folder, or names."""
    files = [value for key, value in options.items() if "#" in key and value]
    if sync:   # uv pip sync takes its requirements files as words
        files, words = files + words, []
    projects = [word for word in words if word in (".", "..") or word.startswith(("./", "../", "/", "~"))]
    names = tuple(word for word in words if word not in projects)
    where = _within(folder, projects[0]) if projects else folder
    absolute = tuple(path for path in (_within(folder, f) for f in files) if path)
    if not names and not absolute and not projects:
        return None
    return InstallSite(manager, where, names, absolute, project=bool(projects))


def install_sites(command: str, folder: str = "") -> list[InstallSite]:
    """Every install *command* runs, in order, each with the folder it runs in (see the module doc)."""
    if not command or not _MANAGERS.search(command):
        return []
    sites: list[InstallSite] = []
    current = folder if os.path.isabs(folder or "") else ""
    for words in _segments(command):
        words = _strip_prefix(words)
        if not words:
            continue
        if words[0] in ("cd", "pushd"):
            target = words[1] if len(words) > 1 else "~"
            current = _within(current, target) if target != "-" else current
            continue
        site = _site(words, current) if words[0] in _SUBCOMMANDS or words[0] in ("pip", "pip3") else None
        if site is not None:
            sites.append(site)
    return sites
