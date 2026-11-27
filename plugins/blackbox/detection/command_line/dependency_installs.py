"""Which packages a shell command installs by name — ``pip install evil==1.0`` is ``pypi`` ``evil`` ``1.0``.

The words are the shell's own (:mod:`..paths.shell_words`, the ONE lexer every check reads
through), so quoting and escaping a name changes nothing: ``pip install e"v"il``, ``ev\\il`` and
``npm install e''vil`` all install ``evil``. A requirement is read the way pip reads it — extras
(``evil[x]``) and every comparison (``==``, ``===``, ``~=``, ``>=``, ``<=``, ``!=``, ``<``, ``>``) taken off
the name; only an exact pin (``==`` / ``===``) gives a version, any other range is the whole
package. An option's value (``-r req.txt``, ``--index-url URL``, ``--registry URL``) is never a package.

Managers: pip (any version suffix, ``pip3.12``, and ``python -m pip``), ``uv pip install``, ``uv add``,
``uv tool install|run``, ``uvx``, ``pipx install|run``, npm ``install|i|add``, ``pnpm add``, ``yarn add``,
``yarn global add``, ``bun add|install|i``, ``npx``, ``bunx``, ``pnpm dlx``, ``yarn dlx``, ``cargo add``,
``gem install``, ``brew install``. What an install that names no package installs is read from
its manifest (:mod:`..manifests`).

Pure and deterministic; reads no files.

Usage::

    parse_dependency_installs('pip install "evil[x]>=1" requests==2.31.0')
    # -> [{"ecosystem": "pypi", "name": "evil", "version": ""},
    #     {"ecosystem": "pypi", "name": "requests", "version": "2.31.0"}]
"""

from __future__ import annotations

import re
from typing import Optional

from ..paths import shell_words

#: The cheap gate, read with quotes and backslashes taken out: no manager word, no parse.
_MANAGER_WORD = re.compile(r"\b(?:pip|uv|uvx|pipx|npm|pnpm|yarn|bun|bunx|npx|cargo|gem|brew)", re.IGNORECASE)
_PIP = re.compile(r"^pip(?:\d+(?:\.\d+)*)?$")
_PYTHON = re.compile(r"^python(?:\d+(?:\.\d+)*)?$")
#: manager → {subcommand (or "" for none): (ecosystem, how many more words before the packages)}.
_MANAGERS: dict[str, dict[str, str]] = {
    "pip": {"install": "pypi"},
    "uv": {"add": "pypi"},
    "uvx": {"": "pypi"},
    "pipx": {"install": "pypi", "run": "pypi"},
    "npm": {"install": "npm", "i": "npm", "add": "npm"},
    "pnpm": {"add": "npm", "dlx": "npm"},
    "yarn": {"add": "npm", "dlx": "npm"},
    "bun": {"add": "npm", "install": "npm", "i": "npm"},
    "npx": {"": "npm"},
    "bunx": {"": "npm"},
    "cargo": {"add": "cargo"},
    "gem": {"install": "rubygems"},
    "brew": {"install": "homebrew"},
}
#: Two-word subcommands: ``uv pip install``, ``uv tool install|run``, ``yarn global add``.
_DEEPER = {("uv", "pip"): ("install",), ("uv", "tool"): ("install", "run"), ("yarn", "global"): ("add",)}
#: Subcommands that run the first package they name; every later word is its own argument.
_RUNS_FIRST = frozenset({"", "run", "dlx"})
#: Options whose next word is their value (a file, an address, a folder), never a package.
_VALUE_OPTIONS = frozenset({
    "-r", "--requirement", "-c", "--constraint", "-e", "--editable", "-i", "--index-url", "--extra-index-url",
    "--index", "--default-index", "-f", "--find-links", "-t", "--target", "--python", "-p", "--prefix", "--root",
    "--src", "--platform", "--python-version", "--implementation", "--abi", "--cache-dir", "--trusted-host",
    "--proxy", "--timeout", "--retries", "--cert", "--client-cert", "--log", "--report", "--exists-action",
    "--upgrade-strategy", "--progress-bar", "--group", "--extra", "--registry", "--tag", "--cache", "--userconfig",
    "-C", "--dir", "--cwd", "--filter", "-w", "--workspace", "--otp", "--scope", "--omit", "--include",
    "--install-strategy", "--source", "--version", "-v", "--install-dir", "--bindir", "--features", "-F",
    "--manifest-path", "--package", "--rename", "--branch", "--rev", "--git", "--path",
})
#: Options that take a value only for one ecosystem (``-v`` is gem's version, a flag elsewhere).
_ECOSYSTEM_ONLY = {"-v": "rubygems", "--version": "rubygems", "-p": "pypi", "-F": "cargo", "-C": "npm"}
#: A PEP 508 requirement: the name, optional extras, then an optional version clause.
_REQUIREMENT = re.compile(r"^([A-Za-z0-9](?:[A-Za-z0-9._-]*[A-Za-z0-9])?)\s*(?:\[[^\]]*\])?\s*(?P<clause>(?:===|==|~=|!=|>=|<=|<|>|@|;).*)?$")
_EXACT_PIN = re.compile(r"^===?\s*([A-Za-z0-9._+!-]+)\s*(?:;.*)?$")
_NOT_A_NAME = ("http://", "https://", "/", ".", "~", "git+", "file:", "@git")
_ARCHIVE_ENDINGS = (".whl", ".tar.gz", ".tgz", ".zip", ".gem")


def _package(token: str, ecosystem: str) -> Optional[dict[str, str]]:
    """``{name, version}`` for one install word in *ecosystem*, or None when it names no package."""
    token = token.strip()
    if not token or token.startswith(_NOT_A_NAME) or token.lower().endswith(_ARCHIVE_ENDINGS):
        return None
    if ecosystem in ("pypi", "rubygems"):
        found = _REQUIREMENT.match(token)
        if not found:
            return None
        pin = _EXACT_PIN.match(found.group("clause") or "")
        return {"name": found.group(1), "version": pin.group(1) if pin else ""}
    at = token.rfind("@")
    if at > 0:   # a scoped npm name starts with @, so a version needs an @ after the first character
        return {"name": token[:at], "version": token[at + 1:]}
    pattern = r"(?:@[A-Za-z0-9._-]+/)?[A-Za-z0-9._-]+" if ecosystem == "npm" else r"[A-Za-z0-9._+/-]+"
    return {"name": token, "version": ""} if re.fullmatch(pattern, token) else None


def _manager_at(words: list[str], index: int) -> tuple[str, str, int]:
    """``(ecosystem, subcommand, where its packages start)`` for a manager word at *index*, else ("", "", -1)."""
    name = words[index].rsplit("/", 1)[-1].lower()
    if _PYTHON.match(name) and words[index + 1:index + 2] == ["-m"] and index + 2 < len(words):
        index, name = index + 2, words[index + 2].lower()
    name = "pip" if _PIP.match(name) else name
    table = _MANAGERS.get(name)
    if table is None:
        return "", "", -1
    sub = words[index + 1].lower() if index + 1 < len(words) else ""
    deeper = _DEEPER.get((name, sub))
    if deeper:
        third = words[index + 2].lower() if index + 2 < len(words) else ""
        return ("pypi" if name == "uv" else "npm", "run" if third == "run" else third, index + 3) if third in deeper else ("", "", -1)
    if "" in table:
        return table[""], "", index + 1
    return (table[sub], sub, index + 2) if sub in table else ("", "", -1)


def parse_dependency_installs(command: str) -> list[dict[str, str]]:
    """Every package *command* installs by name, as ``[{ecosystem, name, version}, ...]`` in order,
    each once (see the module doc). Empty when the command installs nothing by name."""
    if not command or not _MANAGER_WORD.search(re.sub(r"[\"'\\]", "", command)):
        return []
    words = shell_words.words(command)
    out: list[dict[str, str]] = []
    seen: set[str] = set()
    index = 0
    while index < len(words):
        ecosystem, sub, start = _manager_at(words, index)
        if start < 0:
            index += 1
            continue
        index = start
        while index < len(words) and words[index] not in shell_words.SEPARATORS:
            word = words[index]
            index += 1
            if word.startswith("-"):
                if word in _VALUE_OPTIONS and _ECOSYSTEM_ONLY.get(word, ecosystem) == ecosystem:
                    index += 1
                continue
            parsed = _package(word, ecosystem)
            if not parsed:
                continue
            key = f"{ecosystem}:{parsed['name'].lower()}:{parsed['version']}"
            if key not in seen:
                seen.add(key)
                out.append({"ecosystem": ecosystem, **parsed})
            if sub in _RUNS_FIRST:
                break   # ``npx pkg arg…``: only the first word is a package, the rest are its arguments
        while index < len(words) and words[index] not in shell_words.SEPARATORS:
            index += 1
    return out


__all__ = ["parse_dependency_installs"]
