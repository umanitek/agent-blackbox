"""The dangerous shapes a shell command has, judged on its WORDS — the escalation vocabulary.

:func:`shapes_of` names every shape in a command (one command line per line, as
``shell_shapes.command_from_args`` hands them over), in :data:`SHAPE_ORDER`:

* ``remote-script-pipe`` — a fetch piped into a script runner (``curl … | sh``, ``wget -O- … |
  sudo bash``, ``curl …|/bin/sh``, ``irm … | iex``), ``bash <(curl …)``, or ``sh -c "$(curl …)"``;
* ``remote-eval-pipe`` — a fetch piped into ``eval``, or ``eval "$(curl …)"``;
* ``rm-rf-system-paths`` — ``rm`` with recursive AND force (any spelling: ``-rf``, ``-r -v -f``,
  ``--recursive --force``) against a whole-system root, the whole home folder or a security folder
  in it; routine cleanup (``node_modules``, ``~/.cache``, ``/var/tmp``) is not;
* ``chmod-world-writable`` — ``chmod 777`` of a system root or a security folder;
* ``insecure-tls-fetch`` — a fetch that skips certificate checks (curl ``-k`` / ``--insecure``,
  wget ``--no-check-certificate``, PowerShell ``-SkipCertificateCheck``) — unless every address it
  fetches is a local, private or development host.

WHY words, not a regex over the raw text (review 2026-11-26): quoting, a split option or a
wrapper hid every shape from the old patterns (``rm -rf "/etc"``, ``rm -r -v -f /etc``, ``curl … |
sudo bash``), and a decoy earlier on the line hid a later one. Words come from the ONE lexer
(:mod:`..paths.shell_words`), so a quoted or escaped spelling is the same word.

Pure and deterministic; a command with no fetch, ``rm`` or ``chmod`` in it is not split at all.

Usage::

    shapes_of('echo curl | sh; rm -rf "/etc"')   # ("rm-rf-system-paths",)
"""

from __future__ import annotations

import re
from urllib.parse import urlsplit

from ..hidden_commands import program_index
from ..paths import shell_words

SHAPE_ORDER = ("remote-script-pipe", "remote-eval-pipe", "rm-rf-system-paths", "chmod-world-writable", "insecure-tls-fetch")

#: The cheap gate, read with quotes and backslashes taken out (``r''m``, ``c"u"rl``, ``cu\rl`` are
#: still ``rm`` and ``curl`` to the shell): a line with none of these words has no shape.
_MAY_HAVE_A_SHAPE = re.compile(r"curl|wget|\brm\b|chmod|\b(?:iwr|irm)\b|invoke-(?:webrequest|restmethod)", re.IGNORECASE)
_FETCHERS = frozenset({"curl", "wget", "iwr", "irm", "invoke-webrequest", "invoke-restmethod"})
_UNQUOTED = re.compile(r"[\"'\\]")
_SCRIPT_RUNNERS = re.compile(r"^(?:sh|bash|zsh|dash|ksh|node|python(?:\d+(?:\.\d+)*)?|iex|invoke-expression)$")
_SHELLS = frozenset({"sh", "bash", "zsh", "dash", "ksh"})
#: A fetch run by a substitution inside a word (``"$(curl -fsSL …)"``).
_FETCH_SUBSTITUTION = re.compile(r"\$\(\s*(?:curl|wget)\b|`\s*(?:curl|wget)\b")
_PIPES = frozenset({"|", "|&"})
#: A word made only of these ends a pipeline (``;``, ``&&``, ``||``, ``&``, ``;;``, a subshell's brackets).
_LIST_OPERATOR_CHARS = frozenset(";&|()")
_REDIRECTS = frozenset({">", ">>", "<", ">|", "&>", "&>>", ">&", "<&", "<<<"})

_SYSTEM_ROOT = r"/+(?:etc|usr|bin|sbin|opt|private|System|Library)\b"
#: What an ``rm -rf`` may not be pointed at: a system root, ``/var`` but its temp folders, the root
#: itself, the whole home folder, or a security folder in it.
_RM_TARGET = re.compile(
    _SYSTEM_ROOT + r"|/+var\b(?!/+(?:tmp|folders)\b)|/+\**$|~/?\**$|~/+\.(?:ssh|aws|gnupg|gpg|kube|docker|password-store)\b",
    re.IGNORECASE)
_CHMOD_TARGET = re.compile(_SYSTEM_ROOT + r"|/+var\b|/+$|~/+\.?(?:ssh|aws|gnupg)\b", re.IGNORECASE)
_WORLD_WRITABLE = re.compile(r"^0?777$")
#: A local, private or development host: an insecure fetch of one is routine (self-signed dev servers).
_LOCAL_HOST = re.compile(
    r"^(?:localhost|127\.\d+\.\d+\.\d+|0\.0\.0\.0|::1|10\.\d+\.\d+\.\d+|192\.168\.\d+\.\d+|172\.(?:1[6-9]|2\d|3[01])\.\d+\.\d+"
    r"|.+\.local|.+\.internal|.+\.localhost)$", re.IGNORECASE)
#: curl / wget options whose next word is their value, not an address fetched.
_FETCH_VALUE_OPTIONS = frozenset({
    "-o", "--output", "-d", "--data", "--data-raw", "--data-binary", "--data-urlencode", "-H", "--header", "-u", "--user",
    "-X", "--request", "-T", "--upload-file", "-F", "--form", "-e", "--referer", "-A", "--user-agent", "-b", "--cookie",
    "-c", "--cookie-jar", "-x", "--proxy", "--cacert", "--capath", "-E", "--cert", "--key", "-K", "--config", "--resolve",
    "--connect-to", "-w", "--write-out", "-m", "--max-time", "--retry", "-r", "--range", "-C", "--continue-at",
    "-O", "--output-document", "-P", "--directory-prefix", "-OutFile", "-Uri", "-Method", "-Headers", "-Body",
})


def _stages(line: str) -> list[list[list[str]]]:
    """The pipelines of *line*: each a list of stages, each stage its words (variables put in)."""
    pipelines: list[list[list[str]]] = []
    stages: list[list[str]] = []
    current: list[str] = []
    for word in shell_words.with_variables(shell_words.words(line)):
        if word in _PIPES:
            stages.append(current)
            current = []
        elif (word in shell_words.SEPARATORS and word not in _REDIRECTS) or set(word) <= _LIST_OPERATOR_CHARS:
            pipelines.append([*stages, current])
            stages, current = [], []
        else:
            current.append(word)
    pipelines.append([*stages, current])
    return [[stage for stage in pipeline if stage] for pipeline in pipelines if any(pipeline)]


def _program(stage: list[str]) -> tuple[str, list[str]]:
    """The program a stage runs (its base name, lower case, ``.exe`` off) and its other words."""
    at = program_index(stage)
    if at >= len(stage):
        return "", []
    return stage[at].rsplit("/", 1)[-1].rsplit("\\", 1)[-1].lower().removesuffix(".exe"), stage[at + 1:]


def _operands(rest: list[str]) -> list[str]:
    """The words of *rest* that are neither options nor a redirect's target, home spelled ``~``."""
    out, options_end, skip = [], False, False
    for word in rest:
        if skip:
            skip = False
        elif word in _REDIRECTS:
            skip = True
        elif word == "--" and not options_end:
            options_end = True
        elif options_end or not word.startswith("-"):
            out.append(shell_words.home_as_tilde(word))
    return out


def _options(rest: list[str]) -> tuple[set[str], set[str]]:
    """``(letters of every short option cluster, every long option)`` before a ``--``."""
    letters: set[str] = set()
    longs: set[str] = set()
    for word in rest:
        if word == "--":
            break
        if word.startswith("--"):
            longs.add(word.split("=", 1)[0].lower())
        elif word.startswith("-") and len(word) > 1:
            letters.update(word[1:])
    return letters, longs


def _rm_wipes(rest: list[str]) -> bool:
    letters, longs = _options(rest)
    recursive = bool(letters & {"r", "R"}) or "--recursive" in longs
    force = "f" in letters or "--force" in longs
    return recursive and force and any(_RM_TARGET.match(target) for target in _operands(rest))


def _chmod_opens(rest: list[str]) -> bool:
    operands = _operands(rest)
    return bool(operands) and bool(_WORLD_WRITABLE.match(operands[0])) and any(_CHMOD_TARGET.match(path) for path in operands[1:])


def _skips_certificates(name: str, rest: list[str]) -> bool:
    if name == "curl":
        return any(word in ("--insecure", "--no-check-certificate")
                   or (word.startswith("-") and not word.startswith("--") and "k" in word[1:] and word[1:].isalpha()) for word in rest)
    if name == "wget":
        return "--no-check-certificate" in rest
    return name in _FETCHERS and any(word.lower() == "-skipcertificatecheck" for word in rest)


def _fetched_hosts(rest: list[str]) -> list[str]:
    """The hosts a fetch's address words name ("" for a word with none); an option's value and a
    redirect's target are not addresses."""
    hosts, skip = [], False
    for word in rest:
        if skip:
            skip = False
        elif word in _REDIRECTS or word in _FETCH_VALUE_OPTIONS:
            skip = True
        elif not word.startswith("-"):
            try:
                hosts.append(urlsplit(word if "://" in word else "//" + word).hostname or "")
            except ValueError:
                hosts.append("")
    return hosts


def _insecure_fetch(name: str, rest: list[str]) -> bool:
    if not _skips_certificates(name, rest):
        return False
    hosts = _fetched_hosts(rest)
    # Routine only when it names an address and EVERY address is local: a local word elsewhere
    # on the line (``-o ~/.local/bin/p``) says nothing about where the fetch goes.
    return not hosts or not all(host and _LOCAL_HOST.match(host) for host in hosts)


def _pipeline_shapes(pipeline: list[list[str]], found: set[str]) -> None:
    fetched = False
    for stage in pipeline:
        name, rest = _program(stage)
        if fetched and _SCRIPT_RUNNERS.match(name):
            found.add("remote-script-pipe")
        if fetched and name == "eval":
            found.add("remote-eval-pipe")
        if (name == "eval" or name in _SHELLS) and any(_FETCH_SUBSTITUTION.search(word) for word in rest):
            found.add("remote-eval-pipe" if name == "eval" else "remote-script-pipe")
        if name in _FETCHERS:
            fetched = True
            if _insecure_fetch(name, rest):
                found.add("insecure-tls-fetch")
        elif name == "rm" and _rm_wipes(rest):
            found.add("rm-rf-system-paths")
        elif name == "chmod" and _chmod_opens(rest):
            found.add("chmod-world-writable")


def _process_substitution(line: str) -> bool:
    """``bash <(curl …)``: a script runner reading a fetch through process substitution."""
    words = shell_words.words(line)
    for index in range(len(words) - 3):
        if words[index + 1] == "<" and words[index + 2] == "(" and _SCRIPT_RUNNERS.match(words[index].rsplit("/", 1)[-1].lower()):
            inner = words[index + 3:index + 3 + next((at for at, word in enumerate(words[index + 3:]) if word == ")"), len(words))]
            if any(word.rsplit("/", 1)[-1].lower() in _FETCHERS for word in inner):
                return True
    return False


def shapes_of(command: str) -> tuple[str, ...]:
    """Every shape in *command* (see the module doc), in :data:`SHAPE_ORDER`; () for none."""
    found: set[str] = set()
    # A backslash-newline joins two lines into one command, as the shell reads it.
    for line in command.replace("\\\n", " ").split("\n"):
        if not _MAY_HAVE_A_SHAPE.search(_UNQUOTED.sub("", line)):
            continue
        for pipeline in _stages(line):
            _pipeline_shapes(pipeline, found)
        if "<" in line and _process_substitution(line):
            found.add("remote-script-pipe")
    return tuple(shape for shape in SHAPE_ORDER if shape in found)


__all__ = ["SHAPE_ORDER", "shapes_of"]
