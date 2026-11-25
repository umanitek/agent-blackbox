"""The host folders a container command mounts (``docker run -v ~/Documents/Taxes:/x …``).

A container runs outside the agent sandbox, under the container engine, and reads whatever host
folder it is given (KI-622). File Shield's hook layer therefore treats a mount's SOURCE as a path
the call reaches: a protected item mounted into a container is refused like reading it.

Understood: ``docker`` / ``podman`` / ``nerdctl`` ``run`` / ``create`` (and ``container run`` /
``container create``) with ``-v SRC:DST[:opts]``, ``--volume SRC:DST``, ``--volume=…`` and
``--mount type=bind,source=SRC,…`` (``src=`` too). A named volume (no ``/`` or ``~`` in front)
is not a host folder. Pure text; nothing is run.

Usage::

    sources("docker run --rm -v ~/Documents/Taxes:/x alpine cat /x/a")   # ["~/Documents/Taxes"]
"""

from __future__ import annotations

import shlex

ENGINES = frozenset({"docker", "podman", "nerdctl"})
VERBS = frozenset({"run", "create"})
#: The most words of one command read.
MAX_WORDS = 400


def _host(source: str) -> str:
    return source if source.startswith(("/", "~", "$HOME", "${HOME}", ".")) else ""


def _mount_source(spec: str) -> str:
    for part in spec.split(","):
        key, _, value = part.partition("=")
        if key.strip() in ("source", "src"):
            return _host(value.strip())
    return ""


def _from_words(words: list[str]) -> list[str]:
    found: list[str] = []
    index = 0
    while index < len(words):
        word = words[index]
        value = ""
        if word in ("-v", "--volume", "--mount") and index + 1 < len(words):
            value, index = words[index + 1], index + 1
            found.append(_mount_source(value) if word == "--mount" else _host(value.split(":", 1)[0]))
        elif word.startswith(("--volume=", "--mount=")):
            key, value = word.split("=", 1)
            found.append(_mount_source(value) if key == "--mount" else _host(value.split(":", 1)[0]))
        elif word.startswith("-v") and len(word) > 2:
            found.append(_host(word[2:].split(":", 1)[0]))
        index += 1
    return [path for path in found if path]


def sources(command: str) -> list[str]:
    """The host folders *command* mounts into a container, as written (``[]`` for none)."""
    try:
        words = shlex.split(command or "", comments=False)[:MAX_WORDS]
    except ValueError:
        return []
    out: list[str] = []
    for start, word in enumerate(words):
        name = word.rsplit("/", 1)[-1]
        if name not in ENGINES:
            continue
        rest = words[start + 1:]
        if rest[:1] == ["container"]:
            rest = rest[1:]
        if rest[:1] and rest[0] in VERBS:
            out += _from_words(rest[1:])
    return list(dict.fromkeys(out))


__all__ = ["ENGINES", "VERBS", "sources"]
