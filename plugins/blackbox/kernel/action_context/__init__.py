"""The working folder of the action being judged: an ambient, scoped value (Context Object).

WHY: a command names a script by a relative path (``python3 r.py``), and which file that is
depends on the folder the agent runs it in. The agent's hook names that folder (``cwd``); the tool
call itself does not, and the checks only see the tool call. The one caller that knows it — the
guard's verdict for a coding agent's hook, the Hermes hook from inside its own process — sets it
around the verdict; File Shield's script reader asks for it. A ``ContextVar``: per thread and per
task, so two agents judged at the same time never see each other's folder.

Usage::

    with working_in("/Users/me/app"):
        ...                       # the checks run here
    working_folder()              # "/Users/me/app" inside, "" when nobody said
"""

from __future__ import annotations

import contextlib
import contextvars
from typing import Iterator

#: The longest folder kept (the hooks bound theirs the same).
MAX_FOLDER_CHARS = 500

_FOLDER: contextvars.ContextVar[str] = contextvars.ContextVar("blackbox_working_folder", default="")


@contextlib.contextmanager
def working_in(folder: str) -> Iterator[None]:
    """The checks inside this block judge an action run in *folder* (absolute; "" = unknown)."""
    token = _FOLDER.set(folder[:MAX_FOLDER_CHARS] if isinstance(folder, str) and folder.startswith("/") else "")
    try:
        yield
    finally:
        _FOLDER.reset(token)


def working_folder() -> str:
    """The folder the action being judged runs in; "" when its caller did not say."""
    return _FOLDER.get()


__all__ = ["working_folder", "working_in"]
