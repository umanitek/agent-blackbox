"""The working folder and the agent of the action being judged: ambient, scoped values (Context Object).

WHY: a command names a script by a relative path (``python3 r.py``), and which file that is
depends on the folder the agent runs it in. The agent's hook names that folder (``cwd``); the tool
call itself does not, and the checks only see the tool call. The one caller that knows it — the
guard's verdict for a coding agent's hook, the Hermes hook from inside its own process — sets it
around the verdict; File Shield's script reader asks for it. A ``ContextVar``: per thread and per
task, so two agents judged at the same time never see each other's folder.

The agent is set the same way: a folder rule the person scoped to one agent (File Shield's
sandbox permissions) is judged by the hook layer for that agent only (F9).

Usage::

    with working_in("/Users/me/app", agent="claude-code"):
        ...                       # the checks run here
    working_folder()              # "/Users/me/app" inside, "" when nobody said
    acting_agent()                # "claude-code" inside, "" when nobody said
"""

from __future__ import annotations

import contextlib
import contextvars
from typing import Iterator

#: The longest folder kept (the hooks bound theirs the same).
MAX_FOLDER_CHARS = 500

#: The longest agent id kept (catalogue ids are short words).
MAX_AGENT_CHARS = 80

_FOLDER: contextvars.ContextVar[str] = contextvars.ContextVar("blackbox_working_folder", default="")
_AGENT: contextvars.ContextVar[str] = contextvars.ContextVar("blackbox_acting_agent", default="")


@contextlib.contextmanager
def working_in(folder: str, agent: str = "") -> Iterator[None]:
    """The checks inside this block judge an action run in *folder* (absolute; "" = unknown) by
    *agent* (a catalogue id such as ``claude-code``; "" = unknown)."""
    token = _FOLDER.set(folder[:MAX_FOLDER_CHARS] if isinstance(folder, str) and folder.startswith("/") else "")
    agent_token = _AGENT.set(agent[:MAX_AGENT_CHARS] if isinstance(agent, str) else "")
    try:
        yield
    finally:
        _AGENT.reset(agent_token)
        _FOLDER.reset(token)


def working_folder() -> str:
    """The folder the action being judged runs in; "" when its caller did not say."""
    return _FOLDER.get()


def acting_agent() -> str:
    """The agent whose action is being judged; "" when its caller did not say."""
    return _AGENT.get()


__all__ = ["acting_agent", "working_folder", "working_in"]
