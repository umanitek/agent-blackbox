"""Guard — the CHECK hot path: intercept every action the agent is about to take.

Hermes calls these hooks around every tool call and model request:

* :func:`on_pre_tool_call` — detect, and in block mode refuse, BEFORE execution.
* :func:`on_post_tool_call` — log local activity, start background discovery.
* :func:`on_pre_api_request` — scan the untrusted part of a model request.
* :func:`on_session_start` / :func:`on_session_end` — per-session context.
* :func:`blackbox_block_message` — the text shown when a call is blocked.
* :func:`tool_call_verdict` / :func:`text_verdict` — the same checks for a runtime that is not
  Hermes: one tool call, or text it is about to send or read (a prompt, a tool's output);
  :func:`after_tool_call_verdict` — the after-call check (what an install added), likewise.
* :func:`reports_settled` — wait until the report follow-up of earlier calls is done
  (the Playground and tests; a hook never waits for it); :func:`collecting_shares` — the
  community shares started inside a block, so the Playground waits for its own only.

Internals: :mod:`.hooks` (entry points) → :mod:`.reporting` (filter, record,
share) → :mod:`.report_queue` (the node-facing follow-up, after the hook answered) · :mod:`.session_context` (bounded conversation memory) ·
:mod:`.background` (OSV, LLM review, auto-attach threads).

* :mod:`.startup` — what Hermes is handed: the five hooks as gates that wait for (or queue
  until) the guard, which loads on its own thread after ``register()`` returned.

Every name is loaded on first use (this package's import costs nothing).

Usage (the plugin's composition root)::

    from .guard import startup
    ctx.register_hook("pre_tool_call", startup.HERMES_HOOKS["pre_tool_call"])
"""

from __future__ import annotations

import importlib
from typing import Any

# WHY lazy (PEP 562): importing this package must cost nothing, so the plugin's register() can hand
# Hermes the hooks of :mod:`.startup` in microseconds (Linux round L7: Hermes dropped Blackbox when
# its import overran Hermes's 10 s load deadline). Each name below is loaded on first use.
_FROM = {
    "ToolCallVerdict": "hooks", "after_tool_call_verdict": "hooks", "blackbox_block_message": "hooks",
    "on_post_tool_call": "hooks", "on_pre_api_request": "hooks", "on_pre_tool_call": "hooks",
    "on_session_end": "hooks", "on_session_start": "hooks", "tool_call_verdict": "hooks",
    "text_verdict": "text_verdict", "collecting_shares": "reporting",
}


def reports_settled(timeout_s: float) -> bool:
    """Wait up to *timeout_s* for the report follow-up of every finding so far (private
    audit record, community share hand-off) to finish; True when nothing is left."""
    from . import report_queue
    return report_queue.REPORTS.settled(timeout_s)


def __getattr__(name: str) -> Any:
    """A public name (or a submodule, for tests) loaded on first use and kept."""
    if name in _FROM:
        value = getattr(importlib.import_module(f"{__name__}.{_FROM[name]}"), name)
    elif not name.startswith("__"):
        try:
            value = importlib.import_module(f"{__name__}.{name}")
        except ModuleNotFoundError as missing:
            if missing.name != f"{__name__}.{name}":
                raise
            raise AttributeError(f"module {__name__!r} has no attribute {name!r}") from None
    else:
        raise AttributeError(f"module {__name__!r} has no attribute {name!r}")
    globals()[name] = value
    return value


__all__ = [
    "ToolCallVerdict",
    "after_tool_call_verdict",
    "blackbox_block_message",
    "collecting_shares",
    "on_post_tool_call",
    "on_pre_api_request",
    "on_pre_tool_call",
    "on_session_end",
    "on_session_start",
    "reports_settled",
    "startup",
    "text_verdict",
    "tool_call_verdict",
]
