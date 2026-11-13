"""Guard — the CHECK hot path: intercept every action the agent is about to take.

Hermes calls these hooks around every tool call and model request:

* :func:`on_pre_tool_call` — detect, and in block mode refuse, BEFORE execution.
* :func:`on_post_tool_call` — log local activity, start background discovery.
* :func:`on_pre_api_request` — scan the untrusted part of a model request.
* :func:`on_session_start` / :func:`on_session_end` — per-session context.
* :func:`blackbox_block_message` — the text shown when a call is blocked.
* :func:`reports_settled` — wait until the report follow-up of earlier calls is done
  (the Playground and tests; a hook never waits for it); :func:`collecting_shares` — the
  community shares started inside a block, so the Playground waits for its own only.

Internals: :mod:`.hooks` (entry points) → :mod:`.reporting` (filter, record,
share) → :mod:`.report_queue` (the node-facing follow-up, after the hook answered) · :mod:`.session_context` (bounded conversation memory) ·
:mod:`.background` (OSV, LLM review, auto-attach threads).

Usage (the plugin's composition root)::

    from . import guard
    ctx.register_hook("pre_tool_call", guard.on_pre_tool_call)
"""

from __future__ import annotations

from .hooks import (
    blackbox_block_message,
    on_post_tool_call,
    on_pre_api_request,
    on_pre_tool_call,
    on_session_end,
    on_session_start,
)
from . import report_queue
from .reporting import collecting_shares


def reports_settled(timeout_s: float) -> bool:
    """Wait up to *timeout_s* for the report follow-up of every finding so far (private
    audit record, community share hand-off) to finish; True when nothing is left."""
    return report_queue.REPORTS.settled(timeout_s)


__all__ = [
    "blackbox_block_message",
    "collecting_shares",
    "on_post_tool_call",
    "on_pre_api_request",
    "on_pre_tool_call",
    "on_session_end",
    "on_session_start",
    "reports_settled",
]
