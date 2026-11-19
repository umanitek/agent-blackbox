"""The dashboard assistant's helpers: reading what ``blackbox chat`` printed (POST /api/blackbox-chat).

Hermes prints the answer on stdout and its own notices (the session id, a truncated context
file, "↻ Resumed session …") around it; the dashboard shows the answer alone and keeps the
session id to resume. When the model gave no answer — or Hermes answered with its own "out of
credits" text instead (agent/conversation_loop.py) — :func:`answer_payload` says so as a
``model_problem`` so the page points at the AI model card rather than showing a notice as if it
were the assistant's reply (2026-11-19: a free Nous account on a paid model showed only
"↻ Resumed session …").

Usage::

    answer = clean_chat_output(proc.stdout)
    session_id = parse_chat_session_id(proc.stderr) or parse_chat_session_id(proc.stdout)
    return JSONResponse(*answer_payload(answer, clean_chat_output(proc.stderr), session_id))
"""

from __future__ import annotations

import re
from typing import Any, Optional

#: How Hermes begins the text it returns instead of an answer when the provider refused for
#: credits (``_billing_terminal_label`` in agent/conversation_loop.py) — matched exactly (LES-015).
MODEL_PROBLEM_PREFIXES = ("Billing or credits exhausted:", "Provider reported usage/credit exhaustion")
#: Hermes' notice that a chat continued an earlier session — never an answer.
_RESUME_NOTICE = "↻ Resumed session"
NO_ANSWER = "The assistant got no answer from its AI model. Check \"Your agent's AI model\" at the top of the dashboard."


def clean_chat_output(text: str) -> str:
    """The answer without Hermes' notices. Blank lines are kept (one at most in a row): they are
    the answer's paragraph breaks."""
    lines = [line.rstrip() for line in (text or "").splitlines()
             if not line.strip().startswith(("session_id:", _RESUME_NOTICE))
             and "Context file AGENTS.md TRUNCATED" not in line]
    return re.sub(r"\n{3,}", "\n\n", "\n".join(lines)).strip()


def parse_chat_session_id(text: str) -> str | None:
    """The ``session_id: …`` Hermes printed, or None."""
    for line in (text or "").splitlines():
        stripped = line.strip()
        if stripped.startswith("session_id:"):
            return stripped.split(":", 1)[1].strip() or None
    return None


def answer_payload(answer: str, err: str, session_id: Optional[str]) -> tuple[dict[str, Any], int]:
    """(body, HTTP status) for one finished assistant turn (exit status 0).

    A real answer — on stdout, or on stderr when stdout is empty — is 200. No answer, or Hermes'
    own out-of-credits text, is 409 with
    ``model_problem: true`` and the reason in plain words, so the page offers the AI model card.
    """
    # Hermes prints a long reply on stderr with exit status 0 (seen 2026-11-19: stdout empty, the
    # whole answer on stderr), so a finished turn's text is whichever stream carries it.
    text = answer or err
    if text and not text.startswith(MODEL_PROBLEM_PREFIXES):
        return {"ok": True, "answer": text, "session_id": session_id}, 200
    return {"ok": False, "error": text or NO_ANSWER, "model_problem": True, "session_id": session_id}, 409
