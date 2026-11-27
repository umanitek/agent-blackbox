"""One Blackbox assistant turn (``blackbox chat`` in the managed profile) — the one runner.

Moved out of ``server.py``'s ``POST /api/blackbox-chat`` unchanged, so every caller that asks
Blackbox's assistant something shares it: the chat route, and a shield's API through
:class:`~...shields.ShieldContext` (Network Shield's AI Analyst).

Usage::

    payload, status = ask("Is anything on this Mac suspicious?", session_id="")
    payload["answer"]          # or payload["error"], payload["needs_model"]
"""

from __future__ import annotations

import logging
import subprocess
from typing import Any

from ... import attach
from ...kernel.host_command import NO_MODEL_EXIT, hermes_argv
from ..assistant import answer_payload, clean_chat_output, parse_chat_session_id, with_state_brief

logger = logging.getLogger(__name__)

#: The longest question the assistant takes.
MAX_MESSAGE = 4000
#: A small free model answering with tool lookups is slow.
TIMEOUT_SECONDS = 240


def ask(message: str, session_id: str = "") -> tuple[dict[str, Any], int]:
    """Runs one turn; answers ``(payload, http status)`` exactly as the chat route serves them."""
    message = str(message or "").strip()
    if not message:
        return {"ok": False, "error": "Message is required."}, 400
    if len(message) > MAX_MESSAGE:
        return {"ok": False, "error": "Message is too long."}, 400
    session_id = str(session_id or "").strip()
    # WHY on stdin (--query-file=-, read by Hermes' own chat): a command line is readable by every
    # local process (`ps`), and the question and the state brief are the person's (review 2026-11-26).
    # WHY "--opt=value": an id starting with "-" would otherwise be read as an option.
    argv = hermes_argv("blackbox", "chat", "--query-file=-", "--quiet", "--pass-session-id")
    if session_id and len(session_id) <= 128 and all(c.isalnum() or c in "_.:-" for c in session_id):
        argv.append(f"--resume={session_id}")
    try:
        proc = subprocess.run(
            argv,
            cwd=str(attach.repo_root()),
            text=True,
            input=with_state_brief(message), capture_output=True,
            timeout=TIMEOUT_SECONDS, check=False,
        )
    except subprocess.TimeoutExpired:
        return {"ok": False, "error": "Blackbox took too long to answer."}, 504
    except (OSError, ValueError) as exc:   # the browser gets a plain message, never the system error
        logger.warning("blackbox dashboard: could not start the assistant: %s", exc)
        return {"ok": False, "error": "Blackbox could not start the assistant."}, 500
    next_session_id = parse_chat_session_id(proc.stderr) or parse_chat_session_id(proc.stdout) or session_id
    answer = clean_chat_output(proc.stdout)
    err = clean_chat_output(proc.stderr)
    if proc.returncode != 0:   # NO_MODEL_EXIT: no AI model yet — 409 + needs_model, the page shows the fix
        no_model = proc.returncode == NO_MODEL_EXIT
        return ({"ok": False, "error": err or answer or "Blackbox chat failed.", "needs_model": no_model,
                 "session_id": next_session_id}, 409 if no_model else 500)
    return answer_payload(answer, err, next_session_id)   # 409 model_problem: no real answer
