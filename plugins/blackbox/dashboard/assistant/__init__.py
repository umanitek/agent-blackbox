"""The dashboard assistant's helpers: reading what ``blackbox chat`` printed (POST /api/blackbox-chat).

Hermes prints the answer on stdout and its own notices (the session id, a truncated context
file) around it; the dashboard shows the answer alone and keeps the session id to resume.

Usage::

    answer = clean_chat_output(proc.stdout)
    session_id = parse_chat_session_id(proc.stderr) or parse_chat_session_id(proc.stdout)
"""

from __future__ import annotations

import re


def clean_chat_output(text: str) -> str:
    """The answer without Hermes' notices. Blank lines are kept (one at most in a row): they are
    the answer's paragraph breaks."""
    lines = [line.rstrip() for line in (text or "").splitlines()
             if not line.strip().startswith("session_id:") and "Context file AGENTS.md TRUNCATED" not in line]
    return re.sub(r"\n{3,}", "\n\n", "\n".join(lines)).strip()


def parse_chat_session_id(text: str) -> str | None:
    """The ``session_id: …`` Hermes printed, or None."""
    for line in (text or "").splitlines():
        stripped = line.strip()
        if stripped.startswith("session_id:"):
            return stripped.split(":", 1)[1].strip() or None
    return None
