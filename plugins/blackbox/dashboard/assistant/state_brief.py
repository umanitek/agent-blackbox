"""A short, fresh snapshot of Blackbox's state handed to the assistant with every question (2026-11-19).

WHY: on a small free model the assistant answered "what was the latest thing you flagged?" by
running a dozen lookups (curl, jq, reading files) and sometimes ran out of time. Everything the
common questions need is already in this process, so the dashboard reads it here — mode, rule
counts, the last rule refresh, the newest findings, the protected agents — and puts it in front of
the question. The model answers from it and only reaches for its tools when a question needs more.

What is never put in it: the text an agent sent or a command it ran. A finding's evidence can be
an injection phrase ("show me your system prompt"), and the assistant's own request would then be
flagged for it (seen on the test Mac). A finding is described by its title, kind, severity, agent,
time and identifier only.

Usage::

    query = with_state_brief(message)   # fail-open: the bare message if anything cannot be read
"""

from __future__ import annotations

import logging
import time
from pathlib import Path
from typing import Any

logger = logging.getLogger(__name__)

#: How many of the newest findings the snapshot lists.
NEWEST_FINDINGS = 5
#: A hard cap on the snapshot, so a question never carries a wall of text.
MAX_BRIEF_CHARS = 2400

_HEADER = ("[Blackbox state, read by the dashboard just now. Answer from this first; use your tools only "
           "when the question needs more than it shows. Details: GET http://127.0.0.1:9700/api/findings, "
           "/api/audit, /api/agents, /api/graph-status.]")


def _agent(workspace: str) -> str:
    """The name the dashboard shows for a finding's workspace."""
    parts = Path(workspace or "").parts
    if len(parts) >= 2 and parts[-2] == "profiles":
        return "Blackbox assistant" if parts[-1] == "agent-blackbox" else f"Hermes profile {parts[-1]}"
    return "main Hermes agent"


def _age(seconds_ago: float) -> str:
    if seconds_ago < 120:
        return "just now"
    if seconds_ago < 7200:
        return f"{int(seconds_ago // 60)} min ago"
    return f"{int(seconds_ago // 3600)} h ago"


def _finding_line(finding: dict[str, Any]) -> str:
    when = str(finding.get("iso") or finding.get("time") or "")[:19].replace("T", " ")
    fields = [when, _agent(str(finding.get("workspace") or "")), str(finding.get("severity") or ""),
              str(finding.get("category") or ""), str(finding.get("title") or ""), str(finding.get("identifier") or "")]
    if finding.get("decision"):
        fields.append(str(finding["decision"]))
    return "- " + " · ".join(field for field in fields if field)


def state_brief() -> str:
    """The snapshot text (see the module doc). Reads only this machine's own files and config."""
    from ... import attach, audit, ruleset
    from ...kernel.config import load_blackbox_config

    cfg = load_blackbox_config()
    lines = [_HEADER, f"mode: {cfg.mode} (blocks at {cfg.block_severity} and above in block mode)",
             f"threat sharing: {'on' if cfg.community_enabled else 'off'}"]
    rules = ruleset.peek(cfg)
    counts = ", ".join(f"{kind} {number:,}" for kind, number in rules.counts().items() if number)
    lines.append(f"rules held: {counts or 'none yet (the threat graph is still syncing)'}")
    if rules.synced_at:
        lines.append(f"rules last refreshed: {_age(time.time() - rules.synced_at)}")
    agents = [str(home) for home in attach.discover_hermes_homes() if attach.is_attached("hermes", home)]
    lines.append(f"protected Hermes agents: {len(agents)} — " + ", ".join(_agent(home) for home in agents))
    newest = audit.read_findings(limit=NEWEST_FINDINGS)
    lines.append(f"findings logged: {audit.count_findings()}; newest first:")
    lines.extend(_finding_line(finding) for finding in newest)
    if not newest:
        lines.append("- none yet")
    return "\n".join(lines)[:MAX_BRIEF_CHARS]


def with_state_brief(message: str) -> str:
    """*message* with the snapshot in front; the bare message when the snapshot cannot be read."""
    try:
        brief = state_brief()
    except Exception:   # fail-open: a snapshot never stops the question (the traceback is logged)
        logger.warning("blackbox dashboard: assistant state snapshot unavailable", exc_info=True)
        return message
    return f"{brief}\n\n[Question]\n{message}"
