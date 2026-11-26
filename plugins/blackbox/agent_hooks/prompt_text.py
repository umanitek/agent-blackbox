"""Prompt text in the agent history — OFF unless the person turned it on.

By default Blackbox keeps no prompt: a prompt is checked on this machine and only its length is
recorded. A person (or their organisation) may turn ``agent_activity.record_prompt_text`` on to
see, in an instance's timeline, what each agent was asked. Then — and only then:

* each prompt's text is kept with the timeline entry, after the kernel's redaction (secrets,
  seed phrases and private keys become markers) and cut to :data:`MAX_CHARS`;
* it stays on THIS machine: it is never part of a finding, an audit row or a community report,
  and the dashboard serves it only to a request that carries the session token;
* it lives under the history's retention (``agent_activity.history_days``) and is removed when
  that passes (:func:`expire`), or at once on request (:func:`delete_stored`).

Turning it ON is a privacy choice and waits for the person's confirmation
(``approvals.weakening``); turning it OFF applies at once and stops recording — what was stored
stays until :func:`delete_stored` or its retention, and is no longer served. Every change of the
switch is noted in a small consent record (:func:`status` shows the latest).

Usage::

    from . import prompt_text
    prompt_text.recording()            # the switch, read from config.yaml
    prompt_text.keep(text)             # what to store for a prompt now: redacted + bounded, or ""
    prompt_text.status()               # Status(recording, days, stored, since, statement)
    prompt_text.delete_stored()        # how many entries lost their text
"""

from __future__ import annotations

import threading
import time
from dataclasses import dataclass

from ..kernel import constants
from ..kernel.bounded_files import read_json_object, write_json_object
from ..kernel.config import agent_activity
from ..kernel.redaction import redact_secret_values
from .instances import store

__all__ = ["MAX_CHARS", "Status", "clean", "delete_stored", "expire", "keep", "recording", "status"]

#: The most of one prompt that is kept.
MAX_CHARS = 4000
#: How often stored text is checked against its retention.
EXPIRE_EVERY_SECONDS = 3600.0
MAX_CONSENT_ROWS = 50
_lock = threading.Lock()
_last_expiry = 0.0


@dataclass(frozen=True)
class Status:
    """*recording*: the switch. *days*: how long history (and so stored text) is kept. *stored*:
    timeline entries that hold text now. *since*: when the switch last changed (0 = never).
    *statement*: the state in one plain sentence, for the profile and Docs pages."""

    recording: bool
    days: int
    stored: int
    since: float
    statement: str


def consent_path():
    return constants.blackbox_home() / "agent-hooks" / "prompt-text-consent.json"


def recording() -> bool:
    return agent_activity().record_prompt_text


def clean(text: str) -> str:
    """*text* as it may be kept: redacted first, then cut (a secret cut in half would not match)."""
    return redact_secret_values(text or "")[:MAX_CHARS]


def keep(text: str) -> str:
    """What to store for a prompt's *text* right now: its cleaned text while recording is on
    (the consent record is brought in step first), "" otherwise."""
    cfg = agent_activity()
    if not cfg.record_prompt_text or not text:
        return ""
    _note_switch(True, cfg.history_days)
    return clean(text)


def _note_switch(on: bool, days: int) -> float:
    """Keep the consent record in step with the switch; returns when it last changed."""
    with _lock:
        data = read_json_object(consent_path()) or {}
        rows = data.get("changes") if isinstance(data.get("changes"), list) else []
        last = rows[-1] if rows and isinstance(rows[-1], dict) else {}
        if not rows and not on:
            return 0.0   # never turned on: nothing to record
        if last.get("recording") is not on:
            rows.append({"recording": on, "at": time.time(), "history_days": days,
                         "what": "prompt text kept on this machine only, secrets removed" if on else "recording stopped"})
            write_json_object(consent_path(), {"changes": rows[-MAX_CONSENT_ROWS:]}, what="the prompt-text consent record")
            return float(rows[-1]["at"])
        return float(last.get("at") or 0.0)


def status() -> Status:
    cfg = agent_activity()
    on, days = cfg.record_prompt_text, cfg.history_days
    since = _note_switch(on, days)
    stored = store.count_text()
    if on:
        statement = f"Prompt text: recorded on this Mac, kept {days} days."
    elif stored:
        statement = f"Prompt text: not recorded. {stored} earlier entr{'y' if stored == 1 else 'ies'} still hold{'s' if stored == 1 else ''} text until deleted."
    else:
        statement = "Prompt text: not recorded."
    return Status(on, days, stored, since, statement)


def delete_stored() -> int:
    """Remove every stored prompt text now; returns how many entries held one."""
    return store.strip_text()


def expire(now: float | None = None) -> int:
    """Remove stored text older than the history's retention, at most every
    :data:`EXPIRE_EVERY_SECONDS` and only once recording was ever on. Returns how many went."""
    global _last_expiry
    now = time.time() if now is None else now
    with _lock:
        if now - _last_expiry < EXPIRE_EVERY_SECONDS or not consent_path().exists():
            return 0
        _last_expiry = now
    return store.strip_text(older_than=now - agent_activity().history_days * 86400)
