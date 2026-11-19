"""Connect the protected agent to an AI model from the Blackbox dashboard (2026-11-19).

WHY: Blackbox checks each prompt as the agent sends it to its model. A fresh install leaves
Hermes with no model, so the agent cannot chat, nothing is ever checked and the first test
"does nothing" (a new user's report, 2026-11-19). This module is the dashboard's way to fix that
without a terminal, and it does it through Hermes' OWN commands — Hermes stores every credential
in the agent's own files, Blackbox never stores or logs one:

* a free Nous account: :class:`sign_in.NousSignIn` runs ``hermes auth add nous --no-browser``
  and hands the dashboard the sign-in link and code;
* an API key: :func:`save_api_key` runs ``hermes auth add <provider> --type api-key`` with the
  key on the child's stdin (never on a command line another process could read), then
  ``hermes config set model.provider <provider>``; Hermes then picks its own cost-safe default
  model for that provider.

Either way the dashboard re-asks Hermes (``kernel.host_command.agent_model``) and the panel goes
away once the answer is "ready".

Pattern: Facade over Hermes' command line. Usage::

    model_connect.state()                       # "ready" | "missing" | "unknown"
    model_connect.save_api_key("openrouter", key)
    model_connect.nous().start(); model_connect.nous().view()
"""

from __future__ import annotations

import subprocess
from typing import Any, Callable

from ..kernel.host_command import agent_model_state, hermes_argv
from ..kernel.redaction import redact_secret_values
from .sign_in import NousSignIn

#: Providers the panel offers for an API key: Hermes' provider id → the name people know.
KEY_PROVIDERS: dict[str, str] = {
    "openrouter": "OpenRouter",
    "anthropic": "Anthropic",
    "openai-api": "OpenAI",
    "gemini": "Google AI Studio (Gemini)",
}
_KEY_MIN, _KEY_MAX = 8, 512
_CHILD_TIMEOUT_SECONDS = 60

Run = Callable[..., "subprocess.CompletedProcess[str]"]

__all__ = ["KEY_PROVIDERS", "NousSignIn", "nous", "save_api_key", "state"]

_NOUS = NousSignIn()


def nous() -> NousSignIn:
    """The one Nous sign-in this process runs."""
    return _NOUS


def state() -> str:
    """Hermes' answer for this process's agent home: "ready", "missing" or "unknown"."""
    return agent_model_state()


def _key_problem(provider: str, key: str) -> str:
    if provider not in KEY_PROVIDERS:
        return "Choose one of the listed providers."
    if not _KEY_MIN <= len(key) <= _KEY_MAX or any(c.isspace() or not c.isprintable() for c in key):
        return "That does not look like an API key. Paste the whole key, without spaces."
    return ""


def save_api_key(provider: str, key: str, *, run: Run = subprocess.run) -> dict[str, Any]:
    """Store *key* for *provider* through Hermes and make it the agent's provider.

    Returns ``{"ok": True}`` or ``{"ok": False, "error": <plain reason>}``; the key never appears
    in either (any child output is redacted first).
    """
    key = (key or "").strip()
    problem = _key_problem(provider, key)
    if problem:
        return {"ok": False, "error": problem}
    steps = (
        (hermes_argv("auth", "add", provider, "--type", "api-key"), key + "\n"),
        (hermes_argv("config", "set", "model.provider", provider), None),
    )
    for argv, stdin_text in steps:
        try:
            done = run(argv, input=stdin_text, stdin=None if stdin_text else subprocess.DEVNULL,
                       capture_output=True, text=True, timeout=_CHILD_TIMEOUT_SECONDS, check=False)
        except (OSError, subprocess.SubprocessError, ValueError):
            return {"ok": False, "error": "Blackbox could not run Hermes to save the key."}
        if done.returncode != 0:
            lines = [line for line in (done.stdout or "").splitlines() + (done.stderr or "").splitlines()
                     if line.strip()]
            detail = redact_secret_values(lines[-1].strip()).replace(key, "[key]")[:240] if lines else ""
            return {"ok": False, "error": "Hermes did not save the key" + (f": {detail}" if detail else ".")}
    return {"ok": True}
