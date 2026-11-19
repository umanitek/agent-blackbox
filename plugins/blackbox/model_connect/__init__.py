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
  ``hermes config set model.provider <provider>`` on the model Hermes recommends for it.

``settings.py`` reads and changes the choice afterwards — the "Your agent's AI model" card:
the account, the model, Hermes' "exhausted" mark, the recommended (for a free Nous account: free)
model, another model, signing out.

Either way the dashboard re-asks Hermes (``kernel.host_command.agent_model``) and the panel goes
away once the answer is "ready".

Pattern: Facade over Hermes' command line. Usage::

    model_connect.state()                       # "ready" | "missing" | "unknown"
    model_connect.save_api_key("openrouter", key)
    model_connect.nous().start(); model_connect.nous().view()
    model_connect.connection(model_connect.HermesRun())   # the card
"""

from __future__ import annotations

from typing import Any

from ..kernel.host_command import agent_model_state
from .settings import HermesRun, choose_provider, connection, disconnect, set_model, use_recommended_model
from .sign_in import NousSignIn

#: Providers the panel offers for an API key: Hermes' provider id → the name people know.
KEY_PROVIDERS: dict[str, str] = {
    "openrouter": "OpenRouter",
    "anthropic": "Anthropic",
    "openai-api": "OpenAI",
    "gemini": "Google AI Studio (Gemini)",
}
_KEY_MIN, _KEY_MAX = 8, 512

__all__ = ["KEY_PROVIDERS", "HermesRun", "NousSignIn", "connection", "disconnect", "nous", "save_api_key",
           "set_model", "state", "use_recommended_model"]

_NOUS = NousSignIn(lambda: choose_provider("nous", HermesRun()))


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


def save_api_key(provider: str, key: str, run: HermesRun | None = None) -> dict[str, Any]:
    """Store *key* for *provider* through Hermes and make it the agent's provider (on the model
    Hermes recommends for it). Returns ``{"ok": True}`` or ``{"ok": False, "error": <plain reason>}``;
    the key never appears in either (any child output is redacted first)."""
    run = run or HermesRun()
    key = (key or "").strip()
    problem = _key_problem(provider, key)
    if problem:
        return {"ok": False, "error": problem}
    ok, detail = run("auth", "add", provider, "--type", "api-key", stdin_text=key + "\n")
    if not ok:
        detail = detail.replace(key, "[key]")
        return {"ok": False, "error": "Hermes did not save the key" + (f": {detail}" if detail else ".")}
    if not choose_provider(provider, run):
        return {"ok": False, "error": "The key is saved, but Hermes did not make it the agent's provider."}
    return {"ok": True}
