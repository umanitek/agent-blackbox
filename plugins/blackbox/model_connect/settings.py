"""The agent's model choice, read and changed through Hermes' own commands (2026-11-19).

What the dashboard's "Your agent's AI model" card shows and changes: the provider, the model,
the signed-in account and whether Hermes has marked it exhausted (``hermes auth list``), the
model Hermes itself recommends for the account (a free account gets a free model), a model the
person picks, and signing out. Every change goes through a ``hermes`` command in a child of this
same Hermes; Blackbox only reads ``config.yaml`` to show the choice.

WHY the recommendation matters: after a Nous sign-in with no model chosen, Hermes' fallback
picked a paid model (``z-ai/glm-5.2``) and a free account was refused for credits (2026-11-19).
``recommended_nous_default_model`` — what Hermes' own sign-in flows use — honours the account's
tier.

Usage::

    run = HermesRun()
    connection(run)            # {"provider", "model", "account", "status"}
    choose_provider("nous", run); set_model("upstage/solar-mini4:free", run); disconnect(run)
"""

from __future__ import annotations

import re
import subprocess
import sys
from pathlib import Path
from typing import Any, Callable, Optional

from ..kernel import yaml_files
from ..kernel.host_command import hermes_argv
from ..kernel.redaction import redact_secret_values

#: A model id as providers write them (``vendor/name:tag``); anything else is refused before a
#: command runs.
MODEL_ID = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:/@+-]{0,159}$")
_PROVIDER_ID = re.compile(r"^[a-z0-9][a-z0-9.-]{0,63}$")
#: One credential row of ``hermes auth list``: "#1  <label>  <type> … [exhausted …] [←]".
_ACCOUNT_ROW = re.compile(r"^\s*#\d+\s+(?P<label>\S+)\s+(?P<rest>.*)$")
_TIMEOUT_SECONDS = 90
_RECOMMEND = (
    "import sys\n"
    "from hermes_cli import models\n"
    "provider = sys.argv[1]\n"
    "pick = models.recommended_nous_default_model().get('model', '') if provider == 'nous' "
    "else models.get_default_model_for_provider(provider)\n"
    "print(pick or '')\n"
)

Run = Callable[..., "subprocess.CompletedProcess[str]"]


class HermesRun:
    """Runs ``hermes …`` (or this Hermes' Python) as a child; *run* is the test seam."""

    def __init__(self, run: Run = subprocess.run) -> None:
        self._run = run

    def __call__(self, *args: str, stdin_text: Optional[str] = None, python: bool = False) -> tuple[bool, str]:
        """(succeeded, stdout) — the last output line, redacted, stands in for stdout on failure."""
        argv = [sys.executable, "-c", *args] if python else hermes_argv(*args)
        try:
            done = self._run(argv, input=stdin_text, stdin=None if stdin_text else subprocess.DEVNULL,
                             capture_output=True, text=True, timeout=_TIMEOUT_SECONDS, check=False)
        except (OSError, subprocess.SubprocessError, ValueError):
            return False, ""
        if done.returncode == 0:
            return True, done.stdout or ""
        lines = [line.strip() for line in (done.stdout or "").splitlines() + (done.stderr or "").splitlines()
                 if line.strip()]
        return False, redact_secret_values(lines[-1])[:240] if lines else ""


def _hermes_home() -> Path:
    from hermes_cli.config import get_hermes_home
    return Path(get_hermes_home())


def _model_config() -> dict[str, Any]:
    model = yaml_files.load_yaml(_hermes_home() / "config.yaml").get("model")
    if isinstance(model, str):
        return {"default": model}
    return model if isinstance(model, dict) else {}


def connection(run: HermesRun) -> dict[str, Any]:
    """The agent's provider, model, account label and status ("working" | "exhausted" | "unknown")."""
    model = _model_config()
    provider = str(model.get("provider") or "")
    found: dict[str, Any] = {"provider": provider, "model": str(model.get("default") or ""),
                             "account": "", "status": "unknown"}
    if not provider or not _PROVIDER_ID.match(provider):
        return found
    ok, out = run("auth", "list", provider)
    rows = [m for m in (_ACCOUNT_ROW.match(line) for line in out.splitlines()) if m] if ok else []
    active = next((m for m in rows if m.group("rest").rstrip().endswith("←")), rows[0] if rows else None)
    if active is not None:
        found["account"] = active.group("label")
        found["status"] = "exhausted" if "exhausted" in active.group("rest") else "working"
    return found


def set_model(model_id: str, run: HermesRun) -> dict[str, Any]:
    """Make *model_id* the agent's model and clear Hermes' "exhausted" marks for the provider."""
    model_id = (model_id or "").strip()
    if not MODEL_ID.match(model_id):
        return {"ok": False, "error": "That is not a model name (for example vendor/model:free)."}
    ok, detail = run("config", "set", "model.default", model_id)
    if not ok:
        return {"ok": False, "error": "Hermes did not change the model" + (f": {detail}" if detail else ".")}
    provider = str(_model_config().get("provider") or "")
    if provider and _PROVIDER_ID.match(provider):
        run("auth", "reset", provider)   # the old model's refusal must not keep the account "exhausted"
    return {"ok": True}


def recommended_model(provider: str, run: HermesRun) -> str:
    """The model Hermes itself picks for *provider* (for Nous: honouring the account's tier), or ""."""
    if not _PROVIDER_ID.match(provider or ""):
        return ""
    ok, out = run(_RECOMMEND, provider, python=True)
    pick = out.strip().splitlines()[-1].strip() if ok and out.strip() else ""
    return pick if MODEL_ID.match(pick) else ""


def choose_provider(provider: str, run: HermesRun) -> bool:
    """Make *provider* the agent's provider, on the model Hermes recommends for it."""
    if not run("config", "set", "model.provider", provider)[0]:
        return False
    pick = recommended_model(provider, run)
    if pick:
        set_model(pick, run)
    return True


def use_recommended_model(run: HermesRun) -> dict[str, Any]:
    """Switch the agent to the model Hermes recommends for its provider and account."""
    provider = str(_model_config().get("provider") or "")
    pick = recommended_model(provider, run)
    if not pick:
        return {"ok": False, "error": "Hermes has no recommended model for this provider right now."}
    result = set_model(pick, run)
    return {**result, "model": pick} if result.get("ok") else result


def disconnect(run: HermesRun) -> dict[str, Any]:
    """Sign the agent out of its provider and clear the choice; the connect panel comes back."""
    provider = str(_model_config().get("provider") or "")
    if provider and _PROVIDER_ID.match(provider):
        run("auth", "logout", provider)
        ok, out = run("auth", "list", provider)
        remaining = sum(1 for line in out.splitlines() if _ACCOUNT_ROW.match(line)) if ok else 0
        for _ in range(remaining):   # keys added with `auth add` stay pooled after a logout
            run("auth", "remove", provider, "1")
    for key in ("model.provider", "model.default"):
        if not run("config", "set", key, "")[0]:
            return {"ok": False, "error": "Hermes did not clear the agent's model choice."}
    return {"ok": True}
