"""Blackbox actors: one Blackbox installation per role, each in its own process.

Blackbox keeps per-process state (the community membership, the ruleset's
memory generation, the pulse), the same way it runs in production: one
process per machine. So the trial never runs two roles in one interpreter.
Each role (reporter A, reporter B, the late reporter, the two curators) gets
its own ``BLACKBOX_HOME`` / ``HERMES_HOME`` under the run folder and talks to
its own DKG node; every call is a fresh ``python <trial> actor <action>``
subprocess whose JSON answer is the last line it prints
(:mod:`.actor_actions` is the other side).

The node's API token reaches the actor as ``BLACKBOX_DKG_API_TOKEN`` (outside
Hermes Blackbox reads it from the process environment), so Blackbox never
reads or writes the devnet node's own folder.
"""

from __future__ import annotations

import json
import os
import subprocess
import sys
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Mapping, Optional

#: The marker that starts the actor's JSON answer line.
ANSWER_PREFIX = "BLACKBOX-TRIAL-ANSWER "
_KEPT_ENV = ("PATH", "HOME", "LANG", "LC_ALL", "TMPDIR", "USER", "LOGNAME", "SHELL", "SSL_CERT_FILE")


class ActorError(RuntimeError):
    """The actor process failed to give an answer (crash, timeout, bad output)."""


@dataclass(frozen=True)
class NodeEndpoint:
    """Where an actor's DKG node answers: ``url``, its API ``token``, and a label for reports."""

    label: str
    url: str
    token: str


@dataclass
class Actor:
    """One Blackbox installation (a role) bound to one DKG node."""

    name: str
    run_dir: Path
    node: NodeEndpoint
    settings: dict[str, str] = field(default_factory=dict)
    entry: Path = Path(__file__).resolve().parent.parent / "blackbox-one-graph-trial.py"
    repo_root: Path = Path(__file__).resolve().parents[2]

    @property
    def home(self) -> Path:
        return self.run_dir / "actors" / self.name

    @property
    def blackbox_home(self) -> Path:
        return self.home / "blackbox"

    def environment(self) -> dict[str, str]:
        """The process environment of this actor: a clean base, its own homes,
        its node, and the trial's Blackbox settings (``BLACKBOX_*``)."""
        env = {name: os.environ[name] for name in _KEPT_ENV if name in os.environ}
        env.update({
            "HERMES_HOME": str(self.home / "hermes"),
            "BLACKBOX_HOME": str(self.blackbox_home),
            "BLACKBOX_DKG_HOME": str(self.home / "dkg-client"),
            "BLACKBOX_DKG_URL": self.node.url,
            "BLACKBOX_DKG_API_TOKEN": self.node.token,
            "PYTHONUNBUFFERED": "1",
            "PYTHONDONTWRITEBYTECODE": "1",
        })
        env.update(self.settings)
        return env

    def prepare(self) -> None:
        for folder in (self.home / "hermes", self.blackbox_home, self.home / "dkg-client"):
            folder.mkdir(parents=True, exist_ok=True)

    def call(self, action: str, params: Optional[Mapping[str, Any]] = None, *, timeout: float = 300.0,
             env: Optional[Mapping[str, str]] = None) -> dict[str, Any]:
        """Run *action* in a fresh actor process (*env* overrides this one call's
        settings); its JSON answer. Raises :class:`ActorError` when the process
        gives no answer."""
        self.prepare()
        command = [sys.executable, str(self.entry), "actor", action, "--params", json.dumps(dict(params or {}))]
        started = time.time()
        try:
            completed = subprocess.run(command, cwd=self.repo_root, env={**self.environment(), **dict(env or {})},
                                       stdin=subprocess.DEVNULL,
                                       capture_output=True, timeout=timeout, check=False,
                                       text=True, encoding="utf-8", errors="replace")
        except subprocess.TimeoutExpired as exc:
            raise ActorError(f"{self.name} {action}: no answer within {timeout:.0f} s "
                             f"(stderr tail: {_tail(exc.stderr)})") from exc
        self._log(action, params, completed, time.time() - started)
        answer = _answer(completed.stdout)
        if answer is None:
            raise ActorError(f"{self.name} {action}: exit {completed.returncode}, no answer "
                             f"(stderr tail: {_tail(completed.stderr)})")
        return answer

    def _log(self, action: str, params: Optional[Mapping[str, Any]], completed: subprocess.CompletedProcess,
             seconds: float) -> None:
        """Keep each call's full output beside the run (the report quotes only summaries)."""
        log = self.home / "calls.log"
        with log.open("a", encoding="utf-8") as handle:
            handle.write(f"=== {time.strftime('%H:%M:%S')} {action} {json.dumps(dict(params or {}))} "
                         f"exit={completed.returncode} {seconds:.1f}s\n")
            handle.write(completed.stdout or "")
            if completed.stderr:
                handle.write("--- stderr\n" + completed.stderr)


def _answer(stdout: str) -> Optional[dict[str, Any]]:
    for line in reversed((stdout or "").splitlines()):
        if line.startswith(ANSWER_PREFIX):
            try:
                value = json.loads(line[len(ANSWER_PREFIX):])
            except ValueError:
                return None
            return value if isinstance(value, dict) else None
    return None


def _tail(text: Any, lines: int = 12) -> str:
    if isinstance(text, bytes):
        text = text.decode("utf-8", errors="replace")
    return " | ".join(str(text or "").strip().splitlines()[-lines:])
