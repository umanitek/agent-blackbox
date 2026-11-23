"""Homebrew for sandboxed agents: Blackbox installs for them (founder decision, 2026-11-23, KI-593).

Homebrew runs each install inside its own sandbox, and macOS will not start a second sandbox
inside one (``sandbox_apply: Operation not permitted``), so ``brew install`` can not work inside
Blackbox's agent sandbox. Instead, Blackbox installs FOR the agent.

Pattern: **Command** + **Broker**. Inside the sandbox, ``brew`` (first on the sandboxed PATH only,
:func:`install_shim`) is a shim. ``brew install|upgrade|reinstall|uninstall …`` (``--cask`` too)
becomes a request, the argv alone, which the shim's client (``client.py``) sends to the broker.
Every other ``brew`` command (``list``, ``info``, ``search``, ``--version``, ``outdated``, ``deps``)
runs as it is, read-only, inside the sandbox.

The broker is the person's own Blackbox dashboard process: ``POST
/api/shields/file-shield/api/brew``, then ``GET …/brew-job`` for the output. WHY there and not
a new daemon: it already runs as the person (never root), outside the sandbox, on loopback only,
behind the session token and the approval gate. A second per-user service would be one more
process, port and credential to keep, for no extra isolation. For each request it:

1. reads the setting, ``agent_packages.installs`` (:data:`SETTING`): ``allow`` (the default:
   allow and notify), ``ask`` (the approval gate holds each request until the person approves it
   in the companion app's dialog or with their password; :func:`weakening`) or ``off``;
2. validates the argv (``request.parse``: names only, official taps only, a short list of flags);
3. checks each name against the threat graph as a package action (``brew install <name>``, the
   guard's one tool-call verdict through ``ShieldContext.tool_call_verdict``). A name any rule
   matches is refused, and so is every name when the verdict can not be asked (fail closed);
4. runs the FIXED argv ``<brew> <verb> [--cask|--formula] <names>`` as the person, with a clean
   environment (``jobs``), and streams the output back;
5. records the run in the audit log (``agent-sandbox``, ``package_install``) and alerts the person
   (File Shield's alerts, :func:`alerts`).

Loosening the setting (``off`` → ``ask`` → ``allow``) turns protection down and waits for the
person's approval (:func:`setting_weakening`, registered with ``approvals`` by the dashboard).

**Security cost:** Homebrew's own install scripts run outside the sandbox, with the person's rights,
the same as when the person runs ``brew`` (``jobs``).

Usage::

    install_shim(tools_folder)                  # the shim + client, at each sandbox sync
    API_WRITES["brew"](context, {"argv": ["install", "tree"]})   # {"job": "…"}
"""

from __future__ import annotations

import logging
import os
import sys
from pathlib import Path
from typing import Any, Mapping

from ..... import audit
from .....kernel import agent_hosts, settings as kernel_settings
from .....kernel.bounded_files import atomic_write, read_small_text
from .....kernel.config import load_blackbox_config, shield_entry
from ....shield_api import ShieldApiError, ShieldContext
from .. import platform
from . import jobs
from .request import BrewRequest, Refused, parse

__all__ = ["API_READS", "API_WRITES", "SETTING", "alerts", "install_shim", "installs", "setting_weakening", "weakening"]

#: The config section and key: ``plugins.entries.blackbox.agent_packages.installs``.
SECTION, SETTING = "agent_packages", "installs"
ALLOW, ASK, OFF = "allow", "ask", "off"
CHOICES = (OFF, ASK, ALLOW)   # most protective first
DEFAULT = ALLOW
CLIENT_NAME = "brew-client.py"
#: A finding of this source is a guess (a look-alike name), not a rule that lists the package.
HEURISTIC = "heuristic"
_CLIENT = Path(__file__).with_name("client.py")
logger = logging.getLogger(__name__)


def installs() -> str:
    """The person's choice: ``allow`` (default), ``ask`` or ``off``."""
    section = shield_entry().get(SECTION)
    value = section.get(SETTING) if isinstance(section, Mapping) else None
    return value if value in CHOICES else DEFAULT


def validate_section(raw: Any, errors: list[str]) -> dict[str, Any]:
    """The settings writer's validator for ``agent_packages`` (``kernel.settings.SECTION_VALIDATORS``)."""
    if not isinstance(raw, Mapping) or set(raw) - {SETTING} or raw.get(SETTING, DEFAULT) not in CHOICES:
        errors.append(f"{SECTION}.{SETTING} must be one of: {', '.join(CHOICES)}")
        return {}
    return {SETTING: raw[SETTING]} if SETTING in raw else {}


def setting_weakening(raw: Any) -> list[str]:
    """Why a change of ``agent_packages`` turns protection down (``approvals.SECTION_JUDGES``)."""
    wanted = raw.get(SETTING) if isinstance(raw, Mapping) else None
    if wanted not in CHOICES or CHOICES.index(wanted) <= CHOICES.index(installs()):
        return []
    return [f"Let AI agents install packages with Homebrew outside the sandbox ({'ask you each time' if wanted == ASK else 'without asking'})"]


kernel_settings.SECTION_VALIDATORS[SECTION] = validate_section


def _request(body: Mapping[str, Any]) -> BrewRequest:
    # The brew words, and the asking process's pid (who asked, never what runs: KI-605).
    if set(body) - {"argv", "pid"}:
        raise Refused("a request carries the brew words only")
    return parse(body.get("argv") or [])


def weakening(body: Mapping[str, Any]) -> list[str]:
    """In "ask me each time", every valid request waits for the person (the approval gate)."""
    if installs() != ASK:
        return []
    try:
        return [f"Let an AI agent run `{_request(body).shown()}` outside its sandbox (Homebrew)"]
    except Refused:
        return []   # refused by the endpoint itself: nothing to confirm


def _listed(context: ShieldContext, request: BrewRequest) -> list[str]:
    """The names a threat rule matches as a package action; every name when it can not be asked."""
    if request.verb == "uninstall":
        return []
    judge = context.tool_call_verdict
    if judge is None:
        return list(request.names) or ["(the threat graph can not be asked)"]
    listed = []
    for name in request.names:
        try:
            verdict = judge("terminal", {"command": f"brew install {request.kind + ' ' if request.kind else ''}{name}"})
        except Exception:   # health: allow BLE001 -- the verdict could not be asked: fail closed
            listed.append(name)
            continue
        rules = [found for found in verdict.get("findings") or [] if found.get("source") != HEURISTIC]
        if verdict.get("decision") == "block" or rules:
            listed.append(name)
    return listed


def _brew(context: ShieldContext, body: Mapping[str, Any]) -> dict[str, Any]:
    if installs() == OFF:
        raise ShieldApiError(403, "Package installs by AI agents are off in Blackbox's settings; run brew in your own terminal.")
    try:
        request = _request(body)
    except Refused as why:
        raise ShieldApiError(400, str(why)) from None
    listed = _listed(context, request)
    if listed:
        raise ShieldApiError(403, f"{', '.join(listed)}: a threat rule lists this package, so Blackbox will not install it")
    brew = jobs.brew_path()
    if not brew:
        raise ShieldApiError(404, "Homebrew is not installed on this Mac.")
    job = jobs.start(request, brew, done=_record, owner=_asker(context, body))
    return {"job": job.id, "command": request.shown()}


def _asker(context: ShieldContext, body: Mapping[str, Any]) -> Any:
    """The agent instance whose process asked (the client sends its parent's pid; KI-605: the notice
    said "for an AI agent", naming none). None when not known — never guessed."""
    pid = body.get("pid")
    if context.owner_of_pid is None or not isinstance(pid, int) or isinstance(pid, bool) or pid <= 1:
        return None
    try:
        return context.owner_of_pid(pid)
    except Exception:   # health: allow BLE001 -- the install goes ahead; the notice then names no agent
        logger.debug("blackbox: the asking agent of a brew run could not be found", exc_info=True)
        return None


def _who(job: jobs.Job) -> str:
    """``for Claude Code in s4-br1`` (or ``for an AI agent`` when the asker is not known)."""
    owner = job.owner
    if owner is None:
        return "for an AI agent"
    name = agent_hosts.BY_ID[owner.agent].name if owner.agent in agent_hosts.BY_ID else owner.agent or "an AI agent"
    return f"for {name}" + (f" in {owner.folder}" if owner.folder else "")


def _job(_context: ShieldContext, query: Mapping[str, str]) -> dict[str, Any]:
    job = jobs.get(str(query.get("job") or ""))
    if job is None:
        raise ShieldApiError(404, "no such install")
    try:
        start = max(0, int(query.get("from") or 0))
    except ValueError:
        start = 0
    lines, next_line, done, code = job.since(start)
    return {"lines": lines, "next": next_line, "done": done, "exit": code}


def _record(job: jobs.Job) -> None:
    """The audit row of a finished run (local only; the names, the verb and the exit code)."""
    _, _, _, code = job.since(0)
    try:
        owner = job.owner
        audit.record_for(audit.SANDBOX_RECORDER, event="package_install", workspace=getattr(owner, "folder", "") or "",
                         detail={"command": job.request.shown(), "exit": code, "job": job.id,
                                 **({"agent": owner.agent, "session_id": owner.instance} if owner is not None else {})})
    except Exception:   # health: allow BLE001 -- the install happened; a failed record is logged
        logger.warning("blackbox: a brokered brew run was not recorded", exc_info=True)


def alerts() -> list[dict[str, Any]]:
    """One alert per brokered run that ended: ``{key, ts, ok, text}`` (File Shield words them)."""
    rows = []
    for job in jobs.recent():
        _, _, done, code = job.since(0)
        if done:
            verb = {"install": "installed", "upgrade": "upgraded", "reinstall": "reinstalled", "uninstall": "uninstalled"}[job.request.verb]
            what = ", ".join(job.request.names) or "every package"
            rows.append({"key": f"package-install:{job.id}", "ts": job.started, "ok": code == 0,
                         "text": (f"Blackbox {verb} {what} with Homebrew {_who(job)}." if code == 0 else
                                  f"Homebrew could not finish `{job.request.shown()}` {_who(job)}."),
                         **({"agent": job.owner.agent, "instance": job.owner.instance} if job.owner is not None else {})})
    return rows


API_WRITES = {"brew": _brew}
API_READS = {"brew-job": _job}


def install_shim(tools: Path, dashboard_url: str = "") -> None:
    """The ``brew`` shim and its client in the sandbox's tools folder (first on the sandboxed PATH
    only), talking to this Blackbox's dashboard (*dashboard_url*, by default its configured port);
    nothing when this OS has no shim (``platform.brew_shim`` answers "")."""
    url = dashboard_url or f"http://127.0.0.1:{load_blackbox_config().dashboard_port}"
    shim = platform.brew_shim(str(tools), sys.executable, url)
    if not shim or not tools.is_dir():
        return
    client = read_small_text(str(_CLIENT), 256 * 1024) or ""
    for path, text in ((tools / CLIENT_NAME, client), (tools / "brew", shim)):
        if read_small_text(str(path), 256 * 1024) != text or not os.access(path, os.X_OK):
            atomic_write(path, text, mode=0o755)
