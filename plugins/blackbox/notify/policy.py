"""What the person wants to be told: the notification policy (``notifications.*`` in config.yaml).

* ``security`` (ON): refusals, flags, an agent asking for or running as root, an agent running
  without Blackbox, hooks switched off, File Shield and Network Shield alerts.
* ``lifecycle`` (off): an agent or sub-agent started, ended, or waits for you.
* ``digest`` (off): what a session did, in one line, when it ends — and every ``digest_minutes``
  while it runs when that is above 0.
* ``watched`` (ON): a new file arrived in a folder File Shield watches. On by default because
  a companion app told it before the core did — an update keeps what the person saw. Turning it
  off is not a weakening change: a KNOWN-BAD file in a watched folder is a ``security`` notice.
* ``muted_agents``: agent ids never shown. ``quiet_hours``: ``"22:00-07:00"`` (local time) — only
  CRITICAL security notices are shown then. ``details``: add the finding's own (redacted) title to
  a notification; off = lock-screen-safe text only. ``per_minute``: the most shown in a minute
  from each source (an AI agent's security notices, the shields, lifecycle, digest — see
  ``deliver.lane``), so one noisy source never holds back another; the rest are counted into one
  summary.

Turning ``enabled`` or ``security`` OFF, or muting an agent, means Blackbox tells the person less
about a threat: :func:`weakening` names those changes and the approval gate holds them.

Usage::

    policy = read()                       # Policy, from the saved config
    held(policy, notice, now)             # "" (show it) | "off" | "muted" | "quiet-hours"
"""

from __future__ import annotations

import re
import time
from dataclasses import asdict, dataclass
from typing import Any, Mapping

from ..kernel import config
from ..kernel.agent_hosts import BY_ID
from .model import Notice

SECTION = "notifications"
MAX_PER_MINUTE = 60
_HOURS = re.compile(r"^([01]\d|2[0-3]):([0-5]\d)-([01]\d|2[0-3]):([0-5]\d)$")


@dataclass(frozen=True)
class Policy:
    enabled: bool = True
    security: bool = True
    lifecycle: bool = False
    digest: bool = False
    watched: bool = True
    digest_minutes: int = 0
    muted_agents: tuple[str, ...] = ()
    quiet_hours: str = ""
    details: bool = False
    per_minute: int = 6

    def as_json(self) -> dict[str, Any]:
        return {**asdict(self), "muted_agents": list(self.muted_agents)}


def _bool(raw: Mapping[str, Any], key: str, default: bool) -> bool:
    return raw[key] if isinstance(raw.get(key), bool) else default


def _int(raw: Mapping[str, Any], key: str, default: int, low: int, high: int) -> int:
    value = raw.get(key)
    return min(high, max(low, value)) if isinstance(value, int) and not isinstance(value, bool) else default


def parse(raw: Any) -> Policy:
    """*raw* (the saved section) as a Policy; anything malformed keeps its default."""
    raw = raw if isinstance(raw, Mapping) else {}
    muted = raw.get("muted_agents")
    hours = raw.get("quiet_hours")
    return Policy(
        enabled=_bool(raw, "enabled", True), security=_bool(raw, "security", True), lifecycle=_bool(raw, "lifecycle", False),
        digest=_bool(raw, "digest", False), watched=_bool(raw, "watched", True), digest_minutes=_int(raw, "digest_minutes", 0, 0, 720),
        muted_agents=tuple(sorted({str(item) for item in muted if str(item) in BY_ID or item == "hermes"})) if isinstance(muted, list) else (),
        quiet_hours=hours if isinstance(hours, str) and _HOURS.match(hours) else "",
        details=_bool(raw, "details", False), per_minute=_int(raw, "per_minute", 6, 1, MAX_PER_MINUTE))


def read() -> Policy:
    return parse(config.raw_section(SECTION))


def validate(raw: Any, errors: list[str]) -> dict[str, Any]:
    """The valid fields of a proposed ``notifications`` section (the settings writer's validator);
    each problem is appended to *errors* and then nothing is saved."""
    if not isinstance(raw, dict):
        errors.append("notifications must be an object")
        return {}
    out: dict[str, Any] = {}
    for key in ("enabled", "security", "lifecycle", "digest", "watched", "details"):
        if key in raw:
            if isinstance(raw[key], bool):
                out[key] = raw[key]
            else:
                errors.append(f"notifications.{key} must be a boolean")
    for key, low, high in (("digest_minutes", 0, 720), ("per_minute", 1, MAX_PER_MINUTE)):
        if key in raw:
            if isinstance(raw[key], int) and not isinstance(raw[key], bool) and low <= raw[key] <= high:
                out[key] = raw[key]
            else:
                errors.append(f"notifications.{key} must be a number from {low} to {high}")
    if "muted_agents" in raw:
        muted = raw["muted_agents"]
        if isinstance(muted, list) and all(isinstance(item, str) and (item in BY_ID or item == "hermes") for item in muted):
            out["muted_agents"] = sorted(set(muted))
        else:
            errors.append("notifications.muted_agents must be a list of agent ids")
    if "quiet_hours" in raw:
        hours = raw["quiet_hours"]
        if hours == "" or (isinstance(hours, str) and _HOURS.match(hours)):
            out["quiet_hours"] = hours
        else:
            errors.append('notifications.quiet_hours must be "HH:MM-HH:MM" or empty')
    return out


def weakening(proposed: Any, now: Policy) -> list[str]:
    """Why saving *proposed* would tell the person LESS about threats (empty: it would not)."""
    if not isinstance(proposed, Mapping):
        return []
    reasons = []
    if proposed.get("enabled") is False and now.enabled:
        reasons.append("Turn off every Blackbox notification, including when an AI agent is stopped or runs as root")
    if proposed.get("security") is False and now.security:
        reasons.append("Stop notifying you about security events (an agent stopped, asking for root, running without Blackbox)")
    muted = proposed.get("muted_agents")
    if isinstance(muted, list):
        added = [str(item) for item in muted if item not in now.muted_agents]
        if added:
            names = ", ".join(BY_ID[item].name if item in BY_ID else item for item in added[:4])
            reasons.append(f"Stop notifying you about {names}, security events included")
    return reasons


def _in_quiet_hours(hours: str, now: float) -> bool:
    match = _HOURS.match(hours)
    if not match:
        return False
    start = int(match.group(1)) * 60 + int(match.group(2))
    end = int(match.group(3)) * 60 + int(match.group(4))
    local = time.localtime(now)
    minute = local.tm_hour * 60 + local.tm_min
    return start <= minute < end if start < end else (minute >= start or minute < end) if start != end else False


def held(policy: Policy, notice: Notice, now: float) -> str:
    """Why *notice* is not shown under *policy* ("" = show it). ``"off"`` notices are not kept at
    all (the person switched that kind off); the others stay in the history."""
    if not policy.enabled or not getattr(policy, notice.category, False):
        return "off"
    if notice.agent and notice.agent in policy.muted_agents:
        return "muted"
    if _in_quiet_hours(policy.quiet_hours, now) and not (notice.category == "security" and notice.level == "critical"):
        return "quiet-hours"
    return ""
