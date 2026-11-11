"""Run one sandbox test: the protected agent ATTEMPTS a listed threat, through the real check.

Nothing is executed or fetched. The runner hands the agent's pre-tool hook
(``guard.on_pre_tool_call``) exactly what an agent would hand it before
running a tool; the hook checks it against this node's verified rules, records
the finding and — sharing on, the share gate allowing it — shares a privacy-safe
statement. The whole run happens inside :func:`audit.sandbox_run`, so its
finding, activity, cooldown and share ledger land in ``$BLACKBOX_HOME/sandbox/``
and never in the real logs; with sandbox mode on, the share goes to the graph's
``sandbox`` lane, which no rule or community flag ever reads.

Kinds, each a REAL threat already listed in this node's verified rules, picked
at random every run (a repeat would hit the sandbox cooldown):

* ``package`` — ``npm install <malware>@<version>`` (an advisory-backed rule);
* ``domain`` / ``ip`` / ``url`` — the agent's web tool asked to fetch a listed
  malicious domain / C2 address / payload URL.

Only identifiers from the local rules are used — never an attack payload
shipped with the plugin (LES-058).
"""

from __future__ import annotations

import random
import time
from dataclasses import asdict, dataclass
from typing import Any, Iterator, Optional

from .. import audit, guard, ruleset
from ..kernel.config import BlackboxConfig, load_blackbox_config

KINDS = ("package", "domain", "ip", "url")
SESSION_ID = "blackbox-sandbox"   # every sandbox test runs under this agent session
_TRIES = 12                        # random windows of the live tier to look in
_WINDOW = 40                       # rules per window
_SHARE_WAIT_S = 90.0               # the share thread's node round trip (seal → share → poll)


class PlaygroundRefused(Exception):
    """A test cannot run here; the message says why and what to change."""


@dataclass(frozen=True)
class Attempt:
    """What the agent will try: the threat's identifier, the tool and its arguments."""

    identifier: str
    tool: str
    args: dict[str, str]
    severity: str


@dataclass(frozen=True)
class TestResult:
    """The outcome of one sandbox test, as the dashboard shows it.

    ``decision`` is ``blocked`` or ``flagged``; ``shared`` is the sandbox share
    ledger's outcome (``accepted``, ``already-shared``, ``failed``…) or ``""``
    when nothing was sent (sharing off or the gate refused).
    """

    kind: str
    identifier: str
    command: str
    severity: str
    decision: str
    check_ms: float
    shared: str
    at: float

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


def require_sandbox(cfg: BlackboxConfig) -> None:
    """Raise :class:`PlaygroundRefused` unless sandbox mode and sharing are both on."""
    if not cfg.community_sandbox:
        raise PlaygroundRefused("Sandbox mode is off. Turn it on under Community sharing to run tests.")
    if not cfg.community_enabled:
        raise PlaygroundRefused("Community sharing is off. Turn it on (sandbox mode keeps every test in the sandbox lane).")


def run_test(kind: str, cfg: Optional[BlackboxConfig] = None) -> TestResult:
    """Run one sandbox test of *kind* (one of :data:`KINDS`) and wait for its share.

    Raises :class:`PlaygroundRefused` when sandbox mode or sharing is off, the
    kind is unknown, or the local rules hold no threat of that kind.
    """
    if kind not in KINDS:
        raise PlaygroundRefused(f"Unknown test kind {kind!r}; pick one of {', '.join(KINDS)}.")
    cfg = cfg or load_blackbox_config()
    require_sandbox(cfg)
    attempt = _pick(ruleset.get(cfg), kind)
    started = time.time()
    with audit.sandbox_run(), guard.collecting_shares() as shares:
        task = f"sandbox-{int(started * 1000)}-{random.SystemRandom().randrange(1 << 24):06x}"
        verdict = guard.on_pre_tool_call(tool_name=attempt.tool, args=attempt.args, session_id=SESSION_ID,
                                         task_id=task, tool_call_id=task)
        check_ms = round((time.time() - started) * 1000, 1)
        guard.reports_settled(_SHARE_WAIT_S)   # the follow-up that starts the share runs after the hook
        for worker in list(shares):   # this test's own shares, never another agent's
            worker.join(_SHARE_WAIT_S)
        shared = _share_outcome(attempt.identifier)
    blocked = bool(verdict) and verdict.get("action") == "block"
    return TestResult(kind=kind, identifier=attempt.identifier, command=_command_text(attempt),
                      severity=attempt.severity, decision="blocked" if blocked else "flagged",
                      check_ms=check_ms, shared=shared, at=started)


def recent_tests(limit: int = 20) -> list[dict[str, Any]]:
    """The sandbox's own findings, newest first (read from the sandbox folder)."""
    with audit.sandbox_run():
        return audit.read_findings(limit=limit)


def sandbox_activity(max_sessions: int = 60) -> dict[str, Any]:
    """The sandbox's own activity in ``/api/local-activity``'s shape (sessions → events
    → threats), read from the sandbox folder. The dashboard shows it beside the real
    activity in sandbox mode, tagged, and never adds it to a real count."""
    with audit.sandbox_run():
        return audit.read_local_activity(max_sessions=max_sessions)


def sandbox_audit(limit: int = 200) -> list[dict[str, Any]]:
    """The sandbox's own activity trail in ``/api/audit``'s entry shape, newest first (read
    from the sandbox folder). The dashboard merges it into Agent activity, tagged SANDBOX."""
    with audit.sandbox_run():
        return audit.read_audit(limit=limit)


def _pick(rules: Any, kind: str) -> Attempt:
    if kind == "package":
        return _pick_package(rules)
    return _pick_ioc(rules, kind)


def _windows(rules: Any, category: str, ecosystem: str = "") -> Iterator[list[dict[str, Any]]]:
    """Random windows of the live verified tier (plain paging stops at the browse depth)."""
    scope = rules.verified_scope
    counts = scope.verified_counts if scope else {}
    total = int(counts.get(f"dependency:{ecosystem}" if ecosystem else category, 0))
    reach = min(total, ruleset.live.browse.MAX_DEPTH) - _WINDOW
    rng = random.SystemRandom()
    for _ in range(_TRIES):
        page = rules.live_browse(category=category, ecosystem=ecosystem, offset=rng.randrange(max(1, reach)),
                                 limit=_WINDOW)
        if page is None or not page.known:
            raise PlaygroundRefused("The verified rules could not be read on this node; try again once it has synced.")
        yield rng.sample(page.entries, len(page.entries))


def _pick_package(rules: Any) -> Attempt:
    for entries in _windows(rules, "dependency", "npm"):
        for entry in entries:
            name, _, version = entry["identifier"].split(":", 2)[2].rpartition("@")
            if version == "*" or not name:
                continue
            rule = rules.dependency_rules([("npm", name, version)]).rules.get(f"npm:{name}@{version}")
            if rule and rule.get("advisoryId") and rule.get("kind") == "malware":
                return Attempt(entry["identifier"], "terminal", {"command": f"npm install {name}@{version}"},
                               str(rule.get("severity") or "critical"))
    raise PlaygroundRefused("No listed malware package was found in this sample; try again.")


def _pick_ioc(rules: Any, ioc_type: str) -> Attempt:
    for entries in _windows(rules, "ioc"):
        for entry in entries:
            identifier = entry["identifier"]
            if not identifier.startswith(f"ioc:{ioc_type}:"):
                continue
            value = identifier.split(":", 2)[2]
            rule = rules.ioc_rules([identifier]).rules.get(identifier)
            if rule:
                url = value if ioc_type == "url" else f"https://{value}/"
                return Attempt(identifier, "web_fetch", {"url": url}, str(rule.get("severity") or "high"))
    raise PlaygroundRefused(f"No listed {ioc_type} was found in this sample; try again.")


def _command_text(attempt: Attempt) -> str:
    return attempt.args.get("command") or f"{attempt.tool} {attempt.args.get('url', '')}"


def _share_outcome(identifier: str) -> str:
    """What the (sandbox) share ledger says happened to *identifier* ("" = nothing sent)."""
    for row in audit.read_share_ledger(limit=50):
        if row.get("identifier") == identifier:
            return str(row.get("outcome") or ("accepted" if row.get("ok") else "failed"))
    return ""
