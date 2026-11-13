"""Wallet tests: every shield's self-tests for this machine, run through the real check, local only.

The shields list what an agent could attempt here (``shields.self_tests()`` — for Trader
Shield, every wallet found on this machine plus a generated seed phrase and key); this module
runs one by id: it hands the attempt to ``guard.on_pre_tool_call`` exactly as an agent's tool
would, inside :func:`audit.sandbox_run`, so the finding, its activity and any cooldown land
in ``$BLACKBOX_HOME/sandbox/`` and never in the real logs. Nothing is executed or sent:
the check runs BEFORE a tool would, and a test stops there. Shield findings are local-only
(``source="secret"``), so a wallet test never shares anything, sandbox lane included.

Unlike the threat tests (:mod:`.runner`) these need only sandbox mode, not sharing.

Usage::

    from plugins.blackbox import playground
    playground.wallet_tests()                    # [{"id", "group", "title", "shown", "expect", "note"}, …]
    playground.run_wallet_test("seed:sent-in-url").to_dict()
    # {"decision": "blocked", "identifiers": ["secret:seed-phrase"], …}
"""

from __future__ import annotations

import time
from dataclasses import asdict, dataclass
from typing import Any, Optional

from .. import audit, shields
from ..kernel.config import BlackboxConfig, load_blackbox_config
from ..kernel.constants import SEVERITY_RANK
from .runner import PlaygroundRefused, check_in_sandbox

#: How many recent sandbox findings are read to find this run's own (one run adds a few).
_FINDINGS_READ = 50


@dataclass(frozen=True)
class WalletTestResult:
    """One wallet test's outcome, as the dashboard shows it.

    ``decision``: ``blocked`` (the check stopped the tool), ``flagged`` (recorded, let
    through — audit mode, or a finding that only flags) or ``allowed`` (nothing found:
    the shield is off or the item is not chosen — ``note`` says which). ``expect`` is
    what the shield does when on, chosen and in block mode.
    """

    id: str
    shield: str
    title: str
    shown: str
    expect: str
    decision: str
    identifiers: tuple[str, ...]
    severity: str
    note: str
    blocking: bool
    check_ms: float
    at: float

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


def require_sandbox_mode(cfg: BlackboxConfig) -> None:
    """Raise :class:`PlaygroundRefused` unless sandbox mode is on."""
    if not cfg.community_sandbox:
        raise PlaygroundRefused("Sandbox mode is off. Turn it on under Settings → Community sharing to run tests.")


def wallet_tests() -> list[dict[str, Any]]:
    """Every shield's self-tests for this machine, as the dashboard lists them (no secrets)."""
    return [{**test.as_json(), "shield": shield.id, "shield_name": shield.name}
            for shield, test in shields.self_tests()]


def _this_run(task: str) -> list[dict[str, Any]]:
    return [row for row in audit.read_findings(limit=_FINDINGS_READ) if row.get("task_id") == task]


def run_wallet_test(test_id: str, cfg: Optional[BlackboxConfig] = None) -> WalletTestResult:
    """Run self-test *test_id* through the real check; raises :class:`PlaygroundRefused`
    when sandbox mode is off or no shield offers that test on this machine."""
    cfg = cfg or load_blackbox_config()
    require_sandbox_mode(cfg)
    found = next(((shield, test) for shield, test in shields.self_tests() if test.id == test_id), None)
    if found is None:
        raise PlaygroundRefused("That test is not available on this machine any more; reload the list.")
    shield, test = found
    started = time.time()
    with audit.sandbox_run():
        verdict, check_ms, task = check_in_sandbox(test.tool, test.hook_args(), started, prefix="sandbox-wallet")
        rows = _this_run(task)
    blocked = bool(verdict) and verdict.get("action") == "block"
    decision = "blocked" if blocked else ("flagged" if rows else "allowed")
    severities = [str(row.get("severity") or "") for row in rows if row.get("severity")]
    return WalletTestResult(
        id=test.id, shield=shield.id, title=test.title, shown=test.shown, expect=test.expect, decision=decision,
        identifiers=tuple(dict.fromkeys(str(row.get("identifier") or "") for row in rows)),
        severity=max(severities, key=lambda name: SEVERITY_RANK.get(name, -1), default=""),
        note=test.note, blocking=bool(cfg.block_enabled), check_ms=check_ms, at=started)
