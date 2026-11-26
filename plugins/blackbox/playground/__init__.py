"""The Playground: sandbox mode's test bench, built into the product (2026-10-21).

With **sandbox mode** on (``community_sandbox``, a switch under Community
sharing), every share this node makes goes to the community graph's
``sandbox`` lane instead of ``reports``, and the Playground lets the operator
send a real listed threat through the real check to prove the whole path —
membership, signing, the owner keeping the share, delivery to the other
members — with no consequence: no rule, flag or real log ever sees a test.
Switch sandbox mode off and the very next finding is real again.

Public surface (use only these):

* :data:`KINDS` — the test kinds (``package``, ``domain``, ``ip``, ``url``);
* :func:`run_test` — run one test, returns a :class:`TestResult`;
  raises :class:`PlaygroundRefused` with a plain reason when it cannot run; it answers
  within :data:`RUN_BUDGET_S` seconds, a share still on its way then reads :data:`PENDING`;
* :func:`recent_tests` — this node's own sandbox findings, newest first;
* :func:`sandbox_activity` — the same tests as sessions → events → threats;
* :func:`sandbox_audit` — the same tests as Agent activity entries (``/api/audit``'s shape);
* :func:`read_lane` — what every member has shared to the sandbox lane;
* :func:`wallet_tests` / :func:`run_wallet_test` — the shields' self-tests for this machine
  (every wallet found here, generated seed phrases and keys), run through the real check,
  local only; they need sandbox mode but not sharing (:mod:`.wallets`);
* :mod:`graph` — that lane in the Community graph's own response shapes
  (``graph.graph_page``, ``graph.threat_detail``), for the dashboard in sandbox mode.

Usage::

    from plugins.blackbox import playground
    result = playground.run_test("domain")      # sandbox mode + sharing must be on
    view = playground.read_lane(load_blackbox_config())
"""

from __future__ import annotations

from . import graph
from .lane import LaneEntry, LaneView, read_lane
from .runner import (KINDS, PENDING, RUN_BUDGET_S, SESSION_ID, PlaygroundRefused, TestResult, recent_tests,
                     require_sandbox, run_test, sandbox_activity, sandbox_audit)
from .wallets import WalletTestResult, require_sandbox_mode, run_wallet_test, wallet_tests

__all__ = [
    "KINDS",
    "PENDING",
    "RUN_BUDGET_S",
    "SESSION_ID",
    "LaneEntry",
    "LaneView",
    "PlaygroundRefused",
    "TestResult",
    "WalletTestResult",
    "graph",
    "read_lane",
    "recent_tests",
    "require_sandbox",
    "require_sandbox_mode",
    "run_test",
    "run_wallet_test",
    "sandbox_activity",
    "sandbox_audit",
    "wallet_tests",
]
