"""``blackbox sync --wait`` writes "done" only when the catch-up says done (review 2026-11-26, finding 7; LES-159).

The completion gate tested "not queued or running", so a status poll that
raised (state ""), a deferred, unreachable, failed, cancelled or denied job all
counted as complete once any public rule was cached — possibly last-good — and
the sync wrote ``done``. A gate that needs "done" tests the one value that
proves it; every other value takes the protective branch.
"""

from __future__ import annotations

import argparse

import pytest

from plugins.blackbox.kernel.config import BlackboxConfig
from plugins.blackbox.sync import command

NOT_DONE = ("", "queued", "running", "deferred", "unreachable", "failed", "cancelled", "denied", "unknown-new-state")


def _sync(state: str) -> command._CatchupSync:
    run = command._CatchupSync(BlackboxConfig(context_graph_id="0x" + "a" * 40 + "/custom-graph"), object(),
                               argparse.Namespace(wait=True, timeout=1))
    run.public_count, run.subscribed, run.catchup_state = 12, True, state
    return run


@pytest.mark.parametrize("state", NOT_DONE)
def test_every_state_but_done_is_not_a_complete_catchup(state):
    assert _sync(state)._base_sync_complete(fresh_job_complete=False, barrier_job_id="<unscoped>") is False


def test_a_done_catchup_with_rules_is_complete():
    assert _sync("done")._base_sync_complete(fresh_job_complete=False, barrier_job_id="<unscoped>") is True
