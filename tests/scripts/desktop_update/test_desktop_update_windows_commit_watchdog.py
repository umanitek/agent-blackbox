"""Native Windows hand-off contracts, isolated to keep the 300s file limit meaningful."""
from __future__ import annotations
from pathlib import Path
import pytest
from tests.scripts.desktop_update.windows_commit_support import _handoff


@pytest.mark.platforms('windows')
def test_watchdog_remap_after_banner_reports_interrupted_followups(tmp_path: Path) -> None:
    code, out, _argv, result, _ = _handoff(
        tmp_path, '-NoGateway', HANDOFF_HANG='Update complete! (v1.0.0)',
        HERMES_UPDATE_STEP_IDLE_SECONDS='3',
    )
    assert code == 0, out
    assert (result['ok'], result['manual']) == (True, True), result
    assert any('interrupted' in w for w in result['warnings']), result


@pytest.mark.platforms('windows')
def test_cpu_busy_pipe_silent_update_is_not_killed_by_the_idle_watchdog(tmp_path: Path) -> None:
    code, out, _argv, result, _ = _handoff(
        tmp_path, '-NoGateway', HANDOFF_BUSY_SECONDS='15', HERMES_UPDATE_STEP_IDLE_SECONDS='4',
    )
    assert code == 0, out
    assert (result['ok'], result['warnings']) == (True, []), result
