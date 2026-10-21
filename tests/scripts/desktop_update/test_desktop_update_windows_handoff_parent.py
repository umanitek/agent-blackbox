"""Native Windows hand-off contracts, isolated to keep the 300s file limit meaningful."""
from __future__ import annotations
import sys
from pathlib import Path
import subprocess
import pytest
from tests.scripts.desktop_update.windows_handoff_support import MARKER, _wait_for_log
from tests.scripts.desktop_update.windows_lineage_test_support import _old_desktop


@pytest.fixture
def sleeper():
    proc = subprocess.Popen([sys.executable, '-c', 'import time; time.sleep(600)'])
    yield proc
    proc.kill()
    proc.wait()


@pytest.mark.platforms('windows')
@pytest.mark.parametrize('env_matches', [True, False], ids=['env-matches', 'env-differs'])
def test_r4_live_wrapper_not_the_desktops_child_is_adopted_only_with_the_handoff_started_at(
    tmp_path: Path, sleeper: subprocess.Popen, env_matches: bool,
) -> None:
    """The lineage table's divergent row (round 5 D11) on real processes: the cmd.exe wrapper is
    our live parent but not the Desktop's child; line 2 == HERMES_UPDATE_STARTED_AT adopts, as
    in bash. Any other startedAt refuses."""
    home = tmp_path / 'home'; home.mkdir()
    desktop, wrapper, started, _ = _old_desktop(home, 'waiting-wrapper', other_desktop=sleeper.pid,
                                                env_skew=0 if env_matches else -7)
    try:
        log = _wait_for_log(home, 'hand-off start:' if env_matches else 'exiting without claiming')
    finally:
        desktop.kill(); desktop.wait()
    if env_matches:
        assert 'marker=adopted' in log, log
        assert f"desktop pid {sleeper.pid}'s launcher pid {wrapper}" in log, log
        lines = (home / MARKER).read_bytes().decode().split('\n')
        assert lines[1] == str(started) and lines[2].startswith('ct:'), lines
    else:
        assert 'hand-off start:' not in log, log
        assert (home / MARKER).read_bytes().decode() == f'{wrapper}\n{started}\n'
