"""Native Windows hand-off contracts, isolated to keep the 300s file limit meaningful."""
from __future__ import annotations
from pathlib import Path
import subprocess
import sys
import time
import pytest
from tests.scripts.desktop_update.windows_marker_test_support import MARKER, _creation_time, _dead_pid, _result, _run


@pytest.fixture
def sleeper():
    proc = subprocess.Popen([sys.executable, '-c', 'import time; time.sleep(600)'])
    yield proc
    proc.kill()
    proc.wait()


@pytest.mark.platforms('windows')
@pytest.mark.parametrize('bridge', ['absent', 'someone-else'])
def test_desktop_started_handoff_only_adopts_its_bridge(
    tmp_path: Path, sleeper: subprocess.Popen, bridge: str,
) -> None:
    """A4: the Desktop gave up on a late script: it must not claim fresh, run, or leave a result."""
    other = subprocess.Popen([sys.executable, '-c', 'import time; time.sleep(600)'])
    try:
        body = f'{other.pid}\n{int(time.time())}\nct:{_creation_time(other.pid)}\n'.encode()
        if bridge == 'someone-else':
            (tmp_path / MARKER).write_bytes(body)
        _, code, out = _run(tmp_path, '-DesktopPid', str(sleeper.pid))
    finally:
        other.kill(); other.wait()
    assert code == 2, out
    assert not (tmp_path / '.hermes-update-result.json').exists()
    if bridge == 'absent':
        assert not (tmp_path / MARKER).exists()
    else:
        assert (tmp_path / MARKER).read_bytes() == body


@pytest.mark.platforms('windows')
def test_live_desktop_bridge_marker_is_adopted_keeping_its_started_at(
    tmp_path: Path, sleeper: subprocess.Popen,
) -> None:
    started = int(time.time()) - 30
    (tmp_path / MARKER).write_bytes(f'{sleeper.pid}\n{started}\nct:{_creation_time(sleeper.pid)}\n'.encode())
    pid, code, out = _run(tmp_path, '-SelfTestMarker', '-NoMarkerCleanup', '-DesktopPid', str(sleeper.pid))
    assert code == 0, out
    lines = (tmp_path / MARKER).read_bytes().decode().split('\n')
    assert lines[:2] == [str(pid), str(started)], lines
    assert lines[2].startswith('ct:'), lines
    assert _result(tmp_path)['started_at'] == started


@pytest.mark.platforms('windows')
def test_dead_owner_marker_is_reclaimed_and_released(tmp_path: Path) -> None:
    (tmp_path / MARKER).write_bytes(f'{_dead_pid()}\n{int(time.time())}\nct:5.000\n'.encode())
    pid, code, out = _run(tmp_path, '-SelfTestMarker')
    assert code == 0, out
    assert not (tmp_path / MARKER).exists()
    log = (tmp_path / 'logs/desktop-update-handoff.log').read_text(encoding='utf-8-sig')
    assert f'claimed update marker (pid {pid})' in log
    assert 'removed update marker (owned)' in log
