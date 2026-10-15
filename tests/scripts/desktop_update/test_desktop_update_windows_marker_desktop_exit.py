"""Native Windows hand-off contracts, isolated to keep the 300s file limit meaningful."""
from __future__ import annotations
import sys
import os
from pathlib import Path
import subprocess
import time
import pytest
from tests.installation_launcher_fixture import publish_fixture_launcher
from tests.scripts.desktop_update.windows_marker_test_support import CLI, MARKER, SCRIPT, _creation_time, _dead_pid, _run


@pytest.fixture
def sleeper():
    proc = subprocess.Popen([sys.executable, '-c', 'import time; time.sleep(600)'])
    yield proc
    proc.kill()
    proc.wait()


@pytest.mark.platforms('windows')
def test_desktop_that_never_exits_is_not_relaunched_over(
    tmp_path: Path, sleeper: subprocess.Popen, monkeypatch: pytest.MonkeyPatch,
) -> None:
    # The verdict (refuse with 4, never relaunch) is the same at any ceiling; the production
    # 150 s one alone pushed this file to the runner's 300 s per-file cap on a loaded runner.
    monkeypatch.setenv('HERMES_UPDATE_DESKTOP_EXIT_SECONDS', '5')
    install = tmp_path / 'checkout'
    publish_fixture_launcher(install, CLI)
    home = tmp_path / 'home'; home.mkdir()
    # The Desktop's bridge claim, which a -DesktopPid hand-off adopts (A4).
    (home / MARKER).write_bytes(f'{sleeper.pid}\n{int(time.time())}\nct:{_creation_time(sleeper.pid)}\n'.encode())
    relaunch = Path(os.environ.get('SystemRoot', r'C:\Windows')) / 'System32' / 'hostname.exe'
    _, code, out = _run(home, '-DesktopPid', str(sleeper.pid), '-RelaunchExe', str(relaunch),
                        install=install)
    assert code == 4, out
    log = (home / 'logs/desktop-update-handoff.log').read_text(encoding='utf-8-sig')
    assert 'did not exit within 5s' in log, log   # the override reached the script's wait
    assert 'relaunching desktop' not in log, log


@pytest.mark.platforms('windows')
def test_ui_profile_sweep_keeps_dirs_of_live_handoffs(tmp_path: Path, sleeper: subprocess.Popen) -> None:
    live = tmp_path / f'hermes-update-ui-{sleeper.pid}'
    dead = tmp_path / f'hermes-update-ui-{_dead_pid()}'
    live.mkdir(); dead.mkdir()
    home = tmp_path / 'home'; home.mkdir()
    result = subprocess.run(
        ['powershell', '-NoProfile', '-ExecutionPolicy', 'Bypass', '-File', str(SCRIPT), '-SelfTestUi', '-NoUi'],
        cwd=tmp_path, env={**os.environ, 'HERMES_HOME': str(home), 'TEMP': str(tmp_path),
                           'HERMES_SELFTEST_HOLD_SECONDS': '0'},
        capture_output=True, text=True, timeout=120,
        check=False,
    )
    assert result.returncode == 0, result.stdout + result.stderr
    assert live.exists(), 'another live hand-off lost its browser profile'
    assert not dead.exists()
