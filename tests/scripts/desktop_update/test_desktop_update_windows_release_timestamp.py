"""Native Windows hand-off contracts, isolated to keep the 300s file limit meaningful."""
from __future__ import annotations
from concurrent.futures import ThreadPoolExecutor
import json
from pathlib import Path
import subprocess
import sys
import time
import pytest
from tests.scripts.desktop_update.windows_commit_support import _handoff
from tests.scripts.desktop_update.windows_handoff_support import _wait_for_log
from tests.waiting import wait_until


_CHECKOUT_HOLDER = """
import msvcrt, os, sys, time
from pathlib import Path
fd = os.open(sys.argv[1], os.O_RDWR | os.O_CREAT | os.O_BINARY, 0o644)
os.lseek(fd, 1 << 20, os.SEEK_SET)
msvcrt.locking(fd, msvcrt.LK_NBLCK, 1)
Path(sys.argv[2]).touch()
while not Path(sys.argv[3]).exists():
    time.sleep(0.05)
os.close(fd)
"""


@pytest.mark.platforms('windows')
def test_result_finished_at_is_stamped_after_the_r6_release_wait(tmp_path: Path) -> None:
    # The relaunched Desktop drops a non-manual result whose finished_at is 30 minutes old; the
    # R6 wait lasts up to 2 h. The result must carry the time the hand-off actually finished.
    holders = []
    ready = tmp_path / 'checkout-held'
    release = tmp_path / 'release-checkout'
    home = tmp_path / 'home'

    def hold_checkout(_home: Path, install: Path) -> None:
        holder = subprocess.Popen([sys.executable, '-c', _CHECKOUT_HOLDER,
                                   str(install / '.hermes-update.lock'), str(ready), str(release)])
        holders.append(holder)
        wait_until(lambda: ready.exists() or holder.poll() is not None, timeout=30,
                   what='checkout lock acquired')
        assert ready.exists(), 'checkout holder exited before locking'
    try:
        with ThreadPoolExecutor(max_workers=1) as pool:
            handoff = pool.submit(_handoff, tmp_path, '-NoGateway', prepare=hold_checkout)
            try:
                # A fixed 25s holder could expire during PowerShell startup, before R6.
                # Keep it until the real hand-off has entered that wait and its early
                # result is observably older than the release timestamp.
                _wait_for_log(home, 'keeping the update marker')
                early = json.loads((home / '.hermes-update-result.json').read_text(encoding='utf-8-sig'))
                wait_until(lambda: int(time.time()) >= early['finished_at'] + 2, timeout=10,
                           what='release timestamp differs from the pre-wait result')
                released = int(time.time())
            finally:
                release.touch()
            code, out, _, result, home = handoff.result()
    finally:
        release.touch()
        for proc in holders:
            if proc.poll() is None:
                proc.kill()
            proc.wait()
    assert code == 0, out
    log = (home / 'logs/desktop-update-handoff.log').read_text(encoding='utf-8-sig')
    assert 'keeping the update marker' in log, log
    assert result['ok'] is True and result['finished_at'] >= released, (result, released)
    assert not list(home.glob('.hermes-update-result.json.*.tmp'))
