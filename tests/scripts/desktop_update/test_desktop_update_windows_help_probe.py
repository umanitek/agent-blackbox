"""Native Windows hand-off contracts, isolated to keep the 300s file limit meaningful."""
from __future__ import annotations
from pathlib import Path
import pytest
from tests.scripts.desktop_update.windows_commit_support import _handoff


@pytest.mark.platforms('windows')
def test_hanging_update_help_probe_is_bounded(tmp_path: Path) -> None:
    code, out, argv, _result, _ = _handoff(
        tmp_path, '-NoGateway', '-ProbeTimeoutSeconds', '10', timeout=120, HANDOFF_HELP_HANG='1',
    )
    assert code == 0, out
    assert argv[0][:2] == ['update', '--yes'] and '--keep-stash' not in argv[0], argv
