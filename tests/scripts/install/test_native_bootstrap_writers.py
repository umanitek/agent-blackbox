"""Execute the shipped configuration writers for fresh native profiles and upgrades."""
import json
import os
from pathlib import Path
import re
import subprocess
import sys

import pytest

ROOT = Path(__file__).resolve().parents[3]


def writer(extension):
    source = (ROOT / 'scripts' / f'blackbox-install.{extension}').read_text(encoding='utf-8')
    pattern = (r"^ensure_blackbox_dkg_config\(\).*?<<'PYEOF'\n(.*?)^PYEOF" if extension == 'sh'
               else r"^function Ensure-BlackboxDkgConfig \{.*?\$writer = @'\n(.*?)^'@")
    return re.search(pattern, source, re.MULTILINE | re.DOTALL)[1]


@pytest.mark.parametrize('extension', ['sh', 'ps1'])
def test_native_fresh_and_upgrade_preserve_journal_and_explicit_profile(tmp_path, extension):
    plan = {'version': 1, 'source': {'contextGraphId': 'graph'}, 'runtime': {'jarSha256': 'a' * 64}}
    (tmp_path / 'public-bootstrap-plan.json').write_text(json.dumps(plan), encoding='utf-8')
    def invoke(backend):
        return subprocess.run([sys.executable, '-c', writer(extension), str(tmp_path), '9320', backend,
                               '', 'true', 'graph', 'graph', '', '10', '20'],
                              env={**os.environ, 'HERMES_HOME': str(tmp_path)}, capture_output=True, text=True, timeout=30, check=False)
    fresh = invoke('native')
    assert fresh.returncode == 0, fresh.stderr
    config = tmp_path / 'config.json'
    saved = json.loads(config.read_text(encoding='utf-8'))
    assert 'store' not in saved
    assert saved['publicSnapshotBootstrap'] == plan
    journal = tmp_path / 'public-checkpoint-edge' / 'checkpoint-store' / 'store.jnl'
    journal.parent.mkdir(parents=True)
    journal.write_bytes(b'original retained journal')
    saved['DKG_Core_chain_cache'] = False
    config.write_text(json.dumps(saved), encoding='utf-8')
    assert invoke('native').returncode == 0
    assert json.loads(config.read_text(encoding='utf-8'))['DKG_Core_chain_cache'] is False
    before = config.read_bytes()
    rejected = invoke('blazegraph')
    assert rejected.returncode != 0 and 'cannot convert' in rejected.stderr
    assert config.read_bytes() == before
    assert journal.read_bytes() == b'original retained journal'
    assert not list(tmp_path.glob('config.json.pre-*'))
    assert not (tmp_path / '.blackbox-store-reset-pending').exists()
