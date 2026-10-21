"""Native Windows hand-off contracts, isolated to keep the 300s file limit meaningful."""
from __future__ import annotations
import json
from pathlib import Path
import subprocess
import pytest
from tests.scripts.desktop_update.lineage_rule_cases import ENV_CASES, RULE_CASES
from tests.scripts.desktop_update.windows_handoff_support import MARKER, MARKER_PS1, POWERSHELL
from tests.scripts.desktop_update.windows_lineage_test_support import _PASCAL, _RULE_HARNESS


@pytest.mark.platforms('windows')
def test_launcher_lineage_rule_matches_the_shared_table(tmp_path: Path) -> None:
    cases = tmp_path / 'cases.json'
    cases.write_text(json.dumps({
        'rule': [{'id': c['id'], 'facts': {_PASCAL[k]: v for k, v in c['facts'].items()}} for c in RULE_CASES],
        'env': [{'id': c['id'], 'env': c['env'], 'line2': c['line2']} for c in ENV_CASES],
    }), encoding='utf-8')
    harness = tmp_path / 'rule.ps1'
    harness.write_text(_RULE_HARNESS, encoding='utf-8')
    proc = subprocess.run([POWERSHELL, '-NoProfile', '-ExecutionPolicy', 'Bypass', '-File', str(harness),
                           '-MarkerPs1', str(MARKER_PS1), '-Marker', str(tmp_path / MARKER), '-Cases', str(cases)],
                          capture_output=True, text=True, timeout=120, check=False)
    assert proc.returncode == 0, proc.stdout + proc.stderr
    got = dict(line.split('=') for line in proc.stdout.split())
    want = {c['id']: '1' if c['expect'] else '0' for c in RULE_CASES}
    want.update({f"env_{c['id']}": '1' if c['expect'] else '0' for c in ENV_CASES})
    assert got == want, proc.stderr
