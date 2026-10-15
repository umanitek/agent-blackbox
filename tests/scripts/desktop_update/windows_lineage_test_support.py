"""Shared fixtures for independently bounded native Windows hand-off tests."""
from __future__ import annotations
import os
from pathlib import Path
import subprocess
import sys
import time
import pytest
from tests.scripts.desktop_update.windows_handoff_support import SCRIPT, POWERSHELL




OLD_DESKTOP = r"""
import os, subprocess, sys, time
from pathlib import Path
# be3fd671d70 checkout.ts: spawn the cmd.exe wrapper (non-detached), then in the
# same tick overwrite the marker with the WRAPPER's pid as a v1 claim, then
# stay up (the -SelfTestMarker script ends before it would wait us out).
home, script, mode, foreign = Path(sys.argv[1]), sys.argv[2], sys.argv[3], int(sys.argv[4])
other_desktop, env_skew = int(sys.argv[5]), int(sys.argv[6])  # a Desktop that is NOT the wrapper's parent
started = int(time.time())
env = dict(os.environ, HERMES_UPDATE_STARTED_AT=str(started + env_skew))
ps = [os.environ['POWERSHELL'], '-NoProfile', '-ExecutionPolicy', 'Bypass', '-File', script,
      '-InstallRoot', str(home / 'hermes-agent'), '-NoUi', '-SelfTestMarker', '-NoMarkerCleanup',
      '-DesktopPid', str(other_desktop or os.getpid())]
wrapper = ['cmd.exe', '/d', '/s', '/c'] + (['start', '', '/b'] if mode == 'start-b' else [])
child = subprocess.Popen(wrapper + ps, cwd=home, env=env, stdin=subprocess.DEVNULL,
                         stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
owner = foreign or child.pid
(home / '.hermes-update-in-progress').write_bytes(f'{owner}\n{started}\n'.encode())
(home / 'desktop.json').write_text(f'{os.getpid()} {child.pid} {started}', encoding='utf-8')
time.sleep(600)
"""


def _old_desktop(home: Path, mode: str, foreign: int = 0, other_desktop: int = 0,
                 env_skew: int = 0) -> tuple[subprocess.Popen, int, int, int]:
    program = home.parent / 'old_desktop.py'
    program.write_text(OLD_DESKTOP, encoding='utf-8')
    desktop = subprocess.Popen([sys.executable, str(program), str(home), str(SCRIPT), mode, str(foreign),
                                str(other_desktop), str(env_skew)],
                               env={**os.environ, 'HERMES_HOME': str(home), 'POWERSHELL': POWERSHELL})
    deadline = time.monotonic() + 30
    while not (home / 'desktop.json').exists():
        assert time.monotonic() < deadline and desktop.poll() is None, 'old desktop never spawned'
        time.sleep(0.05)
    time.sleep(0.2)
    desktop_pid, wrapper, started = map(int, (home / 'desktop.json').read_text(encoding='utf-8-sig').split())
    return desktop, wrapper, started, desktop_pid


_RULE_HARNESS = r"""
param([string]$MarkerPs1, [string]$Marker, [string]$Cases)
$MarkerPath = $Marker
$NoMarkerCleanup = $true
function Write-HandoffLog([string]$Message) { [Console]::Error.WriteLine($Message) }
. $MarkerPs1
$data = [System.IO.File]::ReadAllText($Cases) | ConvertFrom-Json
foreach ($c in $data.rule) {
    $facts = @{}
    foreach ($p in $c.facts.PSObject.Properties) { $facts[$p.Name] = [bool]$p.Value }
    [Console]::Out.WriteLine("$($c.id)=$([int][bool](Test-MarkerLauncherRule $facts))")
}
foreach ($c in $data.env) {
    $env:HERMES_UPDATE_STARTED_AT = $c.env
    [Console]::Out.WriteLine("env_$($c.id)=$([int][bool](Test-MarkerEnvStartedAt $c.line2))")
}
"""


_PASCAL = {'v1': 'V1', 'names_desktop': 'NamesDesktop', 'named_alive': 'NamedAlive',
           'named_is_our_parent': 'NamedIsOurParent', 'named_parent_is_desktop': 'NamedParentIsDesktop',
           'env_started_matches': 'EnvStartedMatches'}
