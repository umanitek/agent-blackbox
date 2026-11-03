"""The one-line install on a machine that already runs another Hermes installs Blackbox INTO it.

Found 2026-11-03 with Hermes Desktop 0.22.6 on a Mac: the one-liner never looked for an existing
Hermes, so it would clone Agent Blackbox (a Hermes fork) and build a second, older Hermes into the
same ~/.hermes, fighting Desktop over the `hermes` launcher. Now, when `hermes --version` names an
install directory that is not an Agent Blackbox checkout, the installer installs the Blackbox
plugin from the Hermes plugin catalog (the reviewed pin, Hermes's trust model) and hands over to
`hermes blackbox setup`. Our own earlier installs keep the standalone path.

These run the real functions out of the script with a fake `hermes` that logs every call, under
macOS's bash 3.2 (`set -u` with an empty array) and a newer bash when one is installed (LES-038).
"""

from __future__ import annotations

import re
import shlex
import shutil
import subprocess
from pathlib import Path

import pytest

INSTALL_SH = Path(__file__).resolve().parents[1] / "scripts" / "blackbox-install.sh"
TEXT = INSTALL_SH.read_text(encoding="utf-8")
BASHES = [b for b in dict.fromkeys(["/bin/bash", shutil.which("bash") or ""]) if b and Path(b).exists()]


def _body(name: str) -> str:
    match = re.search(rf"^{re.escape(name)}\(\)\s*\{{\s*\n(?P<body>.*?)^\}}", TEXT, re.MULTILINE | re.DOTALL)
    assert match is not None, f"{name}() not found"
    return match["body"]


def _fake_hermes(tmp_path: Path, *, install_dir: Path | None, plugins_list: str = "", install_ok: bool = True) -> Path:
    """~/.local/bin/hermes that answers --version and logs every other call to tmp_path/calls."""
    home = tmp_path / "home"
    (home / ".local" / "bin").mkdir(parents=True, exist_ok=True)
    hermes = home / ".local" / "bin" / "hermes"
    version = "Hermes Agent v0.22.6 (2026.9.24) · stable"
    where = f"Install directory: {install_dir}" if install_dir else ""
    calls = tmp_path / "calls"
    hermes.write_text(f"""#!/bin/sh
if [ "$1" = --version ]; then printf '%s\\n' {shlex.quote(version)} {shlex.quote(where)}; exit 0; fi
echo "$*" >> {shlex.quote(str(calls))}
if [ "$1 $2" = "plugins list" ]; then
  # A real Hermes prints a long table: enough to fill a pipe, so an early-exiting grep -q
  # makes it die of SIGPIPE (what broke the first live run under pipefail).
  printf '%s\\n' {shlex.quote(plugins_list)}
  i=0; while [ $i -lt 4000 ]; do echo "│ other-plugin-$i │ enabled │ 1.0.0 │ a description │ bundled │"; i=$((i+1)); done
  exit 0
fi
if [ "$1 $2" = "plugins install" ]; then exit {0 if install_ok else 1}; fi
exit 0
""", encoding="utf-8")
    hermes.chmod(0o755)
    return hermes


def _stock_hermes_dir(tmp_path: Path) -> Path:
    d = tmp_path / "hermes-agent"
    (d / "hermes_cli").mkdir(parents=True)
    return d


def _run(tmp_path: Path, bash: str, call: str, *, env: str = "") -> subprocess.CompletedProcess:
    script = f"""set -euo pipefail
ok() {{ echo "OK $*"; }}; warn() {{ echo "WARN $*"; }}; step() {{ echo "STEP $*"; }}
err() {{ echo "ERR $*"; }}; heading() {{ echo "== $*"; }}
existing_foreign_hermes() {{
{_body("existing_foreign_hermes")}
}}
install_into_existing_hermes() {{
{_body("install_into_existing_hermes")}
}}
HOME={shlex.quote(str(tmp_path / "home"))}
PATH={shlex.quote(str(tmp_path / "home" / ".local" / "bin"))}:/usr/bin:/bin
BLACKBOX_DKG_STORE_BACKEND=auto
SKIP_DKG=false
HERMES_HOME={shlex.quote(str(tmp_path / "home" / ".hermes"))}
{env}
{call}
"""
    # From a file, not `bash -c`: the suite's live-system guard refuses a command line that contains
    # the words of the function's own advice ("hermes update").
    script_file = tmp_path / "run.sh"
    script_file.write_text(script, encoding="utf-8")
    return subprocess.run([bash, str(script_file)], capture_output=True, text=True, check=False)


def _calls(tmp_path: Path) -> list[str]:
    f = tmp_path / "calls"
    return f.read_text(encoding="utf-8").splitlines() if f.exists() else []


@pytest.mark.parametrize("bash", BASHES)
def test_a_stock_hermes_is_found(tmp_path, bash):
    hermes = _fake_hermes(tmp_path, install_dir=_stock_hermes_dir(tmp_path))
    result = _run(tmp_path, bash, "existing_foreign_hermes")
    assert result.returncode == 0, result.stderr
    assert result.stdout.strip() == str(hermes)


@pytest.mark.parametrize("bash", BASHES)
def test_an_agent_blackbox_checkout_is_ours_and_keeps_the_standalone_install(tmp_path, bash):
    ours = tmp_path / "agent-blackbox"
    (ours / "plugins" / "blackbox").mkdir(parents=True)
    (ours / "plugins" / "blackbox" / "plugin.yaml").write_text("name: blackbox\n", encoding="utf-8")
    _fake_hermes(tmp_path, install_dir=ours)
    assert _run(tmp_path, bash, "existing_foreign_hermes").returncode != 0


@pytest.mark.parametrize("bash", BASHES)
def test_nothing_is_decided_when_hermes_is_absent_or_does_not_say_where_it_lives(tmp_path, bash):
    (tmp_path / "home").mkdir()
    assert _run(tmp_path, bash, "existing_foreign_hermes").returncode != 0      # no hermes at all
    _fake_hermes(tmp_path, install_dir=None)                                     # no "Install directory"
    assert _run(tmp_path, bash, "existing_foreign_hermes").returncode != 0


@pytest.mark.parametrize("bash", BASHES)
def test_the_standalone_install_can_be_kept_on_purpose(tmp_path, bash):
    _fake_hermes(tmp_path, install_dir=_stock_hermes_dir(tmp_path))
    result = _run(tmp_path, bash, "existing_foreign_hermes", env="BLACKBOX_USE_EXISTING_HERMES=0")
    assert result.returncode != 0


@pytest.mark.parametrize("bash", BASHES)
def test_blackbox_is_installed_from_the_catalog_then_setup_runs_and_the_launcher_is_untouched(tmp_path, bash):
    hermes = _fake_hermes(tmp_path, install_dir=_stock_hermes_dir(tmp_path))
    before = hermes.read_bytes()
    result = _run(tmp_path, bash, f"install_into_existing_hermes {shlex.quote(str(hermes))}")
    assert result.returncode == 0, result.stdout + result.stderr
    assert _calls(tmp_path) == ["plugins list", "plugins install blackbox --yes-deps --enable", "blackbox setup"]
    assert hermes.read_bytes() == before
    assert "no second Hermes is installed" in result.stdout


@pytest.mark.parametrize("bash", BASHES)
def test_an_installed_plugin_is_updated_to_the_catalog_pin_and_the_store_choice_is_passed_on(tmp_path, bash):
    hermes = _fake_hermes(tmp_path, install_dir=_stock_hermes_dir(tmp_path),
                          plugins_list="│ blackbox │ enabled │ 1.0.0 │")
    result = _run(tmp_path, bash, f"install_into_existing_hermes {shlex.quote(str(hermes))}",
                  env="BLACKBOX_DKG_STORE_BACKEND=oxigraph")
    assert result.returncode == 0, result.stdout + result.stderr
    assert _calls(tmp_path) == ["plugins list", "plugins update blackbox", "blackbox setup --store oxigraph"]


@pytest.mark.parametrize("bash", BASHES)
def test_a_plugin_folder_left_by_an_earlier_run_is_updated_not_reinstalled(tmp_path, bash):
    """Live run 2026-11-03: an earlier, rolled-back setup left ~/.hermes/plugins/blackbox, and
    `hermes plugins install` refused with "Plugin 'blackbox' already exists"."""
    hermes = _fake_hermes(tmp_path, install_dir=_stock_hermes_dir(tmp_path))
    (tmp_path / "home" / ".hermes" / "plugins" / "blackbox").mkdir(parents=True)
    result = _run(tmp_path, bash, f"install_into_existing_hermes {shlex.quote(str(hermes))}")
    assert result.returncode == 0, result.stdout + result.stderr
    assert _calls(tmp_path) == ["plugins list", "plugins update blackbox", "blackbox setup"]


@pytest.mark.parametrize("bash", BASHES)
def test_a_failed_plugin_install_stops_before_setup(tmp_path, bash):
    hermes = _fake_hermes(tmp_path, install_dir=_stock_hermes_dir(tmp_path), install_ok=False)
    result = _run(tmp_path, bash, f"install_into_existing_hermes {shlex.quote(str(hermes))}")
    assert result.returncode == 1
    assert "blackbox setup" not in _calls(tmp_path)
    assert "Update Hermes (hermes update)" in result.stdout


def test_the_check_runs_before_anything_is_installed_and_only_for_the_one_liner():
    main = _body("main")
    check = main.index("existing_hermes=\"$(existing_foreign_hermes)\"")
    assert check < main.index("install_record_begin") < main.index("resolve_repo")
    guard = main[:check]
    assert 'if [ "$BLACKBOX_SETUP_ONLY" != true ] && ! install_uses_local_checkout; then' in guard


def test_the_plugin_ships_the_same_installer():
    shipped = INSTALL_SH.parents[1] / "plugins" / "blackbox" / "setup" / "blackbox-install.sh"
    assert shipped.read_bytes() == INSTALL_SH.read_bytes()


def test_the_windows_installer_hands_over_to_an_existing_hermes_too():
    """The .ps1 mirrors the .sh (LES-029); its parse test runs where PowerShell is installed (CI)."""
    ps1 = INSTALL_SH.with_suffix(".ps1").read_text(encoding="utf-8")
    main = ps1[ps1.index("function Main {"):]
    check = main.index("$existingHermes = Find-ExistingForeignHermes")
    assert "if (-not $SetupOnly -and -not (Test-RunsFromBlackboxCheckout)) {" in main[:check]
    assert check < main.index("Resolve-Repo")
    assert 'if (Test-Path (Join-Path $dir "plugins\\blackbox\\plugin.yaml")) { return $null }' in ps1
    assert "& $Hermes plugins install blackbox --yes-deps --enable" in ps1
    assert '$setupArgs = @("blackbox", "setup")' in ps1 and 'if ($env:BLACKBOX_USE_EXISTING_HERMES -eq "0")' in ps1
    shipped = INSTALL_SH.parents[1] / "plugins" / "blackbox" / "setup" / "blackbox-install.ps1"
    assert shipped.read_bytes() == INSTALL_SH.with_suffix(".ps1").read_bytes()
