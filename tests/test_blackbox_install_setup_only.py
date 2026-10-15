"""The installer's setup-only mode: everything after Hermes, in the Hermes that runs it.

A Hermes plugin-catalog install brings the plugin only; `hermes blackbox setup`
runs scripts/blackbox-install.sh with BLACKBOX_SETUP_ONLY=true for the rest —
the DKG node, the graphs, attach, sync, dashboard, services. These tests run the
real functions out of the script: setup-only skips every step that installs
Hermes and keeps every step after it, writes `blackbox` beside the user's
`hermes` without touching it, and finds its helper scripts in the plugin.
The curl path (BLACKBOX_SETUP_ONLY unset) is unchanged.
"""

from __future__ import annotations

import re
import shlex
import shutil
import subprocess
import os
import sys
from pathlib import Path

import pytest

INSTALL_SH = Path(__file__).resolve().parents[1] / "scripts" / "blackbox-install.sh"

HERMES_STEPS = ["check_git", "check_python", "resolve_repo", "release_old_hermes_link", "install_python_env", "link_hermes",
                "refresh_blackbox_plugin_copy", "run_hermes_setup"]


def _body(name: str) -> str:
    match = re.search(rf"^{re.escape(name)}\(\)\s*\{{\s*\n(?P<body>.*?)^\}}", INSTALL_SH.read_text(encoding="utf-8"),
                      re.MULTILINE | re.DOTALL)
    assert match is not None, f"{name}() not found"
    return match["body"]


def _main_steps(setup_only: bool) -> list[str]:
    """The step functions main() calls, in order, each stubbed to print its name."""
    steps = set(re.findall(r"^\s+([a-z_]+)\s*$", _body("main"), re.MULTILINE)) - {"else", "fi", "then"}
    stubs = "\n".join(f"{step}() {{ echo {step}; }}" for step in sorted(steps))
    script = f"""
heading() {{ :; }}
{stubs}
BLACKBOX_INSTALL_INCOMPLETE=false
BLACKBOX_SETUP_ONLY={'true' if setup_only else 'false'}
main() {{
{_body("main")}
}}
main
"""
    result = subprocess.run(["bash", "-c", script], capture_output=True, text=True, check=True)
    return result.stdout.split()


def test_curl_install_runs_every_step_in_the_same_order_as_before():
    steps = _main_steps(setup_only=False)

    assert steps[:10] == ["banner", "detect_os", "check_git", "check_python", "ensure_node", "resolve_repo",
                          "release_old_hermes_link", "install_python_env", "link_hermes", "refresh_blackbox_plugin_copy"]
    assert steps.index("run_hermes_setup") < steps.index("install_dkg")


def test_setup_only_skips_the_hermes_steps_and_keeps_everything_after():
    curl = _main_steps(setup_only=False)
    setup = _main_steps(setup_only=True)

    assert not set(HERMES_STEPS) & set(setup)
    assert setup[:4] == ["banner", "detect_os", "ensure_node", "use_running_hermes"]
    after_hermes = curl[curl.index("run_hermes_setup") + 1:]
    assert setup[4:] == after_hermes


def _use_running_hermes(tmp_path: Path, *, hermes_on_path: bool, inner_bin: Path | None = None) -> tuple[subprocess.CompletedProcess, Path]:
    """Run use_running_hermes with the user's `hermes` in tmp/user-bin (or, with
    *inner_bin*, Hermes's internal bin folder first on PATH as Hermes runs the setup)."""
    venv = tmp_path / "venv"
    (venv / "bin").mkdir(parents=True)
    python = venv / "bin" / "python"
    python.write_text("#!/bin/sh\n", encoding="utf-8")
    python.chmod(0o755)
    user_bin = tmp_path / "user-bin"
    user_bin.mkdir()
    hermes = user_bin / "hermes"
    hermes.write_text("#!/bin/sh\necho the-users-hermes\n", encoding="utf-8")
    hermes.chmod(0o755)
    path = f"{user_bin}:/usr/bin:/bin" if hermes_on_path else "/usr/bin:/bin"
    if inner_bin is not None:
        path = f"{inner_bin}:{path}"
    home = tmp_path / "home"
    script = f"""
heading() {{ :; }}
ok() {{ echo "OK $*"; }}
warn() {{ echo "WARN $*"; }}
err() {{ echo "ERR $*"; }}
install_blackbox_shim() {{
{_body("install_blackbox_shim")}
}}
use_running_hermes() {{
{_body("use_running_hermes")}
}}
PATH={shlex.quote(path)}
HOME={shlex.quote(str(home))}
HERMES_BIN={shlex.quote(str(hermes))}
VENV_DIR={shlex.quote(str(venv))}
use_running_hermes
"""
    return subprocess.run(["bash", "-c", script], capture_output=True, text=True, check=False), hermes


def test_setup_only_writes_blackbox_beside_the_users_hermes_and_never_replaces_it(tmp_path):
    result, hermes = _use_running_hermes(tmp_path, hermes_on_path=True)

    assert result.returncode == 0, result.stdout + result.stderr
    shim = hermes.parent / "blackbox"
    assert shim.is_file() and "managed-by: agent-blackbox-installer" in shim.read_text(encoding="utf-8")
    assert not hermes.is_symlink() and hermes.read_text(encoding="utf-8") == "#!/bin/sh\necho the-users-hermes\n"


def test_setup_only_writes_blackbox_beside_the_launcher_hermes_publishes_not_the_inner_binary(tmp_path):
    """Proven on a fresh droplet (2026-10-14): Hermes runs the setup with its own
    .hermes/bin first on PATH, the shim landed there, and `blackbox` was not a command."""
    inner_bin = tmp_path / "hermes-agent" / ".hermes" / "bin"
    inner_bin.mkdir(parents=True)
    (inner_bin / "hermes").write_text("#!/bin/sh\n", encoding="utf-8")
    (inner_bin / "hermes").chmod(0o755)
    launcher_dir = tmp_path / "home" / ".local" / "bin"
    launcher_dir.mkdir(parents=True)
    launcher = launcher_dir / "hermes"
    launcher.write_text(f"#!/bin/sh\nexec {inner_bin / 'hermes'} \"$@\"\n", encoding="utf-8")
    launcher.chmod(0o755)

    result, _ = _use_running_hermes(tmp_path, hermes_on_path=False, inner_bin=inner_bin)

    assert result.returncode == 0, result.stdout + result.stderr
    assert (launcher_dir / "blackbox").is_file()
    assert not (inner_bin / "blackbox").exists()


def test_setup_only_without_the_callers_hermes_stops_with_the_command_to_use(tmp_path):
    script = f"""
heading() {{ :; }}
ok() {{ :; }}
err() {{ echo "ERR $*"; }}
use_running_hermes() {{
{_body("use_running_hermes")}
}}
HERMES_BIN={shlex.quote(str(tmp_path / "missing"))}
VENV_DIR={shlex.quote(str(tmp_path))}
use_running_hermes
"""
    result = subprocess.run(["bash", "-c", script], capture_output=True, text=True, check=False)

    assert result.returncode == 1
    assert "hermes blackbox setup" in result.stdout


def _helper(env: str) -> str:
    script = f"""
blackbox_helper() {{
{_body("blackbox_helper")}
}}
REPO_DIR=/checkout
{env}
blackbox_helper blackbox-blazegraph.mjs
"""
    return subprocess.run(["bash", "-c", script], capture_output=True, text=True, check=True).stdout


def test_helpers_come_from_the_checkout_in_a_curl_install():
    assert _helper("") == "/checkout/scripts/blackbox-blazegraph.mjs"


def test_helpers_come_from_the_plugin_in_setup_only_mode():
    assert _helper("BLACKBOX_HELPER_DIR=/home/x/plugins/blackbox/setup") == \
        "/home/x/plugins/blackbox/setup/blackbox-blazegraph.mjs"


def test_no_step_after_hermes_reads_the_checkout_directly():
    """Everything setup-only mode runs reaches the checkout only through blackbox_helper /
    BLACKBOX_PLUGIN_DIR / BLACKBOX_REVISION, so an empty REPO_DIR never points at the wrong folder."""
    lines = INSTALL_SH.read_text(encoding="utf-8").splitlines()
    guard = '[ -n "$REPO_DIR" ]'
    direct = [line.strip() for index, line in enumerate(lines)
              if "$REPO_DIR" in line and not line.lstrip().startswith("#")
              and guard not in lines[index - 1]]   # the line under a non-empty check is safe
    allowed = ("REPO_DIR=", "${BLACKBOX_HELPER_DIR:-$REPO_DIR/scripts}", "${BLACKBOX_PLUGIN_DIR:-$REPO_DIR/plugins/blackbox}",
               "${BLACKBOX_PLUGIN_DIR:-$REPO_DIR}", '[ -n "$REPO_DIR" ]')
    hermes_steps = "".join(_body(step) for step in ("resolve_repo", "install_python_env", "use_hermes_selected_venv",
                                                    "ensure_web_extra", "minimal_python_env",
                                                    "refresh_blackbox_plugin_copy", "reuse_existing_hermes_api_keys"))
    stray = [line for line in direct if line not in hermes_steps and not any(token in line for token in allowed)]
    assert stray == []


def test_setup_only_keeps_community_sharing_on_by_reading_consent_from_the_plugin_folder(tmp_path, monkeypatch):
    """Stock Hermes has its own `plugins` package, so the config writer's consent check must load
    Blackbox from the plugin folder it is given. If it could not, it would answer "no consent" and
    turn sharing OFF on every catalog install (found while building setup-only mode, 2026-10-14)."""
    helper = INSTALL_SH.read_text(encoding="utf-8").split("def _consent_in_force(checkout):", 1)[1].split("\nif ", 1)[0]
    namespace: dict = {"sys": sys, "os": os}
    exec("def _consent_in_force(checkout):" + helper, namespace)
    monkeypatch.setenv("BLACKBOX_HOME", str(tmp_path / "bb"))   # no sharing record: the default, sharing on
    plugin_dir = Path(__file__).resolve().parents[1] / "plugins" / "blackbox"

    assert namespace["_consent_in_force"](str(plugin_dir)) is True


def test_the_config_writer_is_given_the_plugin_folder_in_setup_only_mode():
    assert '"${BLACKBOX_PLUGIN_DIR:-$REPO_DIR}" <<\'PYEOF\'' in _body("enable_and_configure")


def _install_dkg_package(tmp_path: Path, *, pinned: str, published: str) -> subprocess.CompletedProcess:
    """install_blackbox_dkg_package with a stub npm that publishes *published* and logs installs."""
    fake_bin = tmp_path / "bin"
    fake_bin.mkdir()
    log = tmp_path / "npm-calls"
    npm = fake_bin / "npm"
    npm.write_text(f"""#!/bin/sh
echo "$*" >> {shlex.quote(str(log))}
if [ "$1" = view ]; then echo {shlex.quote(published)}; exit 0; fi
exit 1
""", encoding="utf-8")
    npm.chmod(0o755)
    script = f"""
warn() {{ echo "WARN $*"; }}
ok() {{ echo "OK $*"; }}
step() {{ :; }}
install_blackbox_dkg_package() {{
{_body("install_blackbox_dkg_package")}
}}
PATH={shlex.quote(str(fake_bin))}:/usr/bin:/bin
HERMES_HOME={shlex.quote(str(tmp_path / "home"))}
BLACKBOX_DKG_CLI_DIR={shlex.quote(str(tmp_path / "dkg"))}
BLACKBOX_DKG_PACKAGE=@origintrail-official/dkg@10.0.23
BLACKBOX_DKG_INTEGRITY={shlex.quote(pinned)}
install_blackbox_dkg_package
"""
    result = subprocess.run(["bash", "-c", script], capture_output=True, text=True, check=False)
    result.calls = log.read_text(encoding="utf-8").splitlines() if log.exists() else []
    return result


def test_a_pinned_dkg_package_with_another_checksum_is_never_installed(tmp_path):
    result = _install_dkg_package(tmp_path, pinned="sha512-pinned", published="sha512-something-else")

    assert result.returncode == 1
    assert "not the one this Blackbox release pins" in result.stdout
    assert not any(call.startswith("install") for call in result.calls)


def test_a_pinned_dkg_package_with_the_pinned_checksum_goes_on_to_install(tmp_path):
    result = _install_dkg_package(tmp_path, pinned="sha512-pinned", published="sha512-pinned")

    assert "checksum matches the pinned one" in result.stdout
    assert any(call.startswith("install") and "@origintrail-official/dkg@10.0.23" in call for call in result.calls)


# -- the Windows installer: the same contract (parsed by its own toolchain in CI, LES-037) --------

INSTALL_PS1 = INSTALL_SH.with_suffix(".ps1")


def _ps1_function(name: str) -> str:
    match = re.search(rf"^function {re.escape(name)}\b.*?^\}}", INSTALL_PS1.read_text(encoding="utf-8"),
                      re.MULTILINE | re.DOTALL)
    assert match is not None, f"{name} not found"
    return match.group(0)


def test_windows_setup_only_skips_the_hermes_steps():
    main = _ps1_function("Main")
    setup_branch = main.split("if ($SetupOnly) {", 1)[1].split("} else {", 1)[0]

    assert "Use-RunningHermes" in setup_branch and "Test-NodeJs" in setup_branch
    assert not any(step in setup_branch for step in ("Test-Git", "Resolve-Python", "Resolve-Repo", "Install-PythonEnv"))
    assert main.index("Install-BlackboxCommand") > main.index("} else {")   # after both branches


def test_windows_helpers_come_from_the_plugin_in_setup_only_mode():
    text = INSTALL_PS1.read_text(encoding="utf-8").replace(_ps1_function("Get-BlackboxHelper"), "")

    assert 'Join-Path $RepoDir "scripts' not in text   # only the helper's own curl default builds it
    assert "if ($env:BLACKBOX_HELPER_DIR) { return Join-Path $env:BLACKBOX_HELPER_DIR $Name }" in _ps1_function("Get-BlackboxHelper")


def test_windows_keeps_sharing_on_and_pins_the_dkg_checksum():
    text = INSTALL_PS1.read_text(encoding="utf-8")

    assert 'os.path.isfile(os.path.join(checkout, "plugin.yaml"))' in text
    assert "$(if ($env:BLACKBOX_PLUGIN_DIR) { $env:BLACKBOX_PLUGIN_DIR } else { $RepoDir })" in text
    assert "if ($published -ne $DkgIntegrity)" in _ps1_function("Install-BlackboxDkgPackage")
    assert '$DkgAllowScripts = @("@origintrail-official/dkg", "better-sqlite3", "@openuidev/lang-core")' in text
    assert '-SimpleMatch "had install scripts blocked"' in _ps1_function("Install-BlackboxDkgPackage")
    assert "& npm rebuild --prefix $DkgCliDir better-sqlite3" in _ps1_function("Install-BlackboxDkgPackage")


def _install_with_npm(tmp_path: Path, *, npm_output: str, existing_package_json: str | None = None):
    """install_blackbox_dkg_package with a stub npm that prints *npm_output* and succeeds."""
    fake_bin = tmp_path / "bin"
    fake_bin.mkdir()
    cli_dir = tmp_path / "dkg"
    cli_dir.mkdir()
    if existing_package_json is not None:
        (cli_dir / "package.json").write_text(existing_package_json, encoding="utf-8")
    npm = fake_bin / "npm"
    npm.write_text(f"#!/bin/sh\nprintf '%s\\n' {shlex.quote(npm_output)}\nexit 0\n", encoding="utf-8")
    npm.chmod(0o755)
    script = f"""
warn() {{ echo "WARN $*"; }}
ok() {{ echo "OK $*"; }}
step() {{ :; }}
install_blackbox_dkg_package() {{
{_body("install_blackbox_dkg_package")}
}}
BLACKBOX_DKG_ALLOW_SCRIPTS=(@origintrail-official/dkg better-sqlite3 @openuidev/lang-core)
PATH={shlex.quote(str(fake_bin))}:$PATH
HERMES_HOME={shlex.quote(str(tmp_path / "home"))}
BLACKBOX_DKG_CLI_DIR={shlex.quote(str(cli_dir))}
BLACKBOX_DKG_BIN={shlex.quote(str(cli_dir / "missing-dkg"))}
BLACKBOX_DKG_PACKAGE=@origintrail-official/dkg@10.0.23
BLACKBOX_DKG_INTEGRITY=
install_blackbox_dkg_package
"""
    result = subprocess.run(["bash", "-c", script], capture_output=True, text=True, check=False)
    return result, cli_dir / "package.json"


def test_npm_12_is_told_which_install_scripts_the_dkg_node_needs(tmp_path):
    """npm 12 runs no install script that package.json's allowScripts does not list; without the
    better-sqlite3 build the DKG node crashed on every start (stock Hermes's Node 26 / npm 12, 2026-10-14)."""
    import json as _json
    if not shutil.which("node"):
        pytest.skip("Node.js is not installed")
    _, package_json = _install_with_npm(tmp_path, npm_output="added 1 package",
                                        existing_package_json='{"allowScripts": {"better-sqlite3": false}, "x": 1}')

    data = _json.loads(package_json.read_text(encoding="utf-8"))
    assert data["allowScripts"] == {"better-sqlite3": False, "@origintrail-official/dkg": True, "@openuidev/lang-core": True}
    assert data["x"] == 1   # everything else in the file is kept


def test_a_blocked_install_script_stops_the_install_with_the_package_named(tmp_path):
    if not shutil.which("node"):
        pytest.skip("Node.js is not installed")
    blocked = ("npm warn install-scripts 1 packages had install scripts blocked because they are not covered by allowScripts:\n"
               "npm warn install-scripts   new-native-dep@1.0.0 (install: node-gyp rebuild)")
    result, _ = _install_with_npm(tmp_path, npm_output=blocked)

    assert result.returncode == 1
    assert "npm blocked install scripts the DKG node needs: new-native-dep@1.0.0" in result.stdout



def _link_steps(tmp_path: Path, *, pm_checkout: bool, existing: str | None) -> Path:
    """release_old_hermes_link then link_hermes, as a curl install runs them; returns ~/.local/bin/hermes."""
    home = tmp_path / "home"
    (home / ".local" / "bin").mkdir(parents=True)
    repo = tmp_path / "repo"
    (repo / "scripts").mkdir(parents=True)
    if pm_checkout:
        runner = repo / "scripts" / "run-in-hermes-env"
        runner.write_text("#!/bin/sh\n", encoding="utf-8")
        runner.chmod(0o755)
    venv_hermes = tmp_path / "installs" / "env" / "venv" / "bin" / "hermes"
    venv_hermes.parent.mkdir(parents=True)
    venv_hermes.write_text("#!/bin/sh\n", encoding="utf-8")
    venv_hermes.chmod(0o755)
    link = home / ".local" / "bin" / "hermes"
    if existing == "old-link":
        link.symlink_to(venv_hermes)
    elif existing == "hermes-launcher":
        link.write_text("#!/bin/sh\nexec /somewhere/.hermes/bin/hermes \"$@\"\n", encoding="utf-8")
    script = f"""
ok() {{ :; }}
warn() {{ :; }}
step() {{ :; }}
install_blackbox_shim() {{ :; }}
release_old_hermes_link() {{
{_body("release_old_hermes_link")}
}}
link_hermes() {{
{_body("link_hermes")}
}}
HOME={shlex.quote(str(home))}
REPO_DIR={shlex.quote(str(repo))}
HERMES_BIN={shlex.quote(str(venv_hermes))}
VENV_DIR={shlex.quote(str(venv_hermes.parent.parent))}
release_old_hermes_link
link_hermes
"""
    subprocess.run(["bash", "-c", script], check=True, capture_output=True, text=True)
    return link


def test_on_hermes_0_21_7_the_installer_leaves_hermes_its_own_launcher(tmp_path):
    """Hermes publishes ~/.local/bin/hermes itself and refuses to replace a link pointing outside its
    checkout, so a link made here broke every re-run ("launcher publication failed", 2026-10-14)."""
    link = _link_steps(tmp_path, pm_checkout=True, existing="hermes-launcher")

    assert not link.is_symlink() and "/.hermes/bin/hermes" in link.read_text(encoding="utf-8")


def test_an_old_link_from_an_earlier_install_is_removed_so_hermes_can_publish(tmp_path):
    link = _link_steps(tmp_path, pm_checkout=True, existing="old-link")

    assert not link.exists() and not link.is_symlink()


def test_an_older_hermes_without_a_launcher_still_gets_the_link(tmp_path):
    link = _link_steps(tmp_path, pm_checkout=False, existing=None)

    assert link.is_symlink()


def _install_with_sqlite(tmp_path: Path, *, built_before: bool, rebuild_works: bool):
    """install_blackbox_dkg_package where better-sqlite3 loads only once a `built` marker exists;
    the stub npm's `rebuild` makes the marker when *rebuild_works*. Returns (result, npm calls)."""
    fake_bin = tmp_path / "bin"
    fake_bin.mkdir()
    cli_dir = tmp_path / "dkg"
    sqlite_dir = cli_dir / "node_modules" / "better-sqlite3"
    sqlite_dir.mkdir(parents=True)
    (sqlite_dir / "package.json").write_text('{"main": "index.js"}', encoding="utf-8")
    (sqlite_dir / "index.js").write_text(
        "const fs = require('fs');\n"
        "if (!fs.existsSync(__dirname + '/built')) throw new Error('not built');\n"
        "module.exports = class { constructor() {} close() {} };\n", encoding="utf-8")
    if built_before:
        (sqlite_dir / "built").write_text("", encoding="utf-8")
    calls = tmp_path / "npm-calls"
    npm = fake_bin / "npm"
    npm.write_text(f"""#!/bin/sh
echo "$*" >> {shlex.quote(str(calls))}
if [ "$1" = rebuild ] && [ {'1' if rebuild_works else '0'} = 1 ]; then touch {shlex.quote(str(sqlite_dir / 'built'))}; fi
exit 0
""", encoding="utf-8")
    npm.chmod(0o755)
    script = f"""
warn() {{ echo "WARN $*"; }}
ok() {{ echo "OK $*"; }}
step() {{ echo "STEP $*"; }}
install_blackbox_dkg_package() {{
{_body("install_blackbox_dkg_package")}
}}
BLACKBOX_DKG_ALLOW_SCRIPTS=(better-sqlite3)
PATH={shlex.quote(str(fake_bin))}:$PATH
HERMES_HOME={shlex.quote(str(tmp_path / "home"))}
BLACKBOX_DKG_CLI_DIR={shlex.quote(str(cli_dir))}
BLACKBOX_DKG_BIN={shlex.quote(str(cli_dir / "missing-dkg"))}
BLACKBOX_DKG_PACKAGE=@origintrail-official/dkg@10.0.23
BLACKBOX_DKG_INTEGRITY=
install_blackbox_dkg_package
"""
    result = subprocess.run(["bash", "-c", script], capture_output=True, text=True, check=False)
    return result, calls.read_text(encoding="utf-8").splitlines()


def test_a_half_built_sqlite_module_is_rebuilt_on_the_next_run(tmp_path):
    """A retry of a setup whose npm had blocked the build: npm skips scripts for packages it already
    has, so the DKG node kept crashing until the installer rebuilt the module (2026-10-14)."""
    if not shutil.which("node"):
        pytest.skip("Node.js is not installed")
    result, calls = _install_with_sqlite(tmp_path, built_before=False, rebuild_works=True)

    assert any(call.startswith("rebuild") and "better-sqlite3" in call for call in calls)
    assert "SQLite module built" in result.stdout


def test_a_sqlite_module_that_cannot_be_built_stops_the_install(tmp_path):
    if not shutil.which("node"):
        pytest.skip("Node.js is not installed")
    result, _ = _install_with_sqlite(tmp_path, built_before=False, rebuild_works=False)

    assert result.returncode == 1
    assert "could not be rebuilt" in result.stdout


def test_a_working_sqlite_module_is_not_rebuilt(tmp_path):
    if not shutil.which("node"):
        pytest.skip("Node.js is not installed")
    _, calls = _install_with_sqlite(tmp_path, built_before=True, rebuild_works=True)

    assert not any(call.startswith("rebuild") for call in calls)


def _docker_available(tmp_path: Path, *, docker: str | None, os_name: str = "linux") -> int:
    """blackbox_docker_available with a stub docker: None = not installed, "up" = running, "down" = stopped."""
    fake_bin = tmp_path / "bin"
    fake_bin.mkdir(parents=True, exist_ok=True)
    if docker is not None:
        stub = fake_bin / "docker"
        stub.write_text(f"#!/bin/sh\nexit {0 if docker == 'up' else 1}\n", encoding="utf-8")
        stub.chmod(0o755)
    script = f"""
blackbox_docker_available() {{
{_body("blackbox_docker_available")}
}}
OS={os_name}
HOME={shlex.quote(str(tmp_path))}
PATH={shlex.quote(str(fake_bin))}
blackbox_docker_available
"""
    return subprocess.run(["bash", "-c", script], capture_output=True, text=True, check=False).returncode


def test_docker_counts_as_available_only_when_it_can_run_the_store(tmp_path):
    assert _docker_available(tmp_path / "a", docker=None) != 0
    assert _docker_available(tmp_path / "b", docker="down") != 0
    assert _docker_available(tmp_path / "c", docker="up") == 0


def test_catalog_setup_without_docker_uses_oxigraph_and_curl_keeps_asking():
    """Founder decision 2026-10-14: `hermes blackbox setup` picks Oxigraph by itself when Docker is
    missing; the one-line installer keeps its ask-first fallback (unchanged since the first commit)."""
    body = _body("provision_blackbox_store")
    setup_only = body.index('if [ "$BLACKBOX_SETUP_ONLY" = true ] && [ "$BLACKBOX_DKG_STORE_BACKEND" = "auto" ] && ! blackbox_docker_available; then')
    ask_first = body.index('if ! require_docker_for_blazegraph; then')

    assert setup_only < ask_first
    assert "use_blackbox_oxigraph" in body[setup_only:ask_first]
    assert 'confirm_oxigraph_fallback "Blazegraph cannot be installed because Docker is unavailable."' in body[ask_first:]
    windows = _ps1_function("Initialize-BlackboxStore")
    assert windows.index('if ($SetupOnly -and $StoreBackend -eq "auto" -and -not $dockerRunning)') < windows.index("if (-not (Test-DockerForBlazegraph))")
