"""B10 contract: the installer registers boot persistence (KI-022, KI-032).

Script-level structural checks (the live reboot test runs on the dev
droplet and its evidence lives in the build worklog): the service units
exist in the installer with the right shape, the token gets owner-only
permissions, and registration runs in the install sequence.
"""

from __future__ import annotations

from pathlib import Path

import pytest


INSTALLER = (
    Path(__file__).resolve().parents[2] / "scripts" / "blackbox-install.sh"
)


def _src() -> str:
    return INSTALLER.read_text(encoding="utf-8")


def test_boot_service_function_exists_and_runs_in_main():
    src = _src()
    assert "register_boot_service()" in src
    main_body = src.split("main() {", 1)[1]
    assert "register_boot_service" in main_body
    # Runs after the dashboard is up, before the closing guidance.
    assert main_body.index("start_dashboard") < main_body.index("register_boot_service")
    assert main_body.index("register_boot_service") < main_body.index("next_steps")


def test_systemd_unit_shape():
    src = _src()
    assert "blackbox-dkg.service" in src
    assert "Restart=on-failure" in src
    assert "WantedBy=multi-user.target" in src
    assert "start --foreground" in src  # systemd owns the lifecycle, no daemonize
    assert "DKG_HOME=$BLACKBOX_DKG_HOME" in src


@pytest.mark.parametrize('backend', ['blazegraph', 'oxigraph-server', 'native'])
@pytest.mark.parametrize('platform', ['systemd', 'launchd'])
def test_boot_service_preserves_the_selected_sync_profile(backend, platform):
    """KI-044 remains ON for ordinary stores; explicit native checkpoints boot
    with the same profile as their managed sync, avoiding another journal open."""
    import subprocess
    import plistlib
    src = _src()
    end = 'UNIT' if platform == 'systemd' else 'PLIST'
    template = src.split('<<' + end + '\n', 1)[1].split('\n' + end, 1)[0]
    # Expand the actual shipped template, without registering any service.
    script = 'xml_escape() { printf "%s" "$1"; }; blackbox_dkg_launchd_error_log() { :; };\n'
    script += 'cat <<' + end + '\n' + template + '\n' + end
    rendered = subprocess.run(['bash', '-c', script], capture_output=True, text=True, timeout=30,
                              env={'PATH': '/usr/bin:/bin', 'BLACKBOX_DKG_SELECTED_STORE_BACKEND': backend}, check=False)
    assert rendered.returncode == 0, rendered.stderr
    expected = '0' if backend == 'native' else '1'
    if platform == 'systemd':
        assert f'Environment=DKG_SYNC_ON_CONNECT_ENABLED={expected}' in rendered.stdout.splitlines()
    else:
        assert plistlib.loads(rendered.stdout.encode())['EnvironmentVariables']['DKG_SYNC_ON_CONNECT_ENABLED'] == expected


def test_systemd_unit_leaves_the_reconciler_to_config_and_carries_the_stream_switch():
    """KI-282: the periodic sync reconciler is chosen per graph in config.json
    (off for Umanitek's default graph on DKG 10.0.21). An environment value in
    the unit would override that choice, so the unit must not set it. The exact
    batch stream, by contrast, exists ONLY as an environment switch: without it
    a service-started node recovers the graph about 8x slower."""
    unit = _src().split("[Unit]", 1)[1].split("UNIT", 1)[0]
    assert "DKG_SYNC_RECONCILER_ENABLED" not in unit
    assert "Environment=DKG_EXACT_BATCH_STREAM_ENABLED=$BLACKBOX_DKG_EXACT_BATCH_STREAM_ENABLED" in unit
    assert "Environment=DKG_VM_RECOVERY_PREFETCH_ENABLED=$BLACKBOX_DKG_VM_RECOVERY_PREFETCH_ENABLED" in unit


def test_systemd_unit_clears_orphaned_daemons():
    """KI-045 regression: DKG CLI commands auto-spawn a detached daemon when
    none is running; that orphan holds daemon.pid and crash-loops the unit
    forever. The unit must stop any orphan before starting and own the stop.
    """
    src = _src()
    unit = src.split("[Unit]", 1)[1].split("UNIT", 1)[0]
    assert "ExecStartPre=-" in unit  # '-' prefix: no orphan present is not an error
    assert "stop" in unit.split("ExecStartPre=-", 1)[1].split("\n", 1)[0]
    assert "ExecStop=" in unit


def test_launchd_plist_shape():
    src = _src()
    assert "ai.umanitek.blackbox-dkg.plist" in src
    assert "<key>RunAtLoad</key><true/>" in src
    assert "<key>KeepAlive</key>" in src


def test_token_permissions_tightened():
    """KI-032: any local process reading the token bypasses every gate."""
    src = _src()
    assert "secure_dkg_token_perms" in src
    assert "chmod 600" in src


def test_disable_instructions_documented():
    src = _src()
    assert "systemctl disable --now blackbox-dkg" in src
    assert "launchctl unload" in src


# ---------------------------------------------------------------- the dashboard (KI-296)


def _dashboard_function() -> str:
    import re
    match = re.search(r"^register_dashboard_service\(\) \{.*?\n\}", _src(), re.DOTALL | re.MULTILINE)
    assert match is not None
    return match.group(0)


def test_dashboard_service_is_registered_after_the_node_in_main():
    """KI-296: a rebooted machine got its DKG node back but not the dashboard, whose
    worker refreshes the rules and whose health poll drives the community pulse."""
    main_body = _src().split("main() {", 1)[1]
    assert main_body.index("register_boot_service") < main_body.index("register_dashboard_service")
    assert main_body.index("register_dashboard_service") < main_body.index("next_steps")


def test_dashboard_unit_starts_after_the_node_and_runs_the_dashboard():
    unit = _dashboard_function().split("[Unit]", 1)[1].split("DASHUNIT", 1)[0]
    assert "After=network-online.target blackbox-dkg.service" in unit
    assert "ExecStart=$HERMES_BIN blackbox dashboard" in unit
    assert "Environment=HERMES_HOME=$HERMES_HOME" in unit
    assert "Restart=on-failure" in unit


def test_dashboard_service_respects_auto_dashboard_off():
    body = _dashboard_function()
    assert body.index('case "$BLACKBOX_AUTO_DASHBOARD"') < body.index("[Unit]")


@pytest.mark.live_system_guard_bypass   # systemctl is a stub that records its arguments
def test_dashboard_service_is_written_and_enabled_on_a_systemd_machine(tmp_path):
    """Runs the real function on a Linux-shaped sandbox: a non-root user gets a user
    unit under $HOME, and systemctl is asked to enable it (stub records the calls)."""
    import shutil
    import subprocess
    if shutil.which("bash") is None:
        import pytest
        pytest.skip("needs bash")
    stubs = tmp_path / "bin"
    stubs.mkdir()
    calls = tmp_path / "systemctl.calls"
    for name, body in (("systemctl", f'echo "$*" >> "{calls}"'), ("node", "exit 0"), ("uname", "echo Linux"),
                       ("hermes", "exit 0")):
        (stubs / name).write_text(f"#!/bin/sh\n{body}\n")
        (stubs / name).chmod(0o755)
    script = "\n".join([
        "set -euo pipefail",
        "ok() { echo \"OK $*\"; }", "warn() { echo \"WARN $*\"; }", "step() { :; }",
        "id() { echo 1000; }",           # a non-root user: the unit goes under $HOME
        f"HOME={tmp_path}", f"HERMES_HOME={tmp_path}/.hermes", f"HERMES_BIN={stubs}/hermes",
        "BLACKBOX_AUTO_DASHBOARD=1", "BLACKBOX_DASHBOARD_RESTART_PENDING=false",
        _installer_constant("BLACKBOX_SERVICE_SYSTEM_PATH"),
        _dashboard_function(),
        "register_dashboard_service",
    ])
    result = subprocess.run(["bash", "-c", script], capture_output=True, text=True,
                            env={"PATH": f"{stubs}:/usr/bin:/bin"}, check=False)

    assert result.returncode == 0, result.stderr
    unit = tmp_path / ".config" / "systemd" / "user" / "blackbox-dashboard.service"
    assert f"ExecStart={stubs}/hermes blackbox dashboard" in unit.read_text()
    # a new unit is enabled AND started now, through systemd (KI-455: restart = start for a new unit)
    assert "--user enable blackbox-dashboard" in calls.read_text()
    assert "--user restart blackbox-dashboard" in calls.read_text()
    # a node the dashboard's sync restarts inherits this PATH: it must reach lsof too (KI-427)
    assert "/usr/sbin" in unit.read_text().split("Environment=PATH=", 1)[1].splitlines()[0].split(":")


# ------------------------------------------- an update restarts the running dashboard (KI-300)


def _start_dashboard_run(tmp_path, *, running: bool, marker: str | None):
    """Run the real start_dashboard() with a real git checkout, a curl stub that
    says whether a dashboard answers, and run_detached recorded instead of run."""
    import re
    import subprocess
    repo = tmp_path / "repo"
    repo.mkdir()
    subprocess.run(["git", "init", "-q", "-b", "main"], cwd=repo, check=True)
    (repo / "f").write_text("x")
    subprocess.run(["git", "add", "."], cwd=repo, check=True)
    subprocess.run(["git", "-c", "user.name=T", "-c", "user.email=t@example.com", "commit", "-qm", "v"],
                   cwd=repo, check=True)
    head = subprocess.run(["git", "rev-parse", "HEAD"], cwd=repo, capture_output=True, text=True, check=False).stdout.strip()
    home = tmp_path / ".hermes"
    if marker is not None:
        (home / "blackbox").mkdir(parents=True)
        (home / "blackbox" / ".dashboard-revision").write_text((head if marker == "HEAD" else marker) + "\n")
    stubs = tmp_path / "bin"
    stubs.mkdir()
    (stubs / "curl").write_text(f"#!/bin/sh\nexit {0 if running else 7}\n")
    (stubs / "curl").chmod(0o755)
    launched = tmp_path / "launched"
    (stubs / "uname").write_text("#!/bin/sh\necho Linux\n")   # no machine's own launchd or units
    (stubs / "uname").chmod(0o755)
    func = re.search(r"^start_dashboard\(\) \{.*?\n\}", _src(), re.DOTALL | re.MULTILINE).group(0)
    script = "\n".join([
        "set -euo pipefail", "ok() { :; }", "warn() { :; }", "step() { :; }", "heading() { :; }",
        "sleep() { :; }", f'run_detached() {{ echo launched >> "{launched}"; }}',
        f"HOME={tmp_path}", f"BLACKBOX_SYSTEMD_DIR={tmp_path}/systemd",
        f"HERMES_HOME={home}", f"REPO_DIR={repo}", "HERMES_BIN=/bin/true", "BLACKBOX_AUTO_DASHBOARD=1",
        "BLACKBOX_DASHBOARD_RESTART_PENDING=false", _installer_constant("BLACKBOX_DASHBOARD_LAUNCHD_LABEL"),
        _top_level_function("blackbox_dashboard_supervisor"), func, "start_dashboard",
    ])
    result = subprocess.run(["bash", "-c", script], capture_output=True, text=True,
                            env={"PATH": f"{stubs}:/usr/bin:/bin"}, check=False)
    assert result.returncode == 0, result.stderr
    revision = (home / "blackbox" / ".dashboard-revision")
    return launched.exists(), (revision.read_text().strip() if revision.exists() else ""), head


@pytest.mark.live_system_guard_bypass   # a throwaway temp repo and stubs, never the real checkout
def test_an_update_restarts_a_dashboard_running_older_code(tmp_path):
    """KI-300: re-running the installer updated the code but left the old dashboard
    process running the old code ("Dashboard already running") until a reboot."""
    launched, revision, head = _start_dashboard_run(tmp_path, running=True, marker="0" * 40)
    assert launched and revision == head


@pytest.mark.live_system_guard_bypass   # a throwaway temp repo and stubs, never the real checkout
def test_a_dashboard_already_running_the_current_code_is_left_alone(tmp_path):
    launched, _, _ = _start_dashboard_run(tmp_path, running=True, marker="HEAD")
    assert not launched


@pytest.mark.live_system_guard_bypass   # a throwaway temp repo and stubs, never the real checkout
def test_a_first_launch_records_the_revision(tmp_path):
    launched, revision, head = _start_dashboard_run(tmp_path, running=False, marker=None)
    assert launched and revision == head


# ------------------------------- the boot units carry the node's environment-only settings (KI-308)

def _top_level_function(name: str) -> str:
    """The text of one top-level shell function of the installer."""
    src = _src()
    start = src.index(f"\n{name}() {{\n") + 1
    return src[start:src.index("\n}\n", start) + 3]


_NODE_SETTINGS = {
    "BLACKBOX_DKG_HOME": "/srv/bb/.dkg",
    "BLACKBOX_DKG_BIN": "/srv/bb/dkg/node_modules/.bin/dkg",
    "BLACKBOX_DKG_EXACT_BATCH_STREAM_ENABLED": "1",
    "BLACKBOX_DKG_VM_RECOVERY_PREFETCH_ENABLED": "1",
    "BLACKBOX_DKG_NODE_OPTIONS": "--enable-source-maps --max-old-space-size=6144",
    "BLACKBOX_DKG_STORE_QUEUE_LIMIT": "512",
    "BLACKBOX_DKG_LIST_CONTEXT_GRAPHS_PROJECTION": "1",
}


def _installed_dkg_bin(tmp_path) -> str:
    """A stand-in node binary: register_boot_service registers nothing for a missing one."""
    dkg = tmp_path / "dkg" / "node_modules" / ".bin" / "dkg"
    dkg.parent.mkdir(parents=True)
    dkg.write_text("#!/bin/sh\nexit 0\n")
    dkg.chmod(0o755)
    return str(dkg)


def _installer_constant(name: str) -> str:
    """The `NAME=value` line the installer sets at its top level, so the sandbox cannot drift from it."""
    import re
    match = re.search(rf"^{name}=\S+", _src(), re.MULTILINE)
    assert match is not None, name
    return match.group(0)


def _register_boot_service(tmp_path, os_name: str):
    """Run the real register_boot_service in a sandbox shaped like *os_name*."""
    import shutil
    import subprocess
    if shutil.which("bash") is None:
        pytest.skip("needs bash")
    stubs = tmp_path / "bin"
    stubs.mkdir()
    for name, body in (("uname", f"echo {os_name}"), ("node", "exit 0"), ("systemctl", "exit 0"),
                       ("launchctl", "exit 0")):
        (stubs / name).write_text(f"#!/bin/sh\n{body}\n")
        (stubs / name).chmod(0o755)
    script = "\n".join([
        "set -euo pipefail",
        "ok() { :; }", "warn() { echo \"WARN $*\"; }", "step() { :; }", "heading() { :; }",
        "secure_dkg_token_perms() { :; }", "id() { echo 1000; }",
        "hand_dkg_node_to_service() { :; }", "ensure_user_lingering() { :; }",   # own tests: test_blackbox_install_node_handover.py, _user_linger.py
        f"HOME={tmp_path}",
        *(f"{key}='{value}'" for key, value in _NODE_SETTINGS.items()),
        f"BLACKBOX_DKG_BIN='{_installed_dkg_bin(tmp_path)}'",
        _installer_constant("BLACKBOX_DKG_LAUNCHD_LABEL"),   # the script's own top-level value
        _installer_constant("BLACKBOX_SERVICE_SYSTEM_PATH"),
        _top_level_function("xml_escape"),
        _top_level_function("blackbox_dkg_launchd_error_log"), _top_level_function("register_boot_service"),
        "register_boot_service",
    ])
    result = subprocess.run(["bash", "-c", script], capture_output=True, text=True,
                            env={"PATH": f"{stubs}:/usr/bin:/bin"}, check=False)
    assert result.returncode == 0, result.stderr


def _expected_node_environment():
    return {
        "DKG_EXACT_BATCH_STREAM_ENABLED": "1",
        "DKG_VM_RECOVERY_PREFETCH_ENABLED": "1",
        "NODE_OPTIONS": "--enable-source-maps --max-old-space-size=6144",
        "DKG_STORE_QUEUE_LIMIT": "512",
    }


def test_the_systemd_unit_starts_the_node_with_its_limits_and_switches(tmp_path):
    _register_boot_service(tmp_path, "Linux")
    unit = (tmp_path / ".config" / "systemd" / "user" / "blackbox-dkg.service").read_text()

    environment = {}
    for line in unit.splitlines():
        if line.startswith("Environment="):
            assignment = line[len("Environment="):].strip('"')
            key, _, value = assignment.partition("=")
            environment[key] = value

    for key, value in _expected_node_environment().items():
        assert environment.get(key) == value, key
    assert "DKG_LIST_CONTEXT_GRAPHS_PROJECTION" not in environment   # install-time only
    assert "/usr/sbin" in environment["PATH"].split(":")   # lsof (KI-427)


def test_the_macos_login_item_starts_the_node_with_its_limits_and_switches(tmp_path):
    import plistlib

    _register_boot_service(tmp_path, "Darwin")
    plist = plistlib.loads((tmp_path / "Library" / "LaunchAgents" / "ai.umanitek.blackbox-dkg.plist").read_bytes())

    environment = plist["EnvironmentVariables"]
    for key, value in _expected_node_environment().items():
        assert environment.get(key) == value, key
    assert "DKG_LIST_CONTEXT_GRAPHS_PROJECTION" not in environment   # install-time only
    assert environment["DKG_SYNC_ON_CONNECT_ENABLED"] == "1"
    assert environment["DKG_HOME"] == "/srv/bb/.dkg"
    # launchd has no journal: the node's errors under the LaunchAgent land next to its own log (KI-426)
    assert plist["StandardErrorPath"] == "/srv/bb/.dkg/launchd-errors.log"
    assert "StandardOutPath" not in plist   # errors only: the node writes its own log
    # KI-427: the node runs lsof (macOS keeps it only in /usr/sbin) and refuses to start without it
    assert "/usr/sbin" in environment["PATH"].split(":")


def test_a_plist_value_is_escaped_as_xml_text(tmp_path):
    settings_with_markup = dict(_NODE_SETTINGS, BLACKBOX_DKG_HOME="/srv/a&b<c>/.dkg")
    import plistlib
    import subprocess
    stubs = tmp_path / "bin"
    stubs.mkdir()
    for name, body in (("uname", "echo Darwin"), ("node", "exit 0"), ("launchctl", "exit 0")):
        (stubs / name).write_text(f"#!/bin/sh\n{body}\n")
        (stubs / name).chmod(0o755)
    script = "\n".join([
        "set -euo pipefail", "ok() { :; }", "warn() { :; }", "step() { :; }", "heading() { :; }",
        "secure_dkg_token_perms() { :; }", "hand_dkg_node_to_service() { :; }", "ensure_user_lingering() { :; }", f"HOME={tmp_path}",
        *(f"{key}='{value}'" for key, value in settings_with_markup.items()),
        f"BLACKBOX_DKG_BIN='{_installed_dkg_bin(tmp_path)}'",
        _installer_constant("BLACKBOX_DKG_LAUNCHD_LABEL"),   # the script's own top-level value
        _installer_constant("BLACKBOX_SERVICE_SYSTEM_PATH"),
        _top_level_function("xml_escape"), _top_level_function("blackbox_dkg_launchd_error_log"), _top_level_function("register_boot_service"), "register_boot_service",
    ])
    subprocess.run(["bash", "-c", script], check=True, env={"PATH": f"{stubs}:/usr/bin:/bin"})

    plist = plistlib.loads((tmp_path / "Library" / "LaunchAgents" / "ai.umanitek.blackbox-dkg.plist").read_bytes())
    assert plist["EnvironmentVariables"]["DKG_HOME"] == "/srv/a&b<c>/.dkg"
