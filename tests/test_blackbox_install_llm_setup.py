"""Regression coverage for the Blackbox installer's LLM reviewer setup."""

from __future__ import annotations

import json
import os
import re
import shlex
import shutil
import subprocess
import sys
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

import pytest


REPO_ROOT = Path(__file__).resolve().parent.parent
INSTALL_SH = REPO_ROOT / "scripts" / "blackbox-install.sh"
INSTALL_PS1 = REPO_ROOT / "scripts" / "blackbox-install.ps1"
BLAZEGRAPH_HELPER = REPO_ROOT / "scripts" / "blackbox-blazegraph.mjs"
CURATOR_CONFIG = REPO_ROOT / "scripts" / "blackbox-curator-config.py"
CURATOR_SERVICE = REPO_ROOT / "scripts" / "blackbox-dkg-curator.service.conf"
BLAZEGRAPH_URL = "http://127.0.0.1:9999/bigdata/namespace/test/sparql"


def test_installers_allow_a_full_hour_for_initial_graph_catchup() -> None:
    unix = INSTALL_SH.read_text(encoding="utf-8")
    windows = INSTALL_PS1.read_text(encoding="utf-8")

    assert 'BLACKBOX_DKG_CATCHUP_TIMEOUT="${BLACKBOX_DKG_CATCHUP_TIMEOUT:-3600}"' in unix
    assert (
        '$CatchupTimeout = if ($env:BLACKBOX_DKG_CATCHUP_TIMEOUT) '
        '{ [int]$env:BLACKBOX_DKG_CATCHUP_TIMEOUT } else { 3600 }'
    ) in windows
    assert '"sync_interval": 3600' in unix
    assert '"sync_interval": 3600' in windows


def _extract_function_body(name: str) -> str:
    text = INSTALL_SH.read_text()
    match = re.search(
        rf"^{re.escape(name)}\(\)\s*\{{\s*\n(?P<body>.*?)^\}}",
        text,
        re.MULTILINE | re.DOTALL,
    )
    assert match is not None, f"{name}() not found in scripts/blackbox-install.sh"
    return match["body"]


def _extract_unix_config_writer() -> str:
    text = INSTALL_SH.read_text(encoding="utf-8")
    match = re.search(
        r"^ensure_blackbox_dkg_config\(\)\s*\{.*?<<'PYEOF'\n"
        r"(?P<code>.*?)^PYEOF\n\s*\)\"",
        text,
        re.MULTILINE | re.DOTALL,
    )
    assert match is not None
    return match["code"]


def _extract_unix_blackbox_config_writer() -> str:
    text = INSTALL_SH.read_text(encoding="utf-8")
    match = re.search(
        r"^enable_and_configure\(\)\s*\{.*?<<'PYEOF'\n"
        r"(?P<code>.*?)^PYEOF\n\s*then",
        text,
        re.MULTILINE | re.DOTALL,
    )
    assert match is not None
    return match["code"]


def _run_unix_blackbox_config_writer(
    config_path: Path,
    *,
    dkg_url: str,
    dkg_home: Path,
    dkg_bin: Path,
) -> dict:
    subprocess.run(
        [
            sys.executable,
            "-c",
            _extract_unix_blackbox_config_writer(),
            str(config_path),
            "mainnet-base",
            "owner/agent-blackbox",
            "curator-peer",
            dkg_url,
            str(dkg_home),
            str(dkg_bin),
        ],
        check=True,
        capture_output=True,
        text=True,
    )
    import yaml

    return yaml.safe_load(config_path.read_text(encoding="utf-8")) or {}


def _extract_powershell_function_body(name: str) -> str:
    text = INSTALL_PS1.read_text(encoding="utf-8")
    match = re.search(
        rf"^function\s+{re.escape(name)}\s*\{{\s*\n(?P<body>.*?)^\}}",
        text,
        re.MULTILINE | re.DOTALL,
    )
    assert match is not None, f"{name} not found in scripts/blackbox-install.ps1"
    return match["body"]


def test_unix_installer_creates_global_blackbox_launcher(tmp_path: Path) -> None:
    home = tmp_path / "home"
    hermes_bin = tmp_path / "venv" / "bin" / "hermes"
    args_file = tmp_path / "args.txt"
    hermes_bin.parent.mkdir(parents=True)
    hermes_bin.write_text(
        "#!/bin/sh\n"
        "printf '%s\\n' \"$@\" > \"$BLACKBOX_ARGS_OUT\"\n"
        "exit \"${BLACKBOX_EXIT_CODE:-0}\"\n",
        encoding="utf-8",
    )
    hermes_bin.chmod(0o755)

    body = _extract_function_body("link_hermes")
    command = f"""
ok() {{ :; }}
warn() {{ :; }}
link_hermes() {{
{body}
}}
HOME={shlex.quote(str(home))}
HERMES_BIN={shlex.quote(str(hermes_bin))}
VENV_DIR={shlex.quote(str(hermes_bin.parent.parent))}
PATH=/usr/bin:/bin
link_hermes
"""
    subprocess.run(["bash", "-c", command], check=True)

    launcher = home / ".local" / "bin" / "blackbox"
    assert launcher.is_file()
    assert os.access(launcher, os.X_OK)
    assert "managed-by: agent-blackbox-installer" in launcher.read_text(encoding="utf-8")
    result = subprocess.run(
        [str(launcher), "sync", "--wait", "--require-rules"],
        env={
            **os.environ,
            "BLACKBOX_ARGS_OUT": str(args_file),
            "BLACKBOX_EXIT_CODE": "17",
        },
        check=False,
    )
    assert result.returncode == 17
    assert args_file.read_text(encoding="utf-8").splitlines() == [
        "blackbox",
        "sync",
        "--wait",
        "--require-rules",
    ]


def test_unix_installer_does_not_replace_unmanaged_blackbox_command(tmp_path: Path) -> None:
    home = tmp_path / "home"
    link_dir = home / ".local" / "bin"
    link_dir.mkdir(parents=True)
    existing = link_dir / "blackbox"
    existing.write_text("#!/bin/sh\necho unrelated\n", encoding="utf-8")
    existing.chmod(0o755)
    hermes_bin = tmp_path / "venv" / "bin" / "hermes"
    hermes_bin.parent.mkdir(parents=True)
    hermes_bin.write_text("#!/bin/sh\nexit 0\n", encoding="utf-8")
    hermes_bin.chmod(0o755)

    body = _extract_function_body("link_hermes")
    command = f"""
ok() {{ :; }}
warn() {{ :; }}
link_hermes() {{
{body}
}}
HOME={shlex.quote(str(home))}
HERMES_BIN={shlex.quote(str(hermes_bin))}
VENV_DIR={shlex.quote(str(hermes_bin.parent.parent))}
PATH=/usr/bin:/bin
link_hermes
"""
    subprocess.run(["bash", "-c", command], check=True)

    assert existing.read_text(encoding="utf-8") == "#!/bin/sh\necho unrelated\n"


def test_windows_installer_creates_global_blackbox_launcher() -> None:
    text = INSTALL_PS1.read_text(encoding="utf-8")

    assert "function Install-BlackboxCommand" in text
    assert 'Join-Path $HOME ".local\\bin"' in text
    assert 'Join-Path $shimDir "blackbox.cmd"' in text
    assert "managed-by: agent-blackbox-installer" in text
    assert '"$HermesBin" blackbox %*' in text
    assert 'exit /b %ERRORLEVEL%' in text
    assert '[Environment]::SetEnvironmentVariable("Path", $newUserPath, "User")' in text
    assert text.index("Install-BlackboxCommand") < text.rindex("Install-Dkg")


def _select_unix_install_root(
    home: Path,
    explicit: Path | None = None,
    invocation_dir: Path | None = None,
) -> Path:
    """Evaluate only the install-root preamble with an isolated fake home."""
    text = INSTALL_SH.read_text(encoding="utf-8")
    preamble = text.split('DKG_NETWORK="${BLACKBOX_DKG_NETWORK', 1)[0]
    env = {"HOME": str(home), "PATH": os.environ.get("PATH", "")}
    if explicit is not None:
        env["BLACKBOX_INSTALL_DIR"] = str(explicit)
    result = subprocess.run(
        ["bash", "-c", f'{preamble}\nprintf %s "$BLACKBOX_INSTALL_ROOT"'],
        check=True,
        capture_output=True,
        text=True,
        env=env,
        cwd=invocation_dir or home,
    )
    return Path(result.stdout)


def test_llm_setup_reuses_existing_config_without_prompting() -> None:
    body = _extract_function_body("setup_llm")

    assert "blackbox setup-llm --configure" not in body
    assert "blackbox setup-llm --auto" in body
    assert "existing Blackbox, Hermes, or OpenClaw LLM config" in body
    assert "LLM reviewer not configured; this is optional" in body


def test_llm_setup_is_optional_not_install_blocking() -> None:
    body = _extract_function_body("setup_llm")

    assert "LLM setup skipped" not in body
    assert "blackbox setup-llm --auto" in body
    assert "BLACKBOX_LLM_INCOMPLETE=true" not in body
    assert "BLACKBOX_INSTALL_INCOMPLETE=true" not in body
    assert not re.search(r"<\s*/dev/tty", body), "installer must not prompt for optional LLM setup"


def test_next_steps_only_blocks_on_threat_graph_sync() -> None:
    body = _extract_function_body("next_steps")

    assert "BLACKBOX_THREAT_GRAPH_INCOMPLETE" in body
    assert "BLACKBOX_LLM_INCOMPLETE" not in body
    assert "The LLM reviewer is not configured yet." not in body
    assert "A partial verified ruleset is active" in body
    assert "BLACKBOX_PARTIAL_RULESET_READY" in body


def test_unix_installer_is_directly_executable_and_detaches_background_processes(
    tmp_path: Path,
) -> None:
    assert os.access(INSTALL_SH, os.X_OK)

    fake_bin = tmp_path / "bin"
    fake_bin.mkdir()
    (fake_bin / "nohup").symlink_to(shutil.which("nohup") or "/usr/bin/nohup")
    venv_bin = tmp_path / "venv" / "bin"
    venv_bin.mkdir(parents=True)
    (venv_bin / "python").symlink_to(Path(sys.executable))
    pid_file = tmp_path / "child.pid"
    log_file = tmp_path / "child.log"
    body = _extract_function_body("run_detached")
    child_code = (
        "import os,time,pathlib; "
        f"pathlib.Path({str(pid_file)!r}).write_text(str(os.getpid())); "
        "time.sleep(30)"
    )
    command = f"""
run_detached() {{
{body}
}}
PATH={shlex.quote(str(fake_bin))}
VENV_DIR={shlex.quote(str(tmp_path / "venv"))}
run_detached {shlex.quote(str(log_file))} {shlex.quote(sys.executable)} -c {shlex.quote(child_code)}
exit 1
"""
    installer = subprocess.run(["bash", "-c", command], check=False, timeout=5)
    assert installer.returncode == 1

    deadline = time.monotonic() + 3
    while not pid_file.exists() and time.monotonic() < deadline:
        time.sleep(0.02)
    assert pid_file.exists(), "detached child did not survive the installer shell"
    child_pid = int(pid_file.read_text(encoding="utf-8"))
    try:
        os.kill(child_pid, 0)
    finally:
        # The detached process is intentionally reparented, so the suite's
        # Python-level process-tree guard no longer considers it a child.
        subprocess.run(["/bin/kill", "-TERM", str(child_pid)], check=False)


def test_unix_installer_uses_a_real_session_boundary_for_dashboard() -> None:
    body = _extract_function_body("run_detached")

    assert "start_new_session=True" in body
    assert "stdin=subprocess.DEVNULL" in body
    assert "close_fds=True" in body


def test_unix_installer_starts_dashboard_before_one_controlled_sync() -> None:
    run_body = _extract_function_body("run_detached")
    health_body = _extract_function_body("detached_process_survived_startup")
    sync_body = _extract_function_body("sync_ruleset")

    assert 'BLACKBOX_DETACHED_PID=$!' in run_body
    assert 'kill -0 "$pid"' in health_body
    assert "run_detached" not in sync_body
    assert "restart_blackbox_dkg_for_sync_mode" not in sync_body
    assert 'BLACKBOX_INSTALL_INCOMPLETE=true' in sync_body
    assert 'BLACKBOX_THREAT_GRAPH_INCOMPLETE=true' in sync_body
    assert "one controlled verified graph catch-up" in sync_body
    assert "start_dashboard" in sync_body
    assert ': >"$BLACKBOX_SYNC_LOG"' in sync_body
    assert 'tee -a "$BLACKBOX_SYNC_LOG"' in sync_body
    assert sync_body.index("start_dashboard") < sync_body.index("blackbox sync --wait")


@pytest.mark.skipif(shutil.which("bash") is None, reason="bash is unavailable")
def test_unix_installer_opens_dashboard_before_fresh_sync_starts(
    tmp_path: Path,
) -> None:
    sync_body = _extract_function_body("sync_ruleset")
    hermes_home = tmp_path / "hermes"
    log_dir = hermes_home / "logs"
    log_dir.mkdir(parents=True)
    sync_log = log_dir / "blackbox-sync-install.log"
    # A previous successful install log is cleared before the new sync.
    sync_log.write_text("999 verified threats ready\n", encoding="utf-8")
    events = tmp_path / "events"
    fake_hermes = tmp_path / "fake-hermes"
    fake_hermes.write_text(
        "#!/bin/bash\n"
        f"echo sync-started >> {shlex.quote(str(events))}\n"
        "echo 'starting fresh sync'\n"
        "sleep 0.2\n"
        "echo '  10 verified threats ready'\n"
        "sleep 1.4\n"
        f"echo sync-finished >> {shlex.quote(str(events))}\n",
        encoding="utf-8",
    )
    fake_hermes.chmod(0o755)
    command = f"""
set -euo pipefail
heading() {{ :; }}
step() {{ :; }}
ok() {{ :; }}
err() {{ :; }}
restart_blackbox_dkg_for_sync_mode() {{ return 0; }}
start_dashboard() {{ echo dashboard >> {shlex.quote(str(events))}; }}
sync_ruleset() {{
{sync_body}
}}
DKG_READY=true
HERMES_HOME={shlex.quote(str(hermes_home))}
HERMES_BIN={shlex.quote(str(fake_hermes))}
BLACKBOX_DKG_CATCHUP_TIMEOUT=30
BLACKBOX_DKG_STEADY_DURABLE_SYNC_ENABLED=0
BLACKBOX_AUTO_DASHBOARD=1
BLACKBOX_INSTALL_INCOMPLETE=false
BLACKBOX_THREAT_GRAPH_INCOMPLETE=false
BLACKBOX_SYNC_LOG=''
sync_ruleset
"""

    subprocess.run(["bash", "-c", command], check=True, timeout=10)
    assert events.read_text(encoding="utf-8").splitlines() == [
        "dashboard",
        "sync-started",
        "sync-finished",
    ]


def test_installers_enable_blackbox_noninteractively() -> None:
    unix = _extract_function_body("enable_and_configure")
    windows = _extract_powershell_function_body("Enable-AndConfigure")

    assert "plugins enable blackbox --no-allow-tool-override" in unix
    assert "plugins enable blackbox --no-allow-tool-override" in windows


def test_unix_installer_fresh_config_keeps_community_sharing_off(
    tmp_path: Path,
) -> None:
    config_path = tmp_path / "config.yaml"

    configured = _run_unix_blackbox_config_writer(
        config_path,
        dkg_url="http://127.0.0.1:9320",
        dkg_home=tmp_path / ".dkg",
        dkg_bin=tmp_path / "dkg" / "node_modules" / ".bin" / "dkg",
    )
    blackbox = configured["plugins"]["entries"]["blackbox"]

    assert blackbox["report"] is False
    assert blackbox["daily_report_limit"] == 0


def test_windows_installer_fresh_config_keeps_community_sharing_off() -> None:
    writer = _extract_powershell_function_body("Enable-AndConfigure")

    assert '"report": False' in writer
    assert '"daily_report_limit": 0' in writer
    assert '"report": True' not in writer
    assert '"daily_report_limit": 9999' not in writer


def test_unix_installer_migrates_stale_community_sharing_opt_in(
    tmp_path: Path,
) -> None:
    config_path = tmp_path / "config.yaml"
    config_path.write_text(
        "plugins:\n  entries:\n    blackbox:\n      report: true\n"
        "      daily_report_limit: 9999\n",
        encoding="utf-8",
    )

    configured = _run_unix_blackbox_config_writer(
        config_path,
        dkg_url="http://127.0.0.1:9320",
        dkg_home=tmp_path / ".dkg",
        dkg_bin=tmp_path / "dkg" / "node_modules" / ".bin" / "dkg",
    )
    blackbox = configured["plugins"]["entries"]["blackbox"]

    assert blackbox["report"] is False
    assert blackbox["daily_report_limit"] == 0


def test_windows_installer_migrates_stale_community_sharing_opt_in() -> None:
    writer = INSTALL_PS1.read_text(encoding="utf-8")

    assert 'for k, v in {"report": False, "daily_report_limit": 0}.items()' in writer
    assert "if blackbox.get(k) != v:" in writer


def test_hermes_setup_defaults_to_reuse_without_prompting() -> None:
    text = INSTALL_SH.read_text()
    body = _extract_function_body("run_hermes_setup")

    assert 'BLACKBOX_HERMES_SETUP="${BLACKBOX_HERMES_SETUP:-reuse}"' in text
    assert "reuse_existing_hermes_api_keys" in body
    assert "No existing Hermes API key found; skipping Hermes setup wizard." in body
    assert "Threat-graph sync does not require a Nous subscription or model key." in body


def test_hermes_key_reuse_finds_existing_env_files() -> None:
    body = _extract_function_body("reuse_existing_hermes_api_keys")

    assert '"$REPO_DIR/.env"' in body
    assert '"$HOME/.hermes/.env"' in body
    assert "Reused existing Hermes API key configuration" in body
    assert "grep -E \"$HERMES_API_KEY_RE\"" in body


def test_unix_installer_uses_isolated_blackbox_dkg_node() -> None:
    text = INSTALL_SH.read_text()

    assert 'BLACKBOX_DKG_PORT="${BLACKBOX_DKG_PORT:-9320}"' in text
    assert 'BLACKBOX_DKG_STORE_PORT="${BLACKBOX_DKG_STORE_PORT:-9999}"' in text
    assert 'BLACKBOX_DKG_STORE_URL="${BLACKBOX_DKG_STORE_URL:-}"' in text
    assert 'BLACKBOX_INSTALL_ROOT="$PWD/agent-blackbox"' in text
    assert 'BLACKBOX_DKG_HOME="$BLACKBOX_INSTALL_ROOT/.dkg"' in text
    assert 'BLACKBOX_DKG_CLI_DIR="$BLACKBOX_INSTALL_ROOT/dkg"' in text
    assert 'BLACKBOX_DKG_BIN="$BLACKBOX_DKG_CLI_DIR/node_modules/.bin/dkg"' in text
    assert (
        'BLACKBOX_DKG_PACKAGE="${BLACKBOX_DKG_PACKAGE:-'
        '@origintrail-official/dkg@latest}"'
    ) in text
    assert 'BLACKBOX_DKG_DAEMON_URL="http://127.0.0.1:$BLACKBOX_DKG_PORT"' in text
    assert 'npm install --prefix "$BLACKBOX_DKG_CLI_DIR"' in text
    assert '--prefer-online' in text
    assert "BLACKBOX_DKG_REPO_URL" not in text
    assert "corepack pnpm" not in text
    assert "ensure_blackbox_dkg_config" in text
    assert 'blackbox_dkg start' in text
    assert '"apiPort"] = api_port' in text
    assert '"backend": "blazegraph"' in text
    assert '"options": {"url": store_url, "managedByDkg": store_managed, "timeout": 900000}' in text
    assert "blackbox-blazegraph.mjs" in text
    assert 'blackbox_dkg subscribe "$blackbox_cg" --save' not in text
    assert '"$HERMES_BIN" blackbox sync --wait' in text
    assert "uses_unpaired_shared_dkg_home" in text
    assert "uses_legacy_blackbox_dkg_home" in text
    assert "migrate_legacy_blackbox_dkg_home" in text
    assert 'blackbox["dkg_home"] = dkg_home' in text
    assert 'blackbox["dkg_bin"] = dkg_bin' in text
    assert "npm i -g" not in text
    assert "npm install -g" not in text
    assert '"dkg_url": "http://127.0.0.1:9200"' not in text


def test_unix_installer_rebinds_stale_dkg_paths_as_one_runtime(tmp_path: Path) -> None:
    config_path = tmp_path / "config.yaml"
    stale_checkout = tmp_path / "deleted-agent-blackbox"
    config_path.write_text(
        """plugins:
  entries:
    blackbox:
      dkg_url: http://127.0.0.1:9320
      dkg_home: %s
      dkg_bin: %s
"""
        % (
            stale_checkout / ".dkg",
            stale_checkout / "dkg" / "node_modules" / ".bin" / "dkg",
        ),
        encoding="utf-8",
    )
    target_checkout = tmp_path / "current-agent-blackbox"
    target_home = target_checkout / ".dkg"
    target_bin = target_checkout / "dkg" / "node_modules" / ".bin" / "dkg"

    migrated = _run_unix_blackbox_config_writer(
        config_path,
        dkg_url="http://127.0.0.1:9337",
        dkg_home=target_home,
        dkg_bin=target_bin,
    )
    blackbox = migrated["plugins"]["entries"]["blackbox"]

    assert blackbox["dkg_url"] == "http://127.0.0.1:9337"
    assert blackbox["dkg_home"] == str(target_home)
    assert blackbox["dkg_bin"] == str(target_bin)


def test_unix_installer_rebinds_an_existing_previous_managed_checkout(tmp_path: Path) -> None:
    config_path = tmp_path / "config.yaml"
    old_checkout = tmp_path / "old-agent-blackbox"
    old_home = old_checkout / ".dkg"
    old_bin = old_checkout / "dkg" / "node_modules" / ".bin" / "dkg"
    old_home.mkdir(parents=True)
    old_bin.parent.mkdir(parents=True)
    old_bin.write_text("old managed dkg", encoding="utf-8")
    config_path.write_text(
        """plugins:
  entries:
    blackbox:
      dkg_url: http://127.0.0.1:9320
      dkg_home: %s
      dkg_bin: %s
"""
        % (old_home, old_bin),
        encoding="utf-8",
    )
    target_checkout = tmp_path / "current-agent-blackbox"
    target_home = target_checkout / ".dkg"
    target_bin = target_checkout / "dkg" / "node_modules" / ".bin" / "dkg"

    migrated = _run_unix_blackbox_config_writer(
        config_path,
        dkg_url="http://127.0.0.1:9337",
        dkg_home=target_home,
        dkg_bin=target_bin,
    )
    blackbox = migrated["plugins"]["entries"]["blackbox"]

    assert blackbox["dkg_url"] == "http://127.0.0.1:9337"
    assert blackbox["dkg_home"] == str(target_home)
    assert blackbox["dkg_bin"] == str(target_bin)


def test_unix_installer_rebinds_the_port_for_its_current_managed_checkout(
    tmp_path: Path,
) -> None:
    config_path = tmp_path / "config.yaml"
    target_checkout = tmp_path / "current-agent-blackbox"
    target_home = target_checkout / ".dkg"
    target_bin = target_checkout / "dkg" / "node_modules" / ".bin" / "dkg"
    target_home.mkdir(parents=True)
    target_bin.parent.mkdir(parents=True)
    target_bin.write_text("managed dkg", encoding="utf-8")
    config_path.write_text(
        """plugins:
  entries:
    blackbox:
      dkg_url: http://127.0.0.1:9320
      dkg_home: %s
      dkg_bin: %s
"""
        % (target_home, target_bin),
        encoding="utf-8",
    )

    migrated = _run_unix_blackbox_config_writer(
        config_path,
        dkg_url="http://127.0.0.1:9337",
        dkg_home=target_home,
        dkg_bin=target_bin,
    )
    blackbox = migrated["plugins"]["entries"]["blackbox"]

    assert blackbox["dkg_url"] == "http://127.0.0.1:9337"
    assert blackbox["dkg_home"] == str(target_home)
    assert blackbox["dkg_bin"] == str(target_bin)


def test_unix_installer_preserves_a_valid_custom_dkg_runtime(tmp_path: Path) -> None:
    config_path = tmp_path / "config.yaml"
    custom_home = tmp_path / "custom-state"
    custom_bin = tmp_path / "custom-cli" / "dkg"
    custom_home.mkdir()
    custom_bin.parent.mkdir()
    custom_bin.write_text("custom dkg", encoding="utf-8")
    config_path.write_text(
        """plugins:
  entries:
    blackbox:
      dkg_url: http://127.0.0.1:9444
      dkg_home: %s
      dkg_bin: %s
"""
        % (custom_home, custom_bin),
        encoding="utf-8",
    )

    migrated = _run_unix_blackbox_config_writer(
        config_path,
        dkg_url="http://127.0.0.1:9337",
        dkg_home=tmp_path / "managed" / ".dkg",
        dkg_bin=tmp_path / "managed" / "dkg" / "node_modules" / ".bin" / "dkg",
    )
    blackbox = migrated["plugins"]["entries"]["blackbox"]

    assert blackbox["dkg_url"] == "http://127.0.0.1:9444"
    assert blackbox["dkg_home"] == str(custom_home)
    assert blackbox["dkg_bin"] == str(custom_bin)


@pytest.mark.skipif(shutil.which("bash") is None, reason="bash is unavailable")
def test_unix_installer_uses_agent_blackbox_checkout(
    tmp_path: Path,
) -> None:
    home = tmp_path / "home"
    home.mkdir()

    assert _select_unix_install_root(home) == home / "agent-blackbox"

    repo_checkout = tmp_path / "existing-checkout"
    (repo_checkout / "plugins" / "blackbox").mkdir(parents=True)
    (repo_checkout / "pyproject.toml").write_text("[project]\nname='blackbox'\n")
    assert _select_unix_install_root(home, invocation_dir=repo_checkout) == repo_checkout

    explicit = tmp_path / "custom-blackbox"
    assert _select_unix_install_root(home, explicit) == explicit


def test_windows_installer_uses_agent_blackbox_checkout() -> None:
    text = INSTALL_PS1.read_text(encoding="utf-8")

    assert 'Join-Path ([string](Get-Location)) "agent-blackbox"' in text
    assert '$env:USERPROFILE\\agent-blackbox' not in text


# The four mainnet-base core relays written to config.relayPeers.
# On DKG <=10.0.4 an empty relayPeers left the node with 0 circuit reservations
# 10.0.5+ also resolves relays from preferredRelays and the built-in network config,
# so this explicit configuration is
# now defensive belt-and-suspenders rather than the sole reachability path. It
# stays because it is harmless (deduped) and protects pre-10.0.5 nodes; guard the
# exact multiaddrs and the merge logic against silent regression either way.
MAINNET_BASE_RELAYS = (
    "/ip4/178.104.98.10/tcp/9090/p2p/12D3KooWFWm8sg6dkitmdBd5Uxaqp3CDRL27mFcM7vEHK92Xapyy",
    "/ip4/168.119.127.54/tcp/9090/p2p/12D3KooWMasqzRrim48ZJM64UyTfHufDTmSG3n3jqwsS5phz8m91",
    "/ip4/178.156.237.133/tcp/9090/p2p/12D3KooWDgTunUpkGaE7dYCaDP1CCBT6Dm2HPMXSZhJn2KXYLH15",
    "/ip4/178.105.211.42/tcp/9090/p2p/12D3KooWCodgXHMwybaEe93rbKgWMfGXQvUb6cpT3VCrjCbbnyEu",
)

_RELAY_SEED_ASSERTS = (
    'existing_relays = data.get("relayPeers")',
    "merged_relays = list(dict.fromkeys([*existing_relays, *MAINNET_BASE_RELAYS]))",
    'data["relayPeers"] = merged_relays',
    'data["relayReservationCount"] = int(data.get("relayReservationCount") or 4)',
)


def test_unix_installer_configures_relay_peers_for_reachability() -> None:
    text = INSTALL_SH.read_text()

    for relay in MAINNET_BASE_RELAYS:
        assert relay in text, f"missing mainnet-base relay {relay}"
    for line in _RELAY_SEED_ASSERTS:
        assert line in text, f"relayPeers configuration line missing: {line}"


def test_windows_installer_configures_relay_peers_for_reachability() -> None:
    text = INSTALL_PS1.read_text()

    for relay in MAINNET_BASE_RELAYS:
        assert relay in text, f"missing mainnet-base relay {relay}"
    for line in _RELAY_SEED_ASSERTS:
        assert line in text, f"relayPeers configuration line missing: {line}"


def test_windows_installer_uses_isolated_blackbox_dkg_node() -> None:
    text = INSTALL_PS1.read_text()

    assert "$DkgPort" in text and "9320" in text
    assert "$DkgStorePort" in text and "9999" in text
    assert "$DkgStoreUrl" in text
    assert '$DkgHome     = Join-Path $DefaultRepoDir ".dkg"' in text
    assert '$DkgCliDir   = Join-Path $DefaultRepoDir "dkg"' in text
    assert r'$DkgBin      = Join-Path $DkgCliDir "node_modules\.bin\dkg.cmd"' in text
    assert "@origintrail-official/dkg@latest" in text
    assert '$DkgDaemonUrl = "http://127.0.0.1:$DkgPort"' in text
    assert "npm install --prefix $DkgCliDir --prefer-online $DkgPackage" in text
    assert "BLACKBOX_DKG_REPO_URL" not in text
    assert "corepack pnpm" not in text
    assert "Ensure-BlackboxDkgConfig" in text
    assert "Invoke-BlackboxDkg start" in text
    assert 'data["apiPort"] = api_port' in text
    assert '"backend": "blazegraph"' in text
    assert '"options": {"url": store_url, "managedByDkg": store_managed, "timeout": 900000}' in text
    assert "blackbox-blazegraph.mjs" in text
    assert "uses_unpaired_shared_dkg_home" in text
    assert "uses_legacy_blackbox_dkg_home" in text
    assert "uses_target_managed_home" in text
    assert "uses_other_managed_checkout" in text
    assert "stale_configured_dkg_home" in text
    assert "stale_configured_dkg_bin" in text
    assert "rebind_managed_dkg" in text
    assert "Move-LegacyBlackboxDkgHome" in text
    assert 'blackbox["dkg_home"] = dkg_home' in text
    assert 'blackbox["dkg_bin"] = dkg_bin' in text
    assert "npm i -g" not in text
    assert "npm install -g" not in text
    assert '"dkg_url": "http://127.0.0.1:9200"' not in text


def test_dkg_config_writer_leaves_subscriptions_to_the_dkg_api(tmp_path: Path) -> None:
    home = tmp_path / "dkg"
    home.mkdir()
    config = home / "config.json"
    config.write_text(
        json.dumps(
            {
                "contextGraphs": [
                    "umanitek/guardian-threats-staging",
                    "custom/private-graph",
                ],
                "syncAgentsMeta": True,
                "restrictAutoSubscribeContextGraphs": True,
            }
        ),
        encoding="utf-8",
    )
    writer = _extract_unix_config_writer()

    subprocess.run(
        [
            sys.executable,
            "-c",
            writer,
            str(home),
            "9320",
            "blazegraph",
            BLAZEGRAPH_URL,
            "true",
            "umanitek/blackbox-threats-staging",
        ],
        check=True,
    )
    migrated = json.loads(config.read_text(encoding="utf-8"))

    assert migrated["contextGraphs"] == [
        "umanitek/guardian-threats-staging",
        "custom/private-graph",
    ]
    assert "autoApproveJoinRequests" not in migrated
    assert "syncAgentsMeta" not in migrated
    assert migrated["syncOnConnectEnabled"] is True
    assert migrated["syncReconcilerEnabled"] is True
    assert migrated["durableSyncEnabled"] is True
    assert migrated["syncGlobalMaxInflight"] == 1
    assert migrated["syncGlobalQueueLimit"] == 0
    assert "restrictAutoSubscribeContextGraphs" not in migrated
    assert migrated["store"] == {
        "backend": "blazegraph",
        "options": {"url": BLAZEGRAPH_URL, "managedByDkg": True, "timeout": 900000},
    }

def test_dkg_config_writer_reports_only_real_runtime_changes(tmp_path: Path) -> None:
    home = tmp_path / "dkg"
    writer = _extract_unix_config_writer()
    command = [
        sys.executable,
        "-c",
        writer,
        str(home),
        "9320",
        "blazegraph",
        BLAZEGRAPH_URL,
        "true",
        "umanitek/blackbox-threats-staging",
    ]

    first = subprocess.run(command, check=True, capture_output=True, text=True)
    config = home / "config.json"
    first_mtime = config.stat().st_mtime_ns
    second = subprocess.run(command, check=True, capture_output=True, text=True)

    assert first.stdout.strip() == "changed"
    assert second.stdout.strip() == "unchanged"
    assert config.stat().st_mtime_ns == first_mtime


def test_dkg_config_writer_preserves_oxigraph_config_during_switch(tmp_path: Path) -> None:
    home = tmp_path / "dkg"
    home.mkdir()
    config = home / "config.json"
    previous = {
        "name": "existing-node",
        "store": {
            "backend": "oxigraph-server",
            "options": {"port": 7879, "readyTimeoutMs": 120000},
        },
    }
    config.write_text(json.dumps(previous), encoding="utf-8")

    completed = subprocess.run(
        [
            sys.executable,
            "-c",
            _extract_unix_config_writer(),
            str(home),
            "9320",
            "blazegraph",
            BLAZEGRAPH_URL,
            "true",
            "umanitek/blackbox-threats-staging",
        ],
        check=True,
        capture_output=True,
        text=True,
    )

    assert completed.stdout.strip() == "switched"
    assert json.loads((home / "config.json.pre-blazegraph").read_text()) == previous
    assert (home / ".blackbox-store-reset-pending").read_text() == "blazegraph\n"
    assert json.loads(config.read_text())["store"] == {
        "backend": "blazegraph",
        "options": {"url": BLAZEGRAPH_URL, "managedByDkg": True, "timeout": 900000},
    }


def test_dkg_config_writer_supports_oxigraph_fallback_without_losing_blazegraph_config(
    tmp_path: Path,
) -> None:
    home = tmp_path / "dkg"
    home.mkdir()
    config = home / "config.json"
    previous = {
        "name": "existing-node",
        "store": {
            "backend": "blazegraph",
            "options": {"url": BLAZEGRAPH_URL, "managedByDkg": True},
        },
    }
    config.write_text(json.dumps(previous), encoding="utf-8")

    completed = subprocess.run(
        [
            sys.executable,
            "-c",
            _extract_unix_config_writer(),
            str(home),
            "9320",
            "oxigraph-server",
            "",
            "false",
            "umanitek/blackbox-vm",
        ],
        check=True,
        capture_output=True,
        text=True,
    )

    assert completed.stdout.strip() == "switched"
    assert json.loads((home / "config.json.pre-oxigraph-server").read_text()) == previous
    assert (home / ".blackbox-store-reset-pending").read_text() == "oxigraph-server\n"
    assert json.loads(config.read_text())["store"] == {"backend": "oxigraph-server"}


@pytest.mark.skipif(shutil.which("bash") is None, reason="bash is unavailable")
def test_unix_installer_marks_missing_docker_as_fatal() -> None:
    body = _extract_function_body("require_docker_for_blazegraph")
    command = f"""
require_docker_for_blazegraph() {{
{body}
}}
docker_setup_hint() {{ printf 'docker-setup-hint\\n'; }}
ok() {{ :; }}
BLACKBOX_DOCKER_REQUIRED=false
PATH=
require_docker_for_blazegraph
rc=$?
printf '%s|%s\\n' "$rc" "$BLACKBOX_DOCKER_REQUIRED"
"""
    completed = subprocess.run(
        ["bash", "-c", command],
        check=False,
        capture_output=True,
        text=True,
    )

    assert "docker-setup-hint" in completed.stdout
    assert completed.stdout.rstrip().endswith("1|true")


@pytest.mark.skipif(shutil.which("bash") is None, reason="bash is unavailable")
def test_unix_installer_stops_when_blazegraph_needs_docker(tmp_path: Path) -> None:
    command = f"""
install_dkg() {{
{_extract_function_body("install_dkg")}
}}
heading() {{ :; }}
step() {{ :; }}
warn() {{ :; }}
err() {{ printf '%s\\n' "$*"; }}
dkg_manual_hint() {{ :; }}
prepare_blackbox_dkg_process_environment() {{ return 0; }}
install_blackbox_dkg_package() {{ return 0; }}
migrate_legacy_blackbox_dkg_home() {{ return 0; }}
check_blackbox_dkg_port() {{ return 0; }}
provision_blackbox_store() {{ BLACKBOX_DOCKER_REQUIRED=true; return 2; }}
SKIP_DKG=false
HAS_NODE=true
NODE_MAJOR=22
BLACKBOX_DKG_PACKAGE=test-package
BLACKBOX_DKG_CLI_DIR={shlex.quote(str(tmp_path / "cli"))}
BLACKBOX_DKG_HOME={shlex.quote(str(tmp_path / "home"))}
BLACKBOX_DOCKER_REQUIRED=false
install_dkg
printf 'installer-continued\\n'
"""
    completed = subprocess.run(
        ["bash", "-c", command],
        check=False,
        capture_output=True,
        text=True,
    )

    assert completed.returncode == 1
    assert "Installation stopped before changing the DKG store" in completed.stdout
    assert "installer-continued" not in completed.stdout


@pytest.mark.skipif(
    shutil.which("bash") is None or shutil.which("node") is None,
    reason="bash or Node.js is unavailable",
)
def test_unix_installer_falls_back_to_oxigraph_after_blazegraph_failure(
    tmp_path: Path,
) -> None:
    venv_bin = tmp_path / "venv" / "bin"
    venv_bin.mkdir(parents=True)
    (venv_bin / "python").symlink_to(sys.executable)
    scripts = tmp_path / "repo" / "scripts"
    scripts.mkdir(parents=True)
    (scripts / "blackbox-blazegraph.mjs").write_text("process.exit(1);\n", encoding="utf-8")
    fake_bin = tmp_path / "bin"
    fake_bin.mkdir()
    docker = fake_bin / "docker"
    docker.write_text("#!/bin/sh\nexit 0\n", encoding="utf-8")
    docker.chmod(0o755)

    command = f"""
require_docker_for_blazegraph() {{
{_extract_function_body("require_docker_for_blazegraph")}
}}
use_blackbox_oxigraph() {{
{_extract_function_body("use_blackbox_oxigraph")}
}}
confirm_oxigraph_fallback() {{ return 0; }}
check_blackbox_blazegraph() {{
{_extract_function_body("check_blackbox_blazegraph")}
}}
provision_blackbox_store() {{
{_extract_function_body("provision_blackbox_store")}
}}
step() {{ :; }}
ok() {{ :; }}
warn() {{ :; }}
err() {{ :; }}
docker_setup_hint() {{ :; }}
VENV_DIR={shlex.quote(str(tmp_path / "venv"))}
REPO_DIR={shlex.quote(str(tmp_path / "repo"))}
BLACKBOX_DKG_HOME={shlex.quote(str(tmp_path / "dkg-home"))}
BLACKBOX_DKG_CLI_DIR={shlex.quote(str(tmp_path / "dkg-cli"))}
BLACKBOX_DKG_STORE_PORT=9999
BLACKBOX_DKG_STORE_URL=
BLACKBOX_DKG_STORE_URL_EXPLICIT=false
BLACKBOX_DKG_STORE_MANAGED_BY_DKG=false
BLACKBOX_DKG_STORE_BACKEND=auto
BLACKBOX_DKG_SELECTED_STORE_BACKEND=
BLACKBOX_DOCKER_REQUIRED=false
PATH={shlex.quote(str(fake_bin) + os.pathsep + os.environ.get("PATH", ""))}
provision_blackbox_store
printf '%s|%s|%s\\n' "$BLACKBOX_DKG_SELECTED_STORE_BACKEND" "$BLACKBOX_DKG_STORE_URL" "$BLACKBOX_DKG_STORE_MANAGED_BY_DKG"
"""
    completed = subprocess.run(
        ["bash", "-c", command],
        check=True,
        capture_output=True,
        text=True,
    )

    assert completed.stdout.rstrip().endswith("oxigraph-server||false")


@pytest.mark.skipif(
    shutil.which("bash") is None or shutil.which("node") is None,
    reason="bash or Node.js is unavailable",
)
def test_unix_installer_does_not_fall_back_to_oxigraph_without_confirmation(
    tmp_path: Path,
) -> None:
    venv_bin = tmp_path / "venv" / "bin"
    venv_bin.mkdir(parents=True)
    (venv_bin / "python").symlink_to(sys.executable)
    scripts = tmp_path / "repo" / "scripts"
    scripts.mkdir(parents=True)
    (scripts / "blackbox-blazegraph.mjs").write_text("process.exit(1);\n", encoding="utf-8")
    fake_bin = tmp_path / "bin"
    fake_bin.mkdir()
    docker = fake_bin / "docker"
    docker.write_text("#!/bin/sh\nexit 0\n", encoding="utf-8")
    docker.chmod(0o755)

    command = f"""
require_docker_for_blazegraph() {{
{_extract_function_body("require_docker_for_blazegraph")}
}}
use_blackbox_oxigraph() {{
{_extract_function_body("use_blackbox_oxigraph")}
}}
confirm_oxigraph_fallback() {{ return 1; }}
check_blackbox_blazegraph() {{
{_extract_function_body("check_blackbox_blazegraph")}
}}
provision_blackbox_store() {{
{_extract_function_body("provision_blackbox_store")}
}}
step() {{ :; }}
ok() {{ :; }}
warn() {{ :; }}
err() {{ :; }}
docker_setup_hint() {{ :; }}
VENV_DIR={shlex.quote(str(tmp_path / "venv"))}
REPO_DIR={shlex.quote(str(tmp_path / "repo"))}
BLACKBOX_DKG_HOME={shlex.quote(str(tmp_path / "dkg-home"))}
BLACKBOX_DKG_CLI_DIR={shlex.quote(str(tmp_path / "dkg-cli"))}
BLACKBOX_DKG_STORE_PORT=9999
BLACKBOX_DKG_STORE_URL=
BLACKBOX_DKG_STORE_URL_EXPLICIT=false
BLACKBOX_DKG_STORE_MANAGED_BY_DKG=false
BLACKBOX_DKG_STORE_BACKEND=auto
BLACKBOX_DKG_SELECTED_STORE_BACKEND=
BLACKBOX_DOCKER_REQUIRED=false
PATH={shlex.quote(str(fake_bin) + os.pathsep + os.environ.get("PATH", ""))}
provision_blackbox_store && printf 'unexpected-continue\n'
"""
    completed = subprocess.run(
        ["bash", "-c", command],
        check=False,
        capture_output=True,
        text=True,
    )

    assert completed.returncode != 0
    assert "unexpected-continue" not in completed.stdout


@pytest.mark.skipif(shutil.which("node") is None, reason="Node.js is unavailable")
def test_blazegraph_helper_resets_only_the_exact_local_namespace() -> None:
    requests = []

    class Handler(BaseHTTPRequestHandler):
        def do_POST(self):
            length = int(self.headers.get("content-length", "0"))
            body = self.rfile.read(length).decode("utf-8")
            requests.append((self.path, self.headers.get("content-type"), body))
            if body == "DROP ALL":
                self.send_response(204)
                self.end_headers()
                return
            payload = json.dumps(
                {
                    "results": {
                        "bindings": [{"count": {"type": "literal", "value": "0"}}]
                    }
                }
            ).encode("utf-8")
            self.send_response(200)
            self.send_header("content-type", "application/sparql-results+json")
            self.send_header("content-length", str(len(payload)))
            self.end_headers()
            self.wfile.write(payload)

        def log_message(self, *_args):
            return

    server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        endpoint = (
            f"http://127.0.0.1:{server.server_port}/bigdata/namespace/"
            "agent-blackbox/sparql"
        )
        completed = subprocess.run(
            [
                "node",
                str(BLAZEGRAPH_HELPER),
                "reset",
                str(REPO_ROOT / "dkg"),
                endpoint,
                "agent-blackbox",
            ],
            check=True,
            capture_output=True,
            text=True,
        )
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=5)

    assert json.loads(completed.stdout)["triples"] == 0
    assert requests[0][0] == "/bigdata/namespace/agent-blackbox/sparql"
    assert requests[0][1] == "application/sparql-update"
    assert requests[0][2] == "DROP ALL"
    assert requests[1][1] == "application/sparql-query"


@pytest.mark.skipif(shutil.which("bash") is None, reason="bash is unavailable")
@pytest.mark.parametrize(
    ("fresh", "managed", "explicit", "foreign", "expected_rc", "expected_calls"),
    [
        ("true", "true", "false", "false", 0, 1),
        ("false", "true", "false", "false", 0, 0),
        ("true", "false", "true", "false", 0, 0),
        ("true", "true", "false", "true", 1, 0),
    ],
)
def test_unix_fresh_store_reset_obeys_ownership_boundary(
    tmp_path: Path,
    fresh: str,
    managed: str,
    explicit: str,
    foreign: str,
    expected_rc: int,
    expected_calls: int,
) -> None:
    calls = tmp_path / "calls"
    fake_bin = tmp_path / "bin"
    fake_bin.mkdir()
    node = fake_bin / "node"
    node.write_text(
        f"#!/bin/sh\nprintf '%s\\n' \"$*\" >> {shlex.quote(str(calls))}\n",
        encoding="utf-8",
    )
    node.chmod(0o755)
    command = f"""
reset_fresh_managed_blazegraph() {{
{_extract_function_body("reset_fresh_managed_blazegraph")}
}}
step() {{ :; }}
ok() {{ :; }}
err() {{ :; }}
BLACKBOX_DKG_FRESH_STATE={fresh}
BLACKBOX_DKG_SELECTED_STORE_BACKEND=blazegraph
BLACKBOX_DKG_STORE_MANAGED_BY_DKG={managed}
BLACKBOX_DKG_STORE_URL_EXPLICIT={explicit}
BLACKBOX_DKG_FOREIGN_ENDPOINT={foreign}
BLACKBOX_DKG_STORE_URL=http://127.0.0.1:9999/bigdata/namespace/agent-blackbox/sparql
BLACKBOX_DKG_STORE_NAMESPACE=agent-blackbox
BLACKBOX_DKG_CLI_DIR=/tmp/dkg
REPO_DIR=/tmp/repo
PATH={shlex.quote(str(fake_bin) + os.pathsep + os.environ.get("PATH", ""))}
reset_fresh_managed_blazegraph
"""
    completed = subprocess.run(["bash", "-c", command], check=False)

    assert completed.returncode == expected_rc
    actual_calls = calls.read_text(encoding="utf-8").splitlines() if calls.exists() else []
    assert len(actual_calls) == expected_calls
    if actual_calls:
        assert "reset /tmp/dkg" in actual_calls[0]
        assert actual_calls[0].endswith("agent-blackbox")


def test_windows_fresh_store_reset_has_the_same_ownership_guards() -> None:
    windows = INSTALL_PS1.read_text(encoding="utf-8")
    assert "$script:DkgFreshState = -not (Test-BlackboxDkgState)" in windows
    assert 'if (-not $script:DkgStoreManagedByDkg) { return $true }' in windows
    assert "if ($DkgStoreUrlExplicit) { return $true }" in windows
    assert "if ($script:DkgForeignEndpoint)" in windows
    assert "node $helper reset $DkgCliDir $DkgStoreUrl $script:DkgStoreNamespace" in windows


def test_installers_offer_both_store_backends_and_actionable_docker_setup() -> None:
    unix = INSTALL_SH.read_text(encoding="utf-8")
    windows = INSTALL_PS1.read_text(encoding="utf-8")

    assert "--store MODE" in unix
    assert "Store backend: auto, blazegraph, or oxigraph" in unix
    assert "auto|blazegraph|oxigraph" in windows
    assert "oxigraph-server" in unix and "oxigraph-server" in windows
    assert "https://get.docker.com" in unix
    assert "brew install --cask docker && open -a Docker" in unix
    assert "Docker.DockerDesktop" in windows
    assert "docker info" in unix and "docker info" in windows
    assert "Continue with Oxigraph instead? [y/N]" in unix
    assert "Continue with Oxigraph instead? [y/N]" in windows
    assert "confirm_oxigraph_fallback" in unix
    assert "Confirm-OxigraphFallback" in windows
    assert "Installation stopped before changing the DKG store" in unix
    assert "Installation stopped before changing the DKG store" in windows


@pytest.mark.skipif(shutil.which("bash") is None, reason="bash is unavailable")
def test_piped_installer_oxigraph_prompt_handles_missing_controlling_tty() -> None:
    command = f"""
confirm_oxigraph_fallback() {{
{_extract_function_body("confirm_oxigraph_fallback")}
}}
warn() {{ printf 'warn:%s\\n' "$1"; }}
step() {{ printf 'step:%s\\n' "$1"; }}
confirm_oxigraph_fallback "Docker unavailable"
"""
    completed = subprocess.run(
        ["bash", "-c", command],
        stdin=subprocess.DEVNULL,
        capture_output=True,
        text=True,
        check=False,
    )

    assert completed.returncode == 1
    assert "No interactive terminal is available" in completed.stdout
    assert "Device not configured" not in completed.stderr


@pytest.mark.skipif(shutil.which("bash") is None, reason="bash is unavailable")
def test_macos_installer_starts_installed_docker_desktop(tmp_path: Path) -> None:
    fake_bin = tmp_path / "bin"
    fake_bin.mkdir()
    docker_state = tmp_path / "docker-attempts"
    docker = fake_bin / "docker"
    docker.write_text(
        "#!/bin/sh\n"
        f"state={shlex.quote(str(docker_state))}\n"
        "n=0; [ ! -f \"$state\" ] || n=$(cat \"$state\")\n"
        "n=$((n + 1)); printf '%s' \"$n\" >\"$state\"\n"
        "[ \"$n\" -ge 2 ]\n",
        encoding="utf-8",
    )
    docker.chmod(0o755)
    opened = tmp_path / "opened"
    open_cmd = fake_bin / "open"
    open_cmd.write_text(
        f"#!/bin/sh\nprintf started >{shlex.quote(str(opened))}\n",
        encoding="utf-8",
    )
    open_cmd.chmod(0o755)
    app = tmp_path / "home" / "Applications" / "Docker.app"
    app.mkdir(parents=True)

    command = f"""
require_docker_for_blazegraph() {{
{_extract_function_body("require_docker_for_blazegraph")}
}}
ok() {{ printf 'ok:%s\\n' "$1"; }}
step() {{ printf 'step:%s\\n' "$1"; }}
warn() {{ printf 'warn:%s\\n' "$1"; }}
docker_setup_hint() {{ return 1; }}
sleep() {{ :; }}
OS=macos
HOME={shlex.quote(str(tmp_path / "home"))}
PATH={shlex.quote(str(fake_bin) + os.pathsep + os.environ.get("PATH", ""))}
BLACKBOX_DOCKER_REQUIRED=false
require_docker_for_blazegraph
"""
    completed = subprocess.run(
        ["bash", "-c", command],
        capture_output=True,
        text=True,
        check=True,
    )

    assert opened.read_text(encoding="utf-8") == "started"
    assert "starting it now" in completed.stdout
    assert "Docker Desktop is ready" in completed.stdout


def test_blazegraph_helper_uses_built_dkg_provisioner(tmp_path: Path) -> None:
    node = shutil.which("node")
    if not node:
        pytest.skip("Node.js is not installed")
    cli = tmp_path / "node_modules" / "@origintrail-official" / "dkg"
    module = cli / "dist" / "daemon" / "blazegraph-docker.js"
    module.parent.mkdir(parents=True)
    (cli / "package.json").write_text('{"type":"module"}', encoding="utf-8")
    module.write_text(
        "export async function provisionBlazegraphDocker(options) {\n"
        "  return {url: `http://127.0.0.1:${options.port}/${options.namespace}`, "
        "port: options.port, managedByDkg: true};\n"
        "}\n",
        encoding="utf-8",
    )

    completed = subprocess.run(
        [node, str(BLAZEGRAPH_HELPER), str(tmp_path), "blackbox-test", "10001"],
        check=True,
        capture_output=True,
        text=True,
    )

    assert json.loads(completed.stdout) == {
        "url": "http://127.0.0.1:10001/blackbox-test",
        "port": 10001,
        "managedByDkg": True,
    }


def test_blazegraph_helper_sizes_heap_and_preserves_undersized_store(tmp_path: Path) -> None:
    node = shutil.which("node")
    if not node:
        pytest.skip("Node.js is not installed")
    cli = tmp_path / "node_modules" / "@origintrail-official" / "dkg"
    module = cli / "dist" / "daemon" / "blazegraph-docker.js"
    module.parent.mkdir(parents=True)
    (cli / "package.json").write_text('{"type":"module"}', encoding="utf-8")
    module.write_text(
        "export async function provisionBlazegraphDocker(options) {\n"
        "  const inspected = await options.docker.run(['inspect', 'dkg-blazegraph-test']);\n"
        "  if (inspected.exitCode === 0) throw new Error('undersized container was reused');\n"
        "  const started = await options.docker.run(['run', '-d', 'blazegraph']);\n"
        "  return {url: started.stdout.trim(), port: options.port, managedByDkg: true};\n"
        "}\n",
        encoding="utf-8",
    )
    docker_log = tmp_path / "docker.log"
    fake_bin = tmp_path / "bin"
    fake_bin.mkdir()
    docker = fake_bin / "docker"
    docker.write_text(
        "#!/bin/sh\n"
        f"printf '%s\\n' \"$*\" >> {shlex.quote(str(docker_log))}\n"
        "case \"$1\" in\n"
        "  inspect) printf '%s\\n' '[{\"Config\":{\"Env\":[\"JAVA_OPTS=-Xmx1g\"]}}]' ;;\n"
        "  run) printf '%s\\n' \"$*\" ;;\n"
        "esac\n",
        encoding="utf-8",
    )
    docker.chmod(0o755)

    completed = subprocess.run(
        [node, str(BLAZEGRAPH_HELPER), str(tmp_path), "blackbox-test", "10001"],
        check=True,
        capture_output=True,
        text=True,
        env={**os.environ, "PATH": str(fake_bin) + os.pathsep + os.environ.get("PATH", "")},
    )

    calls = docker_log.read_text(encoding="utf-8").splitlines()
    assert calls[0] == "inspect dkg-blazegraph-test"
    assert calls[1] == "stop dkg-blazegraph-test"
    assert calls[2].startswith("rename dkg-blazegraph-test dkg-blazegraph-test-pre-4g-")
    assert calls[3] == "run --cpus 4 -e JAVA_OPTS=-Xms512m -Xmx4g -d blazegraph"
    assert json.loads(completed.stdout)["url"] == calls[3]


def test_blazegraph_helper_uses_dkg_store_health_check(tmp_path: Path) -> None:
    node = shutil.which("node")
    if not node:
        pytest.skip("Node.js is not installed")
    cli = tmp_path / "node_modules" / "@origintrail-official" / "dkg"
    module = cli / "dist" / "daemon" / "store-health-check.js"
    module.parent.mkdir(parents=True)
    (cli / "package.json").write_text('{"type":"module"}', encoding="utf-8")
    module.write_text(
        "export async function checkExternalStoreReachable(options) {\n"
        "  const endpoint = options.storeConfig.options.url;\n"
        "  return endpoint.includes('healthy')\n"
        "    ? {ok: true, backend: 'blazegraph', endpoint}\n"
        "    : {ok: false, backend: 'blazegraph', endpoint, error: 'HTTP 500'};\n"
        "}\n"
        "export function formatHealthCheckFailure(result) {\n"
        "  return `store unreachable: ${result.endpoint}: ${result.error}`;\n"
        "}\n",
        encoding="utf-8",
    )

    healthy = subprocess.run(
        [node, str(BLAZEGRAPH_HELPER), "check", str(tmp_path), "http://healthy/sparql"],
        check=True,
        capture_output=True,
        text=True,
    )
    failed = subprocess.run(
        [node, str(BLAZEGRAPH_HELPER), "check", str(tmp_path), "http://broken/sparql"],
        check=False,
        capture_output=True,
        text=True,
    )

    assert json.loads(healthy.stdout)["ok"] is True
    assert failed.returncode == 1
    assert "store unreachable: http://broken/sparql: HTTP 500" in failed.stderr


def test_dkg_config_writer_recovers_invalid_utf8(tmp_path: Path) -> None:
    home = tmp_path / "dkg"
    home.mkdir()
    config = home / "config.json"
    config.write_bytes(b"\xff\xfeinvalid")
    writer = _extract_unix_config_writer()

    completed = subprocess.run(
        [
            sys.executable,
            "-c",
            writer,
            str(home),
            "9320",
            "blazegraph",
            BLAZEGRAPH_URL,
            "true",
            "umanitek/blackbox-threats-staging",
        ],
        check=True,
        capture_output=True,
        text=True,
    )

    assert completed.stdout.strip() == "changed"
    recovered = json.loads(config.read_text(encoding="utf-8"))
    assert "contextGraphs" not in recovered


def test_installers_use_native_dkg_membership_without_sync_overrides() -> None:
    unix = INSTALL_SH.read_text(encoding="utf-8")
    windows = INSTALL_PS1.read_text(encoding="utf-8")
    unix_main = _extract_function_body("main")

    for text in (unix, windows):
        assert "blackbox-clean-dkg-subscriptions.py" not in text
        assert "DKG_CATCHUP_MAX_CONCURRENT_PEERS" in text
        assert "DKG_STORE_QUEUE_WAIT_TIMEOUT_MS" in text
        assert "DKG_SYNC_PAGE_TIMEOUT_MS" not in text
        assert "DKG_SYNC_TOTAL_TIMEOUT_MS" in text
        assert "DKG_SYNC_MIN_GRAPH_BUDGET_MS" not in text
        assert "DKG_SYNC_RESPONDER_PER_SNAPSHOT_ROW_LIMIT" not in text
        assert "DKG_SYNC_RESPONDER_GLOBAL_SNAPSHOT_ROW_LIMIT" not in text
        assert "blackbox-dkg-runtime-fingerprint.py" in text
        assert "DKG daemon is ready on npm build" in text
        assert "autoApproveJoinRequests" not in text
        assert 'data["syncOnConnectEnabled"] = True' in text
        assert 'data["syncReconcilerEnabled"] = True' in text
        assert 'data["durableSyncEnabled"] = True' in text
        assert 'data["syncGlobalMaxInflight"] = 1' in text
        assert 'data["syncGlobalQueueLimit"] = 0' in text
        assert 'data.pop("restrictAutoSubscribeContextGraphs", None)' in text
        assert 'data["syncSharedMemoryOnConnect"] = False' in text
        assert 'data["syncContextGraphPriorities"] = priorities' in text
        assert '"backend": "blazegraph"' in text
        assert '"options": {"url": store_url, "managedByDkg": store_managed, "timeout": 900000}' in text
        assert "DKG_ACCEPT_STORE_RESET" in text
        assert "DKG_STORE_QUEUE_LIMIT" in text
        assert "DKG_LIST_CONTEXT_GRAPHS_PROJECTION" in text
        assert "DKG_SYNC_GLOBAL_MAX_INFLIGHT" in text
        assert "DKG_SYNC_GLOBAL_QUEUE_LIMIT" in text
        assert "DKG_SYNC_ON_CONNECT_ENABLED" in text
        assert "DKG_SYNC_RECONCILER_ENABLED" in text
        assert "DKG_DURABLE_SYNC_ENABLED" in text
        assert "NODE_OPTIONS" in text
        assert "blackbox-npm-install.log" in text
        assert "Blazegraph SPARQL endpoint is healthy" in text
        assert "Blazegraph is unavailable or returned an error" in text

    assert 'BLACKBOX_DKG_SYNC_GLOBAL_MAX_INFLIGHT="1"' in unix
    assert 'BLACKBOX_DKG_SYNC_GLOBAL_QUEUE_LIMIT="0"' in unix
    assert 'BLACKBOX_DKG_DURABLE_SYNC_ENABLED="${BLACKBOX_DKG_DURABLE_SYNC_ENABLED:-1}"' in unix
    assert 'BLACKBOX_DKG_CATCHUP_MAX_CONCURRENT_PEERS="1"' in unix
    assert "PYTHONUNBUFFERED=1" in unix
    assert 'BLACKBOX_DKG_STORE_QUEUE_WAIT_TIMEOUT_MS="300000"' in unix
    assert '$DkgSyncGlobalMaxInflight = "1"' in windows
    assert '$DkgSyncGlobalQueueLimit = "0"' in windows
    assert 'else { "1" }' in windows
    assert "restart_blackbox_dkg_for_sync_mode" not in unix
    assert "Restart-BlackboxDkgForSyncMode" not in windows
    assert unix_main.index("sync_ruleset\n") < unix_main.index("start_dashboard\n")
    assert '$DkgCatchupMaxConcurrentPeers = "1"' in windows
    assert '$DkgStoreQueueWaitTimeoutMs = "300000"' in windows
    assert "one large sync at a time" in unix
    assert "one large sync at a time" in windows


@pytest.mark.parametrize("store_backend", ["blazegraph", "oxigraph-server"])
@pytest.mark.skipif(shutil.which("bash") is None, reason="bash is unavailable")
def test_unix_dkg_launcher_applies_memory_and_single_flight_guards(
    tmp_path: Path,
    store_backend: str,
) -> None:
    dkg = tmp_path / "dkg"
    dkg.write_text(
        "#!/bin/sh\n"
        "backend=$(sed -n 's/.*\"backend\": *\"\\([^\"]*\\)\".*/\\1/p' "
        "\"$DKG_HOME/config.json\")\n"
        "printf '%s|%s|%s|%s|%s\\n' \"$backend\" \"$DKG_HOME\" "
        "\"$DKG_SYNC_GLOBAL_MAX_INFLIGHT\" \"$NODE_OPTIONS\" \"$1\"\n",
        encoding="utf-8",
    )
    dkg.chmod(0o755)
    dkg_home = tmp_path / "dkg-home"
    dkg_home.mkdir()
    (dkg_home / "config.json").write_text(
        json.dumps({"store": {"backend": store_backend}}),
        encoding="utf-8",
    )
    body = _extract_function_body("blackbox_dkg")
    command = f"""
blackbox_dkg() {{
{body}
}}
BLACKBOX_DKG_HOME={shlex.quote(str(dkg_home))}
BLACKBOX_DKG_BIN={shlex.quote(str(dkg))}
BLACKBOX_DKG_ACCEPT_STORE_RESET=false
BLACKBOX_DKG_STORE_RESET_MARKER={shlex.quote(str(dkg_home / '.reset'))}
BLACKBOX_DKG_STORE_QUEUE_LIMIT=512
BLACKBOX_DKG_LIST_CONTEXT_GRAPHS_PROJECTION=1
BLACKBOX_DKG_SYNC_GLOBAL_MAX_INFLIGHT=1
BLACKBOX_DKG_NODE_OPTIONS='--enable-source-maps --max-old-space-size=8192'
blackbox_dkg start
"""

    completed = subprocess.run(
        ["bash", "-c", command],
        check=True,
        capture_output=True,
        text=True,
    )

    assert completed.stdout.strip() == (
        f"{store_backend}|{dkg_home}|1|"
        "--enable-source-maps --max-old-space-size=8192|start"
    )


def test_installers_never_patch_the_published_dkg_runtime() -> None:
    unix = INSTALL_SH.read_text(encoding="utf-8")
    windows = INSTALL_PS1.read_text(encoding="utf-8")

    for text in (unix, windows):
        assert "dkg-agent-lifecycle.js" not in text
        assert "dkg-agent-constants.js" not in text
        assert "dist/daemon/routes/memory.js" not in text
        assert "dist\\daemon\\routes\\memory.js" not in text
        assert "Using published upstream DKG" in text
        assert "unchanged" in text

    curator = CURATOR_CONFIG.read_text(encoding="utf-8")
    service = CURATOR_SERVICE.read_text(encoding="utf-8")
    assert "--dkg-agent-dist" not in curator
    assert "--dkg-agent-dist" not in service
    assert "dkg-agent-lifecycle.js" not in curator
    assert "dkg-agent-registry.js" not in curator


def test_installers_restart_running_owned_dkg_only_for_runtime_changes() -> None:
    unix = _extract_function_body("install_dkg")
    windows = INSTALL_PS1.read_text(encoding="utf-8")

    assert "BLACKBOX_DKG_RESTART_REQUIRED" in INSTALL_SH.read_text(encoding="utf-8")
    assert 'if [ "$BLACKBOX_DKG_RESTART_REQUIRED" != true ]; then' in unix
    assert "blackbox_dkg start || true" in unix
    assert "if wait_for_blackbox_dkg_runtime; then" in unix
    assert 'docker start "$managed_container"' in INSTALL_SH.read_text(encoding="utf-8")
    assert "docker start $managedContainer" in windows
    assert "install_blackbox_dkg_package" in unix
    assert "prepare_blackbox_dkg_runtime_fingerprint" in unix
    assert "record_blackbox_dkg_runtime_fingerprint" in unix
    assert ".blackbox-runtime.sha256" in INSTALL_SH.read_text(encoding="utf-8")

    assert "if ($script:DkgAlreadyRunning)" in windows
    assert "if (-not $script:DkgRestartRequired)" in windows
    assert "Invoke-BlackboxDkg stop" in windows
    assert "Invoke-BlackboxDkg start" in windows
    assert "Wait-BlackboxDkgRuntime" in windows
    assert "updated sync settings are not active" in windows
    assert "Prepare-BlackboxDkgRuntimeFingerprint" in windows
    assert "Save-BlackboxDkgRuntimeFingerprint" in windows
    assert ".blackbox-runtime.sha256" in windows


def test_installers_migrate_only_the_known_legacy_blackbox_dkg_paths() -> None:
    unix = INSTALL_SH.read_text(encoding="utf-8")
    windows = INSTALL_PS1.read_text(encoding="utf-8")

    assert '$HOME/.hermes/blackbox/dkg' in unix
    assert '$HOME/.hermes/blackbox/dkg-cli/node_modules/.bin/dkg' in unix
    assert 'mv "$legacy_home" "$BLACKBOX_DKG_HOME"' in unix
    assert 'DKG_HOME="$legacy_home" "$legacy_bin" stop' in unix
    assert '.hermes\\blackbox\\dkg' in windows
    assert 'Move-Item $legacyHome $DkgHome' in windows
    assert '& $legacyBin stop' in windows


@pytest.mark.skipif(shutil.which("bash") is None, reason="bash is unavailable")
def test_unix_legacy_dkg_state_moves_into_project_without_losing_identity(
    tmp_path: Path,
) -> None:
    home = tmp_path / "home"
    legacy = home / ".hermes" / "blackbox" / "dkg"
    target = home / "agent-blackbox" / ".dkg"
    legacy.mkdir(parents=True)
    target.parent.mkdir(parents=True)
    (legacy / "config.json").write_text('{"apiPort":9320}\n', encoding="utf-8")
    (legacy / "agent-key.bin").write_bytes(b"preserved-peer-identity")
    body = _extract_function_body("migrate_legacy_blackbox_dkg_home")
    command = f"""
migrate_legacy_blackbox_dkg_home() {{
{body}
}}
warn() {{ :; }}
step() {{ :; }}
ok() {{ :; }}
HOME={shlex.quote(str(home))}
BLACKBOX_DKG_HOME={shlex.quote(str(target))}
BLACKBOX_INSTALL_INCOMPLETE=false
BLACKBOX_THREAT_GRAPH_INCOMPLETE=false
migrate_legacy_blackbox_dkg_home
"""

    subprocess.run(["bash", "-c", command], check=True)

    assert not legacy.exists()
    assert (target / "config.json").is_file()
    assert (target / "agent-key.bin").read_bytes() == b"preserved-peer-identity"


@pytest.mark.skipif(shutil.which("bash") is None, reason="bash is unavailable")
def test_unix_runtime_marker_survives_interrupted_restart_window(
    tmp_path: Path,
) -> None:
    cli_dir = tmp_path / "dkg-cli"
    home = tmp_path / "dkg-home"
    cli_package = cli_dir / "packages" / "cli"
    agent_package = cli_dir / "packages" / "agent"
    (cli_package / "dist").mkdir(parents=True)
    (agent_package / "dist").mkdir(parents=True)
    home.mkdir()
    (cli_package / "package.json").write_text(
        '{"name":"@origintrail-official/dkg","version":"10.0.6"}\n',
        encoding="utf-8",
    )
    (cli_package / "dist" / "cli.js").write_text(
        "export const cli = 1;\n", encoding="utf-8"
    )
    (agent_package / "package.json").write_text(
        '{"name":"@origintrail-official/dkg-agent","version":"10.0.6"}\n',
        encoding="utf-8",
    )
    agent_runtime = agent_package / "dist" / "agent.js"
    agent_runtime.write_text("export const agent = 1;\n", encoding="utf-8")
    (home / "config.json").write_text("{}\n", encoding="utf-8")
    dkg_bin = tmp_path / "dkg"
    dkg_bin.write_text("launcher\n", encoding="utf-8")
    venv = tmp_path / "venv"
    (venv / "bin").mkdir(parents=True)
    (venv / "bin" / "python").symlink_to(Path(sys.executable))
    fake_bin = tmp_path / "bin"
    fake_bin.mkdir()
    (fake_bin / "node").symlink_to(Path(sys.executable))
    marker = home / ".blackbox-runtime.sha256"
    prepare_body = _extract_function_body(
        "prepare_blackbox_dkg_runtime_fingerprint"
    )
    record_body = _extract_function_body(
        "record_blackbox_dkg_runtime_fingerprint"
    )

    def invoke(*, record: bool) -> tuple[str, ...]:
        command = f"""
warn() {{ :; }}
prepare_blackbox_dkg_runtime_fingerprint() {{
{prepare_body}
}}
record_blackbox_dkg_runtime_fingerprint() {{
{record_body}
}}
REPO_DIR={shlex.quote(str(REPO_ROOT))}
VENV_DIR={shlex.quote(str(venv))}
BLACKBOX_DKG_CLI_DIR={shlex.quote(str(cli_dir))}
BLACKBOX_DKG_HOME={shlex.quote(str(home))}
BLACKBOX_DKG_BIN={shlex.quote(str(dkg_bin))}
BLACKBOX_DKG_RUNTIME_MARKER={shlex.quote(str(marker))}
BLACKBOX_DKG_RUNTIME_FINGERPRINT=''
BLACKBOX_DKG_RESTART_REQUIRED=false
BLACKBOX_INSTALL_INCOMPLETE=false
BLACKBOX_THREAT_GRAPH_INCOMPLETE=false
PATH={shlex.quote(str(fake_bin))}:$PATH
prepare_blackbox_dkg_runtime_fingerprint
prepare_rc=$?
record_rc=skipped
if {str(record).lower()}; then
    record_blackbox_dkg_runtime_fingerprint
    record_rc=$?
fi
fingerprint_length=$(printf %s "$BLACKBOX_DKG_RUNTIME_FINGERPRINT" | wc -c | tr -d ' ')
printf '%s|%s|%s|%s\n' "$prepare_rc" "$BLACKBOX_DKG_RESTART_REQUIRED" "$fingerprint_length" "$record_rc"
"""
        completed = subprocess.run(
            ["bash", "-c", command],
            check=True,
            capture_output=True,
            text=True,
        )
        return tuple(completed.stdout.strip().split("|"))

    assert invoke(record=True) == ("0", "true", "64", "0")
    assert invoke(record=False) == ("0", "false", "64", "skipped")

    # Disk changes without a successful restart must remain stale on every retry.
    agent_runtime.write_text("export const agent = 2;\n", encoding="utf-8")
    assert invoke(record=False) == ("0", "true", "64", "skipped")
    assert invoke(record=False) == ("0", "true", "64", "skipped")


def test_unix_installer_stops_dkg_setup_when_npm_install_fails(tmp_path: Path) -> None:
    install_body = _extract_function_body("install_dkg")
    continued = tmp_path / "continued"
    command = f"""
heading() {{ :; }}
ok() {{ :; }}
step() {{ :; }}
warn() {{ :; }}
dkg_manual_hint() {{ printf 'manual-hint\n'; }}
install_blackbox_dkg_package() {{ return 1; }}
check_blackbox_dkg_port() {{ : > {shlex.quote(str(continued))}; return 0; }}
install_dkg() {{
{install_body}
}}
SKIP_DKG=false
HAS_NODE=true
BLACKBOX_DKG_CLI_DIR={shlex.quote(str(tmp_path / 'dkg-cli'))}
BLACKBOX_DKG_BIN=/bin/true
BLACKBOX_DKG_PACKAGE=@origintrail-official/dkg@10.0.6
install_dkg
"""
    result = subprocess.run(
        ["bash", "-c", command],
        check=True,
        capture_output=True,
        text=True,
    )

    assert "manual-hint" in result.stdout
    assert not continued.exists(), "installer continued into DKG port/config setup"


def test_windows_dkg_npm_failure_is_fatal_to_dkg_setup() -> None:
    install_body = _extract_powershell_function_body("Install-Dkg")
    failure_guard = """if (-not (Install-BlackboxDkgPackage)) {
        $script:InstallIncomplete = $true
        Show-DkgManualHint
        return
    }"""
    assert failure_guard in install_body
    assert install_body.index(failure_guard) < install_body.index(
        "New-Item -ItemType Directory -Force -Path $DkgHome"
    )
