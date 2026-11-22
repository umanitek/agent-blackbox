"""All or nothing: an install either finishes completely or leaves the machine as it was.

Amos, 2026-10-17: a one-line install on a Mac stopped half-way (Docker Desktop never came up,
no terminal to accept the built-in store) and left Hermes installed with no Blackbox in it.
These tests run the installer's real install-record, rollback, pre-flight and store-port
functions in a sandbox HOME, break the install on purpose, and check what is left.
"""

from __future__ import annotations

import json
import os
import pty
import shlex
import signal
import subprocess
import sys
import time
from pathlib import Path

import pytest

from tests.waiting import wait_until

REPO = Path(__file__).resolve().parents[1]
INSTALL_SH = REPO / "scripts" / "blackbox-install.sh"
TEXT = INSTALL_SH.read_text(encoding="utf-8")


def _section(start_marker: str, end_marker: str) -> str:
    start = TEXT.index(start_marker)
    return TEXT[start:TEXT.index(end_marker, start)]


RECORD = _section("# ── All or nothing: the install record", "# ── Main")
PREFLIGHT = _section("# ── Pre-flight: everything that can be known", "# ── All or nothing: the install record")


def _assignment(name: str) -> str:
    """The installer's own ``NAME=value`` line, so a test runs with the shipped value."""
    return next(line for line in TEXT.splitlines() if line.startswith(f"{name}="))


def _function(name: str) -> str:
    """The text of one installer function, skipping `}` lines inside its heredocs."""
    lines = TEXT[TEXT.index(f"\n{name}() {{\n") + 1:].splitlines(keepends=True)
    heredoc_end = None
    for index, line in enumerate(lines):
        if heredoc_end is not None:
            heredoc_end = None if line.strip() == heredoc_end else heredoc_end
        elif "<<'" in line:
            heredoc_end = line.split("<<'", 1)[1].split("'", 1)[0]
        elif line == "}\n":
            return "".join(lines[:index + 1])
    raise AssertionError(f"{name}() has no end")


# The ONLY folder on the sandbox's PATH (LES-064). The rollback under test really runs
# `launchctl bootout`, `systemctl disable --now`, `docker rm`: with /bin on PATH after the
# stubs, one unstubbed call reached the real launchd and unloaded a real Blackbox node on
# the Mac that ran this suite (2026-10-17). Ordinary tools are linked in one by one; every
# tool that can touch the machine's services is a stub that only records its call.
_ORDINARY_TOOLS = ("awk", "cat", "chmod", "cksum", "cp", "cut", "dirname", "grep", "head", "ls", "mkdir",
                   "mktemp", "ps", "rm", "sed", "sleep", "sort", "tail", "touch", "tr", "id", "wc", "date")
_SERVICE_TOOLS = ("launchctl", "systemctl", "loginctl", "osascript", "docker", "pgrep", "open")


def _isolated_bin(bin_dir: Path, calls: Path) -> None:
    import shutil
    for tool in _ORDINARY_TOOLS:
        real = shutil.which(tool, path="/usr/bin:/bin:/usr/sbin:/sbin")
        if real and not (bin_dir / tool).exists():
            (bin_dir / tool).symlink_to(real)
    for tool in _SERVICE_TOOLS:
        if not (bin_dir / tool).exists():
            (bin_dir / tool).write_text(f'#!/bin/sh\necho "{tool} $*" >>{shlex.quote(str(calls))}\nexit 1\n',
                                        encoding="utf-8")
            (bin_dir / tool).chmod(0o755)


def _sandbox(tmp_path: Path) -> dict[str, Path]:
    home = tmp_path / "home"
    home.mkdir()
    bin_dir = tmp_path / "bin"
    bin_dir.mkdir()
    return {"home": home, "bin": bin_dir, "root": home / "agent-blackbox", "hermes": home / ".hermes",
            "service_calls": tmp_path / "service-calls"}


def _script(paths: dict[str, Path], body: str) -> str:
    """A bash program with the record section loaded and the node/service helpers stubbed."""
    q = {key: shlex.quote(str(value)) for key, value in paths.items()}
    return f"""
set -euo pipefail
HOME={q["home"]}
USER=tester
PATH={q["bin"]}
BLACKBOX_INSTALL_ROOT={q["root"]}
HERMES_HOME={q["hermes"]}
BLACKBOX_HOME="$HERMES_HOME/blackbox"
BLACKBOX_DKG_HOME="$BLACKBOX_INSTALL_ROOT/.dkg"
BLACKBOX_DKG_CLI_DIR="$BLACKBOX_INSTALL_ROOT/dkg"
BLACKBOX_DKG_BIN="$BLACKBOX_DKG_CLI_DIR/node_modules/.bin/dkg"
BLACKBOX_SYSTEMD_DIR="$HOME/system-units"
BLACKBOX_LINGER_DIR="$HOME/linger"
step() {{ echo "step: $1"; }}
ok() {{ echo "ok: $1"; }}
warn() {{ echo "warn: $1"; }}
err() {{ echo "err: $1"; }}
heading() {{ :; }}
blackbox_dkg_answers() {{ return 1; }}
blackbox_has_dkg_state() {{ return 1; }}
blackbox_dkg_control() {{ echo "dkg-control $*" >>"$HOME/calls"; }}
blackbox_dkg() {{ echo "dkg $*" >>"$HOME/calls"; }}
{RECORD}
{body}
"""


def _run(paths: dict[str, Path], body: str, **kwargs) -> subprocess.CompletedProcess[str]:
    _isolated_bin(paths["bin"], paths["service_calls"])
    return subprocess.run(["bash", "-c", _script(paths, body)], capture_output=True, text=True,
                          check=False, timeout=60, **kwargs)


def _alive(pid: int) -> bool:
    try:
        os.kill(pid, 0)
    except ProcessLookupError:
        return False
    # A killed child of an exited shell may linger as a zombie until it is reaped.
    state = subprocess.run(["ps", "-o", "stat=", "-p", str(pid)], capture_output=True, text=True, check=False)
    return not state.stdout.strip().startswith("Z") and bool(state.stdout.strip())


def _tree(root: Path) -> set[str]:
    return {str(p.relative_to(root)) for p in root.rglob("*")}


def test_a_failed_fresh_install_removes_everything_it_created(tmp_path: Path) -> None:
    paths = _sandbox(tmp_path)
    zshrc = paths["home"] / ".zshrc"
    zshrc.write_text("export MINE=1\n", encoding="utf-8")
    before = _tree(paths["home"])

    result = _run(paths, """
install_record_begin
mkdir -p "$BLACKBOX_INSTALL_ROOT/.dkg" "$HERMES_HOME/installs/venv" "$HOME/.local/bin" "$HOME/Library/LaunchAgents"
echo hermes >"$HOME/.local/bin/hermes"
echo plist >"$HOME/Library/LaunchAgents/ai.umanitek.blackbox-dkg.plist"
echo 'export PATH="$HOME/.local/bin:$PATH"' >>"$HOME/.zshrc"
false   # any failing step (set -e)
""")

    assert result.returncode != 0
    assert "Nothing from this install attempt was left behind." in result.stdout
    assert _tree(paths["home"]) - {"calls"} == before
    assert zshrc.read_text(encoding="utf-8") == "export MINE=1\n"


def test_an_upgrade_that_fails_keeps_existing_state_and_restores_rewritten_files(tmp_path: Path) -> None:
    paths = _sandbox(tmp_path)
    paths["hermes"].mkdir()
    (paths["hermes"] / "config.yaml").write_text("model: mine\n", encoding="utf-8")
    (paths["hermes"] / "sessions.db").write_text("my history\n", encoding="utf-8")
    (paths["root"] / ".dkg").mkdir(parents=True)
    (paths["root"] / ".dkg" / "config.json").write_text('{"apiPort": 9320}\n', encoding="utf-8")
    (paths["root"] / ".dkg" / "store.db").write_text("synced graph\n", encoding="utf-8")

    result = _run(paths, """
install_record_begin
echo "model: changed" >"$HERMES_HOME/config.yaml"
echo '{"apiPort": 9999}' >"$BLACKBOX_DKG_HOME/config.json"
exit 7
""")

    assert result.returncode == 7
    assert (paths["hermes"] / "config.yaml").read_text(encoding="utf-8") == "model: mine\n"
    assert (paths["hermes"] / "sessions.db").read_text(encoding="utf-8") == "my history\n"
    assert (paths["root"] / ".dkg" / "config.json").read_text(encoding="utf-8") == '{"apiPort": 9320}\n'
    assert (paths["root"] / ".dkg" / "store.db").read_text(encoding="utf-8") == "synced graph\n"


def test_a_committed_install_is_kept(tmp_path: Path) -> None:
    paths = _sandbox(tmp_path)

    result = _run(paths, """
install_record_begin
mkdir -p "$BLACKBOX_INSTALL_ROOT" "$HERMES_HOME"
record="$INSTALL_RECORD_DIR"
install_record_commit
[ ! -e "$record" ] && echo record-cleared
""")

    assert result.returncode == 0, result.stdout + result.stderr
    assert "record-cleared" in result.stdout
    assert paths["root"].is_dir() and paths["hermes"].is_dir()


#: Starts bash with Ctrl-C at its default handling, whatever the test runner's is (see
#: the test below): a tiny launcher resets SIGINT, then becomes bash (no preexec_fn).
_WITH_DEFAULT_SIGINT = [sys.executable, "-c",
                        "import os, signal, sys; signal.signal(signal.SIGINT, signal.SIG_DFL); "
                        "os.execvp('bash', ['bash', '-c', sys.argv[1]])"]


def test_ctrl_c_rolls_the_install_back(tmp_path: Path) -> None:
    """Ctrl-C as a terminal sends it: to the whole foreground process group, once the
    installer is past install_record_begin, into a shell that starts with Ctrl-C at its
    default handling. KI-447: a suite started as a background job runs with SIGINT
    IGNORED, every child inherits that, and bash cannot trap a signal that was ignored
    when it started — so the installer's rollback trap never ran and the test timed
    out. The shell starts through a launcher that resets SIGINT, as a terminal would have it."""
    paths = _sandbox(tmp_path)
    ready = tmp_path / "ready"
    _isolated_bin(paths["bin"], paths["service_calls"])
    process = subprocess.Popen([*_WITH_DEFAULT_SIGINT, _script(paths, f"""
install_record_begin
mkdir -p "$BLACKBOX_INSTALL_ROOT"
touch {shlex.quote(str(ready))}
while :; do sleep 0.1; done
""")], stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, start_new_session=True)
    try:
        assert wait_until(ready.exists, timeout=180), "the installer never reached its ready point"
        os.killpg(process.pid, signal.SIGINT)
        stdout, _ = process.communicate(timeout=60)
    finally:
        if process.poll() is None:
            os.killpg(process.pid, signal.SIGKILL)
            process.communicate()

    assert process.returncode == 130
    assert "Nothing from this install attempt was left behind." in stdout
    assert not paths["root"].exists()


def test_rollback_stops_processes_this_run_started_and_its_new_node(tmp_path: Path) -> None:
    paths = _sandbox(tmp_path)

    result = _run(paths, """
install_record_begin
sleep 300 &
started=$!
install_record_started_pid "$started"
mkdir -p "$(dirname "$BLACKBOX_DKG_BIN")" && touch "$BLACKBOX_DKG_BIN" && chmod +x "$BLACKBOX_DKG_BIN"
echo "$started" >"$HOME/started.pid"
false
""")

    started = int((paths["home"] / "started.pid").read_text(encoding="utf-8"))
    assert wait_until(lambda: not _alive(started), timeout=10)
    calls = (paths["home"] / "calls").read_text(encoding="utf-8").splitlines()
    assert "dkg-control stop" in calls and "dkg stop" in calls
    assert result.returncode != 0


def test_rollback_restarts_a_node_that_was_running_before(tmp_path: Path) -> None:
    paths = _sandbox(tmp_path)

    _run(paths, """
blackbox_dkg_answers() { return 0; }
blackbox_has_dkg_state() { return 0; }
install_record_begin
false
""")

    calls = (paths["home"] / "calls").read_text(encoding="utf-8").splitlines()
    # reload, not restart: the service must run the RESTORED definition, not the failed attempt's
    # that launchd still holds (E2E recheck 2026-11-21: exit 127, node down after rollback).
    assert calls == ["dkg-control reload"]


def test_rollback_removes_only_the_docker_store_this_run_created(tmp_path: Path) -> None:
    paths = _sandbox(tmp_path)
    state = tmp_path / "docker-objects"
    state.write_text("container dkg-blazegraph-old\nvolume dkg-blazegraph-old-data\n", encoding="utf-8")
    removed = tmp_path / "removed"
    docker = paths["bin"] / "docker"
    docker.write_text(f"""#!/bin/sh
case "$1 $2" in
  "info "*) exit 0 ;;
  "ps -a") grep '^container ' {shlex.quote(str(state))} | cut -d' ' -f2 ;;
  "volume ls") grep '^volume ' {shlex.quote(str(state))} | cut -d' ' -f2 ;;
  "rm -f") echo "container $3" >>{shlex.quote(str(removed))} ;;
  "volume rm") echo "volume $4" >>{shlex.quote(str(removed))} ;;
esac
""", encoding="utf-8")
    docker.chmod(0o755)

    _run(paths, f"""
install_record_begin
printf 'container dkg-blazegraph-agent-blackbox\\nvolume dkg-blazegraph-agent-blackbox-data\\n' >>{shlex.quote(str(state))}
false
""")

    assert sorted(removed.read_text(encoding="utf-8").splitlines()) == [
        "container dkg-blazegraph-agent-blackbox",
        "volume dkg-blazegraph-agent-blackbox-data",
    ]


@pytest.mark.parametrize("path", ["", "relative/path", "/", "/Users", "/home", "/usr", "HOME"])
def test_rollback_never_removes_a_top_level_or_home_folder(tmp_path: Path, path: str) -> None:
    paths = _sandbox(tmp_path)
    target = '"$HOME"' if path == "HOME" else shlex.quote(path)

    result = _run(paths, f"install_path_removable {target} && echo removable || echo refused")

    assert result.stdout.strip().endswith("refused")


def _oxigraph_config(tmp_path: Path, *, busy: set[int], running: bool, existing: dict | None) -> dict:
    home = tmp_path / "dkg-home"
    home.mkdir()
    if existing is not None:
        (home / "config.json").write_text(json.dumps(existing), encoding="utf-8")
    venv = tmp_path / "venv" / "bin"
    venv.mkdir(parents=True)
    (venv / "python").symlink_to(sys.executable)
    busy_case = "|".join(str(port) for port in sorted(busy)) or "none"
    script = f"""
set -euo pipefail
err() {{ echo "err: $1"; }}
warn() {{ :; }}
step() {{ :; }}
port_in_use() {{ case "$1" in {busy_case}) return 0 ;; *) return 1 ;; esac; }}
{_assignment("BLACKBOX_OXIGRAPH_FIRST_PORT")}
{_assignment("BLACKBOX_OXIGRAPH_LAST_PORT")}
{_function("choose_blackbox_oxigraph_port")}
{_function("ensure_blackbox_dkg_config")}
VENV_DIR={shlex.quote(str(venv.parent))}
BLACKBOX_DKG_HOME={shlex.quote(str(home))}
BLACKBOX_DKG_PORT=9320
BLACKBOX_DKG_SELECTED_STORE_BACKEND=oxigraph-server
BLACKBOX_DKG_STORE_URL=""
BLACKBOX_DKG_STORE_MANAGED_BY_DKG=false
BLACKBOX_CONTEXT_GRAPH_ID=graph
BLACKBOX_DEFAULT_CONTEXT_GRAPH_ID=graph
BLACKBOX_DKG_ALREADY_RUNNING={'true' if running else 'false'}
ensure_blackbox_dkg_config
"""
    result = subprocess.run(["bash", "-c", script], capture_output=True, text=True, check=False, timeout=60)
    assert result.returncode == 0, result.stdout + result.stderr
    return json.loads((home / "config.json").read_text(encoding="utf-8"))["store"]


def test_a_new_node_gets_a_free_oxigraph_port_beside_another_dkg_node(tmp_path: Path) -> None:
    store = _oxigraph_config(tmp_path, busy={7878}, running=False, existing=None)

    assert store == {"backend": "oxigraph-server", "options": {"port": 7879}}


def test_a_new_node_never_takes_the_dkg_default_store_port(tmp_path: Path) -> None:
    """7878 is every DKG node's default; another node restarting leaves it free for a moment
    (a Mac install took it in a 2-second restart gap and its node could not start)."""
    store = _oxigraph_config(tmp_path, busy=set(), running=False, existing=None)

    assert store["options"]["port"] == 7879


def test_a_configured_oxigraph_port_is_kept(tmp_path: Path) -> None:
    existing = {"store": {"backend": "oxigraph-server", "options": {"port": 7890}}}

    store = _oxigraph_config(tmp_path, busy={7878}, running=False, existing=existing)

    assert store["options"]["port"] == 7890


def test_a_running_blackbox_node_keeps_its_store_port(tmp_path: Path) -> None:
    existing = {"store": {"backend": "oxigraph-server"}}

    store = _oxigraph_config(tmp_path, busy={7878}, running=True, existing=existing)

    assert store == {"backend": "oxigraph-server"}


def _prompt(answer: bytes | None, seconds: int = 5) -> tuple[int, str]:
    """Run confirm_oxigraph_fallback with a real controlling terminal (a pty)."""
    program = f"""
warn() {{ :; }}
step() {{ :; }}
BLACKBOX_STORE_PROMPT_SECONDS={seconds}
{_function("confirm_oxigraph_fallback")}
confirm_oxigraph_fallback "Docker unavailable"
"""
    pid, fd = pty.fork()
    if pid == 0:
        os.execvp("bash", ["bash", "-c", program])
    output = b""
    deadline = time.monotonic() + 30
    while b"[Y/n]" not in output and time.monotonic() < deadline:
        output += os.read(fd, 1024)
    if answer is not None:
        os.write(fd, answer)
    while True:
        try:
            chunk = os.read(fd, 1024)
        except OSError:
            break
        if not chunk:
            break
        output += chunk
    _, status = os.waitpid(pid, 0)
    return os.waitstatus_to_exitcode(status), output.decode(errors="replace")


@pytest.mark.parametrize(("answer", "expected"), [(b"\n", 0), (b"y\n", 0), (b"n\n", 1), (None, 0)])
def test_a_person_is_asked_and_yes_is_the_default(answer: bytes | None, expected: int) -> None:
    code, output = _prompt(answer, seconds=1 if answer is None else 20)

    assert "Continue with Oxigraph? [Y/n]" in output
    assert code == expected


def _preflight(tmp_path: Path, body: str, *, docker_works: bool) -> subprocess.CompletedProcess[str]:
    install_root = tmp_path / "agent-blackbox"
    script = f"""
set -euo pipefail
step() {{ echo "step: $1"; }}
ok() {{ echo "ok: $1"; }}
warn() {{ echo "warn: $1"; }}
err() {{ echo "err: $1"; }}
heading() {{ :; }}
require_docker_for_blazegraph() {{ {'return 0' if docker_works else 'return 1'}; }}
blackbox_docker_available() {{ {'return 0' if docker_works else 'return 1'}; }}
{_function("confirm_oxigraph_fallback")}
{PREFLIGHT}
SKIP_DKG=false
BLACKBOX_SETUP_ONLY=false
BLACKBOX_DKG_STORE_URL_EXPLICIT=false
BLACKBOX_DKG_STORE_BACKEND=auto
BLACKBOX_DOCKER_REQUIRED=true
BLACKBOX_INSTALL_ROOT={shlex.quote(str(install_root))}
BLACKBOX_DKG_HOME="$BLACKBOX_INSTALL_ROOT/.dkg"
{body}
"""
    return subprocess.run(["bash", "-c", script], stdin=subprocess.DEVNULL, capture_output=True, text=True,
                          check=False, timeout=60, start_new_session=True)


def test_without_docker_and_without_a_terminal_the_builtin_store_is_chosen(tmp_path: Path) -> None:
    result = _preflight(tmp_path, 'preflight_store_choice; echo "backend=$BLACKBOX_DKG_STORE_BACKEND docker=$BLACKBOX_DOCKER_REQUIRED"',
                        docker_works=False)

    assert result.returncode == 0, result.stdout
    assert "backend=oxigraph docker=false" in result.stdout


def test_an_explicit_blazegraph_choice_without_docker_stops_before_any_change(tmp_path: Path) -> None:
    result = _preflight(tmp_path, "BLACKBOX_DKG_STORE_BACKEND=blazegraph; preflight_store_choice; echo continued",
                        docker_works=False)

    assert result.returncode == 1
    assert "Stopped before installing anything" in result.stdout
    assert "continued" not in result.stdout


def test_an_existing_node_keeps_its_store(tmp_path: Path) -> None:
    result = _preflight(tmp_path, """mkdir -p "$BLACKBOX_DKG_HOME" && echo '{}' >"$BLACKBOX_DKG_HOME/config.json"
preflight_store_choice; echo "backend=$BLACKBOX_DKG_STORE_BACKEND\"""", docker_works=False)

    assert "backend=auto" in result.stdout


def test_too_little_disk_stops_before_any_change(tmp_path: Path) -> None:
    result = _preflight(tmp_path, "free_kb_at() { echo 1048576; }; preflight_disk; echo continued", docker_works=True)

    assert result.returncode == 1
    assert "Not enough disk space: 1 GB free" in result.stdout
    assert "continued" not in result.stdout


def test_an_unreachable_npm_registry_stops_before_any_change(tmp_path: Path) -> None:
    result = _preflight(tmp_path, """BLACKBOX_SETUP_ONLY=true
BLACKBOX_NPM_REGISTRY_PING=http://127.0.0.1:9/unreachable
BLACKBOX_PREFLIGHT_NETWORK_SECONDS=2
preflight_network; echo continued""", docker_works=True)

    assert result.returncode == 1
    assert "Cannot reach the npm registry" in result.stdout


def _verify(tmp_path: Path, *, hermes_ok: bool, plugin_ok: bool) -> subprocess.CompletedProcess[str]:
    hermes = tmp_path / "hermes"
    hermes.write_text(f"""#!/bin/sh
case "$1" in
  --version) exit {0 if hermes_ok else 1} ;;
  blackbox) exit {0 if plugin_ok else 1} ;;
esac
""", encoding="utf-8")
    hermes.chmod(0o755)
    script = f"""
set -euo pipefail
ok() {{ echo "ok: $1"; }}
err() {{ echo "err: $1"; }}
heading() {{ :; }}
{_function("verify_install")}
HERMES_BIN={shlex.quote(str(hermes))}
BLACKBOX_INSTALL_INCOMPLETE=false
SKIP_DKG=true
BLACKBOX_AUTO_DASHBOARD=0
verify_install
echo committed
"""
    return subprocess.run(["bash", "-c", script], capture_output=True, text=True, check=False, timeout=60)


def test_the_install_is_kept_only_when_every_part_answers(tmp_path: Path) -> None:
    good = _verify(tmp_path, hermes_ok=True, plugin_ok=True)
    no_plugin = _verify(tmp_path, hermes_ok=True, plugin_ok=False)

    assert good.returncode == 0 and "committed" in good.stdout
    assert no_plugin.returncode == 1
    assert "Hermes loads the Blackbox plugin — NOT working" in no_plugin.stdout
    assert "committed" not in no_plugin.stdout


def test_main_commits_only_after_the_final_check() -> None:
    main = _function("main")

    assert main.index("install_record_begin") < main.index("preflight_install") < main.index("resolve_repo")
    assert main.index("verify_install") < main.index("install_record_commit") < main.index("next_steps")


def test_rollback_removes_only_the_commands_this_run_added_to_an_existing_command_folder(tmp_path: Path) -> None:
    paths = _sandbox(tmp_path)
    user_bin = paths["home"] / ".local" / "bin"
    user_bin.mkdir(parents=True)
    (user_bin / "mytool").write_text("mine\n", encoding="utf-8")

    _run(paths, """
install_record_begin
echo uv >"$HOME/.local/bin/uv"
echo hermes >"$HOME/.local/bin/hermes"
false
""")

    assert sorted(p.name for p in user_bin.iterdir()) == ["mytool"]


def test_rollback_closes_docker_desktop_only_when_this_run_opened_it(tmp_path: Path) -> None:
    paths = _sandbox(tmp_path)
    calls = tmp_path / "osascript-calls"
    osascript = paths["bin"] / "osascript"
    osascript.write_text(f'#!/bin/sh\necho "$*" >>{shlex.quote(str(calls))}\n', encoding="utf-8")
    osascript.chmod(0o755)

    _run(paths, "install_record_begin\nfalse\n")
    assert not calls.exists()

    _run(paths, "install_record_begin\nBLACKBOX_OPENED_DOCKER_DESKTOP=true\nfalse\n")
    assert calls.read_text(encoding="utf-8").strip() == '-e quit app "Docker"'


def _docker_start(tmp_path: Path, *, already_open: bool) -> list[str]:
    """require_docker_for_blazegraph on a Mac whose Docker engine never comes up."""
    bin_dir = tmp_path / "bin"
    bin_dir.mkdir()
    calls = tmp_path / "calls"
    for name, body in {
        "docker": "exit 1",
        "open": f'echo "open $*" >>{shlex.quote(str(calls))}',
        "osascript": f'echo "osascript $*" >>{shlex.quote(str(calls))}',
        "pgrep": "exit 0" if already_open else "exit 1",
        "sleep": "exit 0",
    }.items():
        (bin_dir / name).write_text(f"#!/bin/sh\n{body}\n", encoding="utf-8")
        (bin_dir / name).chmod(0o755)
    _isolated_bin(bin_dir, tmp_path / "service-calls")
    apps = tmp_path / "Applications" / "Docker.app"
    apps.mkdir(parents=True)
    script = f"""
step() {{ :; }}
ok() {{ :; }}
warn() {{ :; }}
err() {{ :; }}
heading() {{ :; }}
docker_setup_hint() {{ :; }}
{_function("require_docker_for_blazegraph")}
OS=macos
HOME={shlex.quote(str(tmp_path))}
PATH={shlex.quote(str(bin_dir))}
require_docker_for_blazegraph
echo "opened=${{BLACKBOX_OPENED_DOCKER_DESKTOP:-false}}" >>{shlex.quote(str(calls))}
"""
    subprocess.run(["bash", "-c", script], check=False, timeout=60)
    return calls.read_text(encoding="utf-8").splitlines()


def test_a_docker_desktop_this_run_opened_is_closed_when_its_engine_never_comes_up(tmp_path: Path) -> None:
    calls = _docker_start(tmp_path, already_open=False)

    assert calls == ["open -gja Docker", 'osascript -e quit app "Docker"', "opened=false"]


def test_a_docker_desktop_the_user_had_open_is_left_running(tmp_path: Path) -> None:
    calls = _docker_start(tmp_path, already_open=True)

    assert calls == ["open -gja Docker", "opened=false"]


def test_the_sandbox_reaches_no_real_service_manager(tmp_path: Path) -> None:
    """LES-064 guard: every tool that can change the machine resolves to a recording stub."""
    paths = _sandbox(tmp_path)

    result = _run(paths, 'for tool in launchctl systemctl loginctl osascript docker; do command -v "$tool"; done')

    resolved = result.stdout.split()
    assert len(resolved) == 5
    assert all(path.startswith(str(paths["bin"])) for path in resolved), resolved
    for path in resolved:
        assert not Path(path).is_symlink()


def _no_docker(tmp_path: Path, backend: str) -> list[str]:
    """require_docker_for_blazegraph on a machine with no Docker at all, for a *backend* choice."""
    bin_dir = tmp_path / "bin"
    bin_dir.mkdir()
    said = tmp_path / "said"
    _isolated_bin(bin_dir, tmp_path / "service-calls")
    script = f"""
step() {{ echo "step $*" >>{shlex.quote(str(said))}; }}
ok() {{ :; }}
warn() {{ :; }}
err() {{ echo "err $*" >>{shlex.quote(str(said))}; }}
heading() {{ :; }}
docker_setup_hint() {{ echo "hint" >>{shlex.quote(str(said))}; }}
{_function("require_docker_for_blazegraph")}
OS=macos
HOME={shlex.quote(str(tmp_path))}
PATH={shlex.quote(str(bin_dir))}
BLACKBOX_DKG_STORE_BACKEND={backend}
require_docker_for_blazegraph || true
"""
    subprocess.run(["bash", "-c", script], check=False, timeout=60)
    return said.read_text(encoding="utf-8").splitlines() if said.exists() else []


def test_no_docker_on_the_default_store_path_is_a_neutral_line_not_a_failure(tmp_path: Path) -> None:
    """E2E 2026-11-21: the default install printed a red "✗ Docker Desktop is not installed" and
    then went on fine with Oxigraph — it read as a failed install."""
    said = _no_docker(tmp_path, "auto")
    assert "hint" not in said and not any(line.startswith("err") for line in said)
    assert any("Oxigraph" in line for line in said)


def test_an_explicit_blazegraph_choice_without_docker_still_says_how_to_get_it(tmp_path: Path) -> None:
    assert "hint" in _no_docker(tmp_path, "blazegraph")


def test_rollback_takes_away_the_service_launchers_this_run_wrote_and_restores_older_ones(tmp_path: Path) -> None:
    """E2E recheck 2026-11-21: a failed update left ~/.hermes/blackbox/bin/"Blackbox" and
    "Blackbox Node" behind while it said nothing was left behind."""
    paths = _sandbox(tmp_path)
    launchers = paths["hermes"] / "blackbox" / "bin"
    launchers.mkdir(parents=True)
    (launchers / "Blackbox").write_text("#!/bin/sh\n# the previous install's\n", encoding="utf-8")

    _run(paths, """
install_record_begin
printf 'new\\n' >"$BLACKBOX_HOME/bin/Blackbox"
printf 'new\\n' >"$BLACKBOX_HOME/bin/Blackbox Node"
false
""")

    assert sorted(p.name for p in launchers.iterdir()) == ["Blackbox"]
    assert "the previous install's" in (launchers / "Blackbox").read_text(encoding="utf-8")
