"""Sandbox permissions — Docker (KI-622): the engine's sockets closed unless the ``docker``
permission allows it, the refusal asks the person, and a mount of a protected item is refused
(plugins/blackbox/shields/files/sandbox/platform/macos/profile.py, agent_hooks/protect/sandbox_errors.py,
shields/files/mounts.py; design "Sandbox permissions" 2026-11-23, build step 10, local-only).

Contracts (red on the base ed4152ceac: the Docker socket was open inside the sandbox, so
``docker run -v <protected>:/x`` read a protected item outside it — KI-622):
* on THIS Mac, a REAL Seatbelt run (probe, 2026-11-23): a connect to a socket at a Docker socket
  path is refused in the agent's profile while Docker asks or is blocked, and allowed in the
  profile of the agent it is allowed for — and only that agent;
* the docker CLI's refusal is read as a DOCKER refusal, and it opens one request (Docker asks by
  default, per project — F4);
* the hook layer refuses mounting a protected item (or a folder holding one) into a container,
  and leaves other folders and named volumes alone;
* every refusal kind the catalogue names is one the hook layer reads (LES-137: one definition each);
* KI-679 (Linux round L3, Ubuntu 24.04, docker 29.1.3, REAL sandboxed Claude Code): inside Linux's
  sandbox Docker's socket is the sandbox's mask (an empty mode-0000 file), so the CLI says the
  not-started words; a "cannot connect" naming a MASKED socket is Docker's refusal and asks, one naming
  a real socket or nothing is still an engine that is not started.
"""

from __future__ import annotations

import os
import socket
import subprocess
import sys
import tempfile
import threading
from pathlib import Path

import pytest

from plugins.blackbox.agent_hooks.protect import sandbox_errors
from plugins.blackbox.kernel import config as config_mod
from plugins.blackbox.shields.files import mode as files_mode, mounts, protect, sandbox
from plugins.blackbox.shields.files.sandbox import permissions
from plugins.blackbox.shields.files.sandbox.permissions import catalogue, requests
from plugins.blackbox.shields.files.sandbox.platform.macos import profile as macos_profile

REAL = pytest.mark.skipif(sys.platform != "darwin" or not os.access(macos_profile.SANDBOX_EXEC, os.X_OK),
                          reason="a real Seatbelt sandbox needs macOS")


@pytest.fixture(autouse=True)
def home(monkeypatch):
    # A short home: a unix socket's path is at most 104 bytes on macOS.
    real = Path(tempfile.mkdtemp(prefix="bbd", dir="/tmp")).resolve()
    monkeypatch.setenv("HOME", str(real))
    monkeypatch.setenv("BLACKBOX_HOME", str(real / "bb"))
    (real / "Documents" / "Vault").mkdir(parents=True)
    (real / "work").mkdir()
    requests.reset()
    yield real
    requests.reset()
    subprocess.run(["/bin/rm", "-rf", str(real)], check=False)


@pytest.fixture
def entry(monkeypatch):
    state: dict = {}
    monkeypatch.setattr(config_mod, "_blackbox_entry", lambda: state)
    return state


def _listen(path: Path) -> socket.socket:
    path.parent.mkdir(parents=True, exist_ok=True)
    server = socket.socket(socket.AF_UNIX)
    server.bind(str(path))
    server.listen(4)
    threading.Thread(target=lambda: [server.accept() for _ in range(4)], daemon=True).start()
    return server


def _connect(profile: Path, path: Path) -> str:
    code = ("import socket,sys\ns=socket.socket(socket.AF_UNIX)\ntry:\n s.connect(sys.argv[1]); print('connected')\n"
            "except OSError as e: print('refused', e.errno)")
    done = subprocess.run([macos_profile.SANDBOX_EXEC, "-f", str(profile), sys.executable, "-I", "-c", code, str(path)],
                          capture_output=True, text=True, timeout=30, check=False)
    return done.stdout.strip()


@REAL
def test_the_docker_socket_is_closed_unless_docker_is_allowed_for_that_agent(home, entry):
    entry["agent_sandbox"] = {"permissions": [{"permission": "docker", "mode": "allow", "agent": "codex"}]}
    sandbox.sync(files_mode.build(enabled=True, sandboxed=("claude-code", "codex")))
    for where in (home / ".docker" / "run" / "docker.sock", home / ".colima" / "default" / "docker.sock"):
        server = _listen(where)
        try:
            assert _connect(sandbox.layout.agent_profile("claude-code"), where) == "refused 1"
            assert _connect(sandbox.layout.agent_profile("codex"), where) == "connected"
        finally:
            server.close()


def test_the_docker_cli_refusal_asks_the_person(home, entry):
    output = ("permission denied while trying to connect to the Docker daemon socket at unix:///Users/me/.docker/run/docker.sock: "
              "Get \"http://%2FUsers%2Fme%2F.docker%2Frun%2Fdocker.sock/v1.47/containers/json\": dial unix "
              "/Users/me/.docker/run/docker.sock: connect: operation not permitted")
    found = sandbox_errors.refusals(output)
    assert [each.kind for each in found] == [sandbox_errors.DOCKER] and sandbox_errors.counted(found)
    assert "Docker" in sandbox_errors.note(found)
    assert permissions.refused(sandbox_errors.DOCKER, "claude-code", "s-1", str(home / "work")) is True
    assert [each.permission for each in requests.pending()] == ["docker"]


#: Every real refusal text of a container engine's socket inside the sandbox (KI-646: docker CLI 29
#: in security round 7 said the first; the matcher wanted "docker daemon … operation not permitted",
#: so Docker on "ask" raised no question at all).
SOCKET_REFUSALS = [
    "permission denied while trying to connect to the docker API at unix:///Users/admin/.docker/run/docker.sock",
    "permission denied while trying to connect to the Docker daemon socket at unix:///var/run/docker.sock: Get "
    "\"http://%2Fvar%2Frun%2Fdocker.sock/v1.24/containers/json\": dial unix /var/run/docker.sock: connect: permission denied",
    "Cannot connect to the Docker daemon at unix:///Users/me/.colima/default/docker.sock. Is the docker daemon running? "
    "dial unix /Users/me/.colima/default/docker.sock: connect: operation not permitted",
    "Error: Cannot connect to Podman. Please verify your connection to the Linux system using `podman system connection "
    "list`, or try `podman machine init` and `podman machine start` to manage a new Linux VM\nError: unable to connect to "
    "Podman socket: Get \"http://d/v5.0.0/libpod/_ping\": dial unix /Users/me/.local/share/containers/podman/machine/"
    "podman.sock: connect: operation not permitted",
    "docker.errors.DockerException: Error while fetching server API version: ('Connection aborted.', "
    "PermissionError(1, 'Operation not permitted'))",
    "error during connect: Get \"http://docker.sock/v1.47/version\": dial unix /Users/me/.orbstack/run/docker.sock: "
    "connect: operation not permitted",
]
NOT_DOCKER = [
    "Cannot connect to the Docker daemon at unix:///var/run/docker.sock. Is the docker daemon running?",   # not started
    "docker: Error response from daemon: open /work/x: permission denied.",                          # inside the engine
    "ERROR: failed to solve: failed to read dockerfile: open Dockerfile: permission denied",
]


#: Linux round L3, raw/bA-u24.log: a sandboxed Claude Code's `docker ps`, Docker on "ask" (KI-679).
LINUX_HIDDEN = "Cannot connect to the Docker daemon at unix:///var/run/docker.sock. Is the docker daemon running?"


def _mask(path: Path) -> Path:
    """What Linux's sandbox binds over a hidden socket (helper sandbox/system.rs Masks): empty, mode 0000."""
    path.write_bytes(b"")
    path.chmod(0)
    return path


def test_linuxs_hidden_socket_is_read_as_docker_from_l3s_exact_words(monkeypatch):
    real_lstat = os.lstat
    masked = os.lstat(_mask(Path(tempfile.mkdtemp()) / "docker.sock"))
    monkeypatch.setattr(sandbox_errors.os, "lstat", lambda path: masked if str(path) == "/var/run/docker.sock" else real_lstat(path))
    found = sandbox_errors.refusals(LINUX_HIDDEN)
    assert [each.kind for each in found] == [sandbox_errors.DOCKER] and "Docker" in sandbox_errors.note(found)


def test_the_socket_path_decides_between_a_hidden_socket_and_an_engine_not_started():
    # A short folder: a unix socket's path is limited to ~104 bytes (macOS), and pytest's tmp_path is longer.
    folder = Path(tempfile.mkdtemp(prefix="bb-sock-", dir="/tmp"))
    hidden, served, gone = _mask(folder / "docker.sock"), folder / "podman.sock", folder / "none" / "docker.sock"
    listener = socket.socket(socket.AF_UNIX)
    listener.bind(str(served))
    try:
        for path, expected in ((hidden, [sandbox_errors.DOCKER]), (served, []), (gone, [])):
            for words in (LINUX_HIDDEN.replace("/var/run/docker.sock", str(path)),
                          f'error during connect: Get "http://docker/v1.47/version": dial unix {path}: connect: no such file or directory'):
                kinds = [each.kind for each in sandbox_errors.refusals(words) if each.kind == sandbox_errors.DOCKER]
                assert kinds == expected, (path, words)
    finally:
        listener.close()
        for each in (hidden, served):
            each.unlink()
        folder.rmdir()


def test_linuxs_hidden_socket_asks_the_person(home, entry, monkeypatch):
    masked = os.lstat(_mask(home / "mask"))
    monkeypatch.setattr(sandbox_errors, "_is_mask", lambda path: path == "/var/run/docker.sock" and bool(masked))
    found = sandbox_errors.refusals(LINUX_HIDDEN)
    assert permissions.refused(found[0].kind, "claude-code", "s-1", str(home / "work")) is True
    assert [each.permission for each in requests.pending()] == ["docker"]


@pytest.mark.parametrize("output", SOCKET_REFUSALS)
def test_every_real_socket_refusal_text_is_read_as_docker(output):
    assert [each.kind for each in sandbox_errors.refusals(output)] == [sandbox_errors.DOCKER], output


@pytest.mark.parametrize("output", NOT_DOCKER)
def test_a_docker_error_that_is_not_the_sandbox_is_not_read_as_docker(output):
    assert sandbox_errors.DOCKER not in [each.kind for each in sandbox_errors.refusals(output)], output


def test_round_sevens_docker_refusal_asks_the_person(home, entry):
    """KI-646, p1-dock1: REAL sandboxed Claude Code, `docker ps`, Docker on ask — no request was raised."""
    found = sandbox_errors.refusals(SOCKET_REFUSALS[0])
    assert permissions.refused(found[0].kind, "claude-code", "s-1", str(home / "work")) is True
    assert [each.permission for each in requests.pending()] == ["docker"]


@pytest.mark.parametrize("command, sources", [
    ("docker run --rm -v ~/Documents/Vault:/x alpine cat /x/a", ["~/Documents/Vault"]),
    ("podman create --volume=/tmp/a:/b:ro img", ["/tmp/a"]),
    ("docker container run --mount type=bind,source=/srv/data,target=/d img", ["/srv/data"]),
    ("/usr/local/bin/nerdctl run -v$HOME/x:/y img", ["$HOME/x"]),
    ("docker run -v cache:/root/.cache img", []),
    ("docker ps -v", []),
])
def test_mount_sources_are_read_from_the_command(command, sources):
    assert mounts.sources(command) == sources


def test_mounting_a_protected_item_into_a_container_is_refused(home):
    mode = files_mode.build(enabled=True, protected=("~/Documents/Vault",))
    for command in ("docker run --rm -v ~/Documents/Vault:/x alpine ls /x", "docker run -v ~/Documents:/d alpine ls"):
        [finding] = protect.detect("terminal", {"command": command}, mode)
        assert finding.fields["route"] == "mount" and finding.fields["item"] == "~/Documents/Vault"
    assert protect.detect("terminal", {"command": "docker run -v ~/work:/w alpine ls"}, mode) == []


def test_every_catalogue_refusal_kind_is_one_the_hooks_read():
    hook_kinds = {sandbox_errors.SETUID, sandbox_errors.APP_DRIVER, sandbox_errors.OPEN_APP, sandbox_errors.SIGNAL,
                  sandbox_errors.NESTED, sandbox_errors.FILE, sandbox_errors.DOCKER, sandbox_errors.TOOL_FOLDER,
                  sandbox_errors.LOCAL_PORT, sandbox_errors.DISPLAY, sandbox_errors.SYSTEM_SERVICES}
    named = {kind for each in catalogue.PERMISSIONS for kind in each.refusal_kinds}
    assert named <= hook_kinds
