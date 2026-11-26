"""The agent observer's Linux reader (``agent_hooks/observe/platform/linux.py``, Linux deep
layers step 2) answers in the macOS module's shapes, so the observer's one parser reads both.

Contract, on a fake ``/proc`` tree (the module's ``proc_root`` parameter; runs on every OS, the
module is loaded by path): the process table parses through ``observe.read_table`` with the right
parent and start time; ``read_users`` sees real and effective uids; argv and one variable keep
their spaces; the ancestry walks up to pid 1; a deleted executable reads without its marker; and
a process counts as sandboxed only in Blackbox's scope or under NNP + seccomp + its own mounts.
"""

from __future__ import annotations

import importlib.util
import os
import time
from pathlib import Path

import pytest

from plugins.blackbox.agent_hooks import observe

LINUX_MODULE = Path(__file__).resolve().parents[2] / "plugins/blackbox/agent_hooks/observe/platform/linux.py"
BOOT = 1_700_000_000
TICKS = os.sysconf("SC_CLK_TCK")


def _load():
    spec = importlib.util.spec_from_file_location("blackbox_observe_linux", LINUX_MODULE)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


linux = _load()


def _process(root: Path, pid: int, ppid: int, *, name: str, argv: list[str], uid=(501, 501), start_seconds: int = 10,
             environ: list[str] | None = None, nnp: int = 0, seccomp: int = 0, cgroup: str = "0::/user.slice\n",
             mnt: str = "mnt:[4026531841]") -> None:
    folder = root / str(pid)
    (folder / "ns").mkdir(parents=True)
    # Fields 3.. after "(name)": state, ppid, then filler up to starttime (field 22).
    after = ["S", str(ppid)] + ["0"] * 17 + [str(start_seconds * TICKS)] + ["0"] * 30
    (folder / "stat").write_text(f"{pid} ({name}) {' '.join(after)}\n", encoding="utf-8")
    (folder / "status").write_text(f"Name:\t{name}\nUid:\t{uid[0]}\t{uid[1]}\t{uid[1]}\t{uid[1]}\n"
                                   f"NoNewPrivs:\t{nnp}\nSeccomp:\t{seccomp}\n", encoding="utf-8")
    (folder / "cmdline").write_bytes(b"\0".join(word.encode() for word in argv) + (b"\0" if argv else b""))
    if environ is not None:
        (folder / "environ").write_bytes(b"\0".join(word.encode() for word in environ) + b"\0")
    (folder / "cgroup").write_text(cgroup, encoding="utf-8")
    os.symlink(mnt, folder / "ns" / "mnt")


@pytest.fixture
def proc(tmp_path):
    root = tmp_path / "proc"
    root.mkdir()
    (root / "stat").write_text(f"cpu  1 2 3\nbtime {BOOT}\nprocesses 9\n", encoding="utf-8")
    (root / "self" / "ns").mkdir(parents=True)
    os.symlink("mnt:[4026531841]", root / "self" / "ns" / "mnt")
    _process(root, 1, 0, name="systemd", argv=["/sbin/init"], uid=(0, 0), start_seconds=1)
    _process(root, 2, 0, name="kthreadd", argv=[], uid=(0, 0), start_seconds=1)
    _process(root, 400, 1, name="bash", argv=["-bash"], start_seconds=20)
    _process(root, 500, 400, name="node (claude) x", argv=["node", "/usr/lib/claude/cli.js", "--settings", '{"a": 1}'],
             start_seconds=30, environ=["HOME=/home/amos", "CLAUDE_CONFIG_DIR=/home/amos/my claude"])
    _process(root, 600, 400, name="sudo", argv=["sudo", "ls"], uid=(501, 0), start_seconds=40)
    os.symlink("/home/amos/project", root / "500" / "cwd")
    os.symlink("/usr/bin/node (deleted)", root / "500" / "exe")
    return str(root)


def test_the_table_parses_through_the_observers_own_parser(proc, monkeypatch):
    monkeypatch.setattr(observe.platform, "process_table", lambda: linux.process_table(proc_root=proc))
    table = observe.read_table()
    assert set(table) == {1, 2, 400, 500, 600}
    assert table[500].ppid == 400 and table[500].command.startswith("node /usr/lib/claude/cli.js --settings")
    assert table[2].command == "[kthreadd]", "a kernel thread reads as ps prints it"
    expected = time.mktime(time.localtime(BOOT + 30))
    assert abs(table[500].started - expected) <= 1, "start = boot time + start ticks, to the second"


def test_real_and_effective_uids_are_read_per_process(proc, monkeypatch):
    monkeypatch.setattr(observe.platform, "process_users", lambda: linux.process_users(proc_root=proc))
    users = observe.read_users()
    assert users[600] == (501, 0) and users[1] == (0, 0) and users[500] == (501, 501)


def test_argv_and_a_variable_keep_their_spaces_and_an_unreadable_environment_is_empty(proc):
    assert linux.process_argv(500, proc_root=proc) == ["node", "/usr/lib/claude/cli.js", "--settings", '{"a": 1}']
    assert linux.process_variable(500, "CLAUDE_CONFIG_DIR", proc_root=proc) == "/home/amos/my claude"
    assert linux.process_variable(500, "MISSING", proc_root=proc) == ""
    assert "CLAUDE_CONFIG_DIR=/home/amos/my" in linux.process_environment(500, proc_root=proc)
    assert linux.process_environment(600, proc_root=proc) == "", "no environ (another user's) reads as nothing"
    assert linux.process_argv(9999, proc_root=proc) == []


def test_the_ancestry_walks_up_nearest_first_and_says_when_it_cannot_ask(proc, tmp_path):
    chain = linux.process_ancestry(500, 12, proc_root=proc)
    assert [(pid, ppid) for pid, ppid, _started, _command in chain] == [(500, 400), (400, 1)]
    assert chain[0][3].startswith("node /usr/lib/claude/cli.js")
    assert linux.process_ancestry(9999, 12, proc_root=proc) == []
    assert linux.process_ancestry(500, 12, proc_root=str(tmp_path / "no-proc")) is None


def test_cwd_and_executable_read_from_their_links(proc):
    assert linux.process_cwd(500, proc_root=proc) == "/home/amos/project"
    assert linux.process_path(500, proc_root=proc) == "/usr/bin/node", "a replaced binary still names its path"
    assert linux.process_path(600, proc_root=proc) == ""


def test_a_sandbox_is_blackboxs_scope_or_nnp_seccomp_and_own_mounts(proc):
    root = Path(proc)
    _process(root, 700, 400, name="agent", argv=["claude"], cgroup="0::/user.slice/blackbox-agent-0123456789ab-1.scope\n")
    _process(root, 701, 400, name="bwrap-child", argv=["x"], nnp=1, seccomp=2, mnt="mnt:[4026532999]")
    _process(root, 702, 400, name="nnp-only", argv=["x"], nnp=1, seccomp=2)   # same mounts as us
    assert linux.process_sandboxed(700, proc_root=proc) is True
    assert linux.process_sandboxed(701, proc_root=proc) is True
    assert linux.process_sandboxed(702, proc_root=proc) is False
    assert linux.process_sandboxed(500, proc_root=proc) is False
    assert linux.process_sandboxed(9999, proc_root=proc) is None


SCOPE = "blackbox-agent-0123456789ab-5f3c.scope"


def _in_sandbox(root: Path, pid: int, inner: int, *, cgroup: str = "", environ: list[str] | None = None) -> None:
    _process(root, pid, 1, name="node", argv=["node"], cgroup=cgroup or f"0::/user.slice/user@501.service/blackbox-agents.slice/{SCOPE}\n",
             environ=environ)
    status = root / str(pid) / "status"
    status.write_text(status.read_text(encoding="utf-8") + f"NSpid:\t{pid}\t{inner}\n", encoding="utf-8")


def test_a_pid_namespace_pid_maps_back_to_the_host_pid_of_that_sandbox_only(proc):
    """Linux deep layers step 15: below kernel 6.12 a sandboxed agent's hooks report pids of the
    sandbox's own PID namespace; the scope (or, with no scope, the launcher's variable) says whose."""
    root = Path(proc)
    _in_sandbox(root, 7001, 2)
    _in_sandbox(root, 7002, 2, cgroup="0::/user.slice/user@501.service/blackbox-agents.slice/blackbox-agent-ffffffffffff-1.scope\n")
    _in_sandbox(root, 7003, 3, cgroup="0::/user.slice\n", environ=["BLACKBOX_SANDBOX_ID=noscope-ab12"])
    assert linux.host_pid(SCOPE, 2, proc_root=proc) == 7001
    assert linux.host_pid("blackbox-agent-ffffffffffff-1.scope", 2, proc_root=proc) == 7002
    assert linux.host_pid("noscope-ab12", 3, proc_root=proc) == 7003
    assert linux.host_pid(SCOPE, 500, proc_root=proc) == 500, "no PID namespace: the number is the host's"
    for forged in ["../../etc", "user@501.service", "blackbox-agent-0123456789ab-5f3c.scope\n", ""]:
        assert linux.host_pid(forged, 2, proc_root=proc) == 2, f"{forged!r} is not a launcher's id"


# --- KI-658 (Linux round L1): the observer loop reads Linux, so sessions get pids and end ---------

def test_on_linux_the_observer_loop_ends_a_session_whose_process_left(proc, tmp_path, monkeypatch):
    """L1: every CLI agent instance had pid 0 and stayed "live" after its process exited, because the
    observer read nothing on Linux. With the Linux reader behind the facade, the loop that runs every
    few seconds (``tracking.observe_now``) sees the agent's process and ends its session once it left."""
    import shutil
    from plugins.blackbox.agent_hooks import tracking
    from plugins.blackbox.agent_hooks.instances import store
    from plugins.blackbox.agent_hooks.observe import platform as facade
    monkeypatch.setenv("HOME", str(tmp_path))
    monkeypatch.setenv("BLACKBOX_HOME", str(tmp_path / "bb"))
    for name in ("process_table", "process_users"):
        monkeypatch.setattr(facade, name, lambda name=name: getattr(linux, name)(proc_root=proc))
    monkeypatch.setattr(tracking.hermes_sessions, "catch_up", lambda: None)
    now = time.time()
    store.put(store.Instance("claude-code:" + "a" * 16, "claude-code", "session", now - 60, now - 30, pid=500), flush=True)
    tracking.observe_now()
    live = store.all_instances()[0]
    assert live.ended is None, "its process runs: still live"
    assert 500 in observe.read_table(), "the agent's real pid is seen on Linux"
    shutil.rmtree(Path(proc) / "500")
    tracking.observe_now()
    ended = store.all_instances()[0]
    assert ended.ended is not None and ended.end_reason == "process-exit"
