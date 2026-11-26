"""Blackbox's start inside Hermes never makes Hermes drop it, and a hook called while the guard
still loads never passes what the guard would refuse (``guard.startup``, ``agent_hooks.hermes_load``).

Private security finding ``2026-11-26-linux-hermes-plugin-load-past-hermes-s-1`` (Linux round L7,
High; BB-LINUX-PENDING-cc89c4): Hermes drops a plugin whose import + ``register()`` overruns
``plugins.load_timeout_seconds`` (10 s). ``register()`` imported the whole guard first — 10-15 s on
the busy 4-CPU VM — so Hermes logged "Failed to load plugin 'blackbox': load timed out after 10s"
23 times and ran with no Blackbox: no hook, nothing recorded, no ``blackbox`` command, and nothing
said so.
"""

from __future__ import annotations

import json
import multiprocessing
import os
import subprocess
import sys
import textwrap
import threading
import time
from pathlib import Path

import pytest

from _blackbox_loader import load_blackbox

startup = load_blackbox("guard.startup")
audit = load_blackbox("audit")
constants = load_blackbox("kernel.constants")
hermes_load = load_blackbox("agent_hooks.hermes_load")
unguarded = load_blackbox("agent_hooks.unguarded")

REPO = Path(__file__).resolve().parents[2]
HOOKS = ["pre_tool_call", "post_tool_call", "pre_api_request", "on_session_start", "on_session_end"]

# A fresh interpreter imports the plugin as Hermes does and registers it; it reports what was
# loaded at each registration and how long import + register() took.
REGISTER_PROBE = textwrap.dedent("""
    import json, sys, time, types
    sys.path.insert(0, sys.argv[1])
    namespace = types.ModuleType("hermes_plugins"); namespace.__path__ = []
    sys.modules["hermes_plugins"] = namespace
    import importlib.util
    spec = importlib.util.spec_from_file_location("hermes_plugins.blackbox", sys.argv[1] + "/plugins/blackbox/__init__.py",
                                                  submodule_search_locations=[sys.argv[1] + "/plugins/blackbox"])
    module = importlib.util.module_from_spec(spec)
    sys.modules["hermes_plugins.blackbox"] = module
    seen = []
    class Ctx:
        def register_hook(self, name, fn):
            seen.append([name, "hermes_plugins.blackbox.guard.hooks" in sys.modules])
        def register_cli_command(self, name, help, setup_fn, handler_fn=None, description=""):
            seen.append([name, "hermes_plugins.blackbox.cli" in sys.modules])
    began = time.perf_counter()
    spec.loader.exec_module(module)
    module.register(Ctx())
    took = time.perf_counter() - began
    heavy = sorted(m for m in sys.modules if m.startswith("hermes_plugins.blackbox.")
                   and m.split(".")[2] not in ("guard", "kernel"))
    print(json.dumps({"took": took, "seen": seen, "heavy": heavy,
                      "hooks_loaded": "hermes_plugins.blackbox.guard.hooks" in sys.modules,
                      "threads": [t.name for t in __import__("threading").enumerate()]}))
""")


def _burn(stop) -> None:   # pragma: no cover - a CPU burner child
    while not stop.is_set():
        sum(i * i for i in range(10_000))


def _probe() -> dict:
    out = subprocess.run([sys.executable, "-c", REGISTER_PROBE, str(REPO)], capture_output=True, text=True,
                         timeout=120, check=True, env={**os.environ, "PYTHONDONTWRITEBYTECODE": "1"})
    return json.loads(out.stdout.strip().splitlines()[-1])


def test_register_hands_hermes_every_hook_before_any_heavy_import():
    """The invariant behind the fix: nothing of the guard, the CLI or any feature is imported
    before (or while) Hermes is handed the hooks — and no thread is started during the load."""
    probe = _probe()
    assert [name for name, _ in probe["seen"]] == HOOKS + ["blackbox"]
    assert not any(loaded for _, loaded in probe["seen"])           # each hook registered before the guard loaded
    assert not probe["hooks_loaded"] and probe["heavy"] == []       # register() returned with the guard still unloaded
    assert "blackbox-start" not in probe["threads"]                 # the guard loads at the first hook, not in discovery


def test_register_stays_far_inside_hermess_load_deadline_on_a_fully_loaded_machine():
    """Under stress (two CPU burners per core) import + register() still take a small fraction
    of Hermes's 10 s ``plugins.load_timeout_seconds``; the old register() needed 10-15 s on the L7 VM."""
    stop = multiprocessing.Event()
    burners = [multiprocessing.Process(target=_burn, args=(stop,), daemon=True) for _ in range(2 * (os.cpu_count() or 2))]
    for burner in burners:
        burner.start()
    try:
        probe = _probe()
    finally:
        stop.set()
        for burner in burners:
            burner.join(10)
    assert probe["took"] < 2.0, probe["took"]
    assert not probe["hooks_loaded"]


class _FakeGuard:
    """Stands in for ``guard.hooks``: records every call in order."""

    def __init__(self, verdict=None):
        self.calls: list[tuple[str, dict]] = []
        self.verdict = verdict

    def _config(self):
        return None

    class graph_rules:   # the module's name
        @staticmethod
        def detection_rules(cfg, tool, args):
            return None, {}

    def on_pre_tool_call(self, **kwargs):
        self.calls.append(("pre_tool_call", kwargs))
        return self.verdict

    def __getattr__(self, name):
        if name.startswith("on_"):
            return lambda **kwargs: self.calls.append((name, kwargs))
        raise AttributeError(name)


@pytest.fixture
def slow_start(monkeypatch):
    """A guard whose import is held until the test lets it finish (``release``)."""
    fake = _FakeGuard()
    gate = threading.Event()
    fresh = startup._Start()

    def run():
        gate.wait(30)
        fresh._drain(fake)

    monkeypatch.setattr(fresh, "_run", run)
    monkeypatch.setattr(startup, "START", fresh)
    monkeypatch.setattr(startup, "wait_seconds", lambda: 0.05)
    yield fake, gate.set, fresh
    gate.set()


def test_a_tool_call_while_the_guard_still_loads_is_refused_never_passed(slow_start):
    fake, release, start = slow_start
    answer = startup.HERMES_HOOKS["pre_tool_call"](tool_name="terminal", args={"command": "cat ~/.ssh/id_rsa"})
    assert answer == {"action": "block", "message": startup.NOT_CHECKED_MESSAGE}
    assert fake.calls == []                       # nothing passed unjudged
    release()
    assert start.settled.wait(10) and start.state == startup.READY
    fake.verdict = {"action": "block", "message": "refused by the guard"}
    assert startup.HERMES_HOOKS["pre_tool_call"](tool_name="terminal", args={"command": "cat ~/.ssh/id_rsa"}) == fake.verdict


def test_a_tool_call_waits_for_a_guard_that_comes_up_within_the_wait(monkeypatch, slow_start):
    fake, release, _start = slow_start
    fake.verdict = {"action": "block", "message": "refused by the guard"}
    monkeypatch.setattr(startup, "wait_seconds", lambda: 10.0)
    threading.Timer(0.2, release).start()
    assert startup.HERMES_HOOKS["pre_tool_call"](tool_name="terminal", args={}) == fake.verdict


def test_the_sessions_start_is_applied_before_its_first_tool_call_is_judged(slow_start):
    """Observer hooks never wait: they are queued and replayed IN ORDER before the guard is
    ready, so the session start (which sandboxes the session's shells) comes first."""
    fake, release, start = slow_start
    startup.HERMES_HOOKS["on_session_start"](session_id="s1", model="m")
    startup.HERMES_HOOKS["pre_api_request"](session_id="s1", user_message="hi")
    assert fake.calls == []
    release()
    assert start.settled.wait(10)
    startup.HERMES_HOOKS["pre_tool_call"](tool_name="terminal", args={}, session_id="s1")
    assert [name for name, _ in fake.calls] == ["on_session_start", "on_pre_api_request", "pre_tool_call"]
    assert fake.calls[0][1] == {"session_id": "s1", "model": "m"}


def test_a_guard_that_cannot_load_lets_calls_pass_and_says_so_in_hermess_log(monkeypatch, caplog):
    """Genuine breakage keeps the fail-open invariant — and is never silent: the BROKEN_LINE is
    what the watcher (``agent_hooks.hermes_load``) turns into a HIGH finding."""
    fresh = startup._Start()
    monkeypatch.setattr(fresh, "_run", lambda: fresh._fail("the guard did not load (SyntaxError: bad)"))
    monkeypatch.setattr(startup, "START", fresh)
    caplog.set_level("ERROR")
    assert startup.HERMES_HOOKS["pre_tool_call"](tool_name="terminal", args={}) is None
    assert startup.BROKEN_LINE in caplog.text and "SyntaxError" in caplog.text
    assert startup.BROKEN_LINE == hermes_load.BROKEN_LINE


def test_the_wait_stays_below_hermess_own_hook_timeout(monkeypatch):
    import types as _types
    fake_config = _types.ModuleType("hermes_cli.config")
    monkeypatch.setitem(sys.modules, "hermes_cli.config", fake_config)
    fake_config.load_config_readonly = lambda: {"plugins": {"hook_callback_timeout": 8}}
    assert startup.wait_seconds() == 5.0
    fake_config.load_config_readonly = lambda: {"plugins": {"hook_callback_timeout": 120}}
    assert startup.wait_seconds() == startup.WAIT_CAP_SECONDS
    fake_config.load_config_readonly = dict
    assert startup.wait_seconds() == startup.WAIT_CAP_SECONDS


# --- the watcher: Hermes started without Blackbox ---------------------------------------------

@pytest.fixture
def hermes_logs(monkeypatch, tmp_path):
    root = tmp_path / "hermes-root"
    (root / "logs").mkdir(parents=True)
    (root / "profiles" / "work" / "logs").mkdir(parents=True)
    monkeypatch.setattr(constants, "hermes_root", lambda: root)
    constants.blackbox_home().mkdir(parents=True, exist_ok=True)   # an installed Blackbox
    hermes_load._reported.clear()
    yield root
    hermes_load._reported.clear()


def _stamp(seconds_ago: float = 0.0) -> str:
    return time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(time.time() - seconds_ago)) + ",123"


def _without_blackbox() -> list[dict]:
    return [row for row in audit.read_findings(limit=200) if str(row.get("tool_call_id")).startswith("hermes-load:")]


def test_hermes_dropping_the_plugin_is_one_high_finding(hermes_logs):
    log = hermes_logs / "profiles" / "work" / "logs" / "errors.log"
    log.write_text(f"{_stamp()} WARNING hermes_cli.plugins: Failed to load plugin 'basic': load timed out after 10s\n"
                   f"{_stamp()} WARNING hermes_cli.plugins: Failed to load plugin 'blackbox': load timed out after 10s "
                   "(import + register() never returned)\n", encoding="utf-8")
    assert hermes_load.catch_up() == 1
    found, = _without_blackbox()
    assert found["severity"] == "high" and found["identifier"] == unguarded.UNGUARDED_ID
    assert "load timed out after 10s" in found["evidence"] and found["framework"] == "hermes"
    assert hermes_load.catch_up() == 0                                  # once
    hermes_load._reported.clear()                                       # a restarted dashboard, cursor kept
    assert hermes_load.catch_up() == 0
    with log.open("a", encoding="utf-8") as handle:                     # the next failed start is news again
        handle.write(f"{_stamp()} WARNING hermes_cli.plugins: Failed to load plugin 'blackbox': dictionary changed size "
                     "during iteration\n")
    assert hermes_load.catch_up() == 1 and len(_without_blackbox()) == 2


def test_a_guard_that_could_not_start_is_a_finding_too(hermes_logs):
    (hermes_logs / "logs" / "errors.log").write_text(
        f"{_stamp()} ERROR hermes_plugins.blackbox.guard.startup: {hermes_load.BROKEN_LINE}: the guard did not load "
        "(ImportError: x). Its tool calls pass UNCHECKED until Hermes is restarted.\n", encoding="utf-8")
    assert hermes_load.catch_up() == 1
    assert "did not start" in _without_blackbox()[0]["evidence"]


def test_old_history_on_the_first_look_is_not_news(hermes_logs):
    (hermes_logs / "logs" / "errors.log").write_text(
        f"{_stamp(3 * 86400)} WARNING hermes_cli.plugins: Failed to load plugin 'blackbox': load timed out after 10s\n",
        encoding="utf-8")
    assert hermes_load.catch_up() == 0 and _without_blackbox() == []
