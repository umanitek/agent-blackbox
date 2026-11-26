"""A run Blackbox's own sandbox launcher started is not called "running without Blackbox" before
its first hook could arrive — and a forged launcher mark only delays the alert, never removes it
(``agent_hooks.observe.launched``, ``instances.views.LAUNCHED_GRACE_SECONDS``).

Linux round L7 (BB-LINUX-PENDING-b4bf05, Medium): every sandboxed start raised a false "X is
running without Blackbox" notice and HIGH finding: the back-stop's grace is 20 s and an agent the
launcher started on the busy VM sent its first hook event at +23 s (a hooks-only start at +9 s).
"""

from __future__ import annotations

import time

import pytest

from plugins.blackbox import agent_hooks, audit
from plugins.blackbox.agent_hooks import observe, tracking, unguarded
from plugins.blackbox.agent_hooks.instances import store, views
from plugins.blackbox.agent_hooks.observe import launched
from plugins.blackbox.kernel import constants

DIGEST = "ab" * 32


def _ps(seconds_ago: float, command: str = "claude -p 'read the notes'") -> str:
    started = time.strftime("%a %b %d %H:%M:%S %Y", time.localtime(time.time() - seconds_ago))
    return f"  100     1 Sun Nov 22 06:00:00 2026     /sbin/launchd\n  601   100 {started}     {command}\n"


@pytest.fixture
def machine(monkeypatch, tmp_path):
    profiles = constants.blackbox_home() / "sandbox" / "profiles"
    profiles.mkdir(parents=True, exist_ok=True)
    profile = profiles / "claude-code.policy"
    profile.write_text(f"# blackbox-sandbox policy 1\n# sha256:{DIGEST}\nhide /x\n", encoding="utf-8")
    env: dict[str, str] = {}
    store.reset()
    unguarded._reported.clear()
    monkeypatch.setattr(observe.platform, "process_environment", lambda pid: "")
    monkeypatch.setattr(observe.platform, "process_variable", lambda pid, name: env.get(name, ""))
    monkeypatch.setattr(observe.platform, "process_ancestry", lambda pid, limit: None)
    monkeypatch.setattr(observe.platform, "process_cwd", lambda pid: str(tmp_path))
    monkeypatch.setattr(agent_hooks, "_home", lambda: tmp_path)

    def run(seconds_ago: float, mark: str = "", command: str = "claude -p 'read the notes'") -> list[dict]:
        env.clear()
        if mark:
            env[launched.PROFILE_ENV] = mark
        monkeypatch.setattr(observe.platform, "process_table", lambda: _ps(seconds_ago, command))
        tracking._seen.update(at=0.0, table={}, running=[], pids=frozenset(), new_profiles=False)
        return tracking.live()["unprotected"]

    yield run, profile, tmp_path
    store.reset()


def test_a_launched_run_waits_for_its_first_hook_past_the_plain_grace(machine):
    run, profile, _ = machine
    assert views.GRACE_SECONDS < 30 < views.LAUNCHED_GRACE_SECONDS
    assert run(30, f"{profile}#{DIGEST}") == []                 # the launcher's start at +23 s: no false alarm
    assert [row["agent"] for row in run(30)] == ["claude-code"]  # the same run with no launcher mark: unseen


def test_a_launched_run_that_never_hooks_is_still_reported(machine):
    run, profile, _ = machine
    rows = run(views.LAUNCHED_GRACE_SECONDS + 5, f"{profile}#{DIGEST}")
    assert [row["agent"] for row in rows] == ["claude-code"]
    unguarded.report(rows)
    assert any(row["identifier"] == unguarded.UNGUARDED_ID for row in audit.read_findings(limit=20))


@pytest.mark.parametrize("forge", ["outside", "digest", "bare"])
def test_a_forged_launcher_mark_buys_nothing(machine, forge):
    """An agent's environment is its own: a mark naming a profile outside Blackbox's sandbox
    folder, or with a digest that is not the file's, counts as no mark; and a run whose hooks are
    known to be off is reported at once, launched or not."""
    run, profile, tmp_path = machine
    if forge == "outside":
        fake = tmp_path / "fake.policy"
        fake.write_text(profile.read_text(encoding="utf-8"), encoding="utf-8")
        rows = run(30, f"{fake}#{DIGEST}")
    elif forge == "digest":
        rows = run(30, f"{profile}#{'cd' * 32}")
    else:
        rows = run(5, f"{profile}#{DIGEST}", command="claude --bare -p 'read the notes'")
    assert [row["agent"] for row in rows] == ["claude-code"]
