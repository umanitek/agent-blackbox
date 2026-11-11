"""Multi-agent dashboard plumbing: the one blackbox home carries findings from
every local agent so the single dashboard surfaces them all.

The Python (Hermes) plugin writes ``audit.jsonl`` / ``findings.jsonl``; other
local agents write ``audit.<framework>.jsonl`` / ``findings.<framework>.jsonl``
into the SAME shared home. The dashboard readers merge them newest-first and
tag each row's framework.
"""

import json
import time

from _blackbox_loader import load_blackbox

audit = load_blackbox("audit")
constants = load_blackbox("kernel.constants")


def _write_line(path, *, framework, identifier, severity, ts, category="injection", workspace=None):
    finding = {
        "identifier": identifier,
        "category": category,
        "severity": severity,
        "title": "t",
        "tool_name": "",
        "evidence": "e",
        "confirmed": False,
        "source": "heuristic",
    }
    if framework:
        finding["framework"] = framework
    rec = {
        "ts": ts,
        "iso": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(ts)),
        "event": "pre_tool_call",
        "finding": finding,
    }
    if workspace:
        rec["workspace"] = workspace
    with path.open("a", encoding="utf-8") as fh:
        fh.write(json.dumps(rec) + "\n")


def _write_audit_line(path, *, framework, event, ts, detail):
    rec = {
        "ts": ts,
        "iso": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(ts)),
        "event": event,
        "framework": framework,
        "detail": detail,
    }
    with path.open("a", encoding="utf-8") as fh:
        fh.write(json.dumps(rec) + "\n")


def test_read_findings_merges_hermes_and_openclaw_logs():
    home = constants.blackbox_home()
    home.mkdir(parents=True, exist_ok=True)
    # Hermes log: no framework field on the line → defaults to "hermes".
    _write_line(home / "findings.jsonl", framework=None, identifier="injection:h1", severity="high", ts=1000)
    _write_line(home / "findings.jsonl", framework=None, identifier="injection:h2", severity="critical", ts=1002)
    # OpenClaw log: framework-tagged sibling file.
    _write_line(home / "findings.openclaw.jsonl", framework="openclaw", identifier="escalation:o1",
                severity="critical", ts=1001, category="escalation")

    rows = audit.read_findings(limit=10)
    assert audit.count_findings() == 3
    # Newest-first across BOTH logs by ts.
    assert [r["ts"] for r in rows] == [1002, 1001, 1000]
    frameworks = [r["framework"] for r in rows]
    assert frameworks == ["hermes", "openclaw", "hermes"]
    # The OpenClaw row is tagged and carries its category/severity.
    oc = next(r for r in rows if r["framework"] == "openclaw")
    assert oc["category"] == "escalation" and oc["severity"] == "critical"


def test_findings_from_two_profiles_do_not_dedupe_each_other():
    home = constants.blackbox_home()
    home.mkdir(parents=True, exist_ok=True)
    path = home / "findings.jsonl"
    common = {
        "framework": "hermes",
        "identifier": "injection:same",
        "severity": "high",
        "ts": 1000,
    }
    _write_line(path, **common, workspace="/home/u/.hermes")
    _write_line(path, **common, workspace="/home/u/.hermes/profiles/guardian")

    rows = audit.read_findings(limit=10)

    assert len(rows) == 2
    assert {row["workspace"] for row in rows} == {
        "/home/u/.hermes",
        "/home/u/.hermes/profiles/guardian",
    }


def test_local_frameworks_lists_every_agent_with_a_log():
    home = constants.blackbox_home()
    home.mkdir(parents=True, exist_ok=True)
    _write_line(home / "findings.jsonl", framework=None, identifier="injection:h", severity="high", ts=1)
    _write_line(home / "findings.openclaw.jsonl", framework="openclaw", identifier="injection:o", severity="high", ts=2)
    fws = audit.local_frameworks()
    assert "hermes" in fws and "openclaw" in fws


def test_read_findings_empty_home_is_empty():
    # A fresh home with no logs yields no findings (fail-open, no crash).
    assert audit.read_findings(limit=10) == []
    assert audit.count_findings() == 0
    assert audit.local_frameworks() == []


def test_hermes_audit_and_findings_carry_active_workspace(monkeypatch, tmp_path):
    workspace = tmp_path / "profiles" / "guardian"
    monkeypatch.setattr(constants, "hermes_home", lambda: workspace)
    audit.record(
        event="pre_tool_call",
        findings=[{
            "identifier": "injection:workspace",
            "category": "injection",
            "severity": "high",
            "title": "workspace test",
            "framework": "hermes",
            "confirmed": False,
            "source": "heuristic",
        }],
    )

    audit_row = json.loads((constants.blackbox_home() / "audit.jsonl").read_text(encoding="utf-8"))
    assert audit_row["workspace"] == str(workspace)
    assert audit.read_findings(limit=1)[0]["workspace"] == str(workspace)


def test_openclaw_only_home_still_surfaces_findings():
    # Even with no Hermes log at all, an OpenClaw-only log is read + tagged.
    home = constants.blackbox_home()
    home.mkdir(parents=True, exist_ok=True)
    _write_line(home / "findings.openclaw.jsonl", framework="openclaw", identifier="skill:x", severity="critical",
                ts=5, category="skill")
    rows = audit.read_findings(limit=10)
    assert len(rows) == 1 and rows[0]["framework"] == "openclaw" and rows[0]["category"] == "skill"
    assert audit.local_frameworks() == ["openclaw"]


def test_read_audit_merges_openclaw_routine_activity():
    home = constants.blackbox_home()
    home.mkdir(parents=True, exist_ok=True)
    _write_audit_line(
        home / "audit.jsonl",
        framework="hermes",
        event="session_start",
        ts=10,
        detail={"session_id": "hermes-1"},
    )
    _write_audit_line(
        home / "audit.openclaw.jsonl",
        framework="openclaw",
        event="message_received",
        ts=11,
        detail={"session_id": "agent:main:test", "content_length": 12},
    )

    rows = audit.read_audit(limit=10)

    assert [(row["framework"], row["event"]) for row in rows] == [
        ("openclaw", "message_received"),
        ("hermes", "session_start"),
    ]
    assert audit.count_audit() == 2
    assert audit.local_active_frameworks() == ["hermes", "openclaw"]


def test_local_activity_reconstructs_openclaw_session_and_tool_call():
    home = constants.blackbox_home()
    home.mkdir(parents=True, exist_ok=True)
    path = home / "audit.openclaw.jsonl"
    sid = "agent:main:audit-test"
    _write_audit_line(path, framework="openclaw", event="session_start", ts=20,
                      detail={"session_id": sid})
    _write_audit_line(path, framework="openclaw", event="pre_tool_call", ts=21,
                      detail={"session_id": sid, "tool_call_id": "tc-1", "tool_name": "exec",
                              "args": {"command": "pwd"}})
    _write_audit_line(path, framework="openclaw", event="post_tool_call", ts=22,
                      detail={"session_id": sid, "tool_call_id": "tc-1", "tool_name": "exec",
                              "duration_ms": 25, "result": {"status": "ok"}})
    _write_audit_line(path, framework="openclaw", event="session_end", ts=23,
                      detail={"session_id": sid, "reason": "idle"})

    data = audit.read_local_activity()

    session = data["sessions"][0]
    assert session["id"] == sid
    assert session["agent"] == "openclaw"
    assert session["status"] == "completed"
    assert session["toolCount"] == 1
    assert session["events"][0]["action"] == "pwd"


def test_local_activity_reads_openclaw_visibility_details_and_end_reason():
    home = constants.blackbox_home()
    home.mkdir(parents=True, exist_ok=True)
    path = home / "audit.openclaw.jsonl"
    sid = "agent:main:visibility-test"
    _write_audit_line(path, framework="openclaw", event="session_start", ts=30,
                      detail={"session_id": sid})
    _write_audit_line(path, framework="openclaw", event="file_access", ts=31,
                      detail={"session_id": sid, "tool": "read", "path": "/tmp/a.txt", "mode": "read"})
    _write_audit_line(path, framework="openclaw", event="dependency_install", ts=32,
                      detail={"session_id": sid, "tool": "shell", "ecosystem": "npm",
                              "name": "left-pad", "version": "1.3.0"})
    _write_audit_line(path, framework="openclaw", event="session_end", ts=33,
                      detail={"session_id": sid, "reason": "reset"})

    session = audit.read_local_activity()["sessions"][0]

    assert session["status"] == "completed"
    assert session["events"][0] == {
        "type": "file", "ts": 31, "path": "/tmp/a.txt", "mode": "read", "tool": "read", "threats": []
    }
    assert session["events"][1] == {
        "type": "dependency", "ts": 32, "ecosystem": "npm", "name": "left-pad",
        "version": "1.3.0", "tool": "shell", "threats": []
    }


def test_a_damaged_or_non_object_log_line_never_breaks_the_feed_and_is_not_counted():
    """Each log reader had its own read loop; the findings reader handed any JSON value to
    the row builder, so a line holding a list ended the whole findings view. They all read
    through kernel.bounded_files.read_jsonl now (object rows only), and the feed's total is
    the length of the very rows it pages — a damaged line is neither shown nor counted."""
    home = constants.blackbox_home()
    home.mkdir(parents=True, exist_ok=True)
    _write_audit_line(home / "audit.jsonl", framework="hermes", event="session_start", ts=10,
                      detail={"session_id": "hermes-1"})
    with (home / "audit.jsonl").open("a", encoding="utf-8") as fh:
        fh.write("{not json\n[1, 2]\n")
    (home / "findings.jsonl").write_text('[1, 2]\n"text"\n', encoding="utf-8")

    rows = audit.read_audit(limit=10)

    assert [row["event"] for row in rows] == ["session_start"]
    assert audit.count_audit() == len(rows) == 1
    assert audit.read_findings(limit=10) == []
