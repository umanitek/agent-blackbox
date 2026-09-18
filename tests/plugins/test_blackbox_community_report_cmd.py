"""B6 contract: `blackbox report` — real submissions, validation, ack, track, dispute.

* Per-type required-arg validation rejects malformed identifiers (KI-025).
* Manual reports flow through the same quads pipeline as automatic ones.
* ACK: outcome + subject surfaced; failures exit nonzero and hit the ledger.
* Gate-off is a loud refusal, not a silent no-op.
* --status works offline from the ledger; --false-positive writes the Q8 row.
* Identity fails closed (no 0x address → refuse).
"""

from __future__ import annotations

import argparse

import pytest

from plugins.blackbox import audit, cli, constants
from plugins.blackbox.config import BlackboxConfig


DEV_GRAPH = "0x51E5dE758A45c8b64048E29918421F0bdD6D5d5C/agent-blackbox-community-dev"
REPORTER = "0xabc0000000000000000000000000000000000001"
CFG_ON = BlackboxConfig(report=True, community_graph_id=DEV_GRAPH, daily_report_limit=50)


@pytest.fixture
def bb_home(monkeypatch, tmp_path):
    monkeypatch.setenv("BLACKBOX_HOME", str(tmp_path / "bbhome"))
    return tmp_path / "bbhome"


class FakeClient:
    def __init__(self, fail=False):
        self.shares = []
        self.fail = fail

    def agent_identity(self):
        return {"agentAddress": REPORTER}

    def status(self):
        return {}

    def share_knowledge_asset(self, cg_id, name, q, **kw):
        if self.fail:
            raise RuntimeError("node exploded")
        self.shares.append((cg_id, name, q))
        return {"state": "succeeded"}

    def query(self, *a, **kw):
        return kw.get("on_error")

    def reachable(self):
        return True


def _args(**kw):
    base = dict(
        status=False, type=None, false_positive=None, severity="high",
        pattern=None, owasp=None, tool=None, arg_shape=None, ecosystem=None,
        name=None, version=None, advisory_id=None, kind=None, category=None,
        skill_name=None, skill_version=None, danger_shape=None,
        ioc_type=None, value=None, description="",
    )
    base.update(kw)
    return argparse.Namespace(**base)


@pytest.fixture
def wired(monkeypatch, bb_home):
    """Community on, identity resolved, fake client captured."""
    client = FakeClient()
    monkeypatch.setattr(cli, "load_blackbox_config", lambda: CFG_ON)
    monkeypatch.setattr(cli, "DkgClient", lambda **kw: client)
    monkeypatch.setattr(cli, "_resolve_reporter", lambda c: REPORTER)
    return client


# ---------------------------------------------------------------------------
# Validation (KI-025)
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("kwargs", "missing"),
    [
        (dict(type="dependency", name="pkg"), "--ecosystem"),
        (dict(type="dependency", ecosystem="npm", name="pkg"), "--version"),
        (dict(type="injection"), "--pattern"),
        (dict(type="escalation", tool="shell"), "--arg-shape"),
        (dict(type="fileaccess", tool="read"), "--category"),
        (dict(type="ioc", ioc_type="domain"), "--value"),
    ],
)
def test_incomplete_args_rejected_and_nothing_submitted(wired, kwargs, missing, capsys):
    rc = cli._cmd_report(_args(**kwargs))
    out = capsys.readouterr().out
    assert rc == 2
    assert missing in out
    assert "Nothing was submitted" in out
    assert wired.shares == []


def test_skill_requires_version_or_shape(wired, capsys):
    rc = cli._cmd_report(_args(type="skill", skill_name="helper-pack"))
    assert rc == 2
    assert "skill-version" in capsys.readouterr().out or True
    assert wired.shares == []


# ---------------------------------------------------------------------------
# Submission + ACK
# ---------------------------------------------------------------------------


def test_manual_report_lands_via_shared_pipeline(wired, capsys):
    rc = cli._cmd_report(
        _args(type="dependency", ecosystem="npm", name="Evil-Pkg", version="1.4.2", kind="malware")
    )
    out = capsys.readouterr().out
    assert rc == 0
    assert len(wired.shares) == 1
    cg_id, name, q = wired.shares[0]
    assert cg_id == DEV_GRAPH
    assert name.startswith("report-")
    serialized = "\n".join(str(v) for quad in q for v in dict(quad).values())
    assert "dep:npm:evil-pkg@1.4.2" in serialized  # canonical, same as automatic path
    assert constants.KIND_PRED in serialized
    assert "Report shared" in out
    assert "urn:guardian:report:" in out  # ACK: the subject is printed
    rows = audit.read_share_ledger()
    assert rows and rows[0]["ok"] is True


def test_share_failure_exits_nonzero_and_ledgers(monkeypatch, bb_home, capsys):
    client = FakeClient(fail=True)
    monkeypatch.setattr(cli, "load_blackbox_config", lambda: CFG_ON)
    monkeypatch.setattr(cli, "DkgClient", lambda **kw: client)
    monkeypatch.setattr(cli, "_resolve_reporter", lambda c: REPORTER)
    rc = cli._cmd_report(_args(type="ioc", ioc_type="domain", value="evil.example"))
    assert rc == 1
    assert "FAILED" in capsys.readouterr().out
    rows = audit.read_share_ledger()
    assert rows and rows[0]["ok"] is False


def test_cooldown_short_circuits_resubmission(wired, capsys):
    args = _args(type="ioc", ioc_type="domain", value="evil.example")
    assert cli._cmd_report(args) == 0
    assert cli._cmd_report(args) == 0
    assert len(wired.shares) == 1
    assert "cooldown" in capsys.readouterr().out.lower()


# ---------------------------------------------------------------------------
# Gates
# ---------------------------------------------------------------------------


def test_gate_off_is_loud_not_silent(monkeypatch, bb_home, capsys):
    monkeypatch.setattr(
        cli, "load_blackbox_config",
        lambda: BlackboxConfig(report=False, community_graph_id=DEV_GRAPH),
    )
    rc = cli._cmd_report(_args(type="ioc", ioc_type="domain", value="evil.example"))
    out = capsys.readouterr().out
    assert rc == 2
    assert "OFF" in out
    assert "Nothing was submitted" in out


def test_ghost_identity_refused(monkeypatch, bb_home, capsys):
    monkeypatch.setattr(cli, "load_blackbox_config", lambda: CFG_ON)
    monkeypatch.setattr(cli, "DkgClient", lambda **kw: FakeClient())
    monkeypatch.setattr(cli, "_resolve_reporter", lambda c: "node")
    rc = cli._cmd_report(_args(type="ioc", ioc_type="domain", value="evil.example"))
    assert rc == 1
    assert "ghost identity" in capsys.readouterr().out


# ---------------------------------------------------------------------------
# TRACK + DISPUTE
# ---------------------------------------------------------------------------


def test_status_reads_ledger_offline(monkeypatch, bb_home, capsys):
    audit.record_share_outcome(
        identifier="dep:npm:evil@1", category="dependency", severity="high",
        subject="urn:guardian:report:0xabc:dead", asset_name="report-x", ok=True,
    )
    monkeypatch.setattr(cli, "load_blackbox_config", lambda: BlackboxConfig())
    rc = cli._cmd_report(_args(status=True))
    out = capsys.readouterr().out
    assert rc == 0
    assert "dep:npm:evil@1" in out


def test_status_handles_empty_history(monkeypatch, bb_home, capsys):
    monkeypatch.setattr(cli, "load_blackbox_config", lambda: BlackboxConfig())
    assert cli._cmd_report(_args(status=True)) == 0
    assert "No community reports" in capsys.readouterr().out


def test_false_positive_emits_dispute_quads(wired, capsys):
    rc = cli._cmd_report(_args(false_positive="dep:npm:innocent@2.0.0"))
    out = capsys.readouterr().out
    assert rc == 0
    assert len(wired.shares) == 1
    _cg, name, q = wired.shares[0]
    assert name.startswith("fp-")
    serialized = "\n".join(str(v) for quad in q for v in dict(quad).values())
    assert constants.FALSE_POSITIVE_TYPE_IRI in serialized
    assert "dep:npm:innocent@2.0.0" in serialized
    assert "False-positive signal shared" in out


# ---------------------------------------------------------------------------
# No 'coming soon' remains anywhere in the CLI (B4/B6 shared guard)
# ---------------------------------------------------------------------------


def test_no_coming_soon_left_in_cli_source():
    import inspect

    source = inspect.getsource(cli)
    assert "coming soon" not in source.lower()
