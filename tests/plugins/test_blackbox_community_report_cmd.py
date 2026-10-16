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

from plugins.blackbox import audit, cli
from plugins.blackbox.community.report_cli import report_command
from plugins.blackbox.kernel import constants
from plugins.blackbox.kernel import identity as kernel_identity
from plugins.blackbox.kernel.config import BlackboxConfig


DEV_GRAPH = "0x51E5dE758A45c8b64048E29918421F0bdD6D5d5C/agent-blackbox-community-dev"
REPORTER = "0xabc0000000000000000000000000000000000001"
CFG_ON = BlackboxConfig(report=True, context_graph_id=DEV_GRAPH, daily_report_limit=50)


@pytest.fixture
def bb_home(monkeypatch, tmp_path):
    monkeypatch.setenv("BLACKBOX_HOME", str(tmp_path / "bbhome"))
    return tmp_path / "bbhome"


TEST_NETWORK = "test-network-id"


class FakeClient:
    def __init__(self, fail=False):
        self.shares = []
        self.fail = fail

    def agent_identity(self):
        return {"agentAddress": REPORTER}

    def status(self):
        return {"networkId": TEST_NETWORK}  # real nodes always report one; signing needs it (R0b)

    def share_knowledge_asset(self, cg_id, name, q, **kw):
        if self.fail:
            raise RuntimeError("node exploded")
        self.shares.append((cg_id, name, q))
        return {"state": "succeeded"}

    def query(self, *a, **kw):
        return kw.get("on_error")

    def reachable(self):
        return True


#: Namespace dest -> the flag an operator types, where they differ.
_FLAG_FOR_DEST = {"version": "--package-version"}


def _args(**kw):
    """Parsed `blackbox report` args, built through the REAL parser (KI-114):
    each keyword is the namespace dest, turned into the flag an operator types."""
    argv = ["report"]
    for dest, value in kw.items():
        flag = _FLAG_FOR_DEST.get(dest, "--" + dest.replace("_", "-"))
        if value is True:
            argv.append(flag)
        elif value is not None:
            argv += [flag, str(value)]
    return _parse(argv)


@pytest.fixture
def wired(monkeypatch, bb_home):
    """Community on, identity resolved, fake client captured."""
    client = FakeClient()
    monkeypatch.setattr(report_command, "load_blackbox_config", lambda: CFG_ON)
    monkeypatch.setattr(report_command, "DkgClient", lambda **kw: client)
    monkeypatch.setattr(kernel_identity, "reporter_address", lambda c: REPORTER)
    return client


# ---------------------------------------------------------------------------
# Validation (KI-025)
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("kwargs", "missing"),
    [
        (dict(type="dependency", name="pkg"), "--ecosystem"),
        (dict(type="dependency", ecosystem="npm", name="pkg"), "--package-version"),  # KI-066
        (dict(type="injection", context="in-user-prompt"), "--pattern"),
        (dict(type="escalation", tool="terminal"), "--arg-shape"),
        (dict(type="fileaccess", tool="read_file"), "--category"),
        (dict(type="ioc", ioc_type="domain", context="fetched-by-tool"), "--value"),
    ],
)
def test_incomplete_args_rejected_and_nothing_submitted(wired, kwargs, missing, capsys):
    rc = report_command.cmd_report(_args(**kwargs))
    out = capsys.readouterr().out
    assert rc == 2
    assert missing in out
    assert "Nothing was submitted" in out
    assert wired.shares == []


def test_skill_requires_a_registry_version_or_a_local_artifact(wired, capsys):
    rc = report_command.cmd_report(_args(type="skill", skill_name="helper-pack"))
    assert rc == 2
    assert "--registry" in capsys.readouterr().out
    assert wired.shares == []


# ---------------------------------------------------------------------------
# Submission + ACK
# ---------------------------------------------------------------------------


def test_manual_report_lands_via_shared_pipeline(wired, capsys):
    rc = report_command.cmd_report(
        _args(type="dependency", ecosystem="npm", name="Evil-Pkg", package_version="1.4.2", kind="malware",
              reason="install-hook")
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
    monkeypatch.setattr(report_command, "load_blackbox_config", lambda: CFG_ON)
    monkeypatch.setattr(report_command, "DkgClient", lambda **kw: client)
    monkeypatch.setattr(kernel_identity, "reporter_address", lambda c: REPORTER)
    rc = report_command.cmd_report(_args(type="ioc", ioc_type="domain", value="evil.example", context="fetched-by-tool"))
    assert rc == 1
    assert "refused for now" in capsys.readouterr().out
    rows = audit.read_share_ledger()
    assert rows and rows[0]["ok"] is False


def test_cooldown_short_circuits_resubmission(wired, capsys):
    args = _args(type="ioc", ioc_type="domain", value="evil.example", context="fetched-by-tool")
    assert report_command.cmd_report(args) == 0
    assert report_command.cmd_report(args) == 0
    assert len(wired.shares) == 1
    assert "cooldown" in capsys.readouterr().out.lower()


# ---------------------------------------------------------------------------
# Gates
# ---------------------------------------------------------------------------


def test_gate_off_is_loud_not_silent(monkeypatch, bb_home, capsys):
    monkeypatch.setattr(
        report_command, "load_blackbox_config",
        lambda: BlackboxConfig(report=False, context_graph_id=DEV_GRAPH),
    )
    rc = report_command.cmd_report(_args(type="ioc", ioc_type="domain", value="evil.example", context="fetched-by-tool"))
    out = capsys.readouterr().out
    assert rc == 2
    assert "OFF" in out
    assert "Nothing was submitted" in out


def test_ghost_identity_refused(monkeypatch, bb_home, capsys):
    """No resolvable identity -> refuse; there is no placeholder to report under."""
    monkeypatch.setattr(report_command, "load_blackbox_config", lambda: CFG_ON)
    monkeypatch.setattr(report_command, "DkgClient", lambda **kw: FakeClient())
    monkeypatch.setattr(kernel_identity, "reporter_address", lambda c: None)
    rc = report_command.cmd_report(_args(type="ioc", ioc_type="domain", value="evil.example", context="fetched-by-tool"))
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
    monkeypatch.setattr(report_command, "load_blackbox_config", lambda: BlackboxConfig())
    rc = report_command.cmd_report(_args(status=True))
    out = capsys.readouterr().out
    assert rc == 0
    assert "dep:npm:evil@1" in out


def test_status_handles_empty_history(monkeypatch, bb_home, capsys):
    monkeypatch.setattr(report_command, "load_blackbox_config", lambda: BlackboxConfig())
    assert report_command.cmd_report(_args(status=True)) == 0
    assert "No community reports" in capsys.readouterr().out


def test_false_positive_emits_dispute_quads(wired, capsys):
    rc = report_command.cmd_report(_args(false_positive="dep:npm:innocent@2.0.0", reason="wrong"))
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


# ---------------------------------------------------------------------------
# Through the REAL parser (KI-114: report tests used to build Namespaces by
# hand, which is how KI-066 — the swallowed --version — went unnoticed)
# ---------------------------------------------------------------------------


def _parse(argv):
    parser = argparse.ArgumentParser()
    cli.setup_cli(parser)
    return parser.parse_args(argv)


def test_dependency_report_parses_with_package_version():
    args = _parse(["report", "--type", "dependency", "--ecosystem", "PyPI", "--name", "Evil_Pkg.Name",
                   "--package-version", "1.0.3", "--kind", "malware", "--reason", "typosquat"])
    finding, err = report_command._report_finding_from_args(args)
    assert err == ""
    assert finding["identifier"] == "dep:pypi:evil-pkg-name@1.0.3"
    # The report fields carry the SAME canonical spelling as the identifier.
    assert finding["fields"]["package_name"] == "evil-pkg-name"
    assert finding["fields"]["ecosystem"] == "pypi"


def test_missing_package_version_names_the_real_flag():
    args = _parse(["report", "--type", "dependency", "--ecosystem", "npm", "--name", "evil"])
    finding, err = report_command._report_finding_from_args(args)
    assert finding is None and "--package-version" in err


def test_report_has_no_version_flag_of_its_own():
    """KI-066: Hermes's top-level --version wins over a subcommand's --version
    (prints the banner and exits), so the report command must not rely on it."""
    with pytest.raises(SystemExit):
        _parse(["report", "--type", "dependency", "--ecosystem", "npm", "--name", "evil", "--version", "1.0.0"])


# ---------------------------------------------------------------------------
# Refine R1c: no free text; closed choices; a dispute needs a reason
# ---------------------------------------------------------------------------


def test_the_description_flag_is_gone():
    with pytest.raises(SystemExit):
        _parse(["report", "--type", "ioc", "--description", "free text that would have leaked"])


@pytest.mark.parametrize("argv", [
    ["--type", "escalation", "--tool", "terminal", "--arg-shape", "made-up-shape"],
    ["--type", "fileaccess", "--tool", "read_file", "--category", "my-diary"],
    ["--type", "skill", "--artifact-hash", "a" * 64, "--danger-shape", "made-up"],
    ["--type", "ioc", "--ioc-type", "domain", "--value", "x.example", "--context", "https://site.example"],
    ["--type", "dependency", "--ecosystem", "go", "--name", "x", "--package-version", "1"],
    ["--type", "dependency", "--kind", "vulnerability"],
    ["--type", "injection", "--owasp", "LLM99"],
    ["--type", "skill", "--registry", "local"],
])
def test_values_outside_the_closed_vocabularies_are_refused_by_the_parser(argv):
    with pytest.raises(SystemExit):
        _parse(["report", *argv])


def test_a_bad_manual_report_is_refused_with_its_reason_not_a_traceback(wired, capsys):
    rc = report_command.cmd_report(_args(type="dependency", ecosystem="npm", name="x", package_version="*",
                                         kind="malware", reason="install-hook"))
    out = capsys.readouterr().out
    assert rc == 2 and "whole-package" in out and "Nothing was submitted" in out
    assert wired.shares == []


def test_a_local_skill_is_reported_by_hash_never_by_name(wired, capsys):
    digest = "b" * 64
    assert report_command.cmd_report(_args(type="skill", artifact_hash=digest, danger_shape="obfuscation")) == 0
    _cg, _name, quads = wired.shares[0]
    serialized = "\n".join(str(v) for quad in quads for v in dict(quad).values())
    assert digest in serialized and constants.SKILL_NAME_PRED not in serialized
    assert report_command.cmd_report(_args(type="skill", artifact_hash=digest, danger_shape="obfuscation",
                                           skill_name="acme-internal")) == 2


def test_a_dispute_without_a_reason_is_refused(wired, capsys):
    rc = report_command.cmd_report(_args(false_positive="dep:npm:innocent@2.0.0"))
    assert rc == 2 and "reason" in capsys.readouterr().out
    assert wired.shares == []


def test_a_dispute_carries_its_closed_reason(wired):
    assert report_command.cmd_report(_args(false_positive="dep:npm:innocent@2.0.0", reason="internal-mirror")) == 0
    _cg, _name, quads = wired.shares[0]
    reasons = [q["object"] for q in quads if q["predicate"] == constants.REPORT_REASON_PRED]
    assert reasons == ['"internal-mirror"']
    assert report_command.cmd_report(_args(false_positive="dep:npm:other@1", reason="I just don't like it")) == 2


def test_a_failed_dispute_is_recorded_in_the_ledger(monkeypatch, bb_home, capsys):
    """KI-015: every share attempt, success or failure, lands in the local
    ledger — a failed dispute used to leave no trace (found building R1c)."""
    monkeypatch.setattr(report_command, "load_blackbox_config", lambda: CFG_ON)
    monkeypatch.setattr(report_command, "DkgClient", lambda **kw: FakeClient(fail=True))
    monkeypatch.setattr(kernel_identity, "reporter_address", lambda c: REPORTER)
    assert report_command.cmd_report(_args(false_positive="dep:npm:innocent@2.0.0", reason="wrong")) == 1
    rows = audit.read_share_ledger()
    assert rows and rows[0]["category"] == "false-positive" and rows[0]["ok"] is False
