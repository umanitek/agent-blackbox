"""Refine R1 — a reporter can withdraw its own report (`blackbox report --retract`).

A retraction counts only when signed by the SAME key that signed the report:
it withdraws that signer's voice and nobody else's (LES-014). Readers always
honour it (LES-016: statements that reduce enforcement must get through), and
a retraction read that fails makes the whole read unavailable instead of
re-counting withdrawn reports.
"""

from __future__ import annotations

import argparse
import json

import pytest
from _community_rows import GRAPH, NETWORK, Reporter, signed_retraction_row, signed_row

from plugins.blackbox import audit, cli
from plugins.blackbox.community import ReadState, read_verified_reports, report_builder
from plugins.blackbox.community.report_cli import report_command
from plugins.blackbox.community.report_signer import (
    DISPUTE_STATEMENT, REPORT_STATEMENT, RETRACT_STATEMENT, ReportSigner,
)
from plugins.blackbox.kernel import constants, signing
from plugins.blackbox.kernel import identity as kernel_identity
from plugins.blackbox.kernel.config import BlackboxConfig

CFG = BlackboxConfig(report=True, context_graph_id=GRAPH, daily_report_limit=50)
THREAT = "ioc:domain:evil.example"


class _GraphClient:
    """Serves report rows and retraction rows to the matching query, one page each."""

    def __init__(self, reports, retractions=(), retractions_fail=False):
        self.reports, self.retractions, self.retractions_fail = list(reports), list(retractions), retractions_fail
        self.shares = []

    def status(self):
        return {"networkId": NETWORK}

    def context_graphs(self):
        return []

    def query(self, sparql, cg_id, view=None, on_error=None, **kw):
        if "g:Retraction" in sparql:
            if self.retractions_fail:
                return on_error
            served, self.retractions = self.retractions, []
            return served
        served, self.reports = self.reports, []
        return served

    def agent_identity(self):
        return {"agentAddress": "0x" + "a" * 40}

    def share_knowledge_asset(self, cg_id, name, quads, **kw):
        self.shares.append((cg_id, name, quads))
        return {"state": "succeeded"}


def _authors(read):
    return sorted({(report.author, report.identifier) for report in read.reports})


# ------------------------------------------------------------------ write side


def test_a_retraction_is_signed_as_a_retraction_and_nothing_else():
    reporter = Reporter("0x54fd580f81be3e09ae45a05c507295d1c3635f0a")
    signer = ReportSigner(private_key=reporter.key, environment=NETWORK, graph=GRAPH)
    quads = report_builder.build_retraction_quads(identifier=THREAT, reporter_address=reporter.address, signer=signer)
    assert quads[0]["object"] == constants.RETRACTION_TYPE_IRI
    envelope = signing.from_text(json.loads(next(q["object"] for q in quads
                                                 if q["predicate"] == constants.SIGNED_STATEMENT_PRED)))
    for statement, accepted in ((RETRACT_STATEMENT, True), (REPORT_STATEMENT, False), (DISPUTE_STATEMENT, False)):
        author = signing.verify(envelope, statement_type=statement, environment=NETWORK, graph=GRAPH)
        assert (author is not None) is accepted


# ------------------------------------------------------------------ read side


def test_a_signers_own_retraction_withdraws_its_report():
    one, two = Reporter("0x54fd580f81be3e09ae45a05c507295d1c3635f0a"), Reporter("0xfe26576731c057e0ef78f7a21e8b8b9cceed6bdb")
    client = _GraphClient([signed_row(THREAT, one), signed_row(THREAT, two)], [signed_retraction_row(THREAT, one)])
    read = read_verified_reports(client, CFG)
    assert read.state is ReadState.ROWS
    assert _authors(read) == [(two.author, THREAT)]
    assert [(r.author, r.identifier, r.reporter) for r in read.retractions] == [(one.author, THREAT, "0x54fd580f81be3e09ae45a05c507295d1c3635f0a")]


def test_a_retraction_cannot_withdraw_someone_elses_report():
    """The retraction names the victim's ADDRESS, but is signed by another key."""
    victim, attacker = Reporter("0xf8b016a8471b936ced2d84cb66aeb4a6bc30bf96"), Reporter("0xf8b016a8471b936ced2d84cb66aeb4a6bc30bf96")   # same claimed address, different key
    client = _GraphClient([signed_row(THREAT, victim)], [signed_retraction_row(THREAT, attacker)])
    assert _authors(read_verified_reports(client, CFG)) == [(victim.author, THREAT)]


@pytest.mark.parametrize("row_kwargs", [
    {"signed": False},                      # unsigned
    {"environment": "other-network"},       # signed for another network
    {"graph": "0xother/agent-blackbox-community-dev"},   # signed for another graph
])
def test_an_unverifiable_retraction_is_ignored(row_kwargs):
    one = Reporter("0x54fd580f81be3e09ae45a05c507295d1c3635f0a")
    client = _GraphClient([signed_row(THREAT, one)], [signed_retraction_row(THREAT, one, **row_kwargs)])
    assert _authors(read_verified_reports(client, CFG)) == [(one.author, THREAT)]


def test_a_tampered_retraction_row_is_ignored():
    one = Reporter("0x54fd580f81be3e09ae45a05c507295d1c3635f0a")
    row = signed_retraction_row(THREAT, one)
    row["identifier"] = "ioc:domain:something-else.example"
    client = _GraphClient([signed_row(THREAT, one)], [row])
    assert _authors(read_verified_reports(client, CFG)) == [(one.author, THREAT)]


def test_a_failed_retraction_read_makes_the_whole_read_unavailable():
    """Never count a withdrawn report because the retractions could not be read."""
    one = Reporter("0x54fd580f81be3e09ae45a05c507295d1c3635f0a")
    client = _GraphClient([signed_row(THREAT, one)], retractions_fail=True)
    read = read_verified_reports(client, CFG)
    assert read.state is ReadState.UNAVAILABLE and "retraction" in read.reason


def test_a_retraction_withdraws_only_the_named_threat():
    one = Reporter("0x54fd580f81be3e09ae45a05c507295d1c3635f0a")
    other = "ioc:domain:other.example"
    client = _GraphClient([signed_row(THREAT, one), signed_row(other, one)], [signed_retraction_row(THREAT, one)])
    assert _authors(read_verified_reports(client, CFG)) == [(one.author, other)]


# ------------------------------------------------------------------ the verb


def _parse(argv):
    parser = argparse.ArgumentParser()
    cli.setup_cli(parser)
    return parser.parse_args(argv)


@pytest.fixture
def wired(monkeypatch, tmp_path):
    monkeypatch.setenv("BLACKBOX_HOME", str(tmp_path / "bbhome"))
    client = _GraphClient([])
    monkeypatch.setattr(report_command, "load_blackbox_config", lambda: CFG)
    monkeypatch.setattr(report_command, "DkgClient", lambda **kw: client)
    monkeypatch.setattr(kernel_identity, "reporter_address", lambda c: "0x" + "a" * 40)
    return client


def test_retract_sends_a_signed_retraction_and_ledgers_it(wired, capsys):
    assert report_command.cmd_report(_parse(["report", "--retract", THREAT])) == 0
    _cg, name, quads = wired.shares[0]
    assert name.startswith("retract-")
    assert any(q["object"] == constants.RETRACTION_TYPE_IRI for q in quads)
    assert any(q["predicate"] == constants.SIGNED_STATEMENT_PRED for q in quads)
    assert audit.read_share_ledger()[0]["category"] == "retraction"
    assert "cannot delete" in capsys.readouterr().out   # honest about what a retraction does not do


def test_retract_refuses_free_text(wired, capsys):
    assert report_command.cmd_report(_parse(["report", "--retract", "please remove my report"])) == 2
    assert wired.shares == [] and "Nothing was submitted" in capsys.readouterr().out
