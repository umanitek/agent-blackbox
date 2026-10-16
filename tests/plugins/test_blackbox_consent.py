"""The community-sharing gate (Refine R13, revised 2026-10-16), erase/export end to end.

* Sharing is OPT-IN: with no record neither the automatic share gate nor the
  manual `blackbox report` path sends; only `--enable-sharing` / `--consent` and
  the dashboard toggle record the acceptance that turns it on; an opt-out
  (`--withdraw-consent`, the dashboard toggle) stops sharing on the next
  action. A change of the terms neither pauses nor starts sharing.
* Erasure destroys everything that could re-publish: the key, the ledger, the
  keep-alive memory, the retry queue, the acceptance history — and leaves
  sharing OFF (an erased identity never restarts sharing on its own).
* Export carries the key backup and the ledger (machine-readable).
* The three documents ship with the plugin and the terms carry a version.
"""

from __future__ import annotations

import argparse
import json
from pathlib import Path

import pytest

from _community_rows import GRAPH
from plugins.blackbox import audit
from plugins.blackbox.community import consent as consent_module
from plugins.blackbox.community import keep_alive, share_retry, sharing
from plugins.blackbox.community.report_cli import report_rights
from plugins.blackbox.kernel import reporter_key, settings
from plugins.blackbox.kernel.config import BlackboxConfig

CFG = BlackboxConfig(report=True, community_graph_id=GRAPH)
FINDING = {"identifier": "dep:npm:evil-pkg@1.0.0", "category": "dependency", "severity": "high", "source": "public",
           "fields": {"ecosystem": "npm", "package_name": "evil-pkg", "package_version": "1.0.0", "kind": "malware",
                      "reason": "install-hook"}}
DOCS = Path(consent_module.TERMS_PATH).parent


@pytest.fixture(autouse=True)
def home(monkeypatch, tmp_path):
    monkeypatch.setenv("BLACKBOX_HOME", str(tmp_path / "bbhome"))


# ------------------------------------------------------------------ the record


def test_sharing_is_off_until_the_operator_opts_in_and_an_opt_out_stops_it(real_consent, monkeypatch):
    assert real_consent.current() is None and not real_consent.in_force()          # no record: the default, off
    assert "is off" in real_consent.why_not() and "--enable-sharing" in real_consent.why_not()
    entry = real_consent.record()                                                     # the opt-in
    assert entry is not None and entry.terms_version == "1.5" and real_consent.in_force()
    monkeypatch.setattr(real_consent, "terms_text", lambda: "Version: 2.0\nnew terms")
    assert real_consent.in_force()                                                    # new terms never pause sharing
    assert real_consent.withdraw() and not real_consent.withdraw()                    # opt out once; already off after
    assert real_consent.current().withdrawn_at and not real_consent.in_force()
    assert "turned off on" in real_consent.why_not()


def test_a_record_without_an_acceptance_is_not_an_opt_in(real_consent):
    """Only an `accepted_at` turns sharing on: a record holding terms but no acceptance stays off."""
    path = real_consent._record_path()
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps({"terms_hash": "a", "terms_version": "1.4", "accepted_at": "", "withdrawn_at": ""}), encoding="utf-8")
    assert real_consent.current() is not None and not real_consent.in_force()


def test_without_the_terms_file_sharing_stays_off_and_can_still_be_turned_on(real_consent, monkeypatch):
    monkeypatch.setattr(real_consent, "terms_text", lambda: "")
    assert not real_consent.in_force()
    assert real_consent.record() is not None and real_consent.in_force()
    assert real_consent.withdraw() and not real_consent.in_force()


def test_an_opt_out_that_cannot_be_saved_is_reported_never_assumed(real_consent, monkeypatch, capsys):
    assert real_consent.record() is not None
    monkeypatch.setattr(real_consent, "_save", lambda entry: False)
    assert real_consent.withdraw() is False and real_consent.in_force()
    assert report_rights.withdraw_consent() == 1 and "still ON" in capsys.readouterr().out


# ------------------------------------------------------------------ the gates


def test_the_automatic_and_manual_share_paths_send_only_after_an_opt_in_and_stop_after_an_opt_out(real_consent, capsys, monkeypatch):
    from plugins.blackbox.community.report_cli import report_command
    args = argparse.Namespace(status=False, standing=False, export=None, restore_key=None, erase_identity=False, consent=False,
                              withdraw_consent=False, false_positive=None, retract=None, type="ioc", ioc_type="domain",
                              value="x.example", context="fetched-by-tool", severity="high")
    monkeypatch.setattr(report_command, "load_blackbox_config", lambda: CFG)   # the command reads the config itself
    policy = sharing.CommunitySharePolicy(CFG)
    # no record, even with `report: true` written by hand: neither path sends
    ok, why = policy.decide(FINDING, "0x" + "a" * 40)
    assert not ok and "is off" in why
    assert report_command.cmd_report(args) == 2 and "is off" in capsys.readouterr().out
    real_consent.record()
    assert policy.decide(FINDING, "0x" + "a" * 40)[0]                                  # opted in: allowed
    real_consent.withdraw()
    ok, why = policy.decide(FINDING, "0x" + "a" * 40)
    assert not ok and "turned off" in why
    assert report_command.cmd_report(args) == 2 and "turned off" in capsys.readouterr().out


def test_enable_sharing_records_the_opt_in_and_the_gate_then_sends(real_consent, monkeypatch, capsys):
    """`blackbox report --enable-sharing` is one of the two ways in: it records the
    acceptance and writes `report: true` through the dashboard's settings path."""
    written = []
    monkeypatch.setattr(settings, "write_settings", lambda payload, sharing_consent=False: written.append(
        (payload, sharing_consent)) or {"ok": True})
    assert not real_consent.in_force()
    assert report_rights.set_sharing(True) == 0
    assert written == [({"report": True}, True)] and real_consent.in_force()
    assert "Sharing is on" in capsys.readouterr().out
    assert sharing.CommunitySharePolicy(CFG).decide(FINDING, "0x" + "a" * 40)[0]


def test_turning_sharing_off_never_records_an_opt_in(real_consent, monkeypatch):
    monkeypatch.setattr(settings, "write_settings", lambda payload, sharing_consent=False: {"ok": True})
    assert report_rights.set_sharing(False) == 0
    assert real_consent.current() is None and not real_consent.in_force()


def test_turning_sharing_on_in_the_dashboard_is_the_opt_in(real_consent):
    assert real_consent.for_settings({"mode": "block"}) is False and real_consent.current() is None  # other saves record nothing
    assert real_consent.for_settings({"report": False}) is False and not real_consent.in_force()   # off stays off
    assert real_consent.for_settings({"report": True}) is True and real_consent.in_force()         # on is the opt-in
    real_consent.withdraw()
    assert real_consent.for_settings({"report": True}) is True and real_consent.in_force()         # and the opt-back-in
    updates, errors = settings._validate({"report": True}, sharing_consent=True)
    assert updates.get("report") is True and not errors
    updates, errors = settings._validate({"report": True}, sharing_consent=False)                  # the opt-back-in failed to save
    assert any("writable" in e for e in errors) and "report" not in updates
    updates, errors = settings._validate({"report": False}, sharing_consent=False)
    assert updates.get("report") is False                                                          # turning OFF never needs anything


def test_the_sharing_verbs_record_and_withdraw(real_consent, capsys):
    assert report_rights.withdraw_consent() == 0 and "already off" in capsys.readouterr().out   # the default is off
    assert report_rights.record_consent() == 0 and real_consent.in_force()
    out = capsys.readouterr().out
    assert "Version: 1.5" in out and "Consent recorded" in out
    assert report_rights.withdraw_consent() == 0 and not real_consent.in_force()
    assert report_rights.withdraw_consent() == 0 and "already off" in capsys.readouterr().out
    assert report_rights.wants_local_verb(argparse.Namespace(consent=True))
    assert report_rights.wants_local_verb(argparse.Namespace(withdraw_consent=True))


# ------------------------------------------------------------------ rights end to end


def test_erasure_destroys_every_way_to_re_publish_and_export_carries_the_record(real_consent, capsys, tmp_path):
    store = reporter_key.ReporterKeyStore()
    store.load_or_create()
    real_consent.record()
    audit.record_share_outcome(identifier="dep:npm:x@1", category="dependency", severity="high", subject="s",
                               asset_name="report-x", ok=True, error="", outcome="accepted")
    keep_alive.LiveReportStore().remember(graph=GRAPH, name="report-x", identifier="dep:npm:x@1", subject="s", severity="high",
                                          quads=[{"s": "a"}], epoch=keep_alive.Epoch(1))
    share_retry.queue_failed_share(graph=GRAPH, name="report-y", identifier="dep:npm:y@1", category="dependency", severity="high",
                                   subject="t", quads=[], error="refused")
    from plugins.blackbox.community import digest
    digest.SightingTally().record("ioc:domain:seen.example")                                 # KI-221: the tally is personal-data-adjacent
    export = report_rights.export_document(store)
    assert export["reporter_key_pem"].startswith("-----BEGIN") and len(export["statements"]) >= 1
    # KI-224: the export carries every store erasure covers
    assert export["consent"]["terms_version"] and export["consent"]["withdrawn_at"] == ""
    assert len(export["keep_alive"]) == 1 and len(export["retry_queue"]) == 1
    assert any("ioc:domain:seen.example" in counts for counts in export["sighting_tally"].values())
    assert report_rights.erase_identity(store, confirmed=False) == 2                          # needs --confirm
    assert report_rights.erase_identity(store, confirmed=True) == 0
    assert keep_alive.LiveReportStore().all() == [] and share_retry.default_queue().pending() == []
    assert digest.SightingTally().weeks() == []                                               # KI-221: tally gone
    erased_out = capsys.readouterr().out
    assert "wallet address stays the same" in erased_out                                      # KI-220: honest wording
    assert "Community sharing is now OFF" in erased_out
    assert real_consent.current().withdrawn_at and not real_consent.in_force()           # erasure leaves sharing OFF
    assert audit.read_share_ledger(limit=5) == []
    assert not store.exists() if hasattr(store, "exists") else True


def test_the_documents_ship_with_the_plugin():
    for name in ("REPORTER_TERMS.md", "DPIA.md", "CONTROLLER_MAP.md"):
        text = (DOCS / name).read_text(encoding="utf-8")
        assert text.startswith("#") and "Version: " in text                          # every document is versioned
    terms = consent_module.terms_text()
    for command in ("--enable-sharing", "--withdraw-consent", "--erase-identity", "--export", "--retract"):
        assert command in terms                                                               # the rights are real commands
    assert consent_module.terms_version() == "1.5"
    assert "OFF until you turn it on" in terms                                                # opt-in, said up front


@pytest.mark.parametrize("garbage", ["{nope", "[]", '"text"', "null"])
def test_a_garbage_record_reads_as_the_default(real_consent, garbage):
    """Python and the OpenClaw bridge read every malformed record the same way: as no record (off)."""
    path = real_consent._record_path()
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(garbage, encoding="utf-8")
    assert real_consent.current() is None and not real_consent.in_force()


def test_a_retraction_or_dispute_passes_without_consent_and_with_sharing_off(real_consent, monkeypatch):
    """KI-222 / LES-016: reductions always get through — opting out must not trap
    the operator's own statements. Reports stop after an opt-out."""
    from types import SimpleNamespace

    from plugins.blackbox.community.report_cli import report_command, statement_verbs

    sent = []
    monkeypatch.setattr(report_command, "load_blackbox_config", lambda: SimpleNamespace(
        community_graph_id="0xowner/community-test", community_enabled=False, report=False,
        dkg_url="http://127.0.0.1:9200", dkg_home="/tmp/x", daily_report_limit=20))
    monkeypatch.setattr(report_command, "DkgClient", lambda **kw: object())
    monkeypatch.setattr(report_command, "_reporting_identity", lambda client, graph: ("0x" + "a" * 40, object()))
    monkeypatch.setattr(statement_verbs, "submit_statement",
                        lambda client, cfg, args, reporter, signer: sent.append(args.retract or args.false_positive) or 0)
    base = dict(status=False, standing=False, export=None, restore_key=None, erase_identity=False, consent=False,
                withdraw_consent=False, false_positive=None, retract=None, type="ioc", ioc_type="domain",
                value="x.example", context="fetched-by-tool", severity="high")
    real_consent.withdraw()
    assert not real_consent.in_force()
    assert report_command.cmd_report(argparse.Namespace(**{**base, "retract": "ioc:domain:x.example"})) == 0
    assert report_command.cmd_report(argparse.Namespace(**{**base, "false_positive": "ioc:domain:x.example"})) == 0
    assert sent == ["ioc:domain:x.example", "ioc:domain:x.example"]
    # a REPORT after the opt-out (and with sharing off) is still refused
    assert report_command.cmd_report(argparse.Namespace(**base)) == 2 and len(sent) == 2
