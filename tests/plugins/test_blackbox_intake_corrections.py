"""Community Curation C7 — five intake behaviours brought up to their specification.

1. The partner rule covers every indicator that names someone else's property:
   domains, URLs, wallets and contracts (KI-240).
2. Readers check every signed report against the closed schema again: a
   signature proves who said it, not that it fits.
3. A trusted report of a skill protects other nodes, matched by exact identifier.
4. The curator queue reads the evidence field compiled rules carry, and the
   graduation lane holds threats whose confirmation would credit a newcomer.
5. The intake watcher marks an item announced only when the notification was
   delivered.
"""

from __future__ import annotations

import pytest
from _community_rows import GRAPH, NETWORK, Reporter, signed_row
from test_blackbox_authority import CFG, VM_GRAPH, Network, Side
from test_blackbox_curator_view import _entry
from test_blackbox_stages import _keys, _stage, _view

from plugins.blackbox.community import verification
from plugins.blackbox.community.report_signer import REPORT_STATEMENT, ReportSigner
from plugins.blackbox.community.stages import Enforcement, Stage
from plugins.blackbox.curate import intake, queue
from plugins.blackbox import detection
from plugins.blackbox.detection import action_parsing, detect_skill
from plugins.blackbox.kernel import signing, threat_ids
from plugins.blackbox.kernel.signing.statement_order import CuratorStatement as Kind
from plugins.blackbox.ruleset import community_tier, compiler


@pytest.fixture(autouse=True)
def home(monkeypatch, tmp_path):
    monkeypatch.setenv("BLACKBOX_HOME", str(tmp_path / "bbhome"))
    monkeypatch.delenv("BLACKBOX_CURATOR_ROOT_KEYS", raising=False)
    monkeypatch.delenv("BLACKBOX_COMMUNITY_ROOT_KEYS", raising=False)
    monkeypatch.setattr(community_tier.community, "ensure_community_subscription", lambda client, cfg: None)


# ------------------------------------------------------------------ 1. the partner rule

THIRD_PARTY = ["ioc:domain:evil.example", "ioc:url:https://evil.example/x", "ioc:wallet:0x" + "a" * 40,
               "ioc:contract:0x" + "b" * 40]
OWN_OBSERVATION = ["ioc:ip:203.0.113.7", "ioc:hash:" + "c" * 64]


@pytest.mark.parametrize("identifier", THIRD_PARTY)
def test_an_indicator_naming_someone_elses_property_flags_only_with_a_partner_behind_it(identifier):
    one, five = _keys("e", 1), _keys("e", 5)
    reported = _stage(identifier, one, _view(established=one))
    assert (reported.stage, reported.enforcement) == (Stage.REPORTED, Enforcement.MONITOR)
    corroborated = _stage(identifier, five, _view(established=five))          # five established, no partner
    assert (corroborated.stage, corroborated.enforcement) == (Stage.CORROBORATED, Enforcement.MONITOR)
    partner = _keys("p", 1)
    with_partner = _stage(identifier, [*partner, *one], _view(partners=[(partner[0], "acme")], established=one))
    assert with_partner.enforcement is Enforcement.FLAG


@pytest.mark.parametrize("identifier", OWN_OBSERVATION)
def test_an_indicator_the_reporter_observed_itself_needs_no_partner(identifier):
    one = _keys("e", 1)
    assert _stage(identifier, one, _view(established=one)).enforcement is Enforcement.FLAG


# ------------------------------------------------------------------ 2. the schema, checked again on read


def _resigned(row, reporter, **changed):
    """*row* with its signed payload changed and SIGNED AGAIN by the reporter: validly attributed, outside the schema."""
    payload = dict(signing.from_text(row["signedStatement"]).payload)
    payload.update(changed)
    signer = ReportSigner(private_key=reporter.key, environment=NETWORK, graph=GRAPH)
    return {**row, "signedStatement": signer.sign(REPORT_STATEMENT, payload)}


def test_a_validly_signed_report_that_the_schema_would_refuse_today_is_dropped_and_counted():
    alice = Reporter("0xa")
    good = signed_row("ioc:ip:203.0.113.7", alice)
    free_text = {**_resigned(good, alice, ioc_context="seen on my boss's laptop at 10:42"), "iocContext": "seen on my boss's laptop at 10:42"}
    vulnerability = {**_resigned(signed_row("dep:npm:lodash@4.17.20", alice), alice, kind="vulnerability"), "kind": "vulnerability"}
    verifier = verification.ReportVerifier(NETWORK, GRAPH)
    reports, dropped = verification.verify_report_rows([good, free_text, vulnerability], verifier)
    assert [r.identifier for r in reports] == ["ioc:ip:203.0.113.7"] and dropped == 2
    assert verifier.drops["schema"] == 2 and verifier.drops["other"] == 0


def test_every_report_the_real_writer_builds_passes_the_readers_schema_check():
    """One report of EVERY category, with every optional field: the reader must not refuse what the writer builds."""
    alice = Reporter("0xa")
    shape, path_category = sorted(detection.ESCALATION_SHAPES)[0], sorted(detection.SENSITIVE_PATH_CATEGORIES)[0]
    rows = [
        signed_row("ioc:ip:203.0.113.7", alice), signed_row("ioc:domain:evil.example", alice),
        signed_row("dep:npm:evil-pkg@1.0.0", alice, reason="advisory:MAL-2026-1", advisory_id="MAL-2026-1"),
        signed_row("dep:npm:whole-pkg@*", alice, reason="typosquat"),
        signed_row("skill:evil-skill@1.0.0", alice, registry="clawhub", skill_name="evil-skill", skill_version="1.0.0"),
        signed_row(threat_ids.skill_artifact_identifier("d" * 64, "shell-exec"), alice, category="skill",
                   artifact_hash="d" * 64, danger_shape="shell-exec"),
        signed_row("injection:0123456789abcdef", alice, context="in-tool-output", owasp_category="LLM01"),
        signed_row(threat_ids.escalation_identifier("terminal", shape), alice, category="escalation", tool_name="terminal",
                   arg_shape=shape),
        signed_row(threat_ids.fileaccess_identifier("read_file", path_category), alice, category="fileaccess",
                   tool_name="read_file", file_category=path_category),
    ]
    verifier = verification.ReportVerifier(NETWORK, GRAPH)
    reports, dropped = verification.verify_report_rows(rows, verifier)
    assert len(reports) == len(rows) and dropped == 0 and verifier.drops["schema"] == 0


def test_a_signed_field_the_schema_does_not_know_is_refused():
    alice = Reporter("0xa")
    extra = _resigned(signed_row("ioc:ip:203.0.113.7", alice), alice, hostname="build-box-7")
    verifier = verification.ReportVerifier(NETWORK, GRAPH)
    assert verification.verify_report_rows([extra], verifier) == ([], 1) and verifier.drops["schema"] == 1


# ------------------------------------------------------------------ 3. a trusted skill report protects other nodes

CODE = "import os\nos.system('make build')"


def _tier(reports, listed, monkeypatch, verified_skill=None):
    """The community tier over *reports*, with *listed* reporters on the verified curators'
    counted-author list (one graph since 2026-10-16: the community authority is dormant)."""
    side = Side(VM_GRAPH)
    monkeypatch.setenv("BLACKBOX_CURATOR_ROOT_KEYS", side.root_hex)
    listings = [side.row(Kind.COUNTED_AUTHORS, f"author:{r.author}", _entry(r.author)) for r in listed]
    rs = compiler.Ruleset()
    if verified_skill:
        rs.skill.append(verified_skill)
    community_tier.apply_community_tier(rs, Network(reports=reports, verified=[side.manifest_row(), *listings]), CFG, None)
    return rs


def _skill_report(reporter, version="1.0.0"):
    return signed_row(f"skill:evil-skill@{version}", reporter, registry="clawhub", skill_name="evil-skill", skill_version=version)


def test_a_trusted_report_of_a_registry_skill_flags_that_exact_version_on_another_node(monkeypatch):
    alice = Reporter("0xa")
    rs = _tier([_skill_report(alice)], [alice], monkeypatch)
    found = detect_skill("skill_install", {"name": "evil-skill", "version": "1.0.0"}, rs)
    assert [(f.identifier, f.source, f.confirmed) for f in found] == [("skill:evil-skill@1.0.0", "community", False)]
    assert detect_skill("skill_install", {"name": "evil-skill", "version": "1.0.1"}, rs) == []    # another version: no match
    assert detect_skill("skill_install", {"name": "evil-skill"}, rs) == []                        # no version: no match


def test_a_community_skill_rule_without_a_version_never_matches_every_version():
    """Only a verified rule may say "any version of this skill" (the historical finding)."""
    rule = {"identifier": "skill:evil-skill", "skillName": "evil-skill", "skillVersion": "", "severity": "high"}
    community_rs, public_rs = compiler.Ruleset(), compiler.Ruleset()
    community_rs.skill.append({**rule, "source": "community"})
    public_rs.skill.append({**rule, "source": "public"})
    install = {"name": "evil-skill", "version": "2.0.0"}
    assert detect_skill("skill_install", install, community_rs) == []
    assert [f.kind for f in detect_skill("skill_install", install, public_rs)] == ["historical"]


def test_an_untrusted_skill_report_protects_nobody(monkeypatch):
    mallory = Reporter("0xb")
    rs = _tier([_skill_report(mallory)], [], monkeypatch)
    assert rs.skill == [] and detect_skill("skill_install", {"name": "evil-skill", "version": "1.0.0"}, rs) == []


def test_a_verified_rule_for_the_same_skill_wins(monkeypatch):
    alice = Reporter("0xa")
    public = {"identifier": "skill:evil-skill@1.0.0", "skillName": "evil-skill", "skillVersion": "1.0.0", "source": "public",
              "severity": "critical"}
    rs = _tier([_skill_report(alice)], [alice], monkeypatch, verified_skill=public)
    found = detect_skill("skill_install", {"name": "evil-skill", "version": "1.0.0"}, rs)
    assert [(f.source, f.confirmed) for f in found] == [("public", True)] and len(rs.skill) == 1


def test_a_trusted_report_of_a_local_skill_is_matched_by_its_code_hash_never_its_name(monkeypatch):
    alice = Reporter("0xa")
    artifact = action_parsing.skill_install_arg("skill_install", {"name": "whatever-it-is-called", "code": CODE})["artifact_hash"]
    identifier = threat_ids.skill_artifact_identifier(artifact, "shell-exec")
    report = signed_row(identifier, alice, category="skill", artifact_hash=artifact, danger_shape="shell-exec")
    rs = _tier([report], [alice], monkeypatch)
    found = detect_skill("skill_install", {"name": "renamed-by-the-attacker", "code": CODE}, rs)
    assert [(f.identifier, f.source, f.severity) for f in found] == [(identifier, "community", "high")]
    plain = detect_skill("skill_install", {"name": "renamed-by-the-attacker", "code": CODE}, compiler.Ruleset())
    assert [(f.source, f.severity) for f in plain] == [("heuristic", "low")]                      # without the report: the local heuristic


def test_a_delisted_reporters_skill_rule_is_gone_when_the_tier_is_applied_again(monkeypatch):
    alice = Reporter("0xa")
    side = Side(VM_GRAPH)   # the verified curators' counted-author list (one graph: no community authority)
    monkeypatch.setenv("BLACKBOX_CURATOR_ROOT_KEYS", side.root_hex)
    listing = side.row(Kind.COUNTED_AUTHORS, f"author:{alice.author}", _entry(alice.author))
    rs = compiler.Ruleset()
    community_tier.apply_community_tier(rs, Network(reports=[_skill_report(alice)], verified=[side.manifest_row(), listing]), CFG, None)
    assert [rule["identifier"] for rule in rs.skill] == ["skill:evil-skill@1.0.0"]
    delisting = side.row(Kind.COUNTED_AUTHORS, f"author:{alice.author}", _entry(alice.author, listed="no"), sequence=2)
    community_tier.reapply_community_tier(
        rs, Network(reports=[_skill_report(alice)], verified=[side.manifest_row(), listing, delisting]), CFG)
    assert rs.skill == [] and rs.community["skill:evil-skill@1.0.0"]["enforcement"] == "monitor"
    assert detect_skill("skill_install", {"name": "evil-skill", "version": "1.0.0"}, rs) == []


# ------------------------------------------------------------------ 4. the queue


def test_the_evidence_lane_reads_the_field_compiled_rules_carry():
    assert queue.has_evidence({"reportReason": "advisory:MAL-2026-1"})
    assert queue.has_evidence({"reason": "advisory:MAL-2026-1"}) and queue.has_evidence({"advisoryId": "MAL-2026-1"})
    assert not queue.has_evidence({"reportReason": "typosquat"})


def test_lanes_put_evidence_before_graduation_and_graduation_before_the_rest():
    counted = {"counted": "1", "stage": "reported", "enforcement": "flag"}
    rules = {
        "dep:npm:with-advisory@1.0.0": {**counted, "reportReason": "advisory:MAL-2026-1", "unlistedReporters": "1"},
        "dep:npm:newcomer-first@1.0.0": {**counted, "reportReason": "typosquat", "unlistedReporters": "1"},
        "dep:npm:trusted-only@1.0.0": {**counted, "reportReason": "typosquat", "unlistedReporters": "0"},
        "ioc:ip:203.0.113.7": {**counted, "unlistedReporters": "2"},
        "ioc:ip:203.0.113.8": {**counted, "unlistedReporters": "0"},
        "ioc:ip:203.0.113.9": {"counted": "0", "stage": "reported", "unlistedReporters": "3"},   # nobody counted: admitted to no lane
    }
    view = queue.delta_view(rules, set())
    lanes = {item.identifier: item.lane for item in view.new}
    assert lanes == {
        "dep:npm:with-advisory@1.0.0": queue.Lane.BLOCKABLE_WITH_EVIDENCE,
        "dep:npm:newcomer-first@1.0.0": queue.Lane.GRADUATION,
        "ioc:ip:203.0.113.7": queue.Lane.GRADUATION,
        "dep:npm:trusted-only@1.0.0": queue.Lane.BLOCKABLE_NEEDS_REPRODUCTION,
        "ioc:ip:203.0.113.8": queue.Lane.FLAG_ONLY_SAMPLING,
    }
    assert view.unlisted_only == ("ioc:ip:203.0.113.9",)


def test_the_compiled_tier_says_how_many_of_a_threats_reporters_are_unlisted(monkeypatch):
    alice, newcomer = Reporter("0xa"), Reporter("0xnew")
    threat = "ioc:ip:203.0.113.7"
    rs = _tier([signed_row(threat, alice), signed_row(threat, newcomer)], [alice], monkeypatch)
    assert rs.community[threat]["unlistedReporters"] == "1" and rs.community[threat]["counted"] == "1"
    assert queue.delta_view(rs.community, set()).new[0].lane is queue.Lane.GRADUATION


# ------------------------------------------------------------------ 5. the intake watcher


class FlakySink:
    """A webhook that fails until told otherwise."""

    def __init__(self):
        self.up, self.received = False, []

    def notify(self, event):
        if self.up:
            self.received.append(event.identifier)
        return self.up

    def notify_alarm(self, item):
        return self.notify(type("E", (), {"identifier": item.message})())


def test_an_item_is_marked_announced_only_when_its_notification_was_delivered():
    view = queue.delta_view({"ioc:ip:203.0.113.7": {"counted": "1", "stage": "reported"}}, set())
    watcher, sink = intake.IntakeWatcher(), FlakySink()
    assert watcher.poll(view, sink) == []                                # the webhook is down: nothing announced, nothing forgotten
    sink.up = True
    assert watcher.poll(view, sink) == ["ioc:ip:203.0.113.7"]            # the next round delivers it
    assert watcher.poll(view, sink) == [] and sink.received == ["ioc:ip:203.0.113.7"]   # and only once


def test_an_undelivered_curator_alarm_is_tried_again():
    alarm = type("Alarm", (), {"message": "lane 2 over its time"})()
    watcher, sink = intake.AlarmWatcher(), FlakySink()
    assert watcher.poll([alarm], sink) == []
    sink.up = True
    assert watcher.poll([alarm], sink) == ["lane 2 over its time"] and watcher.poll([alarm], sink) == []


def test_a_sink_that_returns_nothing_counts_as_delivered():
    """Sinks written before delivery was reported keep working."""
    class Quiet:
        def notify(self, event):
            return None

    view = queue.delta_view({"ioc:ip:203.0.113.7": {"counted": "1", "stage": "reported"}}, set())
    assert intake.IntakeWatcher().poll(view, Quiet()) == ["ioc:ip:203.0.113.7"]


def test_the_watch_loop_builds_a_fresh_view_every_round(monkeypatch):
    """The curators' statements and the compiled tier change between rounds; a view built once goes stale (KI-261)."""
    import argparse

    from plugins.blackbox.curate import commands

    rounds = []

    def fresh_context(args):
        rounds.append(len(rounds) + 1)
        return type("Ctx", (), {"compiled": None, "manifest": None,
                                "own_view": type("View", (), {"manifest_expires_day": ""})()})()

    def stop_after_three_rounds(seconds):
        if len(rounds) >= 3:
            raise KeyboardInterrupt

    monkeypatch.setattr(commands, "_ctx", fresh_context)
    monkeypatch.setattr(commands.verbs, "curator_alarms", lambda ctx, compiled, **kw: [])
    monkeypatch.setattr(commands.time, "sleep", stop_after_three_rounds)
    monkeypatch.setattr(commands.watch.delivery.urllib.request, "urlopen", lambda request, timeout: (_ for _ in ()).throw(OSError("offline")))
    with pytest.raises(KeyboardInterrupt):   # W3: an empty --webhook now means "this node's credential file"
        commands._watch(argparse.Namespace(webhook="https://example.test/hook", once=False, interval=5.0))
    assert rounds == [1, 2, 3]
