"""The bounded lab job store (trust-and-threat-lab L1, §03.5, F-034, F-023).

The 501st open job is REFUSED (and not stored); a re-request of a known key
returns the stored record and its evidence; a running job past its deadline
reads COULD_NOT_TELL; URL query strings never reach the file; the requester is
a peer id only, and can be erased.
"""

from __future__ import annotations

import json

import pytest

from plugins.blackbox.curate.lab import evidence_schema, jobs
from plugins.blackbox.curate.lab.jobs import LabJobError, LabJobState, LabJobStore
from plugins.blackbox.curate.queue import Lane

IMAGE = "b" * 64
PEER = "12D3KooWBJskzr2unXQG9mR3LRZFUJoxWr1PN6hTbyWyKndHXjZM"
OTHER_PEER = "12D3KooWAuEHYTWbD3R3yPTcECCYZnrjHNpJmrUw5b4D5T3m5Kr3"


class Clock:
    def __init__(self) -> None:
        self.now = 1_760_000_000.0

    def __call__(self) -> float:
        return self.now


@pytest.fixture
def clock():
    return Clock()


@pytest.fixture
def store(tmp_path, clock):
    return LabJobStore(tmp_path / "lab" / "jobs.jsonl", clock=clock)


def _request(store, identifier="url:https://phish.example.test/login", level=2,
             lane=Lane.GRADUATION, by=PEER):
    return store.request(identifier, level=level, image_sha256=IMAGE, lane=lane, requested_by=by)


def _evidence(key: str):
    return evidence_schema.validate_evidence({
        "job_key": key, "image_sha256": IMAGE, "level": int(key.split(":")[1]), "started_at": 1, "finished_at": 2,
        "contacted_hosts": ["phish.example.test"], "file_fingerprints": [], "observations": [
            {"check": "credential-form", "seen": True}], "notes": ["brand-impersonation"],
    })


def test_the_501st_job_is_refused_and_not_stored(store, tmp_path):
    for number in range(jobs.CAPACITY):
        assert _request(store, f"domain:site{number}.example.test").state is LabJobState.QUEUED
    refused = _request(store, "domain:one-too-many.example.test")
    assert refused.state is LabJobState.REFUSED
    assert store.get(refused.job.key) is None
    reloaded = LabJobStore(tmp_path / "lab" / "jobs.jsonl")
    assert len(reloaded.queued()) == jobs.CAPACITY


def test_a_finished_job_frees_its_place(store):
    first = _request(store, "domain:first.example.test")
    for number in range(jobs.CAPACITY - 1):
        _request(store, f"domain:site{number}.example.test")
    assert _request(store, "domain:waiting.example.test").state is LabJobState.REFUSED
    store.start(first.job.key)
    store.complete(first.job.key, _evidence(first.job.key))
    assert _request(store, "domain:waiting.example.test").state is LabJobState.QUEUED


def test_a_duplicate_key_returns_the_stored_result(store, clock):
    first = _request(store)
    store.start(first.job.key)
    evidence = _evidence(first.job.key)
    done = store.complete(first.job.key, evidence)
    clock.now += 3600
    again = _request(store, by=OTHER_PEER)
    assert again == done and again.state is LabJobState.DONE
    assert again.job.requested_by == PEER
    assert store.evidence(again) == evidence


def test_a_duplicate_of_a_queued_job_is_not_queued_twice(store):
    first = _request(store)
    assert _request(store) == first
    assert len(store.queued()) == 1


def test_the_key_is_digest_level_and_image(store):
    record = _request(store, level=4)
    digest = jobs.threat_digest("url:https://phish.example.test/login")
    assert record.job.key == f"{digest}:4:{IMAGE}"
    assert _request(store, level=2).job.key != record.job.key


def test_a_running_job_past_its_deadline_reads_could_not_tell(store, clock, tmp_path):
    record = _request(store, level=4)
    store.start(record.job.key)
    clock.now += jobs.DEADLINE_SECONDS[4]
    assert store.get(record.job.key).state is LabJobState.RUNNING
    clock.now += 1
    late = store.get(record.job.key)
    assert late.state is LabJobState.COULD_NOT_TELL
    assert LabJobStore(tmp_path / "lab" / "jobs.jsonl").get(record.job.key).state is LabJobState.COULD_NOT_TELL
    with pytest.raises(LabJobError):
        store.complete(record.job.key, _evidence(record.job.key))


def test_a_queued_job_never_times_out(store, clock):
    record = _request(store)
    clock.now += 7 * 24 * 3600
    assert store.get(record.job.key).state is LabJobState.QUEUED


def test_a_query_string_is_stripped_from_a_stored_url(store, tmp_path):
    record = _request(store, "url:https://phish.example.test/login?email=victim@example.test&t=abc#frag")
    assert record.job.identifier == "url:https://phish.example.test/login"
    assert record.job.key == _request(store, "url:https://phish.example.test/login").job.key
    stored = (tmp_path / "lab" / "jobs.jsonl").read_text(encoding="utf-8")
    assert "victim" not in stored and "t=abc" not in stored and "frag" not in stored


@pytest.mark.parametrize("identifier, stored", [
    ("https://x.example.test/a?b=c", "https://x.example.test/a"),
    ("dep:npm:left-pad@1.3.0", "dep:npm:left-pad@1.3.0"),
    ("domain:x.example.test", "domain:x.example.test"),
    # L1 review: a username/password in the URL is personal data too and never reaches the file.
    ("url:https://alice:secret@x.example.test:8443/a?b=c#d", "url:https://x.example.test:8443/a"),
    ("https://alice@x.example.test/a", "https://x.example.test/a"),
])
def test_strip_query(identifier, stored):
    assert jobs.strip_query(identifier) == stored


@pytest.mark.parametrize("requester", ["amos@example.test", "Amos Thomas", "", "0x" + "1" * 40])
def test_the_requester_must_be_a_peer_id(store, requester):
    with pytest.raises(LabJobError, match="peer id"):
        _request(store, by=requester)


def test_forget_requester_erases_the_peer_id(store, tmp_path):
    _request(store, "domain:a.example.test")
    _request(store, "domain:b.example.test", by=OTHER_PEER)
    assert store.forget_requester(PEER) == 1
    stored = (tmp_path / "lab" / "jobs.jsonl").read_text(encoding="utf-8")
    assert PEER not in stored and OTHER_PEER in stored


def test_queued_jobs_are_ordered_by_lane_then_age(store, clock):
    old_low = _request(store, "domain:old-low.example.test", lane=Lane.FLAG_ONLY_SAMPLING)
    clock.now += 10
    new_high = _request(store, "domain:new-high.example.test", lane=Lane.DISPUTES_AND_REVOCATIONS)
    clock.now += 10
    newer_high = _request(store, "domain:newer-high.example.test", lane=Lane.DISPUTES_AND_REVOCATIONS)
    assert [r.job.key for r in store.queued()] == [new_high.job.key, newer_high.job.key, old_low.job.key]


def test_illegal_moves_raise(store):
    record = _request(store)
    with pytest.raises(LabJobError):
        store.complete(record.job.key, _evidence(record.job.key))  # QUEUED cannot become DONE
    store.start(record.job.key)
    with pytest.raises(LabJobError):
        store.start(record.job.key)
    with pytest.raises(LabJobError, match="another job"):
        store.complete(record.job.key, _evidence(evidence_schema.job_key("c" * 64, 2, IMAGE)))


def test_a_tampered_evidence_digest_is_not_loaded(store, tmp_path):
    record = _request(store)
    path = tmp_path / "lab" / "jobs.jsonl"
    row = json.loads(path.read_text(encoding="utf-8"))
    row["evidence_sha256"] = "../../../etc/passwd"
    path.write_text(json.dumps(row) + "\n", encoding="utf-8")
    assert LabJobStore(path).get(record.job.key) is None


def test_a_line_whose_level_disagrees_with_its_key_is_not_loaded(store, tmp_path, clock):
    # L1 review: a level outside the deadline table used to crash get()/request() with KeyError.
    record = _request(store)
    store.start(record.job.key)
    path = tmp_path / "lab" / "jobs.jsonl"
    row = json.loads(path.read_text(encoding="utf-8"))
    row["level"] = 9
    path.write_text(json.dumps(row) + "\n", encoding="utf-8")
    clock.now += 10_000
    reloaded = LabJobStore(path, clock=clock)
    assert reloaded.get(record.job.key) is None
    assert _request(reloaded).state is LabJobState.QUEUED


def test_the_deadline_boundary(store, clock):
    record = _request(store, level=1)
    store.start(record.job.key)
    clock.now += jobs.DEADLINE_SECONDS[1]
    assert store.get(record.job.key).state is LabJobState.RUNNING
    clock.now += 1
    assert store.get(record.job.key).state is LabJobState.COULD_NOT_TELL


def test_concurrent_requests_at_the_last_place_queue_exactly_one(tmp_path):
    import threading

    full = LabJobStore(tmp_path / "c.jsonl", capacity=10)
    for number in range(9):
        _request(full, f"domain:x{number}.example.test")
    states = []
    threads = [threading.Thread(target=lambda n=n: states.append(_request(full, f"domain:y{n}.example.test").state))
               for n in range(16)]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join()
    assert states.count(LabJobState.QUEUED) == 1
    assert states.count(LabJobState.REFUSED) == 15
    assert len(LabJobStore(tmp_path / "c.jsonl").queued()) == 10


def test_records_survive_a_reload(store, tmp_path, clock):
    record = _request(store)
    store.start(record.job.key)
    store.complete(record.job.key, _evidence(record.job.key))
    reloaded = LabJobStore(tmp_path / "lab" / "jobs.jsonl", clock=clock)
    assert reloaded.get(record.job.key).state is LabJobState.DONE
    assert reloaded.evidence(reloaded.get(record.job.key)) == _evidence(record.job.key)


def test_the_job_file_is_private(store, tmp_path):
    _request(store)
    assert (tmp_path / "lab" / "jobs.jsonl").stat().st_mode & 0o077 == 0


# ---------------------------------------------------------------- L4: the lab trigger and the `lab` verbs
#
# The rule (§03.5, F-033): no source hit AND (≥ 2 counted clusters with a partner among them, OR one partner
# cluster plus a curator's typed request) → one job per (digest, level, image); a full store leaves the item
# awaiting lab and still flagging. Levels 1–2 first, 3 via the registry's urlscan, 4 only with a KVM image.

from pathlib import Path

from plugins.blackbox.curate.proposals.consent import ConsentLedger
from plugins.blackbox.curate.lab import commands as lab_commands
from plugins.blackbox.curate.lab import trigger
from plugins.blackbox.curate.lab.trigger import LabCandidate, LabRequests, LabSetup, SubmissionStatus
from plugins.blackbox.curate.queue import QueueItem
from plugins.blackbox.curate.service.evidence import Lookup, OwnCheck
from plugins.blackbox.curate.sources import urlscan

DOMAIN = "ioc:domain:wallet-claim.example"
PACKAGE = "dep:npm/evil-pkg@1.0.0"
LOOK_IMAGE, READ_IMAGE, RUN_IMAGE = "1" * 64, "2" * 64, "4" * 64
SETUP = LabSetup({1: LOOK_IMAGE, 2: READ_IMAGE}, requested_by=PEER)


def _item(identifier=DOMAIN, lane=Lane.FLAG_ONLY_SAMPLING):
    return QueueItem(identifier=identifier, stage="reported", enforcement="flag", reason="", reporters=1,
                     disputed=False, lane=lane)


def _candidate(identifier=DOMAIN, *, partners=1, independents=0, sources=Lookup.CLEAN, requested=False):
    return LabCandidate(_item(identifier), partner_clusters=partners, independent_clusters=independents,
                        sources=sources, curator_requested=requested)


def _submit(candidate, store, setup=SETUP, scan_ready=False):
    return trigger.submit_candidate(candidate, store, setup, scan_ready=lambda identifier: scan_ready)


def test_trigger_one_cluster_without_a_request_makes_no_job(store):
    submission = _submit(_candidate(partners=1), store)
    assert submission.status is SubmissionStatus.NOT_TRIGGERED and store.records() == []


def test_trigger_one_partner_cluster_with_a_typed_request_makes_a_job(store):
    submission = _submit(_candidate(partners=1, requested=True), store)
    assert submission.status is SubmissionStatus.SUBMITTED
    assert [(r.job.level, r.state) for r in store.records()] == [(1, LabJobState.QUEUED)]
    assert store.records()[0].job.requested_by == PEER


@pytest.mark.parametrize("partners, independents", [(2, 0), (1, 1)])
def test_trigger_two_clusters_make_a_job_without_a_request(store, partners, independents):
    assert _submit(_candidate(partners=partners, independents=independents), store).status is SubmissionStatus.SUBMITTED
    assert len(store.records()) == 1


def test_trigger_two_independents_without_a_partner_make_no_job(store):
    assert _submit(_candidate(partners=0, independents=2), store).status is SubmissionStatus.NOT_TRIGGERED
    assert _submit(_candidate(partners=0, independents=2, requested=True), store).status is SubmissionStatus.NOT_TRIGGERED
    assert store.records() == []


@pytest.mark.parametrize("sources", [Lookup.FOUND, Lookup.UNAVAILABLE])
def test_trigger_a_listed_or_unanswered_item_makes_no_job(store, sources):
    """A source listing IS the evidence; "could not tell" is never read as "not listed" (LES-011)."""
    submission = _submit(_candidate(partners=2, requested=True, sources=sources), store)
    assert submission.status is SubmissionStatus.NOT_TRIGGERED and store.records() == []


def test_trigger_a_full_store_leaves_the_item_awaiting_lab_and_still_flagging(tmp_path, clock):
    full = LabJobStore(tmp_path / "lab" / "jobs.jsonl", clock=clock, capacity=1)
    full.request("ioc:domain:other.example", level=1, image_sha256=LOOK_IMAGE, lane=Lane.GRADUATION, requested_by=PEER)
    submission = _submit(_candidate(partners=2), full)
    assert submission.status is SubmissionStatus.AWAITING_LAB
    assert submission.item == _item() and submission.item.enforcement == "flag"     # unchanged: keeps flagging
    assert [r.job.identifier for r in full.records()] == ["ioc:domain:other.example"]  # the refusal is not stored
    roomy = LabJobStore(tmp_path / "lab" / "jobs.jsonl", clock=clock, capacity=2)     # room again: next beat asks
    assert _submit(_candidate(partners=2), roomy).status is SubmissionStatus.SUBMITTED


def test_trigger_one_job_per_digest_level_and_image(store):
    first = _submit(_candidate(partners=2), store)
    again = _submit(_candidate(partners=2), store)
    assert again.records[0] == first.records[0] and len(store.records()) == 1


def test_trigger_levels_one_and_two_first_then_four_only_with_a_kvm_image(store):
    setup = LabSetup({1: LOOK_IMAGE, 2: READ_IMAGE, 4: RUN_IMAGE}, requested_by=PEER)
    first = _submit(_candidate(PACKAGE, partners=2), store, setup)
    assert [r.job.level for r in first.records] == [1, 2]
    for record in first.records:
        store.start(record.job.key)
        store.could_not_tell(record.job.key)
    assert [r.job.level for r in _submit(_candidate(PACKAGE, partners=2), store, setup).records] == [1, 2, 4]
    assert trigger.due_levels(PACKAGE, SETUP, {1, 2}, scan_ready=True) == (1, 2)       # no KVM image: no level 4


def test_trigger_level_three_only_with_a_finished_registry_scan(store):
    setup = LabSetup({1: LOOK_IMAGE, 3: urlscan.IMAGE_SHA256}, requested_by=PEER)
    assert trigger.VISIT_LEVEL == urlscan.LEVEL
    assert trigger.due_levels(DOMAIN, setup, set(), scan_ready=True) == (1,)          # levels 1–2 first
    assert trigger.due_levels(DOMAIN, setup, {1}, scan_ready=False) == (1,)
    assert trigger.due_levels(DOMAIN, setup, {1}, scan_ready=True) == (1, 3)
    submission = trigger.submit_candidate(_candidate(partners=2), store, setup, scan_ready=lambda identifier: True)
    assert [(r.job.level, r.job.key.rsplit(":", 1)[1]) for r in submission.records] == [(1, LOOK_IMAGE)]


@pytest.mark.parametrize("statuses, expected", [
    ([Lookup.CLEAN, Lookup.FOUND, Lookup.UNAVAILABLE], Lookup.FOUND),
    ([Lookup.CLEAN, Lookup.UNAVAILABLE], Lookup.UNAVAILABLE),
    ([], Lookup.UNAVAILABLE),
    ([Lookup.CLEAN, Lookup.NOT_APPLICABLE], Lookup.CLEAN),
])
def test_trigger_folds_source_verdicts_in_three_outcomes(statuses, expected):
    assert trigger.sources_say([OwnCheck(status) for status in statuses]) is expected


# -- the typed request (a human act) and `lab status`

#: An identifier whose text is a command line: it must never reach a log.
COMMAND_LIKE = "escalation:shell:curl-evil.example-pipe-sh"


@pytest.fixture
def ledger(tmp_path, clock):
    return ConsentLedger(tmp_path / "consent.jsonl", clock=clock)


@pytest.fixture
def requests_log(tmp_path, clock):
    return LabRequests(tmp_path / "lab" / "requests.jsonl", clock=clock)


def _code_shown(capsys) -> str:
    return capsys.readouterr().out.rsplit("--code ", 1)[1].split()[0]


def test_typed_request_logs_a_human_act_without_the_identifier_text(ledger, requests_log, tmp_path, capsys):
    assert lab_commands.request_command(COMMAND_LIKE, code=None, ledger=ledger, requests=requests_log) == 0
    code = _code_shown(capsys)
    assert requests_log.requested_digests() == frozenset()                     # shown is not requested
    assert lab_commands.request_command(COMMAND_LIKE, code=code, ledger=ledger, requests=requests_log) == 0
    rows = [json.loads(line) for line in (tmp_path / "lab" / "requests.jsonl").read_text().splitlines()]
    assert rows == [{"ts": rows[0]["ts"], "act": "lab-request", "threat_digest": jobs.threat_digest(COMMAND_LIKE),
                     "code": code}]
    for log in (tmp_path / "lab" / "requests.jsonl", tmp_path / "consent.jsonl"):
        text = log.read_text()
        assert "curl" not in text and "escalation" not in text and "evil" not in text
    assert jobs.threat_digest(COMMAND_LIKE) in requests_log.requested_digests()


def test_only_well_formed_lab_request_rows_count_as_requests(requests_log, tmp_path):
    """A row of another act, a digest that is not a SHA-256, a non-object or a torn line never
    becomes a request — only the human act fires the trigger's path (b)."""
    requests_log.record(DOMAIN, code="1a2b3c4d")
    other_digest = jobs.threat_digest("ioc:domain:other.example")
    with (tmp_path / "lab" / "requests.jsonl").open("a", encoding="utf-8") as handle:
        handle.write(json.dumps({"act": "something-else", "threat_digest": other_digest}) + "\n")
        handle.write(json.dumps({"act": trigger.TYPED_REQUEST_ACT, "threat_digest": "not-a-digest"}) + "\n")
        handle.write(json.dumps([trigger.TYPED_REQUEST_ACT, other_digest]) + "\n")
        handle.write('{"act": "lab-request", "threat_dig')
    assert requests_log.requested_digests() == frozenset({jobs.threat_digest(DOMAIN)})


def test_typed_request_refuses_a_wrong_or_reused_code_and_a_non_identifier(ledger, requests_log, capsys):
    assert lab_commands.request_command(DOMAIN, code="00000000", ledger=ledger, requests=requests_log) == 2
    lab_commands.request_command(DOMAIN, code=None, ledger=ledger, requests=requests_log)
    code = _code_shown(capsys)
    assert lab_commands.request_command(DOMAIN, code=code, ledger=ledger, requests=requests_log) == 0
    assert lab_commands.request_command(DOMAIN, code=code, ledger=ledger, requests=requests_log) == 2   # single-use
    assert lab_commands.request_command("just some words", code=None, ledger=ledger, requests=requests_log) == 2
    assert len(requests_log.requested_digests()) == 1


def test_typed_request_on_file_fires_the_trigger_for_a_partner_cluster(ledger, requests_log, store, capsys):
    """The request is filed under the query-stripped URL — the identifier the queue and the job store use."""
    url = "ioc:url:https://wallet-claim.example/login"
    lab_commands.request_command(url + "?session=secret", code=None, ledger=ledger, requests=requests_log)
    lab_commands.request_command(url + "?session=secret", code=_code_shown(capsys), ledger=ledger,
                                 requests=requests_log)
    requested = jobs.threat_digest(url) in requests_log.requested_digests()
    assert _submit(_candidate(url, partners=1, requested=requested), store).status is SubmissionStatus.SUBMITTED
    assert "secret" not in capsys.readouterr().out


def test_lab_status_lists_jobs_by_state(store, requests_log, clock, capsys):
    _request(store, DOMAIN, level=1)
    clock.now += 600
    assert lab_commands.status_command(store=store, requests=requests_log, clock=clock) == 0
    out = capsys.readouterr().out
    assert "queued 1" in out and "oldest waiting job: 10 min" in out and "typed requests on file: 0" in out
    assert DOMAIN in out


# -- both verbs parse through the real Hermes parser and register from curate/lab/commands.py (LES-035)

@pytest.mark.parametrize("argv, attribute, value", [
    (["blackbox", "curate", "lab", DOMAIN, "--code", "1a2b3c4d"], "code", "1a2b3c4d"),
    (["blackbox", "curate", "lab", "status"], "target", "status"),
])
def test_the_lab_verbs_parse_through_the_real_hermes_parser(argv, attribute, value, tmp_path):
    import os
    import subprocess
    import sys

    from test_blackbox_host_arg_names import _REAL_PARSE

    root = Path(__file__).resolve().parents[2]
    env = {**os.environ, "HERMES_HOME": str(tmp_path / "hermes"), "PYTHONPATH": str(root)}
    probe = _REAL_PARSE + "print(json.dumps([args.func.__module__, args.func.__name__]))\n"
    done = subprocess.run([sys.executable, "-c", probe, json.dumps(argv), attribute], cwd=root, env=env,
                          capture_output=True, text=True, timeout=120, check=False)
    assert done.returncode == 0, done.stderr[-2000:]
    parsed, (module, name) = (json.loads(line) for line in done.stdout.strip().splitlines()[-2:])
    assert parsed == {"version": False, "command": "blackbox", "value": value}
    assert module.endswith("curate.lab.commands") and name == "cmd_lab"


def test_the_lab_verb_does_not_grow_curate_commands():
    curate = Path(__file__).resolve().parents[2] / "plugins" / "blackbox" / "curate"
    text = (curate / "commands.py").read_text(encoding="utf-8")
    assert '"lab"' not in text and "cmd_lab" not in text and "lab.commands" not in text


# --- several stores share one file: readers never write, writers never lose another's job ------

def test_reading_jobs_never_rewrites_the_file(store, clock, tmp_path):
    """The metrics and `lab status` read through their own store; a read used to save its view
    of an expired job, writing a stale snapshot over the controller's newer one."""
    record = _request(store, level=4)
    store.start(record.job.key)
    path = tmp_path / "lab" / "jobs.jsonl"
    before = path.read_bytes()
    clock.now += jobs.DEADLINE_SECONDS[4] + 1
    reader = LabJobStore(path, clock=clock)
    assert reader.get(record.job.key).state is LabJobState.COULD_NOT_TELL
    assert [r.state for r in reader.records()] == [LabJobState.COULD_NOT_TELL]
    assert path.read_bytes() == before


def test_a_job_another_process_added_survives_this_stores_next_write(tmp_path, clock):
    path = tmp_path / "lab" / "jobs.jsonl"
    controller = LabJobStore(path, clock=clock)                 # loaded before the request below existed
    cli = LabJobStore(path, clock=clock)
    asked = _request(cli, identifier="url:https://first.example.test/")
    other = _request(controller, identifier="url:https://second.example.test/")
    keys = {r.job.key for r in LabJobStore(path, clock=clock).records()}
    assert keys == {asked.job.key, other.job.key}
