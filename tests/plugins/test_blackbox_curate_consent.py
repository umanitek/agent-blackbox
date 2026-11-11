"""A consent code is good for 10 minutes from when it was SHOWN, once.

`curate publish` recorded the code as shown again right before checking it, so the
10-minute clock restarted on every attempt and the expiry never applied. The
"already used?" check and the record of its use were also two steps that two
publishes of one code could interleave. Writes run through fakes only.
"""

from __future__ import annotations

import json
import threading
import time

import pytest

from test_blackbox_curate import NETWORK, THREAT, VM_GRAPH, FakeNode, _ctx, _machine, _payload
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from plugins.blackbox.curate import keys, publishing
from plugins.blackbox.curate.context import PromotionDraft
from plugins.blackbox.curate.proposals import consent
from plugins.blackbox.curate.proposals.proposal import Proposal, ProposalState, ProposalStore
from plugins.blackbox.kernel import signing
from plugins.blackbox.kernel.signing import key_manifest as km
from plugins.blackbox.kernel.signing.statement_order import CuratorStatement as Kind


def _approved(monkeypatch, tmp_path):
    curator_keys = [Ed25519PrivateKey.generate() for _ in range(2)]
    hexes = [signing.public_key_hex(k) for k in curator_keys]
    manifest = km.KeyManifest(environment=NETWORK, graph=VM_GRAPH, chain="", root_epoch=1, version=1, threshold=2,
                              **km.roster(dict(zip(hexes, ("acme", "globex")))), promotion_author="0x" + "1" * 40,
                              legacy_assets_hash=km.legacy_assets_hash([]))
    _machine(monkeypatch, tmp_path, "A", curator_keys[1])
    node = FakeNode()
    ctx = _ctx(node, manifest)
    envelope = ctx.cosign(ctx.sign(PromotionDraft(_payload(), sequence=1), curator_keys[0]), curator_keys[1])
    proposal = (Proposal.new(Kind.PROMOTION.value, THREAT, envelope, VM_GRAPH, checks={})
                .transition(ProposalState.PROPOSED).transition(ProposalState.APPROVED))
    store = ProposalStore()
    store.save(proposal)
    publish_module = __import__("importlib").import_module("plugins.blackbox.curate.publishing.publish")
    monkeypatch.setattr(publish_module, "_write", lambda c, p, e: ("promotion-x", VM_GRAPH,
                                                                    publish_module.PublishOutcome.PUBLISHED))
    return ctx, store, proposal


def _shown_at(proposal, when: float) -> str:
    """Record that the proposal's code was shown at *when*, as `curate show` or the console does."""
    code = consent.confirmation_code(proposal.envelope)
    path = keys.curate_home() / "consent.jsonl"
    with path.open("a", encoding="utf-8") as ledger:
        ledger.write(json.dumps({"ts": when, "event": "shown", "code": code, "summary": "x"}) + "\n")
    return code


def test_a_code_shown_more_than_ten_minutes_ago_is_refused_by_publish(monkeypatch, tmp_path):
    ctx, store, proposal = _approved(monkeypatch, tmp_path)
    code = _shown_at(proposal, time.time() - consent.CODE_TTL_SECONDS - 60)
    _, outcome = publishing.publish(ctx, store, proposal.id, typed_code=code, yes=False)
    assert outcome.startswith("not published") and "expired" in outcome


def test_a_fresh_code_publishes_once(monkeypatch, tmp_path):
    ctx, store, proposal = _approved(monkeypatch, tmp_path)
    code = _shown_at(proposal, time.time() - 60)
    _, outcome = publishing.publish(ctx, store, proposal.id, typed_code=code, yes=False)
    assert outcome.startswith("published")


def test_publish_without_a_code_shows_one_and_publishes_nothing(monkeypatch, tmp_path):
    ctx, store, proposal = _approved(monkeypatch, tmp_path)
    _, outcome = publishing.publish(ctx, store, proposal.id, typed_code=None, yes=False)
    assert outcome.startswith("not published") and consent.confirmation_code(proposal.envelope) in outcome


def test_one_code_is_consumed_once_even_when_two_publishes_race(tmp_path):
    ledger = consent.ConsentLedger(tmp_path / "consent.jsonl")
    code = ledger.show('{"a":1}', "x")
    barrier, results = threading.Barrier(8), []

    def attempt():
        barrier.wait()
        results.append(consent.ConsentLedger(tmp_path / "consent.jsonl").consent('{"a":1}', typed=code, sandbox=False,
                                                                                 yes=False)[0])

    threads = [threading.Thread(target=attempt) for _ in range(8)]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join(10)
    assert results.count(True) == 1


def test_a_damaged_ledger_line_does_not_break_every_later_consent(tmp_path):
    path = tmp_path / "consent.jsonl"
    ledger = consent.ConsentLedger(path)
    code = ledger.show('{"a":1}', "x")
    with path.open("a", encoding="utf-8") as handle:
        handle.write(json.dumps({"ts": "not-a-number", "event": "shown", "code": code}) + "\n")
    assert ledger.consent('{"a":1}', typed=code, sandbox=False, yes=False)[0] is True


def test_a_publish_outcome_is_typed_never_read_from_its_wording():
    """publish() returned prose that every caller parsed with startswith("published") —
    "not published — …" contains the word, which is how a refused publish once counted as done.
    It returns a PublishResult: still the operator's text, plus the typed `published` flag."""
    from plugins.blackbox.curate.publishing import PublishResult
    refused = PublishResult("not published — published elsewhere? no", published=False)
    done = PublishResult("published to g as x", published=True)
    assert not refused.published and done.published
    assert str(done) == "published to g as x" and done.startswith("published")   # still the text it was
