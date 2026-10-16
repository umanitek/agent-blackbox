"""A statement is what was SIGNED, not how it is written (KI-266).

One signed statement can be written as many different texts that all verify:
other spacing or key order, an extra key the parser ignores, upper-case hex in
a signature, the signatures in another order, or one of three signatures left
out. Anyone can publish such rewritten copies of a genuine curator statement,
with no key at all. Wherever a reader counts, stores or de-duplicates curator
statements it must therefore key on the signed content — otherwise the copies
crowd its trust store (and, were the community authority awake, its daily cap
on raising statements).

The statements here are the verified authority's: its advisory statements live
in the shared memory anyone can write (one graph since 2026-10-16).
"""

from __future__ import annotations

import json

import pytest
from _community_rows import GRAPH
from test_blackbox_authority import CFG, CITED, Side, TODAY, VM_GRAPH
from test_blackbox_trust_store import Store

from plugins.blackbox.community import read_curator_view
from plugins.blackbox.community.statements import curator_view as cv
from plugins.blackbox.community.trust.trust_store import TrustStore, statement_key
from plugins.blackbox.kernel import signing
from plugins.blackbox.kernel.signing.statement_order import CuratorStatement as Kind

THREAT = "ioc:ip:203.0.113.7"


@pytest.fixture(autouse=True)
def home(monkeypatch, tmp_path):
    monkeypatch.setenv("BLACKBOX_HOME", str(tmp_path / "bbhome"))
    monkeypatch.delenv("BLACKBOX_CURATOR_ROOT_KEYS", raising=False)
    monkeypatch.setattr(cv, "_today", lambda: TODAY)


@pytest.fixture
def curators(monkeypatch):
    """The verified authority: its root trusted, its manifest in Verified Memory."""
    side = Side(VM_GRAPH)
    monkeypatch.setenv("BLACKBOX_CURATOR_ROOT_KEYS", side.root_hex)
    return side


def _node(curators, *shared):
    return Store(shared=shared, verified=[curators.manifest_row()])


def _upper(text: str, nth: int = 0) -> str:
    """*text* with the *nth* lower-case hex letter of its first signature in upper case."""
    start = text.index('"sig":"') + 7
    letters = [i for i in range(start, start + 128) if text[i] in "abcdef"]
    at = letters[nth % len(letters)]
    return text[:at] + text[at].upper() + text[at + 1:]


def _upper_at(text: str, nth: int) -> str:
    """Like :func:`_upper`, counting letters in the ORIGINAL casing (stable while other letters change)."""
    start = text.index('"sig":"') + 7
    letters = [i for i in range(start, start + 128) if text[i].lower() in "abcdef"]
    at = letters[nth]
    return text[:at] + text[at].upper() + text[at + 1:]


def rewritten(text: str) -> dict:
    """Every way an outsider can rewrite *text* (signed by THREE keys) without a key."""
    document = json.loads(text)
    return {
        "upper-case hex in a signature": _upper(text),
        "spaces and another key order": json.dumps(dict(reversed(list(document.items()))), indent=1),
        "an extra key the parser ignores": json.dumps({**document, "note": "x"}, sort_keys=True, separators=(",", ":")),
        "the signatures in another order": json.dumps({**document, "sigs": document["sigs"][::-1]}, sort_keys=True, separators=(",", ":")),
        "one of three signatures left out": json.dumps({**document, "sigs": document["sigs"][:2]}, sort_keys=True, separators=(",", ":")),
    }


def _copies(row: dict, count: int) -> list:
    """*count* distinct rewritten copies of one genuine row (at most 255): copy
    n has the signature's hex letters picked by the bits of n in upper case."""
    copies = []
    for n in range(1, count + 1):
        text = row["signedStatement"]
        for bit in range(8):
            if n >> bit & 1:
                text = _upper_at(text, bit)
        copies.append({**row, "signedStatement": text})
    return copies


# ------------------------------------------------------------------ the identity


def test_every_rewritten_copy_verifies_and_is_the_same_statement(curators):
    row = curators.row(Kind.CONFIRMATION, THREAT, CITED, signers=3)
    genuine = signing.from_text(row["signedStatement"])
    for what, text in rewritten(row["signedStatement"]).items():
        envelope = signing.from_text(text)
        assert text != row["signedStatement"], what
        assert len(curators.manifest.curator_signers(envelope, statement_type=Kind.CONFIRMATION.value, graph=GRAPH)) >= 2, what
        assert signing.content_id(envelope) == signing.content_id(genuine), what          # one statement
        assert statement_key({**row, "signedStatement": text}) == statement_key(row), what
        # Only a copy with fewer signatures is still in canonical form (it is what two curators would
        # have written), which is why identity is the signed content and not "the canonical text".
        assert signing.is_canonical(text) == (what == "one of three signatures left out"), what
    assert signing.is_canonical(row["signedStatement"])


def test_what_was_signed_decides_the_identity_never_who_else_signed_or_how_it_is_written(curators):
    one = curators.row(Kind.CONFIRMATION, THREAT, CITED, sequence=1)
    assert statement_key(one) != statement_key(curators.row(Kind.CONFIRMATION, THREAT, CITED, sequence=2))
    assert statement_key(one) != statement_key(curators.row(Kind.CONFIRMATION, "ioc:ip:203.0.113.8", CITED, sequence=1))
    assert statement_key(one) != statement_key(curators.row(Kind.REJECTION, THREAT, {"reason": "benign"}, sequence=1))
    assert statement_key(one) == statement_key(curators.row(Kind.CONFIRMATION, THREAT, CITED, sequence=1, signers=3))
    junk = {"r": "urn:x", "identifier": THREAT, "signedStatement": "not a statement"}
    assert statement_key(junk) != statement_key({**junk, "signedStatement": "another text"})    # unparseable: keyed by its text


def test_the_trust_store_keeps_one_row_per_signed_statement(curators):
    replayed = curators.row(Kind.CONFIRMATION, THREAT, CITED)
    copies = _copies(replayed, 60)
    assert len({row["signedStatement"] for row in copies}) == 60
    read_curator_view(_node(curators, *copies, replayed), CFG, interest=[THREAT])
    stored = TrustStore().load(GRAPH).statements
    assert len(stored) == 1 and stored[0]["signedStatement"] == replayed["signedStatement"]      # as the curators wrote it


def test_every_formatting_only_copy_reads_back_as_the_original_text(curators):
    row = curators.row(Kind.CONFIRMATION, THREAT, CITED, signers=3)
    for what, text in rewritten(row["signedStatement"]).items():
        canonical = signing.canonical_text(signing.from_text(text))
        assert signing.is_canonical(canonical), what
        assert (canonical == row["signedStatement"]) == (what != "one of three signatures left out"), what


def test_a_signature_an_outsider_added_to_a_genuine_statement_is_not_what_the_reader_keeps(curators):
    """Anyone can sign the same bytes with a key of their own and publish the result: it
    verifies (the two curator signatures are still there). The reader keeps the copy with
    the fewest signatures, whatever order the copies are read in."""
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
    genuine = curators.row(Kind.CONFIRMATION, THREAT, CITED)
    padded = []
    for _ in range(6):
        outsider = Ed25519PrivateKey.generate()                    # gitleaks:allow — a throwaway test key
        padded.append({**genuine, "signedStatement": signing.cosign(signing.from_text(genuine["signedStatement"]), outsider).to_text()})
    for rows in ([*padded, genuine], [genuine, *padded]):
        TrustStore().forget()
        view = read_curator_view(_node(curators, *rows), CFG, interest=[THREAT])
        assert view.verdict(THREAT) is Kind.CONFIRMATION
        assert [row["signedStatement"] for row in TrustStore().load(GRAPH).statements] == [genuine["signedStatement"]]


def test_a_copy_with_a_broken_signature_cannot_stand_in_for_the_genuine_statement(curators):
    genuine = curators.row(Kind.CONFIRMATION, THREAT, CITED)
    document = json.loads(genuine["signedStatement"])
    document["sigs"][0]["sig"] = "0" * 128                                    # same content, one signature destroyed
    broken = {**genuine, "signedStatement": json.dumps(document, sort_keys=True, separators=(",", ":"))}
    assert statement_key(broken) == statement_key(genuine) and broken["signedStatement"] < genuine["signedStatement"]
    for rows in ([broken, genuine], [genuine, broken]):
        TrustStore().forget()
        view = read_curator_view(_node(curators, *rows), CFG, interest=[THREAT])
        assert view.verdict(THREAT) is Kind.CONFIRMATION
        assert [row["signedStatement"] for row in TrustStore().load(GRAPH).statements] == [genuine["signedStatement"]]
