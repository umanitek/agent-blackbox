"""kernel.signing + kernel.reporter_key — the signed-statement envelope (R0a).

A reader believes "who wrote this report" only from a verified signature
(LES-014/017). These tests pin what a signature binds (type, environment,
graph, schema, payload), that untrusted envelopes fail closed, and that the
reporter key file is created once, privately, and never silently replaced.
"""

from __future__ import annotations

import os
import stat
import threading

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from plugins.blackbox.kernel import reporter_key, signing

GRAPH = "0xabc/agent-blackbox-community"
PAYLOAD = {"identifier": "ioc:domain:evil.example", "observed": "2026-10-01"}


@pytest.fixture
def key():
    return Ed25519PrivateKey.generate()


def _sign(key, **overrides):
    args = {"statement_type": "blackbox.report", "environment": "sim", "graph": GRAPH, "payload": PAYLOAD}
    args.update(overrides)
    return signing.sign(key, **args)


def _verify(envelope, **overrides):
    args = {"statement_type": "blackbox.report", "environment": "sim", "graph": GRAPH}
    args.update(overrides)
    return signing.verify(envelope, **args)


# ------------------------------------------------------------------ signing


def test_round_trip_through_text_verifies_to_the_signer(key):
    envelope = signing.from_text(_sign(key).to_text())
    assert _verify(envelope) == signing.public_key_hex(key)


def test_tampered_payload_fails(key):
    envelope = _sign(key)
    forged = signing.SignedEnvelope(**{**envelope.__dict__, "payload": {**PAYLOAD, "identifier": "ioc:domain:other"}})
    assert _verify(forged) is None


@pytest.mark.parametrize("field, value", [
    ("statement_type", "blackbox.dispute"),
    ("environment", "mainnet"),
    ("graph", "0xabc/another-graph"),
])
def test_signature_is_bound_to_its_domain(key, field, value):
    assert _verify(_sign(key), **{field: value}) is None


def test_schema_version_is_signed(key):
    envelope = _sign(key)
    bumped = signing.SignedEnvelope(**{**envelope.__dict__, "schema_version": 2})
    assert _verify(bumped) is None


def test_a_signer_swap_fails(key):
    envelope = _sign(key)
    impostor = signing.public_key_hex(Ed25519PrivateKey.generate())
    swapped = (signing.Signature(signer=impostor, value=envelope.signatures[0].value),)
    assert _verify(signing.SignedEnvelope(**{**envelope.__dict__, "signatures": swapped})) is None


@pytest.mark.parametrize("text", [
    "", "not json", "[]", '{"v": 99}',
    '{"v":1,"type":"t","env":"e","graph":"g","schema":1,"payload":{},"signer":"a","sig":"b"}',   # the R0 v1 shape
    '{"v":2,"type":"t","env":"e","graph":"g","chain":"","epoch":0,"seq":0,"schema":"1","payload":{},'
    '"sigs":[{"signer":"a","sig":"b"}]}',
    '{"v":2,"type":"t","env":"e","graph":"g","chain":"","epoch":0,"seq":0,"schema":1,"payload":{"k":1},'
    '"sigs":[{"signer":"a","sig":"b"}]}',
    '{"v":2,"type":"t","env":"e","graph":"g","chain":"","epoch":0,"seq":0,"schema":1,"payload":{},"sigs":[]}',
    '{"v":2,"type":"t","env":"e","graph":"g","chain":"","epoch":true,"seq":0,"schema":1,"payload":{},'
    '"sigs":[{"signer":"a","sig":"b"}]}',
    "x" * (signing.MAX_ENVELOPE_CHARS + 1),
])
def test_malformed_envelopes_parse_to_none(text):
    assert signing.from_text(text) is None


def test_verify_never_raises_on_garbage_hex(key):
    envelope = _sign(key)
    garbage = signing.SignedEnvelope(**{**envelope.__dict__, "signatures": (
        signing.Signature(signer=envelope.signatures[0].signer, value="zz" * 64),)})
    assert _verify(garbage) is None
    assert _verify(None) is None


def test_payload_must_be_flat_strings(key):
    with pytest.raises(ValueError):
        _sign(key, payload={"count": 3})


def test_oversized_envelope_is_refused(key):
    with pytest.raises(ValueError):
        _sign(key, payload={"blob": "x" * signing.MAX_ENVELOPE_CHARS})


# --------------------------------------------------------------- key store


def test_key_is_created_once_with_owner_only_permissions(tmp_path):
    store = reporter_key.ReporterKeyStore(tmp_path / "reporter_key.pem")
    first = store.public_key_hex()
    assert reporter_key.ReporterKeyStore(tmp_path / "reporter_key.pem").public_key_hex() == first
    if os.name == "posix":
        assert stat.S_IMODE(store.path.stat().st_mode) == 0o600


def test_default_path_lives_in_blackbox_home(tmp_path, monkeypatch):
    monkeypatch.setenv("BLACKBOX_HOME", str(tmp_path / "bbhome"))
    assert reporter_key.ReporterKeyStore().path == tmp_path / "bbhome" / reporter_key.KEY_FILE_NAME


def test_concurrent_first_use_yields_one_key(tmp_path):
    path = tmp_path / "reporter_key.pem"
    keys = []
    threads = [threading.Thread(target=lambda: keys.append(reporter_key.ReporterKeyStore(path).public_key_hex()))
               for _ in range(8)]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join(5)
    assert len(keys) == 8          # every creator succeeded, none crashed
    assert len(set(keys)) == 1     # ...and they all hold the same key
    assert not list(tmp_path.glob("*.tmp.*"))


def test_unusable_key_file_is_an_error_never_a_silent_new_identity(tmp_path):
    path = tmp_path / "reporter_key.pem"
    path.write_text("not a key", encoding="utf-8")
    with pytest.raises(reporter_key.ReporterKeyError):
        reporter_key.ReporterKeyStore(path).load_or_create()
    assert path.read_text(encoding="utf-8") == "not a key"


def test_the_reducing_statement_types_are_one_list_and_the_names_are_shared():
    """Revocation, rejection and correction reduce enforcement; nothing else does. The report and
    correction type names are defined once and the feature modules read them from there."""
    from plugins.blackbox.community import report_signer
    from plugins.blackbox.curate import context as curate_context
    from plugins.blackbox.kernel.signing import promotion_statement, statement_order
    from plugins.blackbox.ruleset.live import corrections

    reducing = {"blackbox.revocation", "blackbox.rejection", "blackbox.correction"}
    every_type = {kind.value for kind in statement_order.CuratorStatement} | {
        "blackbox.report", "blackbox.correction", "blackbox.kill-list", "blackbox.key-manifest", "blackbox.dispute"}
    assert {name for name in every_type if statement_order.reduces_enforcement(name)} == reducing
    assert all(statement_order.reduces_enforcement(kind.value) for kind in statement_order.CuratorStatement
               if kind.terminal)
    assert not any(statement_order.reduces_enforcement(kind.value) for kind in statement_order.CuratorStatement
                   if kind.raises_enforcement)
    assert report_signer.REPORT_STATEMENT == promotion_statement.REPORT_STATEMENT == "blackbox.report"
    assert corrections.CORRECTION_STATEMENT == curate_context.CORRECTION_STATEMENT == "blackbox.correction"


def test_the_kept_copy_is_chosen_by_the_signatures_it_carries_not_by_its_spelling():
    """Two readers chose among copies of one statement: one parsed the envelope, one counted the
    text '"signer":'. A payload key spelled "signer" fooled the count; both now ask one rule."""
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

    from plugins.blackbox.kernel import signing

    one = signing.sign(Ed25519PrivateKey.generate(), statement_type="blackbox.report", environment="e", graph="g",
                       payload={"signer": "x", "subject": "s"})
    two = signing.cosign(one, Ed25519PrivateKey.generate())
    assert signing.copy_rank(signing.canonical_text(one))[0] == 1
    assert signing.copy_rank(signing.canonical_text(two))[0] == 2
    assert signing.copy_rank("not an envelope") == (0, "not an envelope")
