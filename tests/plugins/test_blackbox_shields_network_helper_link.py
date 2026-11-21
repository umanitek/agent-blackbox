"""The plugin's half of the system protection helper's authentication (helper/PLAN.md;
security wave 2, finding 1): plans are signed for the helper's nonce with the per-person key,
reports must carry the helper's signature, and the card says when the two are not paired.

Without this the hardened helper (which obeys only signed plans) refuses every plan from this
plugin, so DNS Shield and the Threat Firewall never apply.
"""

from __future__ import annotations

import json

import pytest

from plugins.blackbox.shields.network import helper, helper_link, status
from plugins.blackbox.shields.network import mode as network_mode
from plugins.blackbox.shields.network.protect import enforcement
from plugins.blackbox.shields.shield_api import RawAnswer, ShieldApiError, ShieldContext

KEY = bytes([7] * 32)
#: The vector the helper crate checks too (helper/src/link.rs, a_shared_vector_…): one key,
#: nonce and body → the same hex on both sides of the contract.
# A made-up nonce for the tests — not a secret (the secret scanner's generic "api key" rule
# matches any long hex next to KEY).
NONCE = "0123456789abcdef0123456789abcdef"  # gitleaks:allow
PLAN_VECTOR = "556ad530e22f4180c7080a144eb88187e9e5c5668311aa23dc2fd484f285eafa"
REPORT_VECTOR = "ed7cae0659cb0798e3f55b0bb6586ee82d23ca413253a304832605c7bf4dd449"


@pytest.fixture
def home(tmp_path, monkeypatch):
    monkeypatch.setenv("HOME", str(tmp_path))
    monkeypatch.setenv("BLACKBOX_HOME", str(tmp_path / "bbhome"))
    return tmp_path


def _pair(home_dir) -> None:
    path = helper_link.key_path()
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(KEY)


def _context(body: bytes = b"", headers: dict | None = None) -> ShieldContext:
    return ShieldContext(network_indicators=lambda: None, ask_assistant=lambda _m: None,
                         request_body=body, request_headers={k.lower(): v for k, v in (headers or {}).items()})


def test_the_shared_vector_matches_the_helper_crate():
    assert helper_link.sign_plan(KEY, "abc", b'{"version":"v1"}') == PLAN_VECTOR
    assert helper_link.sign_report(KEY, b'{"running":true}') == REPORT_VECTOR


def test_a_plan_is_signed_for_the_helpers_nonce_over_the_exact_bytes(home):
    _pair(home)
    answer = helper_link.signed({"version": "v1", "unchanged": True}, {"nonce": NONCE})
    assert isinstance(answer, RawAnswer)
    signature = answer.headers[helper_link.SIGNATURE_HEADER]
    assert signature == helper_link.sign_plan(KEY, NONCE, answer.body)
    assert json.loads(answer.body) == {"version": "v1", "unchanged": True}


def test_without_a_key_or_a_nonce_the_plan_goes_out_plain(home):
    assert helper_link.signed({"v": 1}, {"nonce": "0123456789abcdef"}) == {"v": 1}   # no key: not paired
    _pair(home)
    assert helper_link.signed({"v": 1}, {}) == {"v": 1}                             # a page, not the helper
    assert helper_link.signed({"v": 1}, {"nonce": "NOT-HEX!"}) == {"v": 1}


def test_a_report_must_carry_the_helpers_signature_once_paired(home):
    body = b'{"running":true}'
    helper_link.require_signed_report(_context(body))                   # not paired: a pre-key helper
    _pair(home)
    with pytest.raises(ShieldApiError) as unsigned:
        helper_link.require_signed_report(_context(body))
    assert unsigned.value.status == 401
    with pytest.raises(ShieldApiError):
        helper_link.require_signed_report(_context(body, {helper_link.HELPER_SIGNATURE_HEADER: "00" * 32}))
    with pytest.raises(ShieldApiError):   # signed, but for other bytes
        helper_link.require_signed_report(_context(b'{"running":false}', {helper_link.HELPER_SIGNATURE_HEADER: REPORT_VECTOR}))
    helper_link.require_signed_report(_context(body, {helper_link.HELPER_SIGNATURE_HEADER: REPORT_VECTOR}))


def test_a_key_file_of_the_wrong_kind_is_broken_never_used(home):
    path = helper_link.key_path()
    path.parent.mkdir(parents=True)
    path.write_bytes(b"short")
    assert helper_link.read_key() is None and helper_link.pairing() == helper_link.BROKEN
    path.unlink()
    path.symlink_to(home / "elsewhere")
    (home / "elsewhere").write_bytes(KEY)
    assert helper_link.read_key() is None, "a link is never followed"


def test_the_dashboard_sends_the_plan_bytes_it_signed(home, monkeypatch):
    pytest.importorskip("fastapi")
    from fastapi.testclient import TestClient
    from _blackbox_loader import load_blackbox

    _pair(home)
    server = load_blackbox("dashboard.server")
    nonce = "fedcba9876543210fedcba9876543210"
    with TestClient(server.create_app(), base_url="http://127.0.0.1:9700") as client:
        answer = client.get(f"/api/shields/network-shield/api/system-plan?nonce={nonce}")
    assert answer.status_code == 200
    assert answer.headers[helper_link.SIGNATURE_HEADER] == helper_link.sign_plan(KEY, nonce, answer.content)


def test_the_card_says_not_paired_and_shows_the_helpers_health(home, monkeypatch):
    monkeypatch.setattr(helper, "installed", lambda: True)
    mode = network_mode.build(enabled=True, protections=(network_mode.DNS,))
    rows = [row.text for section in status.build(mode).sections for row in section.rows]
    assert "System protection helper not paired" in rows
    _pair(home)
    enforcement.record_report({"running": True, "dns_active": False, "firewall_active": False, "auth": "signed",
                               "pf_enabled": False, "resolver_ok": False, "last_error": "pfctl -E failed"})
    summary = enforcement.summary()
    assert (summary["auth"], summary["pf_enabled"], summary["resolver_ok"], summary["last_error"]) == (
        "signed", False, False, "pfctl -E failed")
    rows = [row.text for section in status.build(mode).sections for row in section.rows]
    assert "System protection helper not paired" not in rows
    assert {"The macOS packet filter is off", "DNS Shield's resolver is not answering", "The helper reported a problem"} <= set(rows)


def test_a_report_with_a_bad_health_field_is_refused(home):
    with pytest.raises(ShieldApiError):
        enforcement.record_report({"running": True, "dns_active": False, "firewall_active": False, "auth": "root"})
    with pytest.raises(ShieldApiError):
        enforcement.record_report({"running": True, "dns_active": False, "firewall_active": False, "pf_enabled": "yes"})
