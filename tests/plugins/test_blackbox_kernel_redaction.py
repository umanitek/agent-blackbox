"""kernel.redaction — THE redaction implementation (G1).

Regression for KI-178 (2026-10-01): the private-key rule matched only the
BEGIN header, so redaction replaced the header and left the key body in the
local audit log (and in what the opt-in LLM reviewer sends out); secret
assignments like ``DB_PASSWORD=...`` were not redacted in the audit log at all.
"""

from __future__ import annotations

from plugins.blackbox.audit import redaction as audit_redaction
from plugins.blackbox.detection import content_scanners
from plugins.blackbox.kernel.redaction import redact_secret_values

KEY_BODY = "FAKEKEYMATERIAL" * 5   # filler, not a key (no secret-shaped literals in the repo)
# Built from pieces so no PEM block appears literally in the repo (secret scanners).
_KEY_LABEL = "RSA " + "PRIVATE KEY"
PEM = f"-----BEGIN {_KEY_LABEL}-----\n{KEY_BODY}\n-----END {_KEY_LABEL}-----"


def test_private_key_block_is_removed_whole():
    out = redact_secret_values(f"cat id_rsa\n{PEM}\nafter")
    assert KEY_BODY not in out
    assert out == "cat id_rsa\n[REDACTED_PRIVATE_KEY]\nafter"


def test_private_key_block_cut_off_is_removed_to_the_end():
    out = redact_secret_values(f"before\n-----BEGIN {'PRIVATE ' + 'KEY'}-----\n{KEY_BODY}")
    assert out == "before\n[REDACTED_PRIVATE_KEY]"


def test_secret_assignment_keeps_key_drops_value():
    assert redact_secret_values("export DB_PASSWORD=hunter2secret") == "export DB_PASSWORD=[REDACTED]"
    assert redact_secret_values('{"api_key": "notarealvalue"}') == '{"api_key": "[REDACTED]"}'


def test_known_key_inside_an_assignment_keeps_its_typed_marker():
    out = redact_secret_values("ANTHROPIC_API_KEY=sk-ant-abcdefghijklmnopqrstuvwxyz")
    assert out == "ANTHROPIC_API_KEY=[REDACTED_ANTHROPIC_API_KEY]"


def test_bearer_token_is_redacted():
    assert redact_secret_values("Authorization: Bearer abc.def.ghi") == "Authorization: Bearer [REDACTED]"


def test_ordinary_prose_about_secrets_is_untouched():
    for text in ("the token generation process", "password reset link sent", "rotate the api key soon"):
        assert redact_secret_values(text) == text


def test_audit_log_text_drops_key_body_and_assignments():
    out = audit_redaction.sanitize_text(f"{PEM}\nDB_PASSWORD=hunter2secret")
    assert KEY_BODY not in out
    assert "hunter2secret" not in out


def test_audit_redacts_before_truncating():
    out = audit_redaction.sanitize_text(f"x{PEM}", max_len=40)
    assert "FAKEKEYMATERIAL" not in out


def test_detection_still_flags_a_private_key_header():
    hits = content_scanners.scan_secret_values(f"echo {PEM[:40]}")
    assert {"type": "private-key", "severity": "critical"} in hits


# --- KI-373: the assignment rule runs in linear time on hostile text --------
# Every tool call, tool result and model request is redacted, so a fetched page
# full of "tokens-tokens-..." stalled the agent: 4 KB took ~20 s, 50 KB ~75 s.
# The bound is generous (the fixed rule takes well under 0.5 s here); the old
# rule took minutes on these inputs, so a regression cannot pass.

import time

import pytest


@pytest.mark.parametrize("hostile", ["tokens-" * 3000, "a-" * 10000, "privatekey" * 2000, "token_" * 4000])
def test_redaction_stays_fast_on_hostile_text(hostile):
    started = time.perf_counter()
    redact_secret_values(hostile)
    assert time.perf_counter() - started < 3.0


@pytest.mark.parametrize("template, kept_name", [
    ("DB_PASSWORD={v}", "DB_PASSWORD="),
    ('"api_key": "{v}"', '"api_key": '),
    ("x_tokens_y: {v}", "x_tokens_y: "),
    ("MY-CLIENT-SECRET={v}", "MY-CLIENT-SECRET="),
])
def test_the_faster_rule_still_removes_named_secrets(template, kept_name):
    fake_value = "q" * 6 + "7" * 6   # built at run time: no secret-shaped literal in the repo (LES-022)
    redacted = redact_secret_values(template.format(v=fake_value))
    assert redacted.startswith(kept_name) and "[REDACTED" in redacted


# --- one list of the names that hold a secret (kernel.redaction.SECRET_NAME_WORDS) ---

def _fake_value() -> str:
    return "A" + "b1C2d3E4" * 3          # built here, never a literal: not a real credential


@pytest.mark.parametrize("name", ["aws_access_key_id", "AWS_SECRET_ACCESS_KEY", "Authorization", "refresh_token",
                                  "access-token", "clientSecret", "API_KEY", "apikey", "db_password", "passwd",
                                  "private_key", "credentials"])
def test_a_secret_named_key_is_blanked_in_a_logged_structure_and_in_text(name):
    """The two places a name is judged used two lists: `aws_access_key_id` was blanked as
    text but not as a structure's key, and `authorization` the other way round."""
    from plugins.blackbox.audit import redaction as audit_redaction
    from plugins.blackbox.kernel import redaction as kernel_redaction
    value = _fake_value()

    assert audit_redaction.redact({name: value}) == {name: "[REDACTED]"}
    assert value not in kernel_redaction.redact_secret_values(f"{name}={value}")


@pytest.mark.parametrize("name", ["author", "note", "path", "keyboard", "monkey", "command", "sequence"])
def test_an_ordinary_name_is_left_alone_in_both_places(name):
    from plugins.blackbox.audit import redaction as audit_redaction
    from plugins.blackbox.kernel import redaction as kernel_redaction
    value = _fake_value()

    assert audit_redaction.redact({name: "hello"}) == {name: "hello"}
    assert value in kernel_redaction.redact_secret_values(f"{name}={value}")


def test_both_checks_are_built_from_the_one_list():
    from plugins.blackbox.audit import redaction as audit_redaction
    from plugins.blackbox.kernel import redaction as kernel_redaction

    assert audit_redaction._SECRET_KEY_RE is kernel_redaction.SECRET_NAME_RE
    for word in kernel_redaction.SECRET_NAME_WORDS:
        assert word in kernel_redaction._SECRET_ASSIGNMENT_RE.pattern
