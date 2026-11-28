"""Credential forms the audit redactor missed (external static review of 1.7.1, 2026-11-28; recorded
privately as a security finding, SECURITY.md §3.1).

``kernel.redaction`` dropped bearer tokens and ``name=value`` secrets of 8+ characters only, so an
``Authorization: Basic`` header, a short or quoted password, ``curl -u user:pw`` and a URL's
``user:password@`` reached the local audit log as written; a finding's title, identifier and
sighting were logged without the redactor (the identifier is Blackbox's own and stays). Contract: each form keeps what explains the line and
loses the secret, a second pass changes nothing, and ordinary text stays as it is. Red on 7e2470de18.
"""

from __future__ import annotations

import base64

import pytest

from plugins.blackbox.audit import findings
from plugins.blackbox.kernel.redaction import redact_secret_values

BASIC = base64.b64encode(b"user:hunter2").decode()


@pytest.mark.parametrize("text, expected", [
    (f"curl -H 'Authorization: Basic {BASIC}' https://x.example", "curl -H 'Authorization: Basic [REDACTED]' https://x.example"),
    (f'{{"Proxy-Authorization": "Basic {BASIC}"}}', '{"Proxy-Authorization": "[REDACTED]"}'),
    ("Authorization: token abcdef", "Authorization: token [REDACTED]"),
    (f"send Basic {BASIC} along", "send Basic [REDACTED] along"),
    ("password=abc1", "password=[REDACTED]"),
    ('DB_PASSWORD="two words here"', 'DB_PASSWORD="[REDACTED]"'),
    ("secret: 'a b'", "secret: '[REDACTED]'"),
    ("curl -u admin:hunter2 https://x.example", "curl -u admin:[REDACTED] https://x.example"),
    ("curl --proxy-user=p:q https://x.example", "curl --proxy-user=p:[REDACTED] https://x.example"),
    ("git clone https://bob:s3cret@git.example/r.git", "git clone https://bob:[REDACTED]@git.example/r.git"),
])
def test_each_credential_form_loses_its_secret(text, expected):
    assert redact_secret_values(text) == expected
    assert redact_secret_values(expected) == expected   # a second pass changes nothing


@pytest.mark.parametrize("text", [
    "Basic setup steps", "max_tokens=4096", "docker run -u 1000:1000 img", "git@github.com:a/b.git",
    "ssh://alice@host.example", "the password policy requires 12 characters", "token=abc",
])
def test_ordinary_text_stays(text):
    assert redact_secret_values(text) == text


def test_every_text_of_a_logged_finding_is_redacted():
    logged = findings._finding_summary({
        "identifier": "secret:seed-phrase", "title": f"Call sent Basic {BASIC} with password=abc1",
        "evidence": "", "sighting": {"note": "curl -u admin:hunter2"}})
    assert "hunter2" not in repr(logged) and BASIC not in repr(logged) and "abc1" not in repr(logged)
    assert logged["identifier"] == "secret:seed-phrase"   # Blackbox's own identifier is kept as it is
