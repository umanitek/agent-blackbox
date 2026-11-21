"""A displayed code signature is only believed once it VERIFIES (review 2026-11-21, finding 3).

``codesign -dv`` only shows what a binary claims; a self-signed certificate named "Software
Signing" or "Developer ID Application: …", or a binary changed after signing, displays the same.
Contracts: the signature must be intact AND satisfy the requirement of the signer it claims
(Apple / App Store / Developer ID / Apple Development); notarisation comes from Gatekeeper; a
claim that does not verify is its own state — never safe, high (critical for a startup item) —
in listeners and startup items; a check that could not run is not safe either and is retried.

The verifier moved into the core (``kernel/code_signing``, Amos 2026-11-21); Blackbox Desktop's
process verdicts and File Shield import it from there and keep their own tests.
"""

from __future__ import annotations

import pytest

from plugins.blackbox.kernel import code_signing as signing
from plugins.blackbox.shields.network.monitor import exposure, signature

APPLE_DISPLAY = "Executable=/usr/bin/true\nAuthority=Software Signing\nAuthority=Apple Code Signing Certification Authority\nAuthority=Apple Root CA\nTeamIdentifier=not set\n"
DEVID_DISPLAY = ("Executable=/Applications/Brave.app/Contents/MacOS/Brave\nAuthority=Developer ID Application: Brave Software, Inc. (KL8N8XSYF4)\n"
                 "Authority=Developer ID Certification Authority\nAuthority=Apple Root CA\nTeamIdentifier=KL8N8XSYF4\n")


def runner(intact=0, requirement=0, spctl=(0, "accepted\nsource=Notarized Developer ID\n"), timeout=False):
    """A fake tool runner: codesign --verify --strict → *intact*, -R=… → *requirement*, spctl → *spctl*."""
    calls = []

    def run(command):
        calls.append(command)
        if timeout:
            return None
        if command[0] == signing.SPCTL:
            return spctl
        if any(part.startswith("-R=") for part in command):
            return requirement, "" if requirement == 0 else "test-requirement: code failed to satisfy specified code requirement(s)"
        return intact, "" if intact == 0 else "a sealed resource is missing or invalid"
    run.calls = calls
    return run


@pytest.fixture(autouse=True)
def clean():
    signature.forget()
    yield
    signature.forget()


@pytest.fixture()
def program(tmp_path):
    path = tmp_path / "prog"
    path.write_bytes(b"\xcf\xfa\xed\xfe" + b"\0" * 64)
    return str(path)


def test_a_real_apple_signature_verifies_against_anchor_apple(program):
    run = runner()
    found = signature.verified(program, signature.parse(APPLE_DISPLAY), run)
    assert found.kind == "apple"
    assert [part for part in run.calls[1] if part.startswith("-R=")] == ["-R=anchor apple"]


def test_a_self_signed_certificate_named_software_signing_is_invalid(program):
    found = signature.verified(program, signature.parse(APPLE_DISPLAY), runner(requirement=3))
    assert (found.kind, found.claimed) == ("invalid", "apple")


def test_a_binary_changed_after_signing_is_invalid(program):
    found = signature.verified(program, signature.parse(DEVID_DISPLAY), runner(intact=1))
    assert found.kind == "invalid" and found.claimed == "developer_id"


def test_a_fake_developer_id_is_never_rated_safe_or_low(program, monkeypatch):
    found = signature.verified(program, signature.parse(DEVID_DISPLAY), runner(requirement=3))
    monkeypatch.setattr(signature, "lookup", lambda _path: found)
    risk, why, _sig = exposure.judge("/Applications/Brave.app/Contents/MacOS/Brave")
    assert risk == "high" and "does not verify" in why
    assert exposure.judge("/Applications/Brave.app/Contents/MacOS/Brave", startup=True)[0] == "critical"


def test_notarisation_comes_from_gatekeeper_not_the_display(program):
    notarised = signature.verified(program, signature.parse(DEVID_DISPLAY + "Notarization Ticket=stapled\n"),
                                   runner(spctl=(0, "accepted\nsource=Developer ID\n")))
    assert notarised.kind == "developer_id" and notarised.notarised is False
    signature.forget()
    real = signature.verified(program, signature.parse(DEVID_DISPLAY), runner())
    assert real.notarised is True


def test_a_check_that_could_not_run_is_unknown_never_safe_and_is_retried(program):
    found = signature.verified(program, signature.parse(APPLE_DISPLAY), runner(timeout=True))
    assert found.kind == "unknown"
    again = runner()
    assert signature.verified(program, signature.parse(APPLE_DISPLAY), again).kind == "apple"   # not cached
    assert again.calls


def test_an_answer_is_cached_per_program_version(program):
    run = runner()
    signing.verify(program, "apple", run)
    signing.verify(program, "apple", run)
    assert len(run.calls) == 2   # strict + requirement, once
