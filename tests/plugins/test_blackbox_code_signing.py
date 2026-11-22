"""Who signed a program, held to what it claims (plugins/blackbox/kernel/code_signing).

Contracts: a program's signer is believed only when its signature verifies; one that names a
signer and does not verify is ``invalid``; a script has nothing to sign; a link is followed to the
program it names; a tool that cannot run leaves the answer ``unknown`` — never "verified".
Amos, 2026-11-22: an agent profile shows facts read from the system, "nothing made up".
"""

from __future__ import annotations

import os

from plugins.blackbox.kernel import code_signing

DEVELOPER = ("Executable=/x/claude\nAuthority=Developer ID Application: Anthropic PBC (Q6L2SF6YDW)\n"
             "Authority=Developer ID Certification Authority\nAuthority=Apple Root CA\nTeamIdentifier=Q6L2SF6YDW\n")
ADHOC = "Executable=/x/tool\nSignature=adhoc\nTeamIdentifier=not set\n"


def _run(display: str, verifies: bool = True):
    """A stand-in for codesign / spctl: ``-dv`` shows *display*; ``--verify`` passes or fails."""
    def run(command):
        if "-dv" in command:
            return 1 if "not signed" in display else 0, display
        if "--verify" in command:
            return (0, "") if verifies else (1, "invalid signature (code or signature have been modified)")
        return 3, "rejected"
    return run


def _program(tmp_path, name="claude", content=b"\xcf\xfa\xed\xfe binary"):
    path = tmp_path / name
    path.write_bytes(content)
    return str(path)


def test_a_signer_is_named_only_when_the_signature_verifies(tmp_path):
    code_signing.forget()
    found = code_signing.describe(_program(tmp_path), _run(DEVELOPER))
    assert (found.kind, found.signer, found.team, found.verified) == ("developer_id", "Anthropic PBC (Q6L2SF6YDW)", "Q6L2SF6YDW", True)


def test_a_claimed_signer_that_does_not_verify_is_invalid(tmp_path):
    code_signing.forget()
    found = code_signing.describe(_program(tmp_path), _run(DEVELOPER, verifies=False))
    assert (found.kind, found.verified) == ("invalid", False) and found.signer.startswith("Anthropic")


def test_ad_hoc_unsigned_and_scripts_claim_nothing(tmp_path):
    code_signing.forget()
    assert code_signing.describe(_program(tmp_path), _run(ADHOC)).kind == "adhoc"
    assert code_signing.describe(_program(tmp_path, "b"), _run("/x/b: code object is not signed at all")).kind == "unsigned"
    script = _program(tmp_path, "codex", b"#!/usr/bin/env node\nrequire('./cli')\n")
    assert code_signing.describe(script, _run(DEVELOPER)) == code_signing.Signer(kind="script")


def test_a_link_is_followed_to_the_program_it_names(tmp_path):
    code_signing.forget()
    real = _program(tmp_path, "real-binary")
    link = tmp_path / "claude"
    os.symlink(real, link)
    asked = []

    def run(command):
        asked.append(command[-1])
        return _run(DEVELOPER)(command)

    assert code_signing.describe(str(link), run).verified is True
    assert set(asked) == {os.path.realpath(real)}


def test_a_tool_that_cannot_run_never_reads_as_verified(tmp_path):
    code_signing.forget()
    assert code_signing.describe(_program(tmp_path), lambda command: None) == code_signing.Signer(kind="unknown")
    assert code_signing.describe(str(tmp_path / "gone"), _run(DEVELOPER)).kind == "unknown"


def test_a_programs_answer_is_kept_per_version_and_a_timeout_is_not_asked_again_at_once(tmp_path):
    """KI-584: an agent's profile page stayed blank ~5 s on EVERY open — Gatekeeper's check timed
    out and a timeout was never kept, so each open waited for it again."""
    code_signing.forget()
    program = _program(tmp_path)
    asked = []

    def slow(command):   # every tool times out (answers None)
        asked.append(command)

    assert code_signing.described(program) is None   # nothing checked yet: a page does not wait
    assert code_signing.describe(program, slow).kind == "unknown"
    calls = len(asked)
    assert code_signing.describe(program, slow).kind == "unknown" and len(asked) == calls   # kept for a while
    assert code_signing.described(program) == code_signing.Signer(kind="unknown")
    code_signing.forget()
    assert code_signing.describe(program, _run(DEVELOPER)).verified is True
    with open(program, "ab") as handle:   # a new version of the program is checked again
        handle.write(b"changed")
    assert code_signing.describe(program, _run(DEVELOPER, verifies=False)).kind == "invalid"
