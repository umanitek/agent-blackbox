"""The hook runner's "am I inside the sandbox?" answer (``agent_hooks/protect/identity.inside_sandbox``).

Engine sweep 2026-11-27: any PermissionError reading the canary counted as "inside", so a
``chmod 000`` on the canary — outside any sandbox — marked every session as sandboxed. The hook
now applies the same rule as ``shields.files.sandbox.proven``.
"""

from __future__ import annotations

import os

import pytest

from plugins.blackbox.agent_hooks.protect.identity import inside_sandbox


def test_a_readable_canary_is_outside(tmp_path):
    canary = tmp_path / "canary"
    canary.write_text("x", encoding="utf-8")
    assert inside_sandbox(canary) is False


@pytest.mark.skipif(os.geteuid() == 0, reason="root reads a mode-0000 file")
def test_a_canary_made_unreadable_by_its_own_mode_is_not_proof_of_the_sandbox(tmp_path):
    canary = tmp_path / "canary"
    canary.write_text("x", encoding="utf-8")
    canary.chmod(0)
    try:
        assert inside_sandbox(canary) is False
    finally:
        canary.chmod(0o644)


def test_a_missing_canary_or_folder_is_outside(tmp_path):
    assert inside_sandbox(tmp_path / "canary") is False
    assert inside_sandbox(tmp_path / "gone" / "canary") is False
