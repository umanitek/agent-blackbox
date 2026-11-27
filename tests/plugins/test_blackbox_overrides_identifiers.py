"""A local override is keyed on one canonical identifier for every store operation, and the guard
reads the overrides once per judgement (``overrides.store`` / ``guard.hooks``; review findings of
2026-11-26).

* ``unblock()`` saved the identifier trimmed while ``reblock()`` and ``is_unblocked()`` looked the
  raw text up: an override set with a stray space could not be taken back the same way.
* ``_blocking`` and ``_overridden`` each recomputed the would-block findings and re-read
  ``overrides.json`` for one call.
"""

from __future__ import annotations

from plugins.blackbox import overrides
from plugins.blackbox.detection import Finding
from plugins.blackbox.guard import hooks
from plugins.blackbox.kernel.config import BlackboxConfig

THREAT = "dep:npm:evil@1.0.0"


def _finding():
    return Finding(identifier=THREAT, category="dependency", severity="critical", title="evil", confirmed=True,
                   source="public", kind="malware")


def test_every_store_operation_uses_the_same_canonical_identifier(tmp_path):
    store = overrides.OverrideStore(tmp_path / "overrides.json")
    store.unblock(f"  {THREAT} ", "false positive")
    assert store.is_unblocked(f"{THREAT} ") and store.is_unblocked(THREAT)
    assert store.reblock(f" {THREAT}") and not store.is_unblocked(THREAT)


def test_one_judgement_reads_the_overrides_once(tmp_path, monkeypatch):
    monkeypatch.setenv("BLACKBOX_HOME", str(tmp_path / "bb"))
    overrides.OverrideStore().unblock(THREAT, "known good")
    reads: list = []
    real = overrides.OverrideStore.unblocked
    monkeypatch.setattr(overrides.OverrideStore, "unblocked", lambda self: reads.append(1) or real(self))
    cfg = BlackboxConfig(mode="block", block_severity="critical")
    blocking, demoted = hooks._split(cfg, [_finding()])
    assert (blocking, [f.identifier for f in demoted]) == ([], [THREAT]) and len(reads) == 1
    assert hooks._decision(cfg, [_finding()], blocking, demoted) == "flag (local override)" and len(reads) == 1
