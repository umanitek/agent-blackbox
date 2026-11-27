"""The host-length bound reads the normalised kind (review 2026-11-26, finding 12, Low).

``ioc_value_is_well_formed`` tested the raw ``ioc_type`` for ``"domain"``, so ``" Domain"`` — a
spelling every other line of it normalises — skipped DNS's 253-character bound.
"""

from __future__ import annotations

from plugins.blackbox.kernel.threat_ids import ioc_value_is_well_formed


def test_a_too_long_domain_is_refused_in_any_spelling_of_its_kind():
    long_host = ".".join(["a" * 60] * 5) + ".com"   # 309 characters
    assert not ioc_value_is_well_formed("domain", long_host)
    assert not ioc_value_is_well_formed(" Domain", long_host)
    assert ioc_value_is_well_formed(" Domain", "evil.example")
