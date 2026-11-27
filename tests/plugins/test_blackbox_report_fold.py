"""Copies of a statement fold per AUTHOR, so nobody can squat another reporter's subject (review 2026-11-26, finding 8).

A report's subject is ``report_uri(identifier, reporter)`` and the reporter
address is self-described (display only): it is never tied to the signing key.
The reader folded statements by subject, first seen kept, BEFORE keying on the
author — so a report signed by another key under the same reporter address,
read first, displaced the genuine one. The fold is now on (subject, author):
epoch copies of one author's statement still fold to one (KI-207), and a
squatter's copy is just the squatter's own report.
"""

from __future__ import annotations

from _community_rows import NETWORK, GRAPH, Reporter, signed_row
from plugins.blackbox import community

EVIL = "dep:npm:evil-pkg@1.0.0"


def _verified(rows):
    reports, _dropped = community.verify_report_rows(rows, community.ReportVerifier(NETWORK, GRAPH))
    return reports


def test_a_squatter_read_first_never_displaces_the_genuine_report():
    victim = Reporter("edge-1")
    squatter = Reporter(victim.address)          # same reporter address, its own key
    assert squatter.author != victim.author
    reports = _verified([signed_row(EVIL, squatter), signed_row(EVIL, victim)])
    assert victim.author in {report.author for report in reports}
    assert len({report.subject for report in reports}) == 1   # it really is the same subject


def test_an_epoch_copy_of_one_authors_report_still_folds_to_one():
    reporter = Reporter("edge-1")
    row = signed_row(EVIL, reporter)
    assert len(_verified([row, dict(row)])) == 1
