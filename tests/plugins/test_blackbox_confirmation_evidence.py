"""Community Curation C8 — a community confirmation carries its evidence.

The confirmed pool is the hand-off to the verified graph's owner; without a
signed reference to what the curators checked it would be a list of opinions.
So: the reference has a closed format; the curator verbs refuse to sign a
community confirmation without one; and the verified authority's confirmations
stay exactly as shipped.

One graph (2026-10-16): there are no community curators for now, so the
community authority is dormant and no community confirmation counts on a
reader, evidenced or not (``test_blackbox_authority``).
"""

from __future__ import annotations

import pytest
from _community_rows import GRAPH
from test_blackbox_authority import CFG, THREAT, VM_GRAPH, Graphs, Side

from plugins.blackbox.community import EVIDENCE_REFERENCE, read_curator_view
from plugins.blackbox.community.statements import curator_statements as cs
from plugins.blackbox.community.statements import curator_view as cv
from plugins.blackbox.curate import dossier, verbs
from plugins.blackbox.curate.proposal import ProposalStore
from plugins.blackbox.kernel import signing
from plugins.blackbox.kernel.signing.authority import Authority
from plugins.blackbox.kernel.signing.statement_order import CuratorStatement as Kind

SHA = "ab" * 32


@pytest.fixture(autouse=True)
def home(monkeypatch, tmp_path):
    monkeypatch.setenv("BLACKBOX_HOME", str(tmp_path / "bbhome"))
    monkeypatch.delenv("BLACKBOX_CURATOR_ROOT_KEYS", raising=False)
    monkeypatch.delenv("BLACKBOX_COMMUNITY_ROOT_KEYS", raising=False)


# ------------------------------------------------------------------ the closed format


@pytest.mark.parametrize("reference", [
    "advisory:MAL-2026-0001", "advisory:GHSA-abcd-1234-wxyz", f"reproduced:{SHA}",
    "registry-action:https://registry.npmjs.org/-/advisories/1234?x=1",
])
def test_the_three_kinds_of_evidence_reference_can_be_signed(reference):
    side = Side(GRAPH)
    record = cs.parse_statement(side.row(Kind.CONFIRMATION, THREAT, {"evidence": reference}), side.manifest, graph=GRAPH)
    assert record is not None and record.field("evidence") == reference


@pytest.mark.parametrize("fields", [
    {"evidence": "I looked at it and it is bad"},                       # free text
    {"evidence": "advisory:"},                                          # no id
    {"evidence": f"reproduced:{SHA.upper()}"},                          # not a lowercase sha256
    {"evidence": "registry-action:ftp://registry.example/x"},           # not http(s)
    {"evidence": "registry-action:https://registry.example/a b"},       # a space
    {"evidence": "registry-action:https://registry.example/\x1b[31m"},  # a control character
    {"evidence": 'registry-action:https://registry.example/"><script>'},
    {"evidence": "advisory:MAL-2026-0001", "note": "extra"},            # a second field
    {"note": "advisory:MAL-2026-0001"},                                 # the wrong field name
])
def test_anything_outside_the_closed_format_cannot_be_signed(fields):
    side = Side(GRAPH)
    with pytest.raises(ValueError, match="not a valid blackbox.confirmation"):
        side.row(Kind.CONFIRMATION, THREAT, fields)


def test_the_curators_checklist_and_the_signed_field_share_one_format():
    assert dossier._EVIDENCE is EVIDENCE_REFERENCE
    spaced = dossier.checklist("dep:npm:evil@1.0.0", kind="malware", evidence="registry-action:https://x.example/a b", reason="")
    assert not spaced[0].ok


# ------------------------------------------------------------------ what a reader counts: the verified authority's


def test_the_verified_authoritys_confirmation_is_unchanged_and_needs_no_evidence(monkeypatch):
    """Every shipped reader accepts the verified authority's confirmation as it always was."""
    side = Side(VM_GRAPH)
    monkeypatch.setenv("BLACKBOX_CURATOR_ROOT_KEYS", side.root_hex)
    node = Graphs(verified=[side.manifest_row()], community=[side.row(Kind.CONFIRMATION, THREAT, {}, graph=GRAPH)])
    assert read_curator_view(node, CFG).verdict(THREAT) is Kind.CONFIRMATION
    view = cv.build_view(side.manifest, [], [side.row(Kind.CONFIRMATION, THREAT, {}, graph=GRAPH)],
                         verified_graph=VM_GRAPH, community_graph=GRAPH, authority=Authority.VERIFIED)
    assert view.verdict(THREAT) is Kind.CONFIRMATION


# ------------------------------------------------------------------ what a curator may sign


def test_the_verified_authoritys_confirmation_verb_signs_no_evidence_field(tmp_path, monkeypatch):
    """Shipped readers refuse a confirmation with extra fields, so the verified authority's stays bare."""
    side = Side(VM_GRAPH)
    monkeypatch.setenv("BLACKBOX_CURATOR_ROOT_KEYS", side.root_hex)
    view = read_curator_view(Graphs(verified=[side.manifest_row()]), CFG)
    from _community_rows import NETWORK
    from plugins.blackbox.curate.context import CurateContext
    ctx = CurateContext(cfg=CFG, client=Graphs(verified=[side.manifest_row()]), environment=NETWORK, view=view, sandbox=True,
                        compiled=None, authority=Authority.VERIFIED)
    proposal = verbs.propose_statement(ctx, ProposalStore(), kind=Kind.CONFIRMATION, identifier=THREAT, fields={},
                                       evidence="advisory:MAL-2026-0001")
    assert "evidence" not in signing.from_text(proposal.envelope).payload
