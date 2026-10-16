"""Community Curation C3 — trust is looked up by identifier and kept by the reader.

The verified authority's advisory statements (confirmations, rejections,
attestations and its notices) live in the verified graph's shared memory, where
the community's reports live (one graph since 2026-10-16). That memory is open:
anyone can publish beside a curator's statement (same subject, same asset name —
bench 2026-10-03), it forgets after about 30 days, and a busy node answers
"nothing". So:

* trust statements are fetched by EXACT LOOKUP on the identifiers the reader
  holds, never by an ordered scan;
* what was verified is kept in ``$BLACKBOX_HOME/community_trust.json`` and
  re-verified on every load — the state of record;
* a statement that is merely absent from a read stays; a verdict ends only by
  a newer one.

The authority's manifest and its enforcement statements (listings, revocations,
pauses) are in Verified Memory and read by scan, as before. Each test drives one
attack or one rule. The fake node answers lookups the way a triple store does
(it filters on the VALUES the query names) and records every query it is sent.
"""

from __future__ import annotations

import json
import re

import pytest
from _community_rows import GRAPH, NETWORK, Reporter, signed_row
from test_blackbox_authority import CFG, CITED, Side, THREAT, TODAY, VM_GRAPH
from test_blackbox_curator_view import _entry

from plugins.blackbox.community import read_curator_view, read_verified_reports
from plugins.blackbox.community.statements import curator_view as cv
from plugins.blackbox.community.trust import bounded_read, trust_store
from plugins.blackbox.kernel import sparql_text
from plugins.blackbox.kernel.signing.statement_order import CuratorStatement as Kind

SHARED = "shared-working-memory"
OTHER = "ioc:domain:other.example"


@pytest.fixture(autouse=True)
def home(monkeypatch, tmp_path):
    monkeypatch.setenv("BLACKBOX_HOME", str(tmp_path / "bbhome"))
    monkeypatch.delenv("BLACKBOX_CURATOR_ROOT_KEYS", raising=False)
    monkeypatch.delenv("BLACKBOX_COMMUNITY_ROOT_KEYS", raising=False)
    monkeypatch.setattr(cv, "_today", lambda: TODAY)


@pytest.fixture
def curators(monkeypatch):
    """The verified authority: its root trusted, its manifest in Verified Memory."""
    side = Side(VM_GRAPH)
    monkeypatch.setenv("BLACKBOX_CURATOR_ROOT_KEYS", side.root_hex)
    return side


class Store:
    """A node that answers like a triple store: a lookup returns only the rows
    whose identifier (or subject) the query's VALUES names. ``shared`` rows are in
    the shared memory, ``verified`` ones in Verified Memory. ``failing`` makes every
    shared-memory query fail; ``slow_empty`` makes it answer empty after a
    timeout-length wait (the measured behaviour of a busy node)."""

    def __init__(self, shared=(), reports=(), verified=()):
        self.rows = {SHARED: list(shared), "verified": list(verified)}
        self.reports = list(reports)
        self.queries = []   # (memory, sparql)
        self.failing = False
        self.failing_statements = False   # only the curator-statement lookups fail
        self.slow_empty = None    # a Clock to advance, or None

    def status(self):
        return {"networkId": NETWORK}

    def context_graphs(self):
        return [{"id": GRAPH, "subscribed": True, "synced": True}]

    def query(self, sparql, cg_id, view=None, on_error=None, **kw):
        memory = SHARED if view == SHARED else "verified"
        self.queries.append((memory, sparql))
        if memory == SHARED and (self.failing or (self.failing_statements and "g:CuratorStatement" in sparql)):
            return on_error
        if memory == SHARED and self.slow_empty is not None:
            self.slow_empty.now += 10.4
            return []
        if "g:ThreatReport" in sparql:
            return list(self.reports) if memory == SHARED and "COUNT" not in sparql else []
        rows = self.rows[memory]
        if "g:CuratorStatement" in sparql:
            wanted = set(re.findall(r'"((?:[^"\\]|\\.)*)"', sparql.split("VALUES ?identifier", 1)[1].split("}", 1)[0])) \
                if "VALUES ?identifier" in sparql else None
            return [r for r in rows if "curator:" in r["r"] and (wanted is None or r.get("identifier") in wanted)]
        if "VALUES ?r" in sparql:
            subjects = set(re.findall(r"<([^>]+)>", sparql.split("VALUES ?r", 1)[1].split("}", 1)[0]))
            return [r for r in rows if r["r"] in subjects]
        if "g:KeyManifest" in sparql:
            return [r for r in rows if "key-manifest" in r["r"]]
        return []


def _node(curators, *shared, verified=(), reports=()):
    """A node holding the verified manifest (and *verified*) in Verified Memory, *shared* in the shared memory."""
    return Store(shared=shared, reports=reports, verified=[curators.manifest_row(), *verified])


def _rejection(side, identifier=THREAT, sequence=1):
    return side.row(Kind.REJECTION, identifier, {"reason": "benign"}, sequence=sequence)


def _view(node, *reporters, threats=()):
    return read_curator_view(node, CFG, interest=[*(f"author:{r.author}" for r in reporters), *threats])


# ------------------------------------------------------------------ lookups, never scans


def test_trust_statements_are_looked_up_by_identifier_without_ordering(curators):
    alice = Reporter("0xa")
    node = _node(curators, _rejection(curators))
    assert _view(node, alice, threats=[THREAT]).rejected(THREAT)
    statement_queries = [q for memory, q in node.queries if memory == SHARED and "g:CuratorStatement" in q]
    assert statement_queries and all("VALUES ?identifier" in q and "ORDER BY" not in q for q in statement_queries)
    asked = "".join(statement_queries)
    assert f'"author:{alice.author}"' in asked and f'"{THREAT}"' in asked and '"curator"' in asked
    assert all("ORDER BY" not in q for memory, q in node.queries if memory == SHARED)


def test_a_threat_nobody_asked_about_is_not_fetched(curators):
    """A lookup, not a scan: the node is only asked about identifiers the reader holds."""
    view = _view(_node(curators, _rejection(curators), _rejection(curators, OTHER)), threats=[THREAT])
    assert view.rejected(THREAT) and view.verdict(OTHER) is None


def test_many_identifiers_are_asked_in_batches_and_capped(curators):
    node = _node(curators)
    read_curator_view(node, CFG, interest=[f"ioc:ip:10.0.{i // 250}.{i % 250}" for i in range(250)])
    statement_queries = [q for memory, q in node.queries if memory == SHARED and "g:CuratorStatement" in q]
    assert len(statement_queries) == 3                                   # 251 identifiers / 100 per query
    found = bounded_read.lookup_statements(Store(), GRAPH, (f"x:{i}" for i in range(bounded_read.MAX_IDENTIFIERS + 500)))
    assert found.complete and found.rows == ()


def test_an_identifier_is_escaped_before_it_enters_a_query():
    hostile = 'x" } ?s ?p ?o . # '
    assert sparql_text.sparql_string_literal(hostile) in bounded_read.statements_sparql([hostile])


def test_the_reader_asks_about_the_reporters_and_threats_it_holds(curators):
    alice = Reporter("0xa")
    listing = curators.row(Kind.COUNTED_AUTHORS, f"author:{alice.author}", _entry(alice.author))
    node = _node(curators, verified=[listing], reports=[signed_row("ioc:ip:203.0.113.7", alice)])
    read = read_verified_reports(node, CFG)
    assert alice.author in read.curator.counted                          # the listing, from Verified Memory
    asked = "".join(q for memory, q in node.queries if memory == SHARED and "g:CuratorStatement" in q)
    assert f'"author:{alice.author}"' in asked and '"ioc:ip:203.0.113.7"' in asked


# ------------------------------------------------------------------ junk beside the genuine statement


def test_junk_carrying_a_genuine_identifier_is_dropped_and_the_genuine_statement_honoured(curators):
    """KI-250: a second node can publish under the same subject and identifier."""
    genuine = _rejection(curators)
    impostor = Side(VM_GRAPH)                                             # other keys, same identifier, same subject
    forged = dict(impostor.row(Kind.CONFIRMATION, THREAT, CITED, sequence=9), r=genuine["r"])
    garbage = {"r": genuine["r"], "identifier": genuine["identifier"], "signedStatement": "not an envelope"}
    view = _view(_node(curators, forged, garbage, genuine), threats=[THREAT])
    assert view.rejected(THREAT) and view.verdict(THREAT) is Kind.REJECTION


def test_a_flooded_lookup_is_incomplete_and_changes_nothing_already_verified(curators):
    """KI-241: a lookup that reaches its row limit proves nothing about what is missing."""
    assert _view(_node(curators, _rejection(curators)), threats=[THREAT]).rejected(THREAT)   # verified once, now stored
    junk = [{"r": f"urn:guardian:curator:junk:{i}", "identifier": THREAT, "signedStatement": f"junk-{i}"}
            for i in range(bounded_read.LOOKUP_ROW_LIMIT)]
    flooded = _node(curators, *junk)                                       # the genuine row is crowded out
    assert not bounded_read.lookup_statements(flooded, GRAPH, [THREAT]).complete
    view = _view(flooded, threats=[THREAT])
    assert view.rejected(THREAT) and not view.unavailable


# ------------------------------------------------------------------ the store is the state of record


def test_a_rejection_outlives_its_network_copy(curators):
    """KI-251: a rejection that lapsed from shared memory must not let the reports count again."""
    assert _view(_node(curators, _rejection(curators)), threats=[THREAT]).rejected(THREAT)
    assert _view(_node(curators), threats=[THREAT]).rejected(THREAT)       # the shared memory forgot it


def test_an_old_verdict_replayed_after_a_newer_one_is_ignored(curators):
    confirmation = curators.row(Kind.CONFIRMATION, THREAT, CITED, sequence=1)
    assert _view(_node(curators, confirmation, _rejection(curators, sequence=2)), threats=[THREAT]).rejected(THREAT)
    view = _view(_node(curators, confirmation), threats=[THREAT])          # only the OLD statement is on the network now
    assert view.rejected(THREAT) and view.verdict(THREAT) is Kind.REJECTION


def test_a_node_that_times_out_with_empty_answers_changes_nothing(monkeypatch, curators):
    """KI-262: the measured behaviour of a busy node — empty, after ten seconds."""
    from test_blackbox_trust_read import Clock
    clock = Clock()
    monkeypatch.setattr(sparql_text.time, "monotonic", clock)
    before = _view(_node(curators, _rejection(curators)), threats=[THREAT])
    busy = _node(curators)
    busy.slow_empty = clock
    after = _view(busy, threats=[THREAT])
    assert before.rejected(THREAT) and after.rejected(THREAT) and not after.unavailable


def test_first_contact_that_cannot_look_is_unavailable_not_empty(curators):
    """KI-244: with nothing stored, a failed lookup means "unknown", so readers keep last good."""
    node = _node(curators)
    node.failing = True
    assert read_curator_view(node, CFG).unavailable


def test_a_known_manifest_with_unreadable_statements_is_unavailable_on_first_contact(curators):
    """The manifest is found, the statement lookup fails and nothing is stored: this node does not
    know what the curators said, which is not the same as "they said nothing"."""
    node = _node(curators, _rejection(curators))
    node.failing_statements = True
    view = _view(node, threats=[THREAT])
    assert view.unavailable and not view.rejected(THREAT)
    node.failing_statements = False
    assert _view(node, threats=[THREAT]).rejected(THREAT)                  # and it recovers on the next good read


def test_the_stored_file_is_verified_again_on_every_load(tmp_path, curators):
    node = _node(curators, _rejection(curators))
    assert _view(node, threats=[THREAT]).rejected(THREAT)
    path = tmp_path / "bbhome" / "community_trust.json"
    data = json.loads(path.read_text(encoding="utf-8"))
    entry = data["graphs"][GRAPH]
    forged = dict(_rejection(Side(VM_GRAPH), OTHER))                      # signed by keys no root vouches for
    entry["statements"].append({"r": forged["r"], "identifier": forged["identifier"], "signedStatement": forged["signedStatement"]})
    assert '"reason":"benign"' in entry["statements"][0]["signedStatement"]
    entry["statements"][0]["signedStatement"] = entry["statements"][0]["signedStatement"].replace('"reason":"benign"', '"reason":"edited"')
    path.write_text(json.dumps(data), encoding="utf-8")
    view = _view(_node(curators), threats=[THREAT, OTHER])
    assert view.verdict(OTHER) is None                                    # a hand-added rejection verifies under no manifest
    assert not view.rejected(THREAT)                                      # the edited statement fails its signature: it adds nothing
    assert _view(node, threats=[THREAT]).rejected(THREAT)                 # and the network restores the genuine one


def test_an_unwritable_or_unreadable_store_never_breaks_the_read(tmp_path, curators):
    """The fail-open path, run for real: the store file's place is taken by a directory."""
    (tmp_path / "bbhome" / "community_trust.json").mkdir(parents=True)
    assert _view(_node(curators, _rejection(curators)), threats=[THREAT]).rejected(THREAT)
    assert trust_store.TrustStore().load(GRAPH) == trust_store.StoredTrust()


def test_a_keep_alive_copy_of_a_statement_counts_once(curators):
    away = curators.row(Kind.AWAY, "curator", {"key": curators.manifest.curator_keys[0], "from": "2026-10-02", "until": "2026-10-09"},
                        signers=1)
    view = read_curator_view(_node(curators, away, dict(away), dict(away)), CFG)
    assert len(view.away) == 1
    assert len(trust_store.TrustStore().load(GRAPH).statements) == 1


def test_only_the_newest_statement_per_kind_and_identifier_is_kept(curators):
    rows = [curators.row(Kind.ATTESTATION, THREAT, {"stage": stage}, sequence=number)
            for number, stage in ((1, "held"), (2, "corroborated"), (3, "held"))]
    assert _view(_node(curators, *rows), threats=[THREAT]).attestation(THREAT).field("stage") == "held"
    stored = trust_store.TrustStore().load(GRAPH)
    assert len(stored.statements) == 1 and stored.identifiers == [THREAT]
    assert stored.admitted == {}            # the verified authority's word never waits behind the raising cap


def test_statements_signed_long_ago_are_pruned():
    side = Side(GRAPH)
    row = side.row(Kind.CONFIRMATION, THREAT, CITED)                          # signed 2026-10-02
    assert trust_store.current_statements([row], "2027-10-01")             # 364 days: kept
    assert trust_store.current_statements([row], "2028-06-01") == []       # past MAX_STATEMENT_AGE_DAYS


# ------------------------------------------------------------------ manifests


def test_the_next_manifest_subjects_follow_the_newest_known_one():
    assert bounded_read.next_manifest_subjects([])[:2] == ["urn:guardian:key-manifest:0:1", "urn:guardian:key-manifest:0:2"]
    probes = bounded_read.next_manifest_subjects([(1, 3), (1, 2)])
    assert probes[0] == "urn:guardian:key-manifest:1:4" and "urn:guardian:key-manifest:2:1" in probes
