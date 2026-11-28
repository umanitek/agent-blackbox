"""A community rule never shadows a verified one, in every rule table (``ruleset.compiler.build_from_rows``;
external static review of 1.7.1, 2026-11-28, recorded privately per SECURITY.md §3.1).

The compiler's contract was "public beats community" but only the ``ioc`` and ``dependency`` tables
kept it; ``injection``, ``escalation``, ``fileaccess`` and ``skill`` kept the first row seen, so a
community row before a public one with the same key left the warn-only rule in force. Today only
verified rows reach this compile, so it was not reachable; the invariant now holds whatever the
order. Red on 7e2470de18.
"""

from __future__ import annotations

import pytest

from plugins.blackbox.ruleset import compiler, row_adapters


@pytest.fixture
def mapped(monkeypatch):
    """Rows that are already (category, key, rule): the adapter's job is not under test here."""
    monkeypatch.setattr(row_adapters, "_row_to_graph_entry", lambda row, source: None)
    monkeypatch.setattr(row_adapters, "_row_to_rule", lambda row, source: (row["category"], row["key"], {**row["rule"], "source": source}))


@pytest.mark.parametrize("category", ["injection", "escalation", "fileaccess", "skill", "ioc", "dependency"])
def test_a_public_rule_wins_over_a_community_one_with_the_same_key(mapped, category):
    community = {"category": category, "key": "k", "rule": {"name": "community", "confirmed": False}}
    public = {"category": category, "key": "k", "rule": {"name": "public", "confirmed": True}}
    other = {"category": category, "key": "other", "rule": {"name": "other", "confirmed": False}}
    for rows in ([(community, "community"), (public, "public"), (other, "community")],
                 [(public, "public"), (community, "community"), (other, "community")]):
        rs = compiler.build_from_rows(rows)
        table = getattr(rs, category)
        rules = list(table.values()) if isinstance(table, dict) else table
        assert [rule["name"] for rule in rules] == ["public", "other"], rows
