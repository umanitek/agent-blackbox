"""``kernel.sparql_text.page_rows`` reads a statement list whole or says it could not (review 2026-11-26, finding 4).

DKG daemons cap a reply below the LIMIT asked for (KI-052: 5,000 asked, 1,000
returned). The pager used to stop at the first page shorter than its page
size, so community reports, curator statements (revocations), key manifests,
kill lists and promotions were silently cut at 1,000 rows. It now pages until
an EMPTY page, and a read stopped by its row ceiling is None (could not tell),
never a partial list passed off as complete.
"""

from __future__ import annotations

from plugins.blackbox.kernel import sparql_text

DAEMON_CAP = 1000


class _CappingNode:
    """Holds *count* statement rows ``r`` = s00000…; answers rows after the cursor, at most DAEMON_CAP."""

    def __init__(self, count: int) -> None:
        self.subjects = [f"urn:s:{index:05d}" for index in range(count)]
        self.asked = 0

    def query(self, sparql, _graph, *, view=None, on_error=None):
        self.asked += 1
        after = sparql   # the test's query builder sends just the cursor
        return [{"r": subject} for subject in self.subjects if subject > after][:DAEMON_CAP]


def _read(node, **kwargs):
    return sparql_text.page_rows(node, "graph", "view", lambda after: after, **kwargs)


def test_a_daemon_capped_reply_is_not_the_end_of_the_list():
    node = _CappingNode(2500)
    rows = _read(node, page_size=5000)
    assert [row["r"] for row in rows] == node.subjects          # all 2,500, not the first 1,000


def test_a_read_stopped_by_its_row_ceiling_could_not_tell():
    assert _read(_CappingNode(2500), page_size=5000, max_rows=2000) is None


def test_an_empty_graph_is_an_empty_list_and_a_short_list_reads_whole():
    assert _read(_CappingNode(0)) == []
    node = _CappingNode(3)
    assert [row["r"] for row in _read(node)] == node.subjects


def test_a_page_that_repeats_the_last_one_adds_no_duplicates():
    class _IgnoresCursor:
        def query(self, sparql, _graph, *, view=None, on_error=None):
            return [{"r": "urn:s:1"}, {"r": "urn:s:2"}]

    assert [row["r"] for row in _read(_IgnoresCursor())] == ["urn:s:1", "urn:s:2"]
