"""SPARQL helpers shared by every reader of the graph.

* :func:`sparql_string_literal` — THE escaper for any value interpolated into
  a query (never hand-escape at a call site).
* ``MAX_ROWS`` — the hard ceiling on rows any paged read may collect.
* :func:`query_rows` — ONE query whose answer can be believed: None when it
  failed or came back empty after a timeout-length wait (a node answers a
  timed-out query with an empty result, not an error — KI-262).
* :func:`page_rows` — the cursor pager every statement read uses (bounded
  pages, hard row ceiling, None when any page fails).
* :func:`extract_binding` / :func:`normalize_bindings` — reading the daemon's
  answers: one result cell to a plain string, any response shape to a row
  list. Re-exported by :mod:`.dkg_client` (``from ..kernel.dkg_client import
  extract_binding`` keeps working).
"""

from __future__ import annotations

import time
from typing import Any, Callable, Dict, List, Optional

from . import constants


# Safety ceiling so a misbehaving node can never spin the pager forever.
MAX_ROWS = 1_000_000


def sparql_string_literal(value: object) -> str:
    """Escape *value* as a double-quoted SPARQL string literal (KI-029).

    THE one escaping implementation for runtime strings entering SPARQL
    (cursors, identifiers, addresses). Community-graph strings are untrusted
    input that our own read pipeline re-interpolates into queries; everything
    goes through here, nothing is hand-escaped at call sites.
    """
    text = str(value or "")
    text = text.replace("\\", "\\\\").replace('"', '\\"')
    text = text.replace("\n", "\\n").replace("\r", "\\r").replace("\t", "\\t")
    return f'"{text}"'


#: Characters that end an ``<iri>`` early or are never legal inside one.
_UNSAFE_IN_IRI = frozenset('<>"{}|^`\\')


#: The ``g:`` prefix every graph query declares (the guardian ontology, ``constants.BLACKBOX_ONTOLOGY``).
GUARDIAN_PREFIX = f"PREFIX g: <{constants.BLACKBOX_ONTOLOGY}>"


def cursor_filter(after: str, variable: str = "r") -> str:
    """The FILTER that resumes a subject-ordered page after the subject *after* ("" on the first
    page): ``FILTER(STR(?r) > "<after>")``, the value escaped as a SPARQL string literal."""
    return f"FILTER(STR(?{variable}) > {sparql_string_literal(after)})" if after else ""


def is_safe_iri(value: object) -> bool:
    """Whether *value* can be written as ``<value>`` in a query: non-empty text with no
    whitespace of any kind and none of the characters that close or break the brackets.

    THE check for an address (a graph, a subject) that goes back into SPARQL. An IRI has no
    escape syntax, so an unsafe one is never repaired — the caller leaves it out. Three
    modules kept their own character set (one without the space, one with no check at all)."""
    return (isinstance(value, str) and bool(value)
            and not any(char.isspace() or char in _UNSAFE_IN_IRI for char in value))


def sparql_iri(value: object) -> str:
    """``<value>`` when *value* :func:`is_safe_iri`, else ``""`` (nothing to write)."""
    return f"<{value}>" if is_safe_iri(value) else ""


# ---------------------------------------------------------------------------
# SPARQL binding normalization
# ---------------------------------------------------------------------------


def extract_binding(value: Any) -> str:
    """Unwrap a single SPARQL binding cell to a plain string.

    Handles the SPARQL-JSON ``{"value": "..."}`` object shape as well as the
    daemon's bare-string shape (IRIs bare, literals ``"..."``, typed literals
    ``"x"^^<...>``, lang literals ``"x"@en``). Literal escapes are decoded.
    """
    if value is None:
        return ""
    if isinstance(value, dict):
        inner = value.get("value")
        return str(inner) if inner is not None else ""
    if isinstance(value, str):
        if value.startswith('"'):
            return _unquote_literal(value)
        return value
    return str(value)


#: N-Triples string escapes (ECHAR) -> the character each stands for.
_NT_ESCAPES = {"t": "\t", "b": "\b", "n": "\n", "r": "\r", "f": "\f", '"': '"', "'": "'", "\\": "\\"}


def _unquote_literal(term: str) -> str:
    """The value of an N-Triples literal term (``"..."``, optionally followed
    by ``^^<type>`` or ``@lang``) with its escapes decoded.

    The daemon returns literals in this raw form, so any value containing a
    quote or backslash — a signed envelope, a command shape — arrives
    escaped. Scans one character at a time so an escaped backslash right
    before the closing quote is read correctly. A term with no closing quote
    is returned unchanged.
    """
    out: list[str] = []
    i = 1
    while i < len(term):
        ch = term[i]
        if ch == '"':
            return "".join(out)
        if ch == "\\" and i + 1 < len(term):
            nxt = term[i + 1]
            width = {"u": 4, "U": 8}.get(nxt)
            if width and i + 2 + width <= len(term):
                try:
                    out.append(chr(int(term[i + 2:i + 2 + width], 16)))
                    i += 2 + width
                    continue
                except ValueError:
                    pass
            out.append(_NT_ESCAPES.get(nxt, nxt))
            i += 2
            continue
        out.append(ch)
        i += 1
    return term


def normalize_bindings(result: Any) -> list[dict[str, Any]]:
    """Extract a list of binding rows from any of the daemon's response shapes."""
    rows = recognized_bindings(result)
    return [] if rows is None else rows


def recognized_bindings(result: Any) -> Optional[list[dict[str, Any]]]:
    """The binding rows of a response in a shape the daemon is known to use,
    or None for anything else (a malformed reply is NOT an empty result)."""
    if not isinstance(result, dict):
        return None
    rows = None
    if isinstance(result.get("bindings"), list):
        rows = result["bindings"]
    elif isinstance(result.get("results"), dict) and isinstance(result["results"].get("bindings"), list):
        rows = result["results"]["bindings"]
    elif isinstance(result.get("result"), dict) and isinstance(result["result"].get("bindings"), list):
        rows = result["result"]["bindings"]
    if not isinstance(rows, list):
        return None
    return [row for row in rows if isinstance(row, dict)]


def rows_or_fallback(result: Any, on_error: Any) -> Any:
    """What a query returns: the rows of a recognized response, else the
    caller's *on_error* (``[]`` when None). A caller that passes a sentinel
    therefore sees a malformed reply as a failure, never as an empty graph."""
    rows = recognized_bindings(result)
    if rows is None:
        return [] if on_error is None else on_error
    return rows


# ---------------------------------------------------------------------------
# Paged statement reads
# ---------------------------------------------------------------------------

#: Rows per page and the most rows one statement read collects (KI-100).
STATEMENT_PAGE_SIZE = 5000
STATEMENT_MAX_ROWS = 100_000

#: A DKG node answers a query that TIMED OUT with an empty result and a normal
#: success status, after about ten seconds (bench 2026-10-03, DKG 10.0.20:
#: 10-20 s for every query shape while the store was busy; the same queries
#: answered in under a second on a settled node). An empty answer that took at
#: least this long is therefore a failed read, never proof that nothing is there.
SLOW_EMPTY_SECONDS = 8.0

_FAILED = object()


def query_rows(client: Any, sparql: str, graph: str, view: str, *,
               slow_empty_seconds: float = SLOW_EMPTY_SECONDS) -> Optional[list[dict[str, Any]]]:
    """Run ONE query against *graph* / *view* and return its rows — or None
    when the read cannot be believed: the query failed, or it came back EMPTY
    after at least *slow_empty_seconds* (the node's timeout signature, KI-262).

    ``[]`` therefore means "the node answered promptly that there are no such
    rows". Callers keep their last good state on None.

    Usage::

        rows = query_rows(client, sparql, graph, constants.VIEW_SHARED_WORKING_MEMORY)
        if rows is None: ...keep last good...
    """
    started = time.monotonic()
    rows = client.query(sparql, graph, view=view, on_error=_FAILED)
    if rows is _FAILED:
        return None
    if not rows and time.monotonic() - started >= slow_empty_seconds:
        return None
    return rows


def page_rows(client: Any, graph: str, view: str, sparql_after: Callable[[str], str], *,
              page_size: int = STATEMENT_PAGE_SIZE, max_rows: int = STATEMENT_MAX_ROWS) -> Optional[list[dict[str, Any]]]:
    """Page every row a query returns from *graph* / *view*; ``sparql_after(cursor)``
    builds one page's query (subjects after *cursor*, ordered, LIMITed).

    Same cursor discipline as the verified pager (monotonic subject cursor,
    bounded pages, hard row ceiling). Returns None when ANY page fails, comes
    back malformed, or comes back empty after a timeout-length wait
    (:func:`query_rows`), so the caller keeps last-good (fail-open); [] when
    the node answered that the graph holds no such rows.
    """
    rows: list[dict[str, Any]] = []
    after = ""
    while len(rows) < max_rows:
        page = query_rows(client, sparql_after(after), graph, view)
        if page is None:
            # A failed, malformed or timed-out page — even after good ones —
            # makes the whole read unavailable: a partial list must never pass
            # as the graph's contents (R0 tri-state, KI-112, KI-262).
            return None
        if not page:
            break
        rows.extend(page)
        cursors = [extract_binding(r.get("r")) for r in page if extract_binding(r.get("r"))]
        next_cursor = max(cursors) if cursors else ""
        if not next_cursor or next_cursor <= after:
            break  # non-monotonic cursor: stop rather than loop forever
        after = next_cursor
        if len(page) < page_size:
            break
    return rows


def run_query(client, sparql, cg_id, view, on_error, agent_address, timeout, sub_graph):
    """Execute a scoped SELECT using the caller's explicit graph trust."""
    import logging
    from . import constants
    from .dkg_client import DkgError
    logger = logging.getLogger(__name__)
    payload = {"sparql": sparql, "contextGraphId": cg_id}
    evidence = getattr(client, "_chain_evidence", None)
    if evidence and cg_id == evidence[0]:
        payload["chainEvidenceMode"] = evidence[1]
    if view:
        payload["view"] = view
    if view == constants.VIEW_SHARED_WORKING_MEMORY:   # community statements live in their subgraph
        payload["subGraphName"] = sub_graph
    if agent_address:
        payload["agentAddress"] = agent_address
    try:
        result = client.request(
            "POST",
            "/api/query",
            payload,
            timeout=timeout,
        )
    except DkgError as exc:
        logger.debug("blackbox: query failed: %s", exc)
        result = None  # a failure, reported like a malformed reply
    return rows_or_fallback(result, on_error)
