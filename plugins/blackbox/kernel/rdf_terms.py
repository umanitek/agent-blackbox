"""N-Triples terms and quads, with the DKG's literal-size limits enforced.

* ``Quad`` — a ``{subject, predicate, object}`` dict; ``object`` is a ready term.
* :func:`iri`, :func:`literal`, :func:`datetime_literal`, :func:`make_quad` —
  term builders (literals are escaped and capped so no peer's sync breaks).
* :func:`assert_quads_literal_size` — the pre-write check :mod:`.dkg_client` runs.

Usage: ``make_quad(subject, constants.SEVERITY_PRED, literal("high"))``.
"""

from __future__ import annotations

from datetime import datetime, UTC
from typing import Iterable, Optional
from . import constants

# A quad is a ``{subject, predicate, object}`` dict. ``object`` is a ready N-Triples
# term (IRIs bare, literals quoted). No per-quad ``graph`` — the daemon pins it.
Quad = dict[str, str]


# ---------------------------------------------------------------------------
# N-Triples term escaping
# ---------------------------------------------------------------------------


def iri(value: str) -> str:
    """Render an IRI term (bare, per the daemon's quad object convention)."""
    return value


# DKG v10 validates writable RDF literals with dkg-core's
# DKG_RDF_LITERAL_SAFE_MUTF8_BYTES (60,000 Java Modified UTF-8 bytes for the
# full quoted RDF literal term). That is below Java's writeUTF 65,535-byte
# ceiling and is enforced across Oxigraph/Blazegraph-compatible paths. Keep
# Blackbox below it so one oversized threat field cannot abort a peer's sync
# insert for the whole graph.
_DKG_RDF_LITERAL_SAFE_MUTF8_BYTES = 60000
_MAX_LITERAL_BYTES = 50000
_TRUNCATION_MARKER = " ...[truncated]"


def java_modified_utf8_byte_length(value: str) -> int:
    """Java Modified UTF-8 byte length, matching DKG's literal validator."""
    raw = str(value).encode("utf-16-be", "surrogatepass")
    total = 0
    for i in range(0, len(raw), 2):
        code = (raw[i] << 8) | raw[i + 1]
        if code == 0:
            total += 2
        elif code <= 0x7F:
            total += 1
        elif code <= 0x07FF:
            total += 2
        else:
            total += 3
    return total


def _escape_literal_text(text: str) -> str:
    return (
        str(text)
        .replace("\\", "\\\\")
        .replace('"', '\\"')
        .replace("\n", "\\n")
        .replace("\r", "\\r")
        .replace("\t", "\\t")
    )


def literal_term_mutf8_byte_length(term: str) -> Optional[int]:
    """Java MUTF-8 byte length for a quoted RDF literal term, or ``None`` for IRIs."""
    if not str(term).startswith('"'):
        return None
    return java_modified_utf8_byte_length(str(term))


def _literal_term_for_value(value: str) -> str:
    return f'"{_escape_literal_text(value)}"'


def _literal_value_term_mutf8_bytes(value: str) -> int:
    return java_modified_utf8_byte_length(_literal_term_for_value(value))


def _cap_literal_value(value: str) -> str:
    text = str(value)
    if _literal_value_term_mutf8_bytes(text) <= _MAX_LITERAL_BYTES:
        return text

    marker = _TRUNCATION_MARKER
    chars = list(text)
    lo, hi = 0, len(chars)
    best = marker
    while lo <= hi:
        mid = (lo + hi) // 2
        candidate = "".join(chars[:mid]) + marker
        if _literal_value_term_mutf8_bytes(candidate) <= _MAX_LITERAL_BYTES:
            best = candidate
            lo = mid + 1
        else:
            hi = mid - 1
    return best


def assert_quads_literal_size(
    quads: Iterable[Quad],
    *,
    max_bytes: int = _MAX_LITERAL_BYTES,
    label: str = "quads",
) -> None:
    """Raise when any outgoing RDF literal term exceeds Blackbox's DKG budget."""
    for i, q in enumerate(quads):
        obj = q.get("object", "") if isinstance(q, dict) else ""
        actual = literal_term_mutf8_byte_length(obj)
        if actual is not None and actual > max_bytes:
            raise ValueError(
                f"RDF literal {label}[{i}].object is {actual} Java MUTF-8 bytes, "
                f"exceeds Blackbox cap {max_bytes}; subject={q.get('subject')!r} "
                f"predicate={q.get('predicate')!r}"
            )


def literal(value: str) -> str:
    """Render a plain-string literal term with N-Triples escaping.

    Oversized values are truncated to keep every literal below the DKG store's
    per-literal byte cap (:data:`_MAX_LITERAL_BYTES`); an over-limit literal
    aborts a peer's graph sync and hides the whole community graph from them.
    """
    return _literal_term_for_value(_cap_literal_value(str(value)))


def datetime_literal(ts: Optional[datetime] = None) -> str:
    """Render an ``xsd:dateTime`` typed literal (UTC ISO-8601)."""
    when = ts or datetime.now(UTC)
    if when.tzinfo is None:
        when = when.replace(tzinfo=UTC)
    iso = when.astimezone(UTC).isoformat().replace("+00:00", "Z")
    return f'{literal(iso)}^^{constants.XSD_DATETIME}'


def make_quad(subject: str, predicate: str, obj: str) -> Quad:
    return {"subject": subject, "predicate": predicate, "object": obj}
