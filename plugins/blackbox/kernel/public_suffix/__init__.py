"""The Public Suffix List — registrable domains and shared-hosting suffixes (R9).

An allowlist keyed on raw host names is wrong twice: ``login.paypal.com``
and ``paypal.com`` are the same brand, while ``evil.github.io`` and
``github.io`` are not — GitHub Pages is shared hosting where every tenant
is a different party. The Public Suffix List (publicsuffix.org, Mozilla,
MPL-2.0) answers both: the REGISTRABLE domain is the suffix plus one label,
and suffixes in the list's PRIVATE section are shared-hosting providers.

The list is vendored next to this module (``public_suffix_list.dat``, the
``// VERSION:`` line inside it dates the snapshot) and may be refreshed by
replacing the file with a newer download from the same URL — the parser
needs nothing else. ``$BLACKBOX_HOME/public_suffix_list.dat`` overrides the
vendored copy when present (the refresh path for an installed node).

Pattern: one immutable table loaded once per process (functools.lru_cache),
pure lookups. Algorithm per publicsuffix.org: longest matching rule wins;
``*.`` wildcards; ``!`` exceptions.

Usage::

    registrable_domain("login.paypal.co.uk")   # "paypal.co.uk"
    registrable_domain("evil.github.io")        # "evil.github.io" (github.io is a private-section suffix)
    is_shared_hosting("evil.github.io")         # True
"""

from __future__ import annotations

import logging
from dataclasses import dataclass
from functools import lru_cache
from pathlib import Path
from typing import Optional

from .. import constants

logger = logging.getLogger(__name__)

_VENDORED = Path(__file__).with_name("public_suffix_list.dat")
_PRIVATE_MARKER = "// ===BEGIN PRIVATE DOMAINS==="
__all__ = ["SuffixRules", "is_shared_hosting", "load", "public_suffix", "registrable_domain"]   # the surface other modules may import


@dataclass(frozen=True)
class SuffixRules:
    """The parsed list: ``rules`` (plain and ``*.`` wildcard rules, as written,
    lower-case, punycode left as-is), ``exceptions`` (``!`` rules without
    the bang), ``private`` (rules from the PRIVATE section — shared hosting),
    ``version`` (the file's VERSION line)."""

    rules: frozenset[str]
    exceptions: frozenset[str]
    private: frozenset[str]
    version: str


def _parse(text: str) -> SuffixRules:
    rules, exceptions, private = set(), set(), set()
    version = ""
    in_private = False
    for raw in text.splitlines():
        line = raw.strip()
        if line.startswith("// VERSION:"):
            version = line[len("// VERSION:"):].strip()
        if line == _PRIVATE_MARKER:
            in_private = True
        if not line or line.startswith("//"):
            continue
        rule = line.split()[0].lower()
        if rule.startswith("!"):
            exceptions.add(rule[1:])
        else:
            rules.add(rule)
            if in_private:
                private.add(rule)
    return SuffixRules(frozenset(rules), frozenset(exceptions), frozenset(private), version)


@lru_cache(maxsize=1)
def load() -> SuffixRules:
    """The table (home override first, then the vendored file); an unreadable
    file yields an empty table — every host then has no public suffix, which
    only widens matching (fail-open, never a crash)."""
    for path in (constants.blackbox_home() / _VENDORED.name, _VENDORED):
        try:
            return _parse(path.read_text(encoding="utf-8-sig"))
        except OSError:
            continue
    logger.warning("blackbox: no public suffix list could be read; registrable-domain matching is widened")
    return SuffixRules(frozenset(), frozenset(), frozenset(), "")


def _matching_rule(labels: tuple[str, ...], rules: SuffixRules) -> tuple[int, bool]:
    """(number of labels the public suffix spans, whether a private-section
    rule matched) for *labels* (lowest-level label first)."""
    best, best_private = 0, False
    for i in range(len(labels)):
        candidate = ".".join(labels[i:])
        wildcard = ".".join(("*",) + labels[i + 1:]) if i + 1 < len(labels) else ""
        if candidate in rules.exceptions:
            return len(labels) - i - 1, candidate in rules.private
        if candidate in rules.rules or (wildcard and wildcard in rules.rules):
            span = len(labels) - i
            if span > best:
                best, best_private = span, (candidate in rules.private or wildcard in rules.private)
    return (best or 1), best_private   # a host matching no rule has a one-label public suffix


def public_suffix(host: str) -> str:
    """The public suffix of *host* (``"co.uk"`` for ``a.b.co.uk``)."""
    labels = tuple(host.lower().strip(".").split("."))
    span, _ = _matching_rule(labels, load())
    return ".".join(labels[len(labels) - span:])


def registrable_domain(host: str) -> Optional[str]:
    """The suffix plus one label (``"paypal.co.uk"``), or None when *host* IS
    a public suffix (nothing is registrable there)."""
    labels = tuple(host.lower().strip(".").split("."))
    span, _ = _matching_rule(labels, load())
    if span >= len(labels):
        return None
    return ".".join(labels[len(labels) - span - 1:])


def is_shared_hosting(host: str) -> bool:
    """True when *host* sits under a PRIVATE-section suffix (GitHub Pages,
    Netlify, Cloudfront…): tenants there are different parties, so an
    allowlist must match at URL granularity, never the whole provider."""
    labels = tuple(host.lower().strip(".").split("."))
    _, private = _matching_rule(labels, load())
    return private
