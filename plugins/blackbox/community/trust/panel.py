"""The trust layer as one read model (Community Curation C10, plan §11 TRACK).

"Who curates, who is trusted, what is confirmed, is anything wrong" — answered
ONCE, from the verified community read, for both surfaces: the dashboard's
trust panel serves it (``dashboard.trust_routes``) and ``blackbox status``
prints it (:func:`status_lines`), so the two can never disagree.

Values are RAW: reporter addresses, organisations and evidence references come
from signed statements but are still other people's text. Each surface
escapes for itself (the dashboard through ``safe_text``, the terminal through
``term_safe``).

Pattern: a read model — a pure function from the read to :class:`TrustPanel`.

Usage::

    panel = trust_panel(read)                 # read: community.CommunityRead
    for line in status_lines(panel): print(line)
"""

from __future__ import annotations

from datetime import date
from typing import Any, Dict, List, Optional, TypedDict

from ...kernel import display_safety
from ...kernel.signing.statement_order import CuratorStatement
from ..statements import curator_view

#: A curator key without a heartbeat for longer than this is shown as silent (plan §13: 48 hours).
HEARTBEAT_SILENCE_DAYS = 2


class Heartbeat(TypedDict):
    key: str        # the curator key (hex)
    day: str        # its newest heartbeat day ("" = never seen)
    silent: bool


class AuthorityFacts(TypedDict):
    authority: str      # "verified" | "community"
    trusted: bool       # a root-signed key manifest is trusted on this node
    state: str          # "ok" | "pending" | "stale" | "conflict" | "unavailable" | "none"
    state_day: str      # the day a pending manifest takes effect / a stale one expired
    expires: str        # the day the manifest expires ("" = undated)
    root_epoch: int
    version: int
    keys: int
    threshold: int
    heartbeats: list[Heartbeat]


class TrustedReporter(TypedDict):
    key: str            # the reporter key (hex) — the identity
    address: str        # the agent address shown beside it (display only)
    author_class: str   # "partner" | "established"
    org: str
    expires: str
    listed_by: str      # "verified" | "community"


class Confirmed(TypedDict):
    identifier: str
    evidence: str       # the signed evidence reference the curators checked
    day: str
    curators: int       # curator keys that signed the confirmation
    reporters: int      # distinct verified reporters of the threat on this node


class TrustPanel(TypedDict):
    available: bool             # False: the shared memory could not be read (never "nothing is trusted")
    reason: str
    authorities: list[AuthorityFacts]
    reporters: list[TrustedReporter]
    confirmed: list[Confirmed]
    held_raising: int           # raising statements this reader holds under its daily cap
    lookup_incomplete: bool     # the trust lookup was cut short


def _days_between(earlier: str, later: str) -> int:
    try:
        return (date.fromisoformat(later) - date.fromisoformat(earlier)).days
    except ValueError:
        return 0


def _authority(name: str, view: Optional[Any], today: str) -> AuthorityFacts:
    manifest = getattr(view, "manifest", None)
    if view is None or (manifest is None and not view.unavailable and not view.manifest_conflict):
        return AuthorityFacts(authority=name, trusted=False, state="none", state_day="", expires="", root_epoch=0, version=0,
                              keys=0, threshold=0, heartbeats=[])
    state = "conflict" if view.manifest_conflict else "unavailable" if view.unavailable else (view.manifest_state or "ok")
    beats = [Heartbeat(key=key, day=view.heartbeats.get(key, ""),
                       silent=not view.heartbeats.get(key) or _days_between(view.heartbeats[key], today) > HEARTBEAT_SILENCE_DAYS)
             for key in (manifest.curator_keys if manifest is not None else ())]
    return AuthorityFacts(
        authority=name, trusted=manifest is not None, state=state, state_day=view.manifest_state_day,
        expires=view.manifest_expires_day, root_epoch=manifest.root_epoch if manifest is not None else 0,
        version=manifest.version if manifest is not None else 0, keys=len(beats),
        threshold=manifest.threshold if manifest is not None else 0, heartbeats=beats)


def trust_panel(read: Any, today: Optional[str] = None) -> TrustPanel:
    """The trust facts in *read* (a ``CommunityRead``): both authorities, the
    trusted reporters either of them lists, and the community curators'
    standing confirmations."""
    if read is None or not read.available:
        return TrustPanel(available=False, reason=str(getattr(read, "reason", "") or "not read yet"), authorities=[],
                          reporters=[], confirmed=[], held_raising=0, lookup_incomplete=False)
    day = today or curator_view.today_utc()
    combined, community = read.curator, read.curator.community
    listed_by_community = community.counted if community is not None else {}
    reporters = [TrustedReporter(key=key, address=entry.address, author_class=entry.author_class, org=entry.org,
                                 expires=entry.expires, listed_by="community" if key in listed_by_community else "verified")
                 for key, entry in sorted(combined.counted.items(), key=lambda item: (item[1].expires, item[0]))]
    signers: dict[str, set] = {}
    for report in read.reports:
        signers.setdefault(report.identifier, set()).add(report.author)
    confirmed = [Confirmed(identifier=identifier, evidence=record.field("evidence"), day=record.day,
                           curators=len(record.signers), reporters=len(signers.get(identifier, ())))
                 for identifier, record in sorted((community.verdicts if community is not None else {}).items())
                 if record.kind is CuratorStatement.CONFIRMATION and combined.verdict(identifier) is CuratorStatement.CONFIRMATION]
    return TrustPanel(available=True, reason="",
                      authorities=[_authority("verified", combined, day), _authority("community", community, day)],
                      reporters=reporters, confirmed=confirmed,
                      held_raising=community.held_raising if community is not None else 0,
                      lookup_incomplete=bool(community is not None and community.lookup_incomplete))


def status_lines(panel: TrustPanel) -> list[str]:
    """The same facts as `blackbox status` prints them (terminal-safe)."""
    if not panel["available"]:
        return [f"  trust:             unavailable ({display_safety.term_safe(panel['reason'], 120)})"]
    lines = []
    for facts in panel["authorities"]:
        label = f"  {facts['authority']} trust:".ljust(21)      # the column every `blackbox status` value starts in
        if not facts["trusted"]:
            lines.append(f"{label}{'no curators trusted on this network' if facts['state'] == 'none' else facts['state'].upper()}")
            continue
        alive = sum(1 for beat in facts["heartbeats"] if not beat["silent"])
        state = "" if facts["state"] == "ok" else f" · manifest {facts['state'].upper()} {facts['state_day']}".rstrip()
        expires = f" · expires {facts['expires']}" if facts["expires"] else ""
        lines.append(f"{label}{facts['threshold']} of {facts['keys']} curator keys sign (manifest v{facts['version']}){state}{expires} · "
                     f"{alive} of {facts['keys']} alive")
    by_community = sum(1 for reporter in panel["reporters"] if reporter["listed_by"] == "community")
    lines.append(f"  trusted reporters: {len(panel['reporters'])} ({by_community} listed by the community curators)")
    held = f" · {panel['held_raising']} held by this node's daily cap" if panel["held_raising"] else ""
    cut = " · trust lookup cut short" if panel["lookup_incomplete"] else ""
    lines.append(f"  confirmed pool:    {len(panel['confirmed'])} threat(s) confirmed by the community curators{held}{cut}")
    return lines
