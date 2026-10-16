"""Whether this machine may share with the community — the ONE gate
every send path asks (Refine R13, revised 2026-10-16).

Community sharing is OPT-IN: off until the operator turns it on (2026-10-16,
for the Hermes plugin catalog listing — telemetry in a catalog entry must be
opt-in; it was on by default from 2026-10-12). Only two actions record the
acceptance: `blackbox report --enable-sharing` (or `--consent`) and the
dashboard's sharing toggle, both through :func:`for_settings` / :func:`record`.
No installer, upgrade or automatic path ever writes it. Nothing sent is ever a
prompt, command, path or file (see ``docs/REPORTER_TERMS.md``). Turning it off
is one action (`blackbox report --withdraw-consent`, `--disable-sharing`, or the
dashboard toggle) and it actually stops processing: the share gate refuses on
the next call.

The record is local, owner-readable, atomic (``$BLACKBOX_HOME/sharing_consent.json``)
and is erased with the identity (`--erase-identity`). No record means the
default: sharing OFF. A record is in force only when it holds an acceptance
(``accepted_at``) and no ``withdrawn_at``, whatever terms version it names (a
terms change does not pause sharing; the terms' "What changed" section is
shown to the operator instead).

Usage::

    consent.in_force()                      # the gate's question: True only after an opt-in
    consent.record()                        # opt in (CLI `--consent` / `--enable-sharing`)
    consent.for_settings(payload)           # a settings write that turns sharing on opts in
    consent.withdraw()                      # opt out: stops sharing
    consent.terms_text()                    # the terms shown to the operator
"""

from __future__ import annotations

import hashlib
import json
import logging
import os
import secrets
from dataclasses import dataclass
from datetime import datetime, timezone, UTC
from pathlib import Path
from typing import Any, Mapping, Optional

from ..kernel import constants

logger = logging.getLogger(__name__)

#: The reporter terms the record is bound to (shipped next to the code).
TERMS_PATH = Path(__file__).resolve().parent.parent / "docs" / "REPORTER_TERMS.md"
_RECORD_FILE = "sharing_consent.json"


@dataclass(frozen=True)
class SharingConsentRecord:
    """``terms_hash`` — sha256 of the terms text consented to; ``terms_version``
    — the version line of that text; ``accepted_at`` — UTC time; ``withdrawn_at``
    — UTC time the consent was withdrawn ("" while in force)."""

    terms_hash: str
    terms_version: str
    accepted_at: str
    withdrawn_at: str = ""


def terms_text() -> str:
    """The reporter terms as shipped ("" when the file is missing — then nothing can be consented to)."""
    try:
        return TERMS_PATH.read_text(encoding="utf-8-sig")
    except OSError:
        return ""


def terms_hash(text: Optional[str] = None) -> str:
    return hashlib.sha256((terms_text() if text is None else text).encode("utf-8")).hexdigest()


def terms_version(text: Optional[str] = None) -> str:
    for line in (terms_text() if text is None else text).splitlines():
        if line.lower().startswith("version:"):
            return line.split(":", 1)[1].strip().split()[0]   # "1.0 (draft …)" → "1.0"
    return "unversioned"


def _record_path() -> Path:
    return constants.blackbox_home() / _RECORD_FILE


def _text(value: Any) -> str:
    """A record field as text: a string as written; anything else (null, a number) is
    no value. The OpenClaw bridge reads the same file the same way (consent.ts)."""
    return value if isinstance(value, str) else ""


def current() -> Optional[SharingConsentRecord]:
    """The saved sharing choice, or None when there is no readable record (a missing
    file, malformed JSON, or JSON that is not an object)."""
    try:
        data = json.loads(_record_path().read_text(encoding="utf-8-sig"))
    except (OSError, ValueError):
        return None
    if not isinstance(data, dict):
        return None
    return SharingConsentRecord(terms_hash=_text(data.get("terms_hash")), terms_version=_text(data.get("terms_version")),
                                accepted_at=_text(data.get("accepted_at")), withdrawn_at=_text(data.get("withdrawn_at")))


def in_force() -> bool:
    """True only when the operator opted in: a record with an acceptance
    (``accepted_at``) and no withdrawal. No record is the default — sharing off.
    An unreadable or malformed record file reads as no record (off)."""
    record = current()
    return record is not None and bool(record.accepted_at) and not record.withdrawn_at


def sharing_on(cfg: Any) -> bool:
    """Whether this node shares with the community right now: the build and the
    operator's switch and a graph (``cfg.community_enabled``) AND a consent in force
    — the two checks the share gate makes. Every "is sharing on?" display reads this, so an
    opt-out made with ``blackbox report --withdraw-consent`` never shows as on."""
    return bool(getattr(cfg, "community_enabled", False)) and in_force()


def why_not() -> str:
    """"" when consent is in force; otherwise ONE plain sentence saying why not —
    never turned on (the default), or turned off on a given day. The share gates, `blackbox report --consent` and the
    operator's health list all say it the same way. It never disagrees
    with :func:`in_force`: when that says yes, this says nothing."""
    if in_force():
        return ""
    entry = current()
    if entry is not None and entry.withdrawn_at:
        return (f"community sharing was turned off on {entry.withdrawn_at[:10]} "
                "(`blackbox report --enable-sharing` or the dashboard toggle turns it back on)")
    return "community sharing is off — `blackbox report --enable-sharing` or the dashboard toggle turns it on"


def changes_section(text: Optional[str] = None) -> str:
    """The terms' "What changed" section ("" when there is none) — shown first to
    an operator who consented to an earlier version."""
    lines = (terms_text() if text is None else text).splitlines()
    start = next((i for i, line in enumerate(lines) if line.lower().startswith("## what changed")), None)
    if start is None:
        return ""
    end = next((i for i in range(start + 1, len(lines)) if lines[i].startswith("## ")), len(lines))
    return "\n".join(lines[start:end]).strip()


def record() -> Optional[SharingConsentRecord]:
    """Record acceptance of the terms as they are now — the operator's opt-in
    (first time, or back in after an opt-out). Works without the terms file too (the record then names no version):
    turning sharing back on must never depend on it. None when it could not be saved."""
    text = terms_text()
    entry = SharingConsentRecord(terms_hash=terms_hash(text) if text else "", terms_version=terms_version(text) if text else "",
                                 accepted_at=datetime.now(UTC).replace(microsecond=0).isoformat())
    return entry if _save(entry) else None


def for_settings(payload: Mapping[str, Any]) -> bool:
    """The ``sharing_consent`` a settings write passes on: turning sharing ON
    (``report: true`` in *payload*) is the operator's opt-back-in, so a
    standing opt-out is replaced by a fresh acceptance first. The dashboard
    toggle and `blackbox report --enable-sharing` both call this — one rule.

        settings.write_settings(payload, sharing_consent=consent.for_settings(payload))
    """
    if payload.get("report") is True and not in_force():
        record()
    return in_force()


def withdraw() -> bool:
    """Opt out: record the withdrawal (keeping any earlier acceptance as history).
    True when sharing was allowed and the opt-out is now SAVED; False when it was
    already off or the record could not be written (callers must say so: sharing
    would otherwise continue). An opt-out on the default writes its own record."""
    entry = current()
    if entry is not None and entry.withdrawn_at:
        return False
    text = terms_text()
    base = entry or SharingConsentRecord(terms_hash=terms_hash(text) if text else "", terms_version=terms_version(text) if text else "",
                                         accepted_at="")
    return _save(SharingConsentRecord(base.terms_hash, base.terms_version, base.accepted_at,
                                      withdrawn_at=datetime.now(UTC).replace(microsecond=0).isoformat()))


def erase() -> bool:
    """Identity erasure: drop the acceptance history and leave sharing OFF. The
    history is replaced by a bare opt-out (not deleted) so the record says the
    operator chose off; the operator turns sharing back on deliberately. True
    when a record existed before."""
    existed = _record_path().exists()
    _save(SharingConsentRecord(terms_hash="", terms_version="", accepted_at="",
                               withdrawn_at=datetime.now(UTC).replace(microsecond=0).isoformat()))
    return existed


def _save(entry: SharingConsentRecord) -> bool:
    """Write *entry* atomically (mode 600); True when it is on disk."""
    path = _record_path()
    try:
        path.parent.mkdir(parents=True, exist_ok=True)
        tmp = path.with_name(f"{path.name}.tmp.{os.getpid()}.{secrets.token_hex(6)}")
        tmp.write_text(json.dumps(entry.__dict__), encoding="utf-8")
        os.chmod(tmp, 0o600)
        os.replace(tmp, path)
        return True
    except OSError as exc:   # an opt-out that could not be written must be loud: sharing would continue
        logger.warning("blackbox: could not save the community sharing choice (%s)", exc)
        return False
