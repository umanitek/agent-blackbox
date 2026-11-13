"""The curator-PRIVATE reputation ledger (R4, plan §10 / §13 data protection).

Never published. Each reporter is keyed by a pseudonym — HMAC of its key
under a per-reporter random salt — and ERASURE deletes the salt, after which
nothing in the file can be tied to the key again (crypto-shredding). The
index that maps keys to salts is sealed (:mod:`.sealed_index`), so a copied
index file identifies nobody. Entries
inactive for :data:`RETENTION_DAYS` are dropped on load. One lock, atomic
tmp+rename writes, the same shape as every other store in the plugin.

Usage (curator machine)::

    ledger = ReputationLedger()                                   # $BLACKBOX_HOME/curate/reputation.json
    ledger.record(key, Outcome("2026-10-02", confirmed=True), novel=True, first_seen_day="2026-09-10")
    standing = ledger.standing(key)                               # ReporterStanding
    ledger.reputation(key, today="2026-10-02")                    # Beta mean with forgetting
    ledger.erase(key)                                             # deletes the salt: the entry is unreadable forever

A curator's published verdict is credited to each reporter of the threat
exactly once (:meth:`ReputationLedger.record_once`), so the ledger can be
REBUILT from the public record by any curator node, any number of times,
and reach the same counts.
"""

from __future__ import annotations

import hashlib
import hmac
import json
import logging
import secrets
import threading
from dataclasses import replace
from datetime import date, timedelta
from pathlib import Path
from typing import Any, Optional

from ...kernel import constants
from ...kernel.health import today_utc
from . import sealed_index
from .bands import ReporterStanding, ReputationBand
from .scoring import Outcome, beta_reputation
from ...kernel.bounded_files import atomic_write

logger = logging.getLogger(__name__)

#: Entries with no outcome for two years are deleted on load.
RETENTION_DAYS = 730
_LEDGER_FILE = "reputation.json"


def pseudonym(salt_hex: str, key: str) -> str:
    """HMAC-SHA256(salt, reporter key) — the ledger's only handle on a reporter."""
    return hmac.new(bytes.fromhex(salt_hex), key.lower().encode("utf-8"), hashlib.sha256).hexdigest()


class ReputationLedger:
    """Three owner-only files in ``$BLACKBOX_HOME/curate``: ``reputation.json``
    (``{"entries": {pseudonym: entry}}``), ``reputation_salts.json`` (the index
    ``{key: salt}``, SEALED — no reporter key is readable in it, KI-257) and
    ``reputation_index.key`` (the key that opens the index).

    An entry holds the standing fields plus its outcome list. The index is
    the only link from a key to its entry; erasing a key deletes its salt. The
    entries file alone, or the index alone, identifies nobody.
    """

    def __init__(self, path: Optional[Path] = None) -> None:
        self._path = path or (constants.blackbox_home() / "curate" / _LEDGER_FILE)
        #: Round 4: the salt map (key → salt) lives in its own owner-only file, so the
        #: entries file alone links no key to any outcome. C11: that file is sealed.
        self._salts_path = self._path.with_name(self._path.stem + "_salts.json")
        self._index_key_path = self._path.with_name(self._path.stem + "_index.key")
        self._lock = threading.Lock()

    # -- reads ---------------------------------------------------------------

    def standing(self, key: str) -> ReporterStanding:
        with self._lock:
            data = self._load()
            entry = self._entry(data, key)
        return _standing_from(key, entry) if entry is not None else ReporterStanding(key=key)

    def reputation(self, key: str, today: str) -> float:
        with self._lock:
            entry = self._entry(self._load(), key)
        outcomes = [Outcome(o["day"], bool(o["confirmed"])) for o in (entry or {}).get("outcomes", [])]
        return beta_reputation(outcomes, today)

    def keys(self) -> list[str]:
        with self._lock:
            return sorted(self._load()["salts"])

    # -- writes --------------------------------------------------------------

    def record(self, key: str, outcome: Outcome, *, novel: bool = False, strike: bool = False,
               first_seen_day: str = "") -> ReporterStanding:
        """Add one curator outcome (creating the entry and its salt on first use)."""
        with self._lock:
            data = self._load()
            salt = data["salts"].setdefault(key.lower(), secrets.token_hex(16))
            entry = data["entries"].setdefault(pseudonym(salt, key), _new_entry(first_seen_day or outcome.day))
            entry["outcomes"].append({"day": outcome.day, "confirmed": outcome.confirmed})
            entry["confirmed" if outcome.confirmed else "rejected"] += 1
            entry["novel_credits"] += 1 if (novel and outcome.confirmed) else 0
            entry["strikes"] += 1 if strike else 0
            entry["last_day"] = max(entry.get("last_day", ""), outcome.day)
            self._save(data)
            return _standing_from(key, entry)

    def record_once(self, key: str, outcome: Outcome, *, threat: str, novel: bool = False,
                    first_seen_day: str = "", publisher: str = "") -> bool:
        """Credit *outcome* for one THREAT at most once; True when the ledger changed.

        Idempotent per (reporter, threat): repeating the same verdict changes
        nothing, so a sync over the whole public record is safe to run on
        every beat. A verdict that FLIPPED (a confirmation later rejected)
        records the new outcome and takes back the novelty credit the first
        one gave. The memory of what was credited survives a lockout, so a
        demoted reporter is not re-credited for its old reports. *publisher*
        — the upstream publisher a NOVEL credit is charged to (at most one
        credit per publisher across all reporters)."""
        confirmed = "confirmed" if outcome.confirmed else "rejected"
        tag = hashlib.sha256(threat.encode("utf-8")).hexdigest()[:20]
        with self._lock:
            data = self._load()
            salt = data["salts"].setdefault(key.lower(), secrets.token_hex(16))
            entry = data["entries"].setdefault(pseudonym(salt, key), _new_entry(first_seen_day or outcome.day))
            credited = entry.setdefault("credited", {})
            previous = credited.get(tag)
            if previous is not None and previous.get("v") == confirmed:
                return False
            if previous is not None and previous.get("novel"):
                entry["novel_credits"] = max(0, int(entry.get("novel_credits") or 0) - 1)
            grants_novel = bool(novel and outcome.confirmed)
            entry["outcomes"].append({"day": outcome.day, "confirmed": outcome.confirmed})
            entry[confirmed] += 1
            entry["novel_credits"] += 1 if grants_novel else 0
            entry["last_day"] = max(entry.get("last_day", ""), outcome.day)
            if first_seen_day and first_seen_day < (entry.get("first_seen_day") or first_seen_day):
                entry["first_seen_day"] = first_seen_day
            credited[tag] = {"v": confirmed, "novel": grants_novel}
            if grants_novel and publisher:
                data["publishers"][publisher] = int(data["publishers"].get(publisher, 0)) + 1
            self._save(data)
            return True

    def publisher_credits(self, publisher: str) -> int:
        """How many novelty credits were already granted for *publisher* (any reporter)."""
        with self._lock:
            return int(self._load()["publishers"].get(publisher, 0))

    def set_standing(self, standing: ReporterStanding) -> None:
        """Store band / org / sponsor / lockout decisions (counters come from outcomes)."""
        with self._lock:
            data = self._load()
            salt = data["salts"].setdefault(standing.key.lower(), secrets.token_hex(16))
            entry = data["entries"].setdefault(pseudonym(salt, standing.key), _new_entry(standing.first_seen_day))
            entry.update({"band": standing.band.value, "org": standing.org, "sponsor": standing.sponsor,
                          "lockout_until": standing.lockout_until, "first_seen_day": standing.first_seen_day,
                          "confirmed": standing.confirmed, "rejected": standing.rejected, "strikes": standing.strikes,
                          "novel_credits": standing.novel_credits})
            if standing.lockout_until:
                entry["outcomes"] = []   # re-graduation starts from zero
            self._save(data)

    def erase(self, key: str) -> bool:
        """Crypto-shred: drop the salt (and the now-unreachable entry). True when something was erased."""
        with self._lock:
            data = self._load()
            salt = data["salts"].pop(key.lower(), None)
            if salt is None:
                return False
            data["entries"].pop(pseudonym(salt, key), None)
            self._save(data)
            return True

    # -- storage -------------------------------------------------------------

    def _entry(self, data: dict[str, Any], key: str) -> Optional[dict[str, Any]]:
        salt = data["salts"].get(key.lower())
        return data["entries"].get(pseudonym(salt, key)) if salt else None

    def _load(self) -> dict[str, Any]:
        entries: dict[str, dict[str, Any]] = {}
        publishers: dict[str, int] = {}
        try:
            data = json.loads(self._path.read_text(encoding="utf-8-sig"))
            entries = {str(k): dict(v) for k, v in data.get("entries", {}).items() if isinstance(v, dict)}
            publishers = {str(k): int(v) for k, v in dict(data.get("publishers") or {}).items()}
        except (OSError, ValueError, AttributeError, TypeError):
            pass   # missing or unreadable: an empty ledger
        salts = self._load_salts()
        # UTC, like every `last_day` it is compared with: the machine's local date is a day off for part of each day.
        cutoff = (date.fromisoformat(today_utc()) - timedelta(days=RETENTION_DAYS)).isoformat()
        live = {p: e for p, e in entries.items() if e.get("last_day", "") >= cutoff or not e.get("outcomes")}
        live_salts = {key: salt for key, salt in salts.items() if pseudonym(salt, key) in live or not entries}
        return {"salts": live_salts, "entries": live, "publishers": publishers}

    def _load_salts(self) -> dict[str, str]:
        """The index (reporter key -> salt). A sealed index that cannot be
        opened is an EMPTY index: its entries are unreachable, as after an
        erasure. An index written before sealing (a clear map) is read once
        and sealed at once, so reporter keys do not stay readable on disk."""
        try:
            text = self._salts_path.read_text(encoding="utf-8-sig")
        except OSError:
            return {}
        if sealed_index.is_sealed(text):
            opened = sealed_index.open_sealed(text, self._index_key())
            if opened is None:
                logger.warning("blackbox: the reputation ledger's index cannot be opened (its key file is missing or "
                               "does not match); its entries are unreachable")
            return _well_formed(opened or {})
        try:
            legacy = _well_formed({str(k): str(v) for k, v in json.loads(text).items()})
        except (ValueError, AttributeError):
            return {}
        if legacy:
            self._write(self._salts_path, self._sealed(legacy))
        return legacy

    def _index_key(self) -> Optional[bytes]:
        try:
            return sealed_index.load_or_create_key(self._index_key_path)
        except OSError as exc:
            logger.warning("blackbox: the reputation ledger's index key could not be created (%s)", exc)
            return None

    def _sealed(self, salts: dict[str, str]) -> str:
        key = self._index_key()
        if key is None:   # never fall back to a clear index: an unsaved ledger is safer than a readable one
            raise OSError("the ledger index key is unreadable")
        return sealed_index.seal(salts, key)

    @staticmethod
    def _write(path: Path, text: str) -> None:
        atomic_write(path, text, mode=0o600)

    def _save(self, data: dict[str, Any]) -> None:
        try:
            self._path.parent.mkdir(parents=True, exist_ok=True)
            index = self._sealed(data["salts"])
            self._write(self._path, json.dumps({"entries": data["entries"], "publishers": data.get("publishers", {})}))
            self._write(self._salts_path, index)
        except OSError as exc:
            logger.warning("blackbox: could not save the reputation ledger (%s)", exc)


_HEX = frozenset("0123456789abcdef")


def _well_formed(salts: dict[str, str]) -> dict[str, str]:
    """Only the index rows whose salt can be used (non-empty, even-length lower-case hex). A row with a
    damaged salt could never reach its entry anyway; it is dropped instead of crashing the ledger. Keys
    are not judged here: whatever key the ledger was given is the key it must find again."""
    return {key: salt for key, salt in salts.items()
            if key and salt and len(salt) % 2 == 0 and set(salt) <= _HEX}


def _new_entry(first_seen_day: str) -> dict[str, Any]:
    return {"band": ReputationBand.PROBATION.value, "first_seen_day": first_seen_day, "confirmed": 0, "rejected": 0,
            "strikes": 0, "novel_credits": 0, "org": "", "sponsor": "", "lockout_until": "", "last_day": "",
            "outcomes": []}


def _standing_from(key: str, entry: dict[str, Any]) -> ReporterStanding:
    try:
        band = ReputationBand(entry.get("band") or "probation")
    except ValueError:
        band = ReputationBand.PROBATION
    return replace(ReporterStanding(key=key), band=band, first_seen_day=str(entry.get("first_seen_day") or ""),
                   confirmed=int(entry.get("confirmed") or 0), rejected=int(entry.get("rejected") or 0),
                   strikes=int(entry.get("strikes") or 0), novel_credits=int(entry.get("novel_credits") or 0),
                   org=str(entry.get("org") or ""), sponsor=str(entry.get("sponsor") or ""),
                   lockout_until=str(entry.get("lockout_until") or ""))
