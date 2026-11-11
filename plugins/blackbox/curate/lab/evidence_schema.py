"""The lab's evidence contract — one typed format, written by the lab runner,
read by the curators (proposal §03.5, F-015).

STANDARD LIBRARY ONLY: the lab runner (``integrations/threat-lab/``, a separate
deployable) loads this one file by path, so it may import nothing from the
plugin. A guard test parses the imports.

Evidence never carries raw page text. A hostile page can carry instructions
aimed at an AI reader, so every field is typed and capped: fingerprints are
sha256 hex, hosts are hostnames or IP addresses, observations are yes/no
answers to a closed list of checks, and notes are codes from a closed
vocabulary. There is no free-text field, and unknown keys are refused.

Usage::

    evidence = validate_evidence(json.loads(raw))   # raises EvidenceError
    text = to_json(evidence)                         # canonical; validates back to an equal Evidence
"""

from __future__ import annotations

import ipaddress
import json
import re
from dataclasses import dataclass
from enum import Enum
from typing import Any, Callable, Mapping

#: Caps from §03.5: the extractor drops nothing silently — over a cap is an error.
MAX_CONTACTED_HOSTS = 20
MAX_FILE_FINGERPRINTS = 50
MAX_NOTES = 20
MAX_NOTE_CHARS = 200
MAX_HOST_CHARS = 253
#: Lab levels: 1–2 on Lab 1, 3 via urlscan, 4 in a microVM on the KVM host.
LEVELS = (1, 2, 3, 4)

_HOSTNAME = re.compile(r"^(?=.{1,253}$)([a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?)(\.[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?)*$")
#: 64 lowercase hex characters. This file is loaded on its own by the lab runner (standard
#: library only), so it cannot import the kernel's ``threat_ids.is_hex64``; a test holds the two
#: to the same answers. Used with ``fullmatch``: ``^…$`` with ``match`` let a trailing newline pass.
_SHA256 = re.compile(r"[0-9a-f]{64}")
_JOB_KEY = re.compile(r"([0-9a-f]{64}):([1-4]):([0-9a-f]{64})")


class EvidenceError(ValueError):
    """The mapping is not valid evidence; the message names the field."""


class Check(Enum):
    """What the lab looked for. An Observation answers one check yes or no."""

    NETWORK_CONTACTED = "network-contacted"
    REDIRECTED_OFF_DOMAIN = "redirected-off-domain"
    CREDENTIAL_FORM = "credential-form"
    WALLET_PROMPT = "wallet-prompt"
    DOWNLOAD_TRIGGERED = "download-triggered"
    INSTALL_SCRIPT_RAN = "install-script-ran"
    PROCESS_SPAWNED = "process-spawned"
    FILE_WRITTEN_OUTSIDE_PACKAGE = "file-written-outside-package"
    BAIT_CREDENTIAL_SENT = "bait-credential-sent"
    CLIPBOARD_WRITTEN = "clipboard-written"


class NoteCode(Enum):
    """The closed note vocabulary. A note is one of these codes, never prose."""

    PAGE_UNREACHABLE = "page-unreachable"
    TLS_ERROR = "tls-error"
    CLOAKING_SUSPECTED = "cloaking-suspected"
    OBFUSCATED_SCRIPT = "obfuscated-script"
    BRAND_IMPERSONATION = "brand-impersonation"
    NETWORK_AFTER_INSTALL = "network-after-install"
    SCANNING_KILLED = "scanning-killed"
    HOST_CAP_REACHED = "host-cap-reached"
    DEADLINE_REACHED = "deadline-reached"
    RESOURCE_CAP_REACHED = "resource-cap-reached"
    INCONCLUSIVE = "inconclusive"


@dataclass(frozen=True)
class Observation:
    """A yes/no answer: did the lab see *check* happen?"""

    check: Check
    seen: bool


@dataclass(frozen=True)
class Evidence:
    """One lab run's typed result for one job.

    ``job_key`` is :func:`job_key` of (threat digest, level, image hash) and
    must agree with ``level`` and ``image_sha256``. Times are UTC epoch
    seconds. Build one only through :func:`validate_evidence`.
    """

    job_key: str
    image_sha256: str
    level: int
    started_at: int
    finished_at: int
    contacted_hosts: tuple[str, ...]
    file_fingerprints: tuple[str, ...]
    observations: tuple[Observation, ...]
    notes: tuple[NoteCode, ...]


_FIELDS = frozenset(Evidence.__dataclass_fields__)


def job_key(threat_digest: str, level: int, image_sha256: str) -> str:
    """``"<threat digest>:<level>:<image hash>"`` — the one key a lab job and its
    evidence share. Both hashes are lowercase sha256 hex."""
    key = f"{threat_digest}:{level}:{image_sha256}"
    if not _JOB_KEY.fullmatch(key):
        raise EvidenceError("job key needs two sha256 hex digests and a level 1-4")
    return key


def is_sha256(value: object) -> bool:
    """Whether *value* is lowercase sha256 hex."""
    return isinstance(value, str) and _SHA256.fullmatch(value) is not None


def is_job_key(value: object) -> bool:
    """Whether *value* has the shape :func:`job_key` builds."""
    return isinstance(value, str) and bool(_JOB_KEY.fullmatch(value))


def validate_evidence(mapping: Mapping[str, Any]) -> Evidence:
    """The :class:`Evidence` *mapping* describes, or :class:`EvidenceError`.

    Every field is required, unknown fields are refused, and every cap holds.
    """
    if not isinstance(mapping, Mapping):
        raise EvidenceError("evidence must be a JSON object")
    unknown = set(mapping) - _FIELDS
    missing = _FIELDS - set(mapping)
    if unknown or missing:
        raise EvidenceError(f"evidence fields: unknown {sorted(unknown)}, missing {sorted(missing)}")
    key = _text(mapping["job_key"], "job_key")
    matched = _JOB_KEY.fullmatch(key)
    if not matched:
        raise EvidenceError("job_key is not '<sha256>:<level>:<sha256>'")
    image = _sha256(mapping["image_sha256"], "image_sha256")
    level = _integer(mapping["level"], "level")
    if (int(matched.group(2)), matched.group(3)) != (level, image):
        raise EvidenceError("job_key does not match level and image_sha256")
    started, finished = _integer(mapping["started_at"], "started_at"), _integer(mapping["finished_at"], "finished_at")
    if finished < started:
        raise EvidenceError("finished_at is before started_at")
    return Evidence(
        job_key=key,
        image_sha256=image,
        level=level,
        started_at=started,
        finished_at=finished,
        contacted_hosts=_capped(mapping["contacted_hosts"], "contacted_hosts", MAX_CONTACTED_HOSTS, canonical_host),
        file_fingerprints=_capped(mapping["file_fingerprints"], "file_fingerprints", MAX_FILE_FINGERPRINTS, _sha256),
        observations=_observations(mapping["observations"]),
        notes=_capped(mapping["notes"], "notes", MAX_NOTES, _note),
    )


def to_mapping(evidence: Evidence) -> dict[str, Any]:
    """The JSON-ready mapping :func:`validate_evidence` reads back."""
    return {
        "job_key": evidence.job_key,
        "image_sha256": evidence.image_sha256,
        "level": evidence.level,
        "started_at": evidence.started_at,
        "finished_at": evidence.finished_at,
        "contacted_hosts": list(evidence.contacted_hosts),
        "file_fingerprints": list(evidence.file_fingerprints),
        "observations": [{"check": o.check.value, "seen": o.seen} for o in evidence.observations],
        "notes": [note.value for note in evidence.notes],
    }


def to_json(evidence: Evidence) -> str:
    """Canonical JSON (sorted keys, no spaces): the same evidence is always the same bytes."""
    return json.dumps(to_mapping(evidence), sort_keys=True, separators=(",", ":"))


def _text(value: Any, field: str) -> str:
    if not isinstance(value, str):
        raise EvidenceError(f"{field} must be a string")
    return value


def _integer(value: Any, field: str) -> int:
    # bool is an int subclass; True is not a level or a timestamp.
    if isinstance(value, bool) or not isinstance(value, int) or value < 0:
        raise EvidenceError(f"{field} must be a non-negative integer")
    if field == "level" and value not in LEVELS:
        raise EvidenceError(f"level must be one of {LEVELS}")
    return value


def _sha256(value: Any, field: str) -> str:
    if not is_sha256(_text(value, field)):
        raise EvidenceError(f"{field} must be lowercase sha256 hex")
    return value


def canonical_host(value: Any, field: str) -> str:
    """*value* as the one spelling evidence stores a host in (an IP address canonical, a
    hostname lowercase and well-formed), else :class:`EvidenceError` naming *field*."""
    host = _text(value, field)
    if len(host) > MAX_HOST_CHARS:
        raise EvidenceError(f"{field}: a host is at most {MAX_HOST_CHARS} characters")
    try:
        return _address_text(ipaddress.ip_address(host))
    except ValueError:
        pass
    if not _HOSTNAME.match(host):
        raise EvidenceError(f"{field}: {host[:64]!r} is not a lowercase hostname or IP address")
    return host


def _address_text(address: ipaddress.IPv4Address | ipaddress.IPv6Address) -> str:
    """One spelling per address on every Python (FIX-0090).

    CPython changed how an IPv4-mapped IPv6 address prints: ``::ffff:0:1`` on
    3.11.7, ``::ffff:0.0.0.1`` on 3.11.15 and 3.13+. The curator, the other
    curator and the lab runner (which loads this file by path) may sit on
    different patch levels, and each would sign a different Evidence for the
    same run. So the dotted form, RFC 5952 §5's recommendation, is spelt out
    here rather than trusted to ``str()``."""
    mapped = getattr(address, "ipv4_mapped", None)
    if mapped is not None:
        return f"::ffff:{mapped}"
    return str(address)


def _note(value: Any, field: str) -> NoteCode:
    note = _text(value, field)
    if len(note) > MAX_NOTE_CHARS:
        raise EvidenceError(f"{field}: a note is at most {MAX_NOTE_CHARS} characters")
    try:
        return NoteCode(note)
    except ValueError:
        raise EvidenceError(f"{field}: {note[:64]!r} is not a known note code") from None


def _capped(values: Any, field: str, cap: int, parse: Callable[[Any, str], Any]) -> tuple:
    if not isinstance(values, (list, tuple)):
        raise EvidenceError(f"{field} must be a list")
    if len(values) > cap:
        raise EvidenceError(f"{field}: {len(values)} entries, at most {cap}")
    parsed = tuple(parse(value, field) for value in values)
    if len(set(parsed)) != len(parsed):
        raise EvidenceError(f"{field} has duplicates")
    return parsed


def _observation(value: Any, field: str) -> Observation:
    if not isinstance(value, Mapping) or set(value) != {"check", "seen"}:
        raise EvidenceError(f"{field}: an observation is exactly {{check, seen}}")
    if not isinstance(value["seen"], bool):
        raise EvidenceError(f"{field}: seen must be true or false")
    try:
        return Observation(Check(value["check"]), value["seen"])
    except ValueError:
        raise EvidenceError(f"{field}: {str(value['check'])[:64]!r} is not a known check") from None


def _observations(values: Any) -> tuple[Observation, ...]:
    observations = _capped(values, "observations", len(Check), _observation)
    if len({o.check for o in observations}) != len(observations):
        raise EvidenceError("observations answers a check twice")
    return observations
