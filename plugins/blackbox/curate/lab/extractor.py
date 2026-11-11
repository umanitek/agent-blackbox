"""The Evidence Extractor — raw lab output → typed :class:`Evidence` (proposal §03.5, F-015).

Deterministic code, never an LLM. Raw lab output is attacker-shaped: a page's
DOM, the hosts its traffic named, the paths a package wrote. None of that text
crosses into the Evidence. Only four kinds of value do: hostnames or IP
addresses, sha256 fingerprints, yes/no answers to the closed :class:`Check`
list, and :class:`NoteCode` codes. Raw artifacts stay in lab storage, where
they are keyed by sha256. Their content is never copied in. Every result is
built through ``validate_evidence``, so the extractor cannot hand the
controller evidence that the readers would refuse.

The raw output is one JSON object, ``GET /jobs/<key>/output``. Every section
is optional, but at least one section or note must be present::

    {
      "job_key":     "<the job's key>",            # optional; must match the job
      "started_at":  1760000000,                   # UTC epoch seconds, required
      "finished_at": 1760000030,                   # required
      "pcap":      {"hosts": [str], "bait_seen": bool, "after_install": bool},
      "processes": [{"name": str, "phase": "install" | "run"}],   # what the probe started
      "dom":       str,                            # the rendered DOM
      "files":     {"root": str, "artifact_sha256": str, "entries": [{"path": str, "sha256": str}]},
      "urlscan":   {"page": {"domain": str}, "lists": {"domains": [], "ips": [], "hashes": []},
                    "verdicts": {"overall": {"brands": []}}},     # urlscan.io's result format
      "notes":     [str]                           # NoteCode values the lab itself set
    }

Rules:

* **Caps never truncate in silence.** More than 20 contacted hosts keeps the
  first 20 in sorted order and adds ``host-cap-reached``. More than 50
  fingerprints keeps the artifact plus the first 49 in sorted order and adds
  ``resource-cap-reached``, as does a DOM over :data:`MAX_DOM_CHARS`.
* **The result depends on the input's content, not its order.** Hosts and
  fingerprints are deduplicated and sorted, observations follow
  :class:`Check` order and notes follow :class:`NoteCode` order. The same
  output always gives the same Evidence.
* **A check is answered only by a section that can witness it (LES-011).** A
  missing section answers nothing; it never answers "no". A process list
  fully witnesses ``process-spawned`` and ``install-script-ran``, so it
  answers them yes or no. A curl in the list proves a download, but no curl
  does not prove there was none, so ``download-triggered`` and
  ``clipboard-written`` are only ever answered yes. The DOM answers
  ``wallet-prompt`` the same way.
* **Hosts are attacker-influenced** (SNI, DNS names), so a value that is not a
  hostname or an IP address is dropped, not refused. A malformed structure,
  digest or note is a broken lab, and that raises.
* **Only :class:`EvidenceError` escapes**: ``LabController.poll`` catches nothing
  else, so any other exception would stop the beat.

Pattern: pure functions. One reader per section folds into a ``_Findings``
accumulator, and ``_build`` turns that into the Evidence.

Usage::

    controller = LabController(ctx, lab_key, LabTransport(url), extract)
    evidence = extract(job, raw_output)            # raises EvidenceError only
"""

from __future__ import annotations

import ipaddress
import posixpath
from dataclasses import dataclass, field
from typing import Any, Dict, List, Mapping, Optional
from urllib.parse import urlsplit

from ...kernel import threat_ids
from ...kernel.public_suffix import registrable_domain
from . import evidence_schema
from .evidence_schema import Check, Evidence, EvidenceError, NoteCode
from .jobs import LabJob, url_part

#: The DOM the extractor reads. Past this it reads the start and notes the cap.
MAX_DOM_CHARS = 1_000_000

_SECTIONS = ("pcap", "processes", "dom", "files", "urlscan", "notes")
_TOP_LEVEL_KEYS = frozenset(_SECTIONS) | {"job_key", "started_at", "finished_at"}
_PHASES = frozenset({"install", "run"})

# Executable basenames whose start is the act itself.
_DOWNLOAD_TOOLS = frozenset({"curl", "wget", "aria2c"})
_CLIPBOARD_TOOLS = frozenset({"xclip", "xsel", "wl-copy", "pbcopy"})

# DOM markers, matched against the DOM lowercased with ALL whitespace removed,
# so 'type = "password"' and 'type="password"' read alike. A plain substring
# scan is linear: no regex runs over attacker text (FIX-0025).
_PASSWORD_INPUT = ('type="password"', "type='password'", "type=password")
_WALLET_MARKERS = ("window.ethereum", "eth_requestaccounts", "walletconnect", "window.solana",
                   "seedphrase", "recoveryphrase", "mnemonicphrase")
_OBFUSCATION_MARKERS = ("eval(atob(", "eval(unescape(", "eval(function(p,a,c,k,e,", "string.fromcharcode(",
                        "\\x65\\x76\\x61\\x6c")


@dataclass
class _Findings:
    """What the section readers found, before the caps and the canonical order."""

    hosts: set = field(default_factory=set)
    artifact: Optional[str] = None
    fingerprints: set = field(default_factory=set)
    observations: dict[Check, bool] = field(default_factory=dict)
    notes: set = field(default_factory=set)

    def answer(self, check: Check, seen: bool) -> None:
        """Record an answer. Yes wins over no: a second section can add a
        sighting but cannot erase one."""
        self.observations[check] = self.observations.get(check, False) or seen

    def add_host(self, value: Any) -> None:
        host = _contact_host(value)
        if host is not None:
            self.hosts.add(host)


def extract(job: LabJob, raw: Mapping[str, Any]) -> Evidence:
    """The Evidence for *job* in the lab's raw output *raw* (format in the
    module doc). Satisfies ``controller.Extractor``. Raises :class:`EvidenceError`
    and nothing else."""
    try:
        return _extract(job, raw)
    except EvidenceError:
        raise
    except (TypeError, ValueError, AttributeError, KeyError, UnicodeError) as exc:
        # A shape no reader anticipated. It is still unusable output, never a crash.
        raise EvidenceError(f"unreadable lab output ({type(exc).__name__})") from None


def _extract(job: LabJob, raw: Mapping[str, Any]) -> Evidence:
    if not isinstance(raw, Mapping):
        raise EvidenceError("lab output must be a JSON object")
    unknown = set(raw) - _TOP_LEVEL_KEYS
    if unknown:
        raise EvidenceError(f"lab output has unknown sections {sorted(str(key) for key in unknown)[:5]}")
    if raw.get("job_key", job.key) != job.key:
        raise EvidenceError("the lab answered with another job's output")
    if not any(section in raw for section in _SECTIONS):
        raise EvidenceError("lab output has no section")
    findings = _Findings()
    if "pcap" in raw:
        _read_pcap(raw["pcap"], findings)
    if "processes" in raw:
        _read_processes(raw["processes"], findings)
    if "dom" in raw:
        _read_dom(raw["dom"], findings)
    if "files" in raw:
        _read_files(raw["files"], findings)
    if "urlscan" in raw:
        _read_urlscan(raw["urlscan"], job.identifier, findings)
    if "notes" in raw:
        _read_notes(raw["notes"], findings)
    return _build(job, raw.get("started_at"), raw.get("finished_at"), findings)


# -- section readers -----------------------------------------------------------

def _read_pcap(section: Any, findings: _Findings) -> None:
    pcap = _mapping(section, "pcap")
    hosts = _list(pcap.get("hosts", []), "pcap.hosts")
    for host in hosts:
        findings.add_host(host)
    findings.answer(Check.NETWORK_CONTACTED, bool(hosts))
    if "bait_seen" in pcap:
        findings.answer(Check.BAIT_CREDENTIAL_SENT, _flag(pcap["bait_seen"], "pcap.bait_seen"))
    if _flag(pcap.get("after_install", False), "pcap.after_install"):
        findings.notes.add(NoteCode.NETWORK_AFTER_INSTALL)


def _read_processes(section: Any, findings: _Findings) -> None:
    processes = _list(section, "processes")
    names, phases = set(), set()
    for entry in processes:
        process = _mapping(entry, "processes[]")
        names.add(posixpath.basename(_text(process.get("name"), "processes[].name")).lower())
        phase = process.get("phase")
        if phase not in _PHASES:
            raise EvidenceError("processes[].phase must be 'install' or 'run'")
        phases.add(phase)
    findings.answer(Check.PROCESS_SPAWNED, bool(processes))
    findings.answer(Check.INSTALL_SCRIPT_RAN, "install" in phases)
    if names & _DOWNLOAD_TOOLS:
        findings.answer(Check.DOWNLOAD_TRIGGERED, True)
    if names & _CLIPBOARD_TOOLS:
        findings.answer(Check.CLIPBOARD_WRITTEN, True)


def _read_dom(section: Any, findings: _Findings) -> None:
    dom = _text(section, "dom")
    if len(dom) > MAX_DOM_CHARS:
        dom = dom[:MAX_DOM_CHARS]
        findings.notes.add(NoteCode.RESOURCE_CAP_REACHED)
    squeezed = "".join(dom.lower().split())
    findings.answer(Check.CREDENTIAL_FORM, any(marker in squeezed for marker in _PASSWORD_INPUT))
    if any(marker in squeezed for marker in _WALLET_MARKERS):
        findings.answer(Check.WALLET_PROMPT, True)
    if any(marker in squeezed for marker in _OBFUSCATION_MARKERS):
        findings.notes.add(NoteCode.OBFUSCATED_SCRIPT)


def _read_files(section: Any, findings: _Findings) -> None:
    files = _mapping(section, "files")
    if files.get("artifact_sha256") is not None:
        findings.artifact = _digest(files["artifact_sha256"], "files.artifact_sha256")
    root = files.get("root")
    root = posixpath.normpath(_text(root, "files.root")) if root is not None else None
    outside = False
    for entry in _list(files.get("entries", []), "files.entries"):
        item = _mapping(entry, "files.entries[]")
        findings.fingerprints.add(_digest(item.get("sha256"), "files.entries[].sha256"))
        path = _text(item.get("path"), "files.entries[].path")
        if root is not None and not _inside(root, path):
            outside = True
    if root is not None:
        findings.answer(Check.FILE_WRITTEN_OUTSIDE_PACKAGE, outside)


def _read_urlscan(section: Any, identifier: str, findings: _Findings) -> None:
    """urlscan.io's result: ``lists.domains``/``lists.ips`` are the hosts contacted,
    ``lists.hashes`` the sha256 of response bodies, and ``page.domain`` the host
    after all redirects. Brand names never cross; only the fact of a match does."""
    result = _mapping(section, "urlscan")
    lists = _mapping(result.get("lists", {}), "urlscan.lists")
    hosts = _list(lists.get("domains", []), "urlscan.lists.domains") + _list(lists.get("ips", []), "urlscan.lists.ips")
    for host in hosts:
        findings.add_host(host)
    findings.answer(Check.NETWORK_CONTACTED, bool(hosts))
    # A third party's format may drift; a value that is not sha256 is not a fingerprint.
    findings.fingerprints.update(value for value in _list(lists.get("hashes", []), "urlscan.lists.hashes")
                                 if evidence_schema.is_sha256(value))
    landed = _contact_host(_mapping(result.get("page", {}), "urlscan.page").get("domain"))
    asked = _identifier_host(identifier)
    if landed and asked:
        findings.answer(Check.REDIRECTED_OFF_DOMAIN, _site(landed) != _site(asked))
    overall = _mapping(_mapping(result.get("verdicts", {}), "urlscan.verdicts").get("overall", {}),
                       "urlscan.verdicts.overall")
    if _list(overall.get("brands", []), "urlscan.verdicts.overall.brands"):
        findings.notes.add(NoteCode.BRAND_IMPERSONATION)


def _read_notes(section: Any, findings: _Findings) -> None:
    for value in _list(section, "notes"):
        try:
            findings.notes.add(NoteCode(value))
        except ValueError:
            raise EvidenceError(f"notes: {str(value)[:64]!r} is not a known note code") from None


# -- building the Evidence -------------------------------------------------------

def _build(job: LabJob, started_at: Any, finished_at: Any, findings: _Findings) -> Evidence:
    notes = set(findings.notes)
    hosts = sorted(findings.hosts)
    if len(hosts) > evidence_schema.MAX_CONTACTED_HOSTS:
        hosts = hosts[:evidence_schema.MAX_CONTACTED_HOSTS]
        notes.add(NoteCode.HOST_CAP_REACHED)
    fingerprints = ([findings.artifact] if findings.artifact else []) + sorted(findings.fingerprints - {findings.artifact})
    if len(fingerprints) > evidence_schema.MAX_FILE_FINGERPRINTS:
        fingerprints = fingerprints[:evidence_schema.MAX_FILE_FINGERPRINTS]
        notes.add(NoteCode.RESOURCE_CAP_REACHED)
    level, image = _level_and_image(job.key)
    return evidence_schema.validate_evidence({
        "job_key": job.key,
        "image_sha256": image,
        "level": level,
        "started_at": started_at,
        "finished_at": finished_at,
        "contacted_hosts": hosts,
        "file_fingerprints": fingerprints,
        "observations": [{"check": check.value, "seen": findings.observations[check]}
                         for check in Check if check in findings.observations],
        "notes": [note.value for note in NoteCode if note in notes],
    })


def _level_and_image(key: str) -> tuple:
    """The level and image hash come from the curator's own job key, not the lab's word."""
    if not evidence_schema.is_job_key(key):
        raise EvidenceError("the job's key is not '<sha256>:<level>:<sha256>'")
    _digest_part, level, image = key.split(":")
    return int(level), image


# -- small typed readers -----------------------------------------------------------

def _contact_host(value: Any) -> Optional[str]:
    """*value* as a canonical contacted host, or None when it is not one."""
    if not isinstance(value, str) or len(value) > evidence_schema.MAX_HOST_CHARS + 1:
        return None
    host = value.strip().rstrip(".").lower()
    if not host.isascii():
        try:
            host = host.encode("idna").decode("ascii")
        except UnicodeError:
            return None
    try:
        # The schema's own host rule (same package), so the extractor and the
        # validator can never disagree on what a host is.
        return evidence_schema.canonical_host(host, "contacted_hosts")
    except EvidenceError:
        return None


def _identifier_host(identifier: str) -> Optional[str]:
    """The host an identifier names: a URL's host (past any ``url:``/``ioc:url:``
    prefix, found by the job store's own URL rule), or the value of an ``ioc:domain:``
    identifier (what a domain visit is built from) or a bare ``domain:`` one."""
    url = url_part(identifier)
    if url is not None:
        try:
            return _contact_host(urlsplit(url).hostname)
        except ValueError:
            return None
    parsed = threat_ids.parse_ioc_identifier(identifier)
    if parsed is not None and parsed[0] == "domain":
        return _contact_host(parsed[1])
    if identifier.startswith("domain:"):
        return _contact_host(identifier[len("domain:"):])
    return None


def _site(host: str) -> str:
    """The registrable domain (``paypal.co.uk``). An IP address, or a host that
    is itself a public suffix, stands for itself."""
    try:
        ipaddress.ip_address(host)
        return host
    except ValueError:
        return registrable_domain(host) or host


def _inside(root: str, path: str) -> bool:
    resolved = posixpath.normpath(posixpath.join(root, path))
    return resolved == root or resolved.startswith(root.rstrip("/") + "/")


def _mapping(value: Any, name: str) -> Mapping[str, Any]:
    if not isinstance(value, Mapping):
        raise EvidenceError(f"{name} must be an object")
    return value


def _list(value: Any, name: str) -> list[Any]:
    if not isinstance(value, list):
        raise EvidenceError(f"{name} must be a list")
    return value


def _text(value: Any, name: str) -> str:
    if not isinstance(value, str):
        raise EvidenceError(f"{name} must be a string")
    return value


def _flag(value: Any, name: str) -> bool:
    if not isinstance(value, bool):
        raise EvidenceError(f"{name} must be true or false")
    return value


def _digest(value: Any, name: str) -> str:
    if not evidence_schema.is_sha256(value):
        raise EvidenceError(f"{name} must be lowercase sha256 hex")
    return value
