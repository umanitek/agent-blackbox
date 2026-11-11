"""Lab — the curator side of the threat lab: sends jobs to the lab and pulls back evidence.

Patterns: Command (a ``LabJob`` is the request object) + State (the job
lifecycle); the Evidence Extractor is pure functions.

Public surface:

* ``LabJobStore`` (``jobs.py``) — one lock, ``<curate home>/lab/jobs.jsonl``,
  bounded at 500 open jobs (a full store REFUSES); evidence files at
  ``<curate home>/lab/evidence/<sha256>.json``.
* ``validate_evidence`` / ``to_json`` (``evidence_schema.py``) — the evidence
  contract, standard library only; the lab runner (``integrations/threat-lab/``,
  a separate deployable, not plugin code) loads this one file by path.
* ``LabTransport`` (``transport.py``) — the link to the lab over the tunnel's
  loopback port: one hard timeout, three outcomes (``LabOutcome``).
* ``LabController`` (``controller.py``) — the only party that talks to the lab:
  submit, poll, collect, sign (through ``CurateContext.sign``), store; at most
  3 runs a job; ``lab_only_verdict_may_block`` (the tier rule) and
  ``LabMetrics`` (jobs/h, queue depth, oldest job age, the scale rule).

* ``extract`` / ``Extractor`` (``extractor.py`` / ``controller.py``) — the
  Evidence Extractor: raw lab output → typed Evidence, pure functions; wire it
  as ``LabController(ctx, key, LabTransport(url), extract)``.

Imported by path, not from this surface (``curate.service`` loads this package
at import time, and these read ``curate.service``):

* ``trigger.py`` — the lab trigger rule (``lab_trigger``), the level order,
  the beat's wait-and-flag submit step (``submit_candidate``) and the
  human-act log of typed requests (``LabRequests``).
* ``commands.py`` — ``blackbox curate lab <identifier>`` / ``lab status``,
  registered by ``curate/parser.py``.
"""

from .evidence_schema import Check, Evidence, EvidenceError, NoteCode, Observation, to_json, validate_evidence
from .jobs import LabJob, LabJobError, LabJobRecord, LabJobState, LabJobStore, strip_query
from .transport import LabAnswer, LabOutcome, LabTransport
from .extractor import extract
from .controller import (Extractor, LabController, LabMetrics, ScaleStep, SignedEvidence,
                         lab_only_verdict_may_block, verify_signed_evidence)

__all__ = [
                         "Check",
                         "Evidence",
                         "EvidenceError",
                         "Extractor",
                         "LabAnswer",
                         "LabController",
                         "LabJob",
                         "LabJobError",
                         "LabJobRecord",
                         "LabJobState",
                         "LabJobStore",
                         "LabMetrics",
                         "LabOutcome",
                         "LabTransport",
                         "NoteCode",
                         "Observation",
                         "ScaleStep",
                         "SignedEvidence",
                         "extract",
                         "lab_only_verdict_may_block",
                         "strip_query",
                         "to_json",
                         "validate_evidence",
                         "verify_signed_evidence",
]
