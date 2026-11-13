"""Sources — look-ups against outside threat sources for the curator's dossier and beat.

Pattern: Strategy — one strategy per outside source, chosen from a registry.

Public surface:

* ``SOURCES`` — the registry of source strategies (a frozen tuple; adding a
  source is a deliberate code change): OSV/GHSA, URLhaus, ThreatFox,
  MalwareBazaar (one shared abuse.ch fetcher and Auth-Key), PhishTank,
  ScamSniffer (look-up only) and urlscan.io (the level-3 visit). Each
  carries its publisher ``terms`` row (§03.3 table).
* ``Source`` / ``SourceTerms`` / ``SourceVerdict`` — the Strategy, its
  publisher terms, and its answer (reusing ``service.evidence.Lookup``).
* ``SourceRegistry.lookup(items, budget, today=…)`` — ask every source about
  the items a beat's ``LookupBudget`` selects.
* ``TokenBucket`` — one per source, its own lock, honouring each source's rate limit.
* ``NotListedCache`` — one lock, ``<curate home>/sources/not_listed_cache.json``.
* ``queue_metrics`` — queue depth and oldest item age for the console / Slack.
* ``UrlscanScan`` — a finished urlscan.io visit; its ``lab_output()`` is the
  Evidence Extractor's raw input for a level-3 job.
* ``WithdrawalWatcher`` — the weekly re-check of source-cited confirmations:
  a withdrawn source → a REVOCATION proposal (signed through the choke
  point); an address untested for 180 days → a ``CorrectionRequest`` for the
  P5 path; ``rechecks_for(SOURCES)`` builds its per-source re-checks.
* ``load_credentials`` — source keys from ``<curate home>/sources/credentials.json``
  (mode 0600), never in the repo or in logs.
"""


from .budget import LookupBudget, LookupItem, QueueMetrics, TokenBucket, queue_metrics, select_for_lookup
from .cache import NotListedCache
from .credentials import CredentialsError, load_credentials
from .abusech import AbuseChFetcher, MalwareBazaarSource, ThreatFoxSource, UrlhausSource
from .osv import OsvSource
from .phishtank import PhishTankSource
from .scamsniffer import ScamSnifferSource
from .urlscan import UrlscanScan, UrlscanSource
from .withdrawal import CitedConfirmation, CorrectionRequest, Extension, WithdrawalReport, WithdrawalWatcher, rechecks_for
from .protocol import LookupResult, Source, SourceRegistry, SourceTerms, SourceVerdict

_ABUSE_CH = AbuseChFetcher()
SOURCES: tuple[Source, ...] = (
    OsvSource(), UrlhausSource(_ABUSE_CH), ThreatFoxSource(_ABUSE_CH), MalwareBazaarSource(_ABUSE_CH), PhishTankSource(),
    ScamSnifferSource(), UrlscanSource(),
)

__all__ = [
    "SOURCES",
    "CitedConfirmation",
    "CorrectionRequest",
    "CredentialsError",
    "Extension",
    "LookupBudget",
    "LookupItem",
    "LookupResult",
    "NotListedCache",
    "QueueMetrics",
    "Source",
    "SourceRegistry",
    "SourceTerms",
    "SourceVerdict",
    "TokenBucket",
    "UrlscanScan",
    "WithdrawalReport",
    "WithdrawalWatcher",
    "load_credentials",
    "queue_metrics",
    "rechecks_for",
    "select_for_lookup",
]
