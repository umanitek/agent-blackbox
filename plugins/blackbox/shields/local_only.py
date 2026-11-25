"""Which source a shield finding carries so it never leaves the machine.

Every shield finding is local-only (community.NEVER_SHARED_SOURCES). A finding whose source is
already local-only is kept as raised; any other source becomes :data:`LOCAL_ONLY_SOURCE`.
"""

from __future__ import annotations

import dataclasses
import logging

from ..detection import Finding

logger = logging.getLogger(__name__)

#: The finding source a shield finding is given when it names no local-only one itself: never shared
#: (community.NEVER_SHARED_SOURCES).
LOCAL_ONLY_SOURCE = "secret"
#: Sources that are already local-only and are KEPT as raised. "custom" is the person's own rule
#: (File Shield, protected paths): the audit log keeps its fields (item, path, route) and the refusal
#: names it as the person's rule. WHY (KI-530, E2E full3 2026-11-22): rewriting "custom" to "secret"
#: dropped those fields (every hit row had an empty item) and named File Shield "built-in secret
#: protection".
LOCAL_ONLY_SOURCES = frozenset({"custom", LOCAL_ONLY_SOURCE})


def local_only(shield_id: str, finding: Finding) -> Finding:
    """*finding* marked never-shared: a local-only source is kept, any other becomes LOCAL_ONLY_SOURCE."""
    if finding.source in LOCAL_ONLY_SOURCES:
        return finding
    logger.warning("blackbox: shield %s finding %s had source %r; made local-only",
                   shield_id, finding.identifier, finding.source)
    return dataclasses.replace(finding, source=LOCAL_ONLY_SOURCE)
