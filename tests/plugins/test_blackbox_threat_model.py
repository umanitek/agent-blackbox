"""The threat model names only tests and code that exist.

Contract (2026-11-24): every test file and every ``plugins/blackbox/…`` path that
``plugins/blackbox/docs/THREAT_MODEL.md`` cites is in the repository, so a claim "checked by" a test
can not quietly point at a test that was renamed or removed.
"""

from __future__ import annotations

import re
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
MODEL = ROOT / "plugins" / "blackbox" / "docs" / "THREAT_MODEL.md"


def test_every_test_and_path_the_threat_model_cites_exists():
    text = MODEL.read_text(encoding="utf-8")
    cited = set(re.findall(r"`((?:tests|plugins/blackbox)/[\w./-]+?)`", text))
    assert len([c for c in cited if c.startswith("tests/")]) > 40
    missing = sorted(c for c in cited if not (ROOT / c.rstrip("/")).exists())
    assert missing == []
