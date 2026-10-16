"""Make ``tests/plugins`` importable for shared helpers (e.g. ``_blackbox_loader``)."""

import sys
from pathlib import Path

_HERE = str(Path(__file__).resolve().parent)
if _HERE not in sys.path:
    sys.path.insert(0, _HERE)

import pytest

from plugins.blackbox.community import consent as _consent_module

_REAL_IN_FORCE = _consent_module.in_force


@pytest.fixture(autouse=True)
def _fresh_community_membership(monkeypatch):
    """Blackbox keeps per-process subscribe/join state (community/membership.py);
    each test starts from a fresh one so retry windows never leak between tests.
    Only touches the module when a test has already imported it."""
    for name in ("plugins.blackbox.community.membership", "hermes_plugins.blackbox.community.membership"):
        module = sys.modules.get(name)
        if module is not None:
            monkeypatch.setattr(module, "MEMBERSHIP", module.CommunityMembership())
    yield


@pytest.fixture(autouse=True)
def _sharing_consent_in_force(monkeypatch):
    """R13: sharing is opt-in and refused without a consent record. The suite's
    share-path tests predate the gate and test OTHER things, so consent is in
    force by default; the gate's own tests ask for ``real_consent``."""
    for name in ("plugins.blackbox.community.consent", "hermes_plugins.blackbox.community.consent"):
        module = sys.modules.get(name)
        if module is not None:
            monkeypatch.setattr(module, "in_force", lambda: True)
    yield


@pytest.fixture(autouse=True)
def _no_real_dashboard_pulse(monkeypatch):
    """A test that starts the dashboard app (``with TestClient(app)``) also starts
    its PulseDriver (KI-283). A real beat runs ``ruleset.pulse`` on a thread
    nothing joins; it can finish after its test and leave community rules in
    the process-wide ruleset cache, which a later test then reads (one failure
    in three full runs on 2026-10-07: "assert 3 == 0" community threats). Real
    beats stay out of tests unless a test injects its own beat."""
    from plugins.blackbox.dashboard import pulse_driver
    monkeypatch.setattr(pulse_driver, "beat_once", lambda: None)
    yield


@pytest.fixture
def real_consent(monkeypatch):
    """The real consent gate (undoes the autouse stub for one test)."""
    from plugins.blackbox.community import consent
    monkeypatch.setattr(consent, "in_force", _REAL_IN_FORCE)
    return consent


@pytest.fixture
def time_lock_one_day(monkeypatch):
    """Run with the curator-list time-lock at ONE day. The live value is 0 (no wait,
    founder decision 2026-10-12), but the mechanism stays in place for when it is
    switched back on, so its tests pin a positive lock instead of being deleted."""
    from plugins.blackbox.kernel.signing import key_manifest
    monkeypatch.setattr(key_manifest, "MANIFEST_TIME_LOCK_DAYS", 1)


@pytest.fixture
def no_graph(monkeypatch):
    """Load settings as an install that names NO graph would: the shipped default
    is the verified graph, where the community also lives (one graph since
    2026-10-16), so tests of the dormant path say "no graph" explicitly instead of
    relying on an empty default."""
    from plugins.blackbox.kernel import constants
    monkeypatch.setattr(constants, "DEFAULT_CONTEXT_GRAPH_ID", "")
    monkeypatch.delenv("BLACKBOX_CONTEXT_GRAPH_ID", raising=False)
