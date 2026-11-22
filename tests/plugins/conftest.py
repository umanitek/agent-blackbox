"""Make ``tests/plugins`` importable for shared helpers (e.g. ``_blackbox_loader``)."""

import os
import sys
from pathlib import Path

_HERE = str(Path(__file__).resolve().parent)
if _HERE not in sys.path:
    sys.path.insert(0, _HERE)

import pytest

from plugins.blackbox.community import consent as _consent_module

_REAL_IN_FORCE = _consent_module.in_force


@pytest.fixture(autouse=True)
def _no_system_protection_helper(monkeypatch, tmp_path):
    """Network Shield asks whether the system protection helper's LaunchDaemon is installed
    (/Library/LaunchDaemons/…). Tests never read the real machine: the helper is absent unless a
    test installs its own (``helper.LAUNCH_DAEMON`` pointed at a file it creates)."""
    from plugins.blackbox.shields.network import helper
    monkeypatch.setattr(helper, "LAUNCH_DAEMON", tmp_path / "no-helper" / "ai.umanitek.blackbox.netd.plist")
    yield


@pytest.fixture(autouse=True)
def _fresh_community_membership(monkeypatch):
    """Blackbox keeps per-process subscribe/join state (community/membership/);
    each test starts from a fresh one so retry windows never leak between tests.
    Only touches the module when a test has already imported it."""
    for name in ("plugins.blackbox.community.membership", "hermes_plugins.blackbox.community.membership"):
        module = sys.modules.get(name)
        if module is not None:
            monkeypatch.setattr(module, "MEMBERSHIP", module.CommunityMembership())
    yield


class _NothingAddedYet:
    """KI-449 test double: no community subscription recorded, and nothing written to the
    real Blackbox home. The record itself is tested with an explicit
    ``CommunityMembership(readiness=GraphReadiness(...))``."""

    def shared_memory_added(self, graph):
        return False

    def mark_shared_memory_added(self, graph):
        return None


@pytest.fixture(autouse=True)
def _verified_graph_ready(monkeypatch):
    """Membership's community record (KI-449) never touches the real Blackbox home in
    tests. Only touches the module when a test has already imported it."""
    for name in ("plugins.blackbox.community.membership", "hermes_plugins.blackbox.community.membership"):
        module = sys.modules.get(name)
        if module is not None:
            monkeypatch.setattr(module, "READINESS", _NothingAddedYet())
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


class _InlineReports:
    """Report follow-up run at once on the calling thread: a test that calls a hook can
    assert on the private record and the share right after. The real queue has its own
    tests (test_blackbox_report_queue.py), which ask for ``real_report_queue``."""

    def submit(self, job):
        job()
        return True

    def settled(self, timeout_s):
        return True


@pytest.fixture(autouse=True)
def _report_follow_up_inline(request, monkeypatch):
    if "real_report_queue" in request.fixturenames:
        yield
        return
    for name in ("plugins.blackbox.guard.report_queue", "hermes_plugins.blackbox.guard.report_queue"):
        module = sys.modules.get(name)
        if module is not None:
            monkeypatch.setattr(module, "REPORTS", _InlineReports())
    yield


@pytest.fixture
def real_report_queue():
    """Keep the real background report queue for one test (undoes the autouse inline stub)."""
    from plugins.blackbox.guard import report_queue
    return report_queue.REPORTS


@pytest.fixture(autouse=True)
def _no_real_notifications(monkeypatch):
    """A test that starts the dashboard app also starts the notification pump (``notify.PUMP``),
    and a real tick would read this machine's processes and could show a real notification on
    the developer's screen. The pump does not start and the system notifier shows nothing unless
    a test injects its own."""
    from plugins.blackbox import notify
    for module in (notify, sys.modules.get("hermes_plugins.blackbox.notify")):
        if module is None:
            continue
        nothing = module.Delivery("not-shown", "a test never shows a notification")
        monkeypatch.setattr(module.Pump, "start", lambda self: None)
        monkeypatch.setattr(module.platform, "send", lambda *args, **kwargs: nothing)
        monkeypatch.setattr(module.platform, "request", lambda: module.platform.status())     # macOS never asks from a test
        monkeypatch.setattr(module.platform, "open_settings", lambda: False)
    yield


# ---- never the real home (2026-11-22) -----------------------------------------------------------
# A Blackbox test that wrote to the developer's real ~/.hermes/blackbox (File Shield state, a
# ruleset) and a test dashboard that showed real notifications on the founder's Mac: every
# Blackbox test runs with HOME pointed at its own temporary folder, and a test run that creates
# the real ~/.hermes/blackbox fails.

_REAL_HOME = Path.home()
_REAL_BLACKBOX = _REAL_HOME / ".hermes" / "blackbox"
_BLACKBOX_EXISTED = {"before": _REAL_BLACKBOX.exists()}


def pytest_configure(config):
    """Before any test module is imported (several read ``~`` at import): a run of Blackbox test
    files gets HOME — and any Hermes/Blackbox/DKG home still inside the real one — in a temporary
    folder of its own. ``scripts/run_tests.sh`` runs one file per process, so this is per file."""
    if not any(Path(str(arg).split("::")[0]).name.startswith("test_blackbox_") for arg in config.args):
        return
    import tempfile
    home = Path(tempfile.mkdtemp(prefix="blackbox-test-home-"))
    os.environ["HOME"] = str(home)
    for name in ("HERMES_HOME", "BLACKBOX_HOME", "BLACKBOX_DKG_HOME"):
        value = os.environ.get(name, "")
        inside = bool(value) and Path(value).expanduser().resolve().is_relative_to(_REAL_HOME.resolve())
        if inside or (name == "HERMES_HOME" and not value):
            os.environ[name] = str(home / (".hermes" if name == "HERMES_HOME" else name.lower()))


def pytest_sessionfinish(session, exitstatus):
    """Fail the run when its tests created Blackbox's home inside the developer's real home."""
    if not _BLACKBOX_EXISTED["before"] and _REAL_BLACKBOX.exists():
        session.exitstatus = 1
        print(f"\nBLACKBOX TEST GUARD: a test created {_REAL_BLACKBOX} — tests must never write to the real home.")
