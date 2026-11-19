"""The machine's MAIN Hermes home — where the one Blackbox for every profile lives (2026-11-19).

Each named Hermes profile used to keep its own Blackbox folder: no compiled verified rules (only
the general patterns fired), settings copied once, logs the dashboard never read — Blackbox's own
assistant (profile ``agent-blackbox``) was one. Now the rules, logs and settings live with the
main home (``~/.hermes`` even while a profile runs), so a chat in any profile is checked against
the same rules, under the same settings, and shows on the same dashboard.

Hermes answers (``get_default_hermes_root``) for the active home ``constants.hermes_home()``: a
profile under ``~/.hermes`` → ``~/.hermes``; a custom or Docker root's ``<root>/profiles/<name>``
→ ``<root>``; any other home (a test's temporary one) is its own root.

Usage::

    constants.hermes_root() / "config.yaml"     # the one set of Blackbox settings
"""

from __future__ import annotations

from pathlib import Path


def hermes_root() -> Path:
    """The main Hermes home for the active one; the active home itself when Hermes cannot say."""
    from .. import constants   # constants re-exports this function: imported here, not at the top

    home = constants.hermes_home()
    try:
        from hermes_constants import get_default_hermes_root

        return Path(get_default_hermes_root(home=home))
    except (ImportError, AttributeError, OSError, ValueError, TypeError):   # an older Hermes, or a home it cannot read
        return home
