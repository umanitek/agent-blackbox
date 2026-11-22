"""Whether the system protection helper is on this machine — what DNS Shield, the Threat Firewall,
cutting connections, SSH lockdown and Lock remote access need.

The helper (``blackbox-netd``) is a small root daemon: it applies the plan Network Shield builds
(:mod:`.protect.enforcement`) and reports back. It is installed as the LaunchDaemon
:data:`LAUNCH_DAEMON` — by Blackbox's installer when the person says yes to system protection, or
by a companion app. Installed is not the same as working: a protection is shown active only
while the helper REPORTS it active (:func:`.protect.enforcement.summary`).

Usage::

    from plugins.blackbox.shields.network import helper
    helper.installed()   # True once the LaunchDaemon is in place
"""

from __future__ import annotations

from ...kernel import system_helper

#: The helper's launchd label and its LaunchDaemon file (root-owned, system domain).
LABEL = system_helper.LABEL
LAUNCH_DAEMON = system_helper.LAUNCH_DAEMON


def installed() -> bool:
    """True when the system protection helper is installed on this machine."""
    try:
        return LAUNCH_DAEMON.is_file()
    except OSError:   # an unreadable /Library is "not installed", never a crash
        return False
