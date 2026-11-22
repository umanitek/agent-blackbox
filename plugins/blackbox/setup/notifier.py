"""``blackbox notifications`` — the plugin's own native notifier, from the command line.

* ``blackbox notifications setup [--from <archive> --sha256 <hex>]`` — put Blackbox's notifier in
  place (macOS: ``Blackbox.app`` from the verified archive; the system then asks once whether
  Blackbox may show notifications). Without an archive nothing is installed and the system's
  own notifier is used. The installer runs this step; it never fails an install.
* ``blackbox notifications status`` — what is in use, whether you allowed it, and — while it is
  off or not asked yet — how to change that (the System Settings link).
* ``blackbox notifications test`` — hand one harmless notification to the system now and say
  what became of it: "delivered to Notification Center", or why macOS did not show it (permission
  off; banners hidden while the screen is shared or mirrored). Never "shown" when it was not.

Removal needs no command: the notifier lives in Blackbox's own data folder
(``$BLACKBOX_HOME/notifier``), which ``blackbox uninstall`` removes.
"""

from __future__ import annotations

import argparse
from pathlib import Path
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from ..notify import NotifierStatus


def cmd_notifications(args: argparse.Namespace) -> int:
    from .. import notify   # late: the dashboard's packages load only when this command runs
    action = getattr(args, "notifications_command", None) or "status"
    if action == "setup":
        source = Path(args.source).expanduser() if args.source else None
        try:
            status = notify.install_notifier(source, (args.sha256 or "").strip().lower())
        except ValueError as problem:
            print(f"Blackbox's notifier was not installed: {problem}")
            return 1
        print(f"Notifications: {status.detail}")
        return 0
    if action == "test":
        delivery = notify.send_test()
        print(f"Test notification: {delivery.detail}")
        if delivery.outcome != "delivered":
            _print_settings(notify.notifier_status())
        return 0 if delivery.reached_system else 1
    status = notify.notifier_status()
    print(f"Notifications: {status.detail}")
    print(f"  notifier: {status.kind} · permission: {status.permission}")
    _print_settings(status)
    return 0


def _print_settings(status: NotifierStatus) -> None:
    """The way to change it, when there is one: the System Settings link, to open or click."""
    if status.settings:
        print(f"  {status.settings_label}: open '{status.settings}'")


def add_notifications_parser(sub: argparse._SubParsersAction) -> None:
    """Register ``blackbox notifications`` on the ``blackbox`` command's sub-parsers."""
    parser = sub.add_parser("notifications", help="Blackbox's native notifications: set up, status, test")
    actions = parser.add_subparsers(dest="notifications_command")
    setup = actions.add_parser("setup", help="Install Blackbox's own notifier from a verified archive")
    setup.add_argument("--from", dest="source", help="the notifier archive (macOS: blackbox-notify-darwin.zip)")
    setup.add_argument("--sha256", help="the archive's SHA-256 (64 hex characters)")
    actions.add_parser("status", help="What shows Blackbox's notifications, whether you allowed it, and how to change it")
    actions.add_parser("test", help="Send one harmless notification now and say whether macOS showed it")
    parser.set_defaults(func=cmd_notifications)
