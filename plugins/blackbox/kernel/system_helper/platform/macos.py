"""macOS's system protection helper: its root-only folder, its program, its LaunchDaemon (system
domain), its public receipt, and the person's key folder (``~/Library/Application Support/Blackbox/helper``)."""

from __future__ import annotations

from pathlib import Path

HOME = Path("/Library/Application Support/Blackbox/netd")
BINARY = HOME / "blackbox-netd"
LABEL = "ai.umanitek.blackbox.netd"
#: The service definition the helper's own install writes (a LaunchDaemon).
SERVICE = Path("/Library/LaunchDaemons") / f"{LABEL}.plist"
SERVICE_KIND = "LaunchDaemon"
#: How a person installs it here (the cards that need it say this).
INSTALL_HOW = "Install it with Blackbox's installer (system protection), or from a companion app that offers it."
#: ``sha256 <hex>`` of the installed program, 0644, readable without root.
RECEIPT = HOME.parent / "netd-installed"


def user_key_folder() -> Path:
    """The person's folder holding the key that signs the helper's plans and checks its reports."""
    return Path.home() / "Library" / "Application Support" / "Blackbox" / "helper"
