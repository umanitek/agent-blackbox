"""Linux's system protection helper (``helper/src/platform/linux/install.rs`` writes these): its
root-only folder, its program, its systemd unit, its public receipt, and the person's key folder
(``$XDG_CONFIG_HOME/blackbox/helper``, else ``~/.config/blackbox/helper``)."""

from __future__ import annotations

import os
from pathlib import Path

HOME = Path("/var/lib/blackbox/netd")
BINARY = Path("/usr/local/libexec/blackbox/blackbox-netd")
#: The systemd unit's name (what ``systemctl`` takes).
LABEL = "blackbox-netd.service"
#: The service definition the helper's own install writes (a systemd unit).
SERVICE = Path("/etc/systemd/system") / LABEL
SERVICE_KIND = "systemd service"
#: ``sha256 <hex>`` of the installed program, 0644, readable without root.
RECEIPT = Path("/var/lib/blackbox/netd-installed")


def user_key_folder() -> Path:
    """The person's folder holding the key that signs the helper's plans and checks its reports."""
    config = os.environ.get("XDG_CONFIG_HOME", "").strip()
    base = Path(config) if config.startswith("/") else Path.home() / ".config"
    return base / "blackbox" / "helper"
