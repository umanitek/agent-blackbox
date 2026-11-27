"""An agent writing the machine's own folders as root — refused in Block mode, flagged in Audit.

Private security finding ``2026-11-24-linux-passwordless-sudo-turns-a-hooks-on`` (Linux round L1,
High): on a machine with passwordless sudo (Ubuntu's cloud images, most CI runners, many dev
boxes), REAL Claude Code and REAL Codex ran ``echo … | sudo -n tee /etc/cron.d/x``, wrote
``/etc/sudoers.d`` and ``/etc/profile.d`` files and ``sudo systemctl enable``\\ d a root unit they
had copied into ``/etc/systemd/system`` — every one only flagged as "an agent asked for root".

The sudo policy (Block mode):

* a privileged write to a persistence place (``/etc/cron.d``, ``sudoers.d``, ``profile.d``,
  ``systemd/system``, ``ld.so.preload``, PAM …) is refused in EVERY mode, as any write there is
  (``persistence_writes``; ``systemctl enable`` of a system unit is a scheduler there too);
* a privileged write to any other place of the machine's own (``kernel.persistence_places.ROOT_PLACES``:
  ``/etc``, ``/usr``, ``/boot``, ``/bin``, ``/lib*``, ``/var/spool``, root's home …) is refused here
  in Block mode and flagged in Audit mode — ``sudo tee /etc/hosts``, ``sudo cp x /usr/local/bin/git``,
  ``sudo sed -i … /etc/pam.d/sudo``, ``sudo rm -rf /etc/…``;
* every other ``sudo`` stays a flag (``elevation``, the person's decision D7: agents keep their
  sudo) — ``sudo apt install``, ``sudo systemctl restart nginx``, ``sudo cat /var/log/syslog``.

WHY only a privileged command: without root such a write fails anyway, and ``/usr/local`` is the
person's own on an Intel Mac (Homebrew). The command is read as every path check reads it (nested
shells, ``tee``, copies, links, ``sed -i``, ``dd of=`` …: ``guard_settings.tampering``) against the
ROOT place set (``guard_places.judging``). A program that writes as root without naming the place
(``sudo make install``, ``sudo apt install``) is beyond a hook: only the flag remains.

Usage::

    detect_privileged_write("terminal", {"command": "echo 1.2.3.4 x | sudo tee -a /etc/hosts"})
    # -> [Finding(identifier="fileaccess:terminal:root-write", severity="critical", ...)]
    detect_privileged_write("terminal", {"command": "sudo apt install jq"})   # -> []
"""

from __future__ import annotations

from typing import Any

from . import shell_shapes
from .elevation import way_of
from .finding import Finding
from ..kernel import persistence_places, threat_ids
from .paths import guard_places, guard_settings

MATCHED = persistence_places.ROOT_WRITE
TITLE = "Would change the machine's own files as root"
ADVICE = ("An AI agent may not use sudo to change this machine's own folders (/etc, /usr, /boot and the like): "
          "in Block mode Blackbox refuses it. If you meant it, run the command yourself in your own terminal.")
_EVIDENCE = {"command": "a command run as root that writes a system folder", "long": "a command run as root, too long to read whole"}


def _privileged(command: str) -> bool:
    """True when a line of *command* (nested shells included) runs a command as root."""
    return any(way_of(line) == "sudo" for line in shell_shapes.with_nested_commands(command).split("\n"))


def detect_privileged_write(tool_name: str, args: Any) -> list[Finding]:
    """A finding when a privileged shell command writes one of the machine's own folders, else []."""
    tool = (tool_name or "").strip().lower()
    try:
        if tool not in shell_shapes.SHELL_TOOLS or not _privileged(shell_shapes.whole_command_from_args(tool_name, args)):
            return []
        with guard_places.judging(guard_places.ROOT):
            _tool, how = guard_settings.tampering(tool_name, args)
        if how not in _EVIDENCE:
            return []
        return [Finding(identifier=threat_ids.fileaccess_identifier(tool, MATCHED), category="fileaccess", severity="critical",
                        title=TITLE, advice=ADVICE, tool_name=tool, matched=MATCHED, evidence=_EVIDENCE[how], confirmed=False,
                        source="custom", fields={})]
    except Exception:  # pragma: no cover  # health: allow BLE001 -- fail open: a detector fault never breaks the agent's tool call
        return []


__all__ = ["ADVICE", "MATCHED", "TITLE", "detect_privileged_write"]
