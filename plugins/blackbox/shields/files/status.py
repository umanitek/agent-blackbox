"""File Shield's dashboard card: what it protects, whether agents were refused, and whether the
real-time watch is running.

Protection runs inside Blackbox's own guard, so a protected item is protected whenever the shield
is on — no helper needed. The real-time watch (changes inside protected items and watched
folders) is the system protection helper's: without it the card says so plainly. An add-on
(Blackbox Desktop: fingerprints and file reputation) may decorate the card.
"""

from __future__ import annotations

from ...kernel.config import load_blackbox_config
from ...kernel import system_helper
from ..contract import ShieldMode, ShieldStatus, StatusRow, StatusSection
from . import changes, events, mode as mode_module
from .protect import is_folder

#: Items listed on the card before "and N more".
MAX_ROWS = 8


def _items_section(mode: ShieldMode) -> StatusSection:
    items = mode_module.protected(mode)
    counts: dict[str, int] = {}
    for hit in events.hits():
        counts[hit["item"]] = counts.get(hit["item"], 0) + 1
    rows = tuple(StatusRow(icon="folder" if is_folder(item) else "file", state="on", text=item,
                           sub=f"{counts[item]} refused" if counts.get(item) else "No agent has tried")
                 for item in items[:MAX_ROWS])
    if len(items) > MAX_ROWS:
        rows += (StatusRow(icon="more", state="on", text=f"and {len(items) - MAX_ROWS} more"),)
    if not items:
        rows = (StatusRow(icon="file", state="off", text="Nothing protected yet",
                          sub="Add a file or folder no AI agent may touch."),)
    return StatusSection("Protected from every AI agent",
                         "Refused in Audit and Block mode, by any route an agent's tools take.", rows)


def _watch_section(mode: ShieldMode) -> StatusSection:
    installed = system_helper.LAUNCH_DAEMON.is_file()   # the helper is installed (its LaunchDaemon)
    last = changes.recent(1)
    row = (StatusRow(icon="live", state="on", text="Watching in real time",
                     sub=f"{len(mode_module.watch_paths(mode))} places; last change {last[0].path}" if last
                     else f"{len(mode_module.watch_paths(mode))} places")
           if installed else
           StatusRow(icon="live", state="needs-helper", text="Real-time watch needs the system protection helper",
                     sub="Install it with Blackbox's installer (system protection), or from Blackbox Desktop."))
    return StatusSection("Real-time watch", "Changes inside protected items and new files in watched folders.", (row,))


def build(mode: ShieldMode) -> ShieldStatus:
    """The card for *mode*."""
    return ShieldStatus(shield_id=mode_module.SHIELD_ID, mode=mode, blocking=load_blackbox_config().mode == "block",
                        sections=(_items_section(mode), _watch_section(mode)) if mode.enabled else ())
