"""The add-on places the agent sandbox keeps closed to writes, as it keeps the plugin's own.

Every add-on folder beside the plugin (``kernel.addons.folders``) and every place the loaded add-ons
declare (``kernel.addons.places``; a ``*`` pattern expanded to what exists now, bounded). WHY
(private security finding, security round 3): the hook guarded these, the kernel profile did not —
a sandboxed agent's script the static judge could not read changed and removed a file inside an
add-on's folder. Asked on every ``sandbox.sync`` (the helper's watch plan polls it about every
2 s), so an add-on installed after the profile was written is covered within seconds.

Usage::

    of(Path("~/.hermes/plugins").expanduser())   # ["/Users/me/.hermes/plugins/example_companion", …]
"""

from __future__ import annotations

import glob
from pathlib import Path

from ....kernel import addons

#: The most add-on places put in the profile.
MAX_ADDON_PLACES = 200


def of(plugins_dir: Path) -> list[str]:
    """The add-on folders in *plugins_dir* and the places the loaded add-ons declare."""
    places = list(addons.folders(str(plugins_dir)))
    for place in addons.places():
        places += sorted(glob.glob(place))[:MAX_ADDON_PLACES] if any(mark in place for mark in "*?[") else [place]
    return places[:MAX_ADDON_PLACES]


__all__ = ["MAX_ADDON_PLACES", "of"]
