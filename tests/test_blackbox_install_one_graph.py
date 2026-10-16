"""One graph (2026-10-16): the installers drop the retired community graph's settings.

Community reports live in the verified graph's shared memory, so an update removes
``community_graph_id`` and ``community_graph_peer_id`` from an existing config —
on Unix and on Windows — and leaves the verified graph's own settings alone.
"""

from __future__ import annotations

import re
import subprocess
import sys
from pathlib import Path

from tests.test_blackbox_install_llm_setup import INSTALL_PS1, _run_unix_blackbox_config_writer


def test_unix_installer_drops_the_retired_community_graph_settings(tmp_path: Path) -> None:
    """One graph (2026-10-16): community reports live in the verified graph's shared
    memory, so an update removes the separate community graph and its owner's peer id
    from an existing config, and leaves the verified graph's own settings alone."""
    config_path = tmp_path / "config.yaml"
    config_path.write_text(
        "plugins:\n  entries:\n    blackbox:\n"
        "      context_graph_id: owner/custom-graph\n"
        "      community_graph_id: 0xowner/agent-blackbox-community\n"
        "      community_graph_peer_id: 12D3KooWowner\n",
        encoding="utf-8",
    )
    configured = _run_unix_blackbox_config_writer(
        config_path,
        dkg_url="http://127.0.0.1:9320",
        dkg_home=tmp_path / ".dkg",
        dkg_bin=tmp_path / "dkg" / "node_modules" / ".bin" / "dkg",
    )
    blackbox = configured["plugins"]["entries"]["blackbox"]
    assert "community_graph_id" not in blackbox and "community_graph_peer_id" not in blackbox
    assert blackbox["context_graph_id"] == "owner/custom-graph"


def test_windows_installer_drops_the_retired_community_graph_settings(tmp_path: Path) -> None:
    """The Windows config writer (the Python the installer hands to Hermes' interpreter)
    drops the retired community graph settings the same way."""
    writer = re.search(r"\$configWriter = @'\n(?P<code>.*?)\n'@", INSTALL_PS1.read_text(encoding="utf-8"), re.DOTALL)
    assert writer is not None
    config_path = tmp_path / "config.yaml"
    config_path.write_text(
        "plugins:\n  entries:\n    blackbox:\n"
        "      community_graph_id: 0xowner/agent-blackbox-community\n"
        "      community_graph_peer_id: 12D3KooWowner\n",
        encoding="utf-8",
    )
    subprocess.run(
        [sys.executable, "-c", writer["code"], str(config_path), "http://127.0.0.1:9320", str(tmp_path / ".dkg"),
         str(tmp_path / "dkg.cmd"), "owner/agent-blackbox-vm", "curator-peer"],
        check=True, capture_output=True, text=True,
    )
    import hermes_yaml as yaml

    blackbox = yaml.safe_load(config_path.read_text(encoding="utf-8"))["plugins"]["entries"]["blackbox"]
    assert "community_graph_id" not in blackbox and "community_graph_peer_id" not in blackbox
    assert blackbox["context_graph_id"] == "owner/agent-blackbox-vm"
