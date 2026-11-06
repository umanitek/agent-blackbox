"""Blackbox keeps the comments in a user's Hermes config.yaml when it writes its own settings.

2026-11-03, Hermes Desktop on a Mac: its config.yaml is ~2,400 lines, 2,147 of them comments
that document every setting. `hermes blackbox setup` added plugins.entries.blackbox by loading
the file with safe_load and writing it back with safe_dump, which left 217 lines and no
comments. Hermes 0.21.7+ ships a comment-preserving editor (hermes_yaml.roundtrip_yaml); the
plugin's YAML helpers and the installer's config writers (.sh and .ps1) now use it, so only the
keys Blackbox sets change. Older Hermes (PyYAML, no editor) keeps the plain dump.
"""

from __future__ import annotations

import os
import re
import shlex
import subprocess
import sys
from pathlib import Path

from plugins.blackbox.kernel import yaml_files

REPO = Path(__file__).resolve().parents[2]
INSTALL_SH = REPO / "scripts" / "blackbox-install.sh"
DESKTOP_LIKE = """\
# Hermes Agent CLI Configuration
# Copy settings from this example into ~/.hermes/config.yaml
model:
  # The model the agent uses by default.
  default: "nous/hermes-4"   # quoted on purpose
plugins:
  enabled:
    - blackbox
  # Per-plugin settings live under entries.
  entries: {}
"""


def _comments(text: str) -> list[str]:
    return [line.split("#", 1)[1].strip() for line in text.splitlines() if "#" in line]


def test_a_load_change_dump_keeps_every_comment_and_quote(tmp_path):
    cfg = tmp_path / "config.yaml"
    cfg.write_text(DESKTOP_LIKE, encoding="utf-8")
    data = yaml_files.load_yaml(cfg)
    data["plugins"]["entries"]["blackbox"] = {"mode": "audit"}
    yaml_files.dump_yaml(cfg, data)

    after = cfg.read_text(encoding="utf-8")
    assert _comments(after) == _comments(DESKTOP_LIKE)
    assert 'default: "nous/hermes-4"' in after
    assert yaml_files.load_yaml(cfg)["plugins"]["entries"]["blackbox"] == {"mode": "audit"}


def test_a_new_file_is_still_written_plainly(tmp_path):
    cfg = tmp_path / "new.yaml"
    yaml_files.dump_yaml(cfg, {"plugins": {"entries": {"blackbox": {"mode": "block"}}}})
    assert yaml_files.load_yaml(cfg) == {"plugins": {"entries": {"blackbox": {"mode": "block"}}}}


def _function(name: str) -> str:
    text = INSTALL_SH.read_text(encoding="utf-8")
    match = re.search(rf"^{re.escape(name)}\(\)\s*\{{\s*\n(?P<body>.*?)^\}}", text, re.MULTILINE | re.DOTALL)
    assert match is not None, f"{name}() not found"
    return match["body"]


def test_the_installers_mode_writer_keeps_the_users_comments(tmp_path):
    """write_blackbox_mode run for real, with this repository's Hermes (hermes_yaml) as its Python."""
    home = tmp_path / "hermes"
    home.mkdir()
    cfg = home / "config.yaml"
    cfg.write_text(DESKTOP_LIKE, encoding="utf-8")
    venv_bin = tmp_path / "venv" / "bin"
    venv_bin.mkdir(parents=True)
    python = venv_bin / "python"
    python.write_text(f"#!/bin/sh\nPYTHONPATH={shlex.quote(str(REPO))} exec {shlex.quote(sys.executable)} \"$@\"\n",
                      encoding="utf-8")
    python.chmod(0o755)
    script = f"""set -euo pipefail
write_blackbox_mode() {{
{_function("write_blackbox_mode")}
}}
VENV_DIR={shlex.quote(str(tmp_path / "venv"))}
HERMES_HOME={shlex.quote(str(home))}
write_blackbox_mode block
"""
    run = tmp_path / "run.sh"
    run.write_text(script, encoding="utf-8")
    result = subprocess.run(["bash", str(run)], capture_output=True, text=True, check=False,
                            env={**os.environ, "PATH": f"{venv_bin}:/usr/bin:/bin"})

    assert result.returncode == 0, result.stdout + result.stderr
    after = cfg.read_text(encoding="utf-8")
    assert _comments(after) == _comments(DESKTOP_LIKE)
    assert yaml_files.load_yaml(cfg)["plugins"]["entries"]["blackbox"]["mode"] == "block"


def test_every_installer_config_writer_uses_the_roundtrip_editor():
    for installer in (INSTALL_SH, INSTALL_SH.with_suffix(".ps1")):
        text = installer.read_text(encoding="utf-8")
        writers = text.count("yaml.safe_dump(data, f, default_flow_style=False, sort_keys=False)")
        assert writers == text.count("        editor.dump(data, f)") == 2, installer.name
        assert text.count('_roundtrip = getattr(yaml, "roundtrip_yaml", None)') >= 2, installer.name
