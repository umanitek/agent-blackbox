"""The Unix installer runs under the bash macOS ships (3.2), the first ``bash`` on most Macs.

That bash scans the body of a heredoc inside ``$( … )`` for quotes, even a quoted
``<<'PYEOF'`` one: a single apostrophe in the embedded Python, comments included, and
it refuses the whole script before running a line of it.
"""

from __future__ import annotations

import subprocess

import pytest

from tests.test_blackbox_install_llm_setup import INSTALL_SH


@pytest.mark.platforms("macos")
def test_the_unix_installer_parses_with_the_bash_macos_ships() -> None:
    result = subprocess.run(["/bin/bash", "-n", str(INSTALL_SH)], capture_output=True, text=True,
                            check=False, timeout=60)
    assert result.returncode == 0, result.stderr
