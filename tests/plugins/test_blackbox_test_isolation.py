"""A Blackbox test never runs against the developer's real home (2026-11-22: a test wrote the real
~/.hermes/blackbox/file-shield/state.json, and a dashboard started for a test showed the founder
real notifications). ``tests/plugins/conftest.py`` points HOME and every Blackbox/Hermes home at
a temporary folder before a test module is imported; this file proves it from inside a test.
"""

from __future__ import annotations

import os
import pwd
from pathlib import Path

from plugins.blackbox.kernel import constants

REAL_HOME = Path(pwd.getpwuid(os.getuid()).pw_dir).resolve()


def test_home_and_every_blackbox_home_are_temporary():
    assert Path.home().resolve() != REAL_HOME
    for path in (constants.hermes_home(), constants.hermes_root(), constants.blackbox_home(), Path(os.path.expanduser("~"))):
        assert not path.resolve().is_relative_to(REAL_HOME / ".hermes"), path
        assert not path.resolve().is_relative_to(REAL_HOME / "Library"), path
