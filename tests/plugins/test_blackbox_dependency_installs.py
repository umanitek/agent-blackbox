"""A package is the package however its install is spelled (review 2026-11-26, finding 5, Critical).

The dependency parser had its own tokenizer, so against a whole-package rule ``pypi:evil@*`` the
installs below all missed: quoting or escaping the name, any comparison but ``==``, extras, a
versioned pip, ``bun install`` / ``yarn global add``; and ``-r req.txt`` was looked up as a
package. Words now come from the one shell lexer and requirements are read as pip reads them.
"""

from __future__ import annotations

import pytest

from plugins.blackbox.detection import parse_dependency_installs


@pytest.mark.parametrize("command, ecosystem, version", [
    ('pip install e"v"il==1.0', "pypi", "1.0"),
    ("pip install ev\\il", "pypi", ""),
    ("npm install e''vil", "npm", ""),
    ('pip install "evil>=1"', "pypi", ""),
    ("pip install evil>=1", "pypi", ""),
    ('pip install "evil[x]==1.0"', "pypi", "1.0"),
    ("pip install evil~=1.0", "pypi", ""),
    ("pip3.12 install evil", "pypi", ""),
    ("python3.12 -m pip install evil===2", "pypi", "2"),
    ("bun install evil", "npm", ""),
    ("yarn global add evil", "npm", ""),
])
def test_every_spelling_names_the_package(command, ecosystem, version):
    assert parse_dependency_installs(command) == [{"ecosystem": ecosystem, "name": "evil", "version": version}]


def test_an_options_value_is_never_a_package():
    assert parse_dependency_installs("pip install -r req.txt --index-url https://example.test/simple evil") == [
        {"ecosystem": "pypi", "name": "evil", "version": ""}]
    assert parse_dependency_installs("pip install -r requirements.txt") == []
