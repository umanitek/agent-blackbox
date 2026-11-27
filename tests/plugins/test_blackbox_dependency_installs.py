"""A package is the package however its install is spelled (review 2026-11-26, finding 5, Critical).

The dependency parser had its own tokenizer, so against a whole-package rule ``pypi:evil@*`` the
installs below all missed: quoting or escaping the name, any comparison but ``==``, extras, a
versioned pip, ``bun install`` / ``yarn global add``; and ``-r req.txt`` was looked up as a
package. Words now come from the one shell lexer and requirements are read as pip reads them.

Field report 2026-11-27 (a false CRITICAL on a Markdown file): the lexer read a line break as a space,
so a bare ``npm install`` followed by prose or a JSON example on the next lines named the npm packages
``at`` and ``name``. A line break now ends a command as the shell ends it (red on c08cc276db).
"""

from __future__ import annotations

import pytest

from plugins.blackbox.detection import command_from_args, parse_dependency_installs


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


#: A README an agent writes: bare installs, a JSON example, prose with ``at`` and an apostrophe.
README = """# Setup

```bash
npm install
npm run build
npm test
```

The manifest looks like this:

```json
{
  "name": "my-app",
  "version": "1.0.0"
}
```

Don't run it as root: the server listens at port 3000.
"""


def test_a_document_after_a_bare_install_names_no_package():
    command = command_from_args("write_file", {"path": "docs/SETUP.md", "content": README}, any_tool=True)
    assert parse_dependency_installs(command) == []


@pytest.mark.parametrize("command, names", [
    ("npm install left-pad\nnpm i evil@1.0", ["left-pad", "evil"]),   # two commands, each its own install
    ("cd app &&\n  npm i evil@1.0", ["evil"]),                         # a list carried on to the next line
    ("npm i \\\n  evil@1.0", ["evil"]),                              # a line continuation
    ("npm install\n- name: at", []),
])
def test_a_line_break_ends_an_install_as_the_shell_ends_it(command, names):
    assert [found["name"] for found in parse_dependency_installs(command)] == names
