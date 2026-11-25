"""Load installer functions into a test's bash program WITH everything they call.

The installer tests run real functions of ``blackbox-install.sh`` in a throwaway bash program.
They used to list the functions by hand, so a helper added to a function under test
(``resolve_repo`` → ``clone_this_machines_checkout`` in the sparse-checkout change) failed every
such test with ``command not found`` — ten failures from one refactor (fix wave 7). This module
works the list out instead: the named functions plus every installer function they call,
transitively, in the installer's own order.

Usage::

    from tests.plugins._blackbox_installer_shell import functions_with_callees
    text = INSTALL_SH.read_text(encoding="utf-8")
    script = f"step() {{ :; }}\\n{functions_with_callees(text, ['resolve_repo'], provided={'step'})}\\nresolve_repo"

``provided`` names the functions and variables the test defines itself (``step``, ``ok``,
``err``…): they are never loaded, so a test's stand-in is not replaced by the real one.

The installer's literal constants the chosen functions read (``NAME="text"`` or ``NAME=200`` at
the start of a line, nothing expanded) come first, so a function runs with the shipped value
under ``set -u``; a constant built from other values (``"$HOME/…"``) is the test's to set.
"""

from __future__ import annotations

import re
from collections.abc import Iterable

#: A function definition at the start of a line: ``name() {``.
_DEFINITION = re.compile(r"^([A-Za-z_][A-Za-z0-9_]*)\(\)\s*\{", re.MULTILINE)
#: A literal constant at the start of a line: ``NAME="text"``, ``NAME='text'`` or ``NAME=word``,
#: with nothing for the shell to expand.
_CONSTANT = re.compile(r"""^([A-Z][A-Z0-9_]*)=("[^"$`]*"|'[^']*'|[^\s"'$`;|&()<>]*)\s*$""", re.MULTILINE)


def _body_end(text: str, start: int) -> int:
    """Index just past the function starting at *start*: a one-line ``name() { …; }`` or the
    first column-0 ``}`` line, skipping the lines of a quoted heredoc (whose ``}`` is data)."""
    first_line_end = text.find("\n", start)
    first_line = text[start:first_line_end if first_line_end != -1 else len(text)]
    if first_line.rstrip().endswith("}") and first_line.count("{") == first_line.count("}"):
        return first_line_end + 1
    heredoc_end = None
    position = first_line_end + 1
    while position < len(text):
        line_end = text.find("\n", position)
        line_end = len(text) if line_end == -1 else line_end
        line = text[position:line_end]
        if heredoc_end is not None:
            heredoc_end = None if line.strip() == heredoc_end else heredoc_end
        elif "<<'" in line:
            heredoc_end = line.split("<<'", 1)[1].split("'", 1)[0]
        elif line == "}":
            return line_end + 1
        position = line_end + 1
    raise AssertionError(f"function at offset {start} has no end")


def installer_functions(text: str) -> dict[str, str]:
    """Every function the installer defines, name → its text, in the installer's order.
    A name defined twice keeps its LAST definition, as bash would."""
    found: dict[str, str] = {}
    for match in _DEFINITION.finditer(text):
        found.pop(match.group(1), None)
        found[match.group(1)] = text[match.start():_body_end(text, match.start())]
    return found


def functions_with_callees(text: str, names: Iterable[str], *, provided: Iterable[str] = ()) -> str:
    """The literal constants and the text of *names* and every installer function they call
    (transitively), in the installer's order, leaving out *provided*. A name the installer does
    not define fails."""
    defined = installer_functions(text)
    skip = set(provided)
    wanted = [name for name in names if name not in skip]
    missing = [name for name in wanted if name not in defined]
    assert not missing, f"not defined in the installer: {missing}"
    calls = re.compile(r"(?<![A-Za-z0-9_$-])(" + "|".join(map(re.escape, defined)) + r")(?![A-Za-z0-9_-])")
    chosen: set[str] = set()
    pending = list(wanted)
    while pending:
        name = pending.pop()
        if name in chosen:
            continue
        chosen.add(name)
        pending.extend(called for called in set(calls.findall(defined[name]))
                       if called not in chosen and called not in skip)
    bodies = [body for name, body in defined.items() if name in chosen]
    used = "\n".join(bodies)
    constants = [match.group(0) for match in _CONSTANT.finditer(text)
                 if match.group(1) not in skip and re.search(rf"\$\{{?{match.group(1)}\b", used)]
    return "\n".join([*constants, *bodies])
