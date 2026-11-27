"""How a shell command line reads — the words it splits into and what they do.

* :mod:`.lexer` — the ONE shell lexer every check splits a command line through (quotes, escapes,
  per-word Windows paths, subshell brackets, brace expansion); :mod:`..paths.shell_words` is its
  front for the path checks.
* :mod:`.escalation_shapes` — the dangerous shapes a command has (``rm -rf /etc``, ``curl … | sh``),
  judged on its words; :mod:`..shell_shapes` names them for a tool call.
* :mod:`.dependency_installs` — which packages a command installs by name; named by
  :mod:`..action_parsing` for its callers.

Import the module you need (``from ..command_line import lexer``): this entry imports nothing, so
the path checks can stand on the lexer without an import cycle.
"""

__all__: list[str] = []
