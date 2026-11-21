"""Network Shield — PROTECT (act): what changes the system, every part reversible.

The enforcement plan the root helper applies and its reports (:mod:`.enforcement`), the public
block lists (:mod:`.blocklists`) and the agent guard for listed hosts (:mod:`.listed`).

Rule: each module documents its **Undo** — switched off, everything it did is undone (the plan
turns all-off and the helper restores DNS and pf exactly). May import :mod:`..monitor`.
"""
