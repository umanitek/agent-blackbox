"""Coding-agent protection — PROTECT (act): hooks installed into each agent's own config
(:mod:`.config_edit`, :mod:`.own_files`), the runner every hook calls (:mod:`.runner`) and the
guard verdict for each event (:mod:`.events`). **Undo:** ``set_protection(agent, False)``
removes Blackbox's hook entries and restores the user's config from its backup.
"""
