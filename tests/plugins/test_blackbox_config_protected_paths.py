"""A malformed ``protected_paths`` keeps the default list (review 2026-11-26, finding 10).

A scalar (``protected_paths: ~/.ssh/*`` — a list written without its dash) was read as an empty
list, so the defaults went too, Blackbox's own state among them. Only a real list replaces them;
an explicit empty list still clears them.
"""

from __future__ import annotations

from plugins.blackbox.kernel.config import DEFAULT_PROTECTED_PATHS, load_blackbox_config


def test_a_scalar_keeps_the_defaults():
    assert load_blackbox_config(entry={"protected_paths": "~/.ssh/*"}).protected_paths == DEFAULT_PROTECTED_PATHS


def test_a_list_replaces_them_and_an_empty_one_clears_them():
    assert load_blackbox_config(entry={"protected_paths": ["~/.ssh/*"]}).protected_paths == ("~/.ssh/*",)
    assert load_blackbox_config(entry={"protected_paths": []}).protected_paths == ()
