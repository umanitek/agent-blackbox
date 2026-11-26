"""Test helper: every registered shield's attack table joined with what each row does.

A shield ships the page's table (``shields/<id>/attacks.json``: title, how, outcome,
targets, evidence …), served by the registry as ``shields.attack_table(id)`` with
``systems`` and ``tested_with`` composed from its packs. What a row DOES — ``tool``,
``hook``, ``args``, ``graph``, ``block_severity`` — is test data in
``<id>_shield_attack_scenarios.json`` beside this file, keyed by row id: shipped attack
strings read as attacks to Hermes's plugin install scanner (catalog admission).

Usage::

    from _trader_attack_table import ATTACKS, TABLE   # Trader Shield's, as before
    from _trader_attack_table import TABLES
    for shield_id, joined in TABLES.items():
        local = [row for row in joined.attacks if row["proof"] == "test"]   # rows with their tool calls
"""

from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from plugins.blackbox import shields

#: Scenario fields: they belong to the tests and never ship in a shield's table.
SCENARIO_FIELDS = frozenset({"tool", "hook", "args", "graph", "block_severity", "lockdown"})


@dataclass(frozen=True)
class JoinedTable:
    """One shield's table as served (*table*), its *scenarios* by row id, and *attacks*: each
    row with its scenario merged in and ``shield`` set to the shield's id — what tests drive."""

    shield_id: str
    table: dict[str, Any]
    scenarios: dict[str, Any]
    attacks: list[dict[str, Any]]


def scenarios_file(shield_id: str) -> Path:
    """Where *shield_id*'s scenarios live: ``<id>_shield_attack_scenarios.json`` beside this file."""
    return Path(__file__).with_name(f"{shield_id}_shield_attack_scenarios.json")


def join(shield_id: str) -> JoinedTable:
    """*shield_id*'s served table joined with its scenarios (a missing scenario joins as nothing)."""
    table = shields.attack_table(shield_id)
    scenarios = json.loads(scenarios_file(shield_id).read_text(encoding="utf-8"))["scenarios"]
    attacks = [{**row, **scenarios.get(row["id"], {}), "shield": shield_id} for row in table["attacks"]]
    return JoinedTable(shield_id, table, scenarios, attacks)


#: Every registered shield's joined table, by shield id.
TABLES = {shield.id: join(shield.id) for shield in shields.all_shields()}
TABLE, SCENARIOS, ATTACKS = TABLES["trader"].table, TABLES["trader"].scenarios, TABLES["trader"].attacks
