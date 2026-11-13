"""Predicate IRI -> the field name the dashboard's single-threat view shows it under.

Used by the ``GET /api/threat`` lookup in :mod:`.server`: every triple of a
threat whose predicate is listed here becomes ``detail[<field>]``. Covers both
the published ontology (``kernel.constants`` IRIs) and the legacy
``urn:defender:p:*`` predicates older corpus rows still carry.
"""

from __future__ import annotations


from ..kernel import constants

DETAIL_FIELDS: dict[str, str] = {
    constants.SEVERITY_PRED: "severity",
    constants.KIND_PRED: "kind",
    constants.SCHEMA_NAME_PRED: "name",
    constants.SCHEMA_DESCRIPTION_PRED: "description",
    constants.OWASP_CATEGORY_PRED: "owasp",
    constants.PACKAGE_ECOSYSTEM_PRED: "ecosystem",
    constants.PACKAGE_NAME_PRED: "package",
    constants.PACKAGE_VERSION_PRED: "version",
    constants.FIXED_VERSION_PRED: "fixed_version",
    constants.TOOL_NAME_PRED: "tool",
    constants.ARG_SHAPE_PRED: "arg_shape",
    constants.CATEGORY_PRED: "file_category",
    constants.SKILL_NAME_PRED: "skill",
    constants.SKILL_VERSION_PRED: "skill_version",
    constants.DANGER_SHAPE_PRED: "danger_shape",
    constants.PATTERN_PRED: "pattern",
    constants.CURATED_PRED: "curated",
    constants.SCHEMA_DATE_MODIFIED_PRED: "modified",
    constants.SCHEMA_CONTRIBUTOR_PRED: "contributor",
    "urn:defender:p:severity": "severity",
    "urn:defender:p:kind": "kind",
    "urn:defender:p:pattern": "pattern",
    "urn:defender:p:ecosystem": "ecosystem",
    "urn:defender:p:package": "package",
    "urn:defender:p:version": "version",
    "urn:defender:p:advisoryId": "advisory_id",
    "urn:defender:p:iocType": "ioc_type",
    "urn:defender:p:value": "value",
}
