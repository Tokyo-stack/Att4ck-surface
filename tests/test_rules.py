"""Registry / model unit tests: the 40-surface contract and rule hygiene."""

from __future__ import annotations

import pytest

from attack_surface.models import Severity
from attack_surface.rules import (
    SURFACE_BY_KEY,
    SURFACE_COUNT,
    SURFACE_KEYS,
    SURFACES,
    load_rules,
    resolve_surface_keys,
    rules_by_surface,
    rules_for_surfaces,
)


def test_exactly_forty_surfaces():
    assert SURFACE_COUNT == 40
    assert len(SURFACES) == 40
    assert len(SURFACE_KEYS) == 40
    assert tuple(s.number for s in SURFACES) == tuple(range(1, 41))


def test_surface_keys_unique():
    assert len(set(SURFACE_KEYS)) == 40


def test_every_surface_has_at_least_one_rule():
    grouped = rules_by_surface()
    for surface in SURFACES:
        assert grouped[surface.key], f"surface {surface.key} has no rules"


def test_rule_ids_unique():
    ids = [r.id for r in load_rules()]
    assert len(ids) == len(set(ids))


def test_rules_reference_valid_surface():
    for rule in load_rules():
        assert rule.surface in SURFACE_BY_KEY


def test_rule_confidence_bounds():
    for rule in load_rules():
        assert 0 <= rule.confidence <= 100


def test_rules_have_metadata():
    for rule in load_rules():
        assert rule.name and rule.description
        assert rule.cwe.startswith("CWE-") or rule.cwe == "N/A"
        assert rule.recommendation, f"{rule.id} lacks a recommendation"


def test_every_rule_has_detection_logic():
    for rule in load_rules():
        assert rule.patterns or rule.file_checker or rule.path_only


@pytest.mark.parametrize("selector,expected", [
    ("1", "authentication"),
    ("24", "database"),
    ("database", "database"),
    ("iam", "authentication"),
])
def test_resolve_surface_keys(selector, expected):
    assert expected in resolve_surface_keys([selector])


def test_resolve_all():
    assert resolve_surface_keys(["all"]) == SURFACE_KEYS
    assert resolve_surface_keys(None) == SURFACE_KEYS


def test_resolve_unknown_raises():
    with pytest.raises(ValueError):
        resolve_surface_keys(["definitely-not-a-surface"])


def test_rules_for_subset():
    subset = rules_for_surfaces(["database"])
    assert subset
    assert all(r.surface == "database" for r in subset)


def test_severity_ordering():
    assert Severity.CRITICAL.rank > Severity.HIGH.rank > Severity.MEDIUM.rank
    assert Severity.INFO.rank == 0
    assert Severity.HIGH.downgrade() is Severity.MEDIUM
    assert Severity.CRITICAL.upgrade() is Severity.CRITICAL  # bounded
    assert Severity.parse("high") is Severity.HIGH


def test_all_rule_regexes_compile():
    # __post_init__ compiles them; this simply forces evaluation of the registry.
    assert len(load_rules()) >= 40
