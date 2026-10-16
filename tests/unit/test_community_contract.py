"""Compare public community interfaces with the recorded released baseline."""

# Copyright 2026 sustainablelobster
# SPDX-License-Identifier: GPL-3.0-or-later

import ast
import json
from pathlib import Path
from typing import Any

import pytest

# The locked YAML package does not distribute typing metadata.
import yaml  # type: ignore[import-untyped]

from tests.unit.payload_support import ROOT

COLLECTION = ROOT / "legacy_community_windows"
REFERENCE = json.loads(
    (ROOT / "tests/fixtures/community_windows_contract.json").read_text()
)
# Native capability notes can replace PowerShell-specific returned-condition
# prose; behavior tests check when values actually appear.
FIELDS = {"type", "elements", "default", "required", "choices", "aliases"}


def _contract(value: dict[str, Any]) -> dict[str, Any]:
    result = {name: item for name, item in value.items() if name in FIELDS}
    for name in ("suboptions", "contains"):
        if name in value:
            result[name] = {key: _contract(item) for key, item in value[name].items()}
    return result


def _documents(path: Path) -> dict[str, Any]:
    tree = ast.parse(path.read_text())
    return {
        target.id: yaml.safe_load(ast.literal_eval(node.value)) or {}
        for node in tree.body
        if isinstance(node, ast.Assign)
        for target in node.targets
        if isinstance(target, ast.Name) and target.id in {"DOCUMENTATION", "RETURN"}
    }


def test_source_inventory_covers_every_released_module_and_lookup() -> None:
    assert len(REFERENCE["modules"]) == 55
    for section, directory in (("modules", "modules"), ("lookups", "lookup")):
        actual = {
            path.stem
            for path in (COLLECTION / "plugins" / directory).glob("*.py")
            if path.name != "__init__.py"
        }
        assert actual == set(REFERENCE[section])


@pytest.mark.parametrize("name", REFERENCE["modules"])
def test_module_arguments_and_return_contract(name: str) -> None:
    document = _documents(COLLECTION / "plugins/modules" / (name + ".py"))
    expected = REFERENCE["modules"][name]
    assert {
        key: _contract(value)
        for key, value in document["DOCUMENTATION"].get("options", {}).items()
    } == expected["options"]
    assert {
        key: _contract(value) for key, value in document.get("RETURN", {}).items()
    } == {key: _contract(value) for key, value in expected["returns"].items()}


@pytest.mark.parametrize("name", REFERENCE["lookups"])
def test_lookup_arguments_and_return_contract(name: str) -> None:
    document = _documents(COLLECTION / "plugins/lookup" / (name + ".py"))
    expected = REFERENCE["lookups"][name]
    assert {
        key: _contract(value)
        for key, value in document["DOCUMENTATION"].get("options", {}).items()
    } == expected["options"]
    assert {
        key: _contract(value) for key, value in document.get("RETURN", {}).items()
    } == {key: _contract(value) for key, value in expected["returns"].items()}


def test_redirects_deprecations_and_removed_interfaces_match_baseline() -> None:
    actual = yaml.safe_load((COLLECTION / "meta/runtime.yml").read_text())
    expected = json.loads(
        json.dumps(REFERENCE["routing"])
        .replace("ansible.windows.", "sustainablelobster.legacy_windows.")
        .replace("microsoft.ad.", "sustainablelobster.legacy_ad.")
    )
    assert actual["plugin_routing"] == expected
