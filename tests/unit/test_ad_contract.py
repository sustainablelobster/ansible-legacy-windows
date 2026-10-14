"""Keep public module schemas and helper staging aligned with the released reference."""

# Copyright 2026 sustainablelobster
# SPDX-License-Identifier: GPL-3.0-or-later

import ast
import json
from pathlib import Path
from typing import Any, cast

import pytest

# The locked YAML and Ansible packages do not distribute typing metadata.
import yaml  # type: ignore[import-untyped]
from ansible.plugins.loader import (  # type: ignore[import-untyped]
    action_loader,
    module_loader,
)

from tests.unit.payload_support import HELPER, ROOT
from tests.unit.test_python_action import _action

AD = ROOT / "legacy_ad"
REFERENCE = json.loads((ROOT / "tests/fixtures/microsoft_ad_contract.json").read_text())
FIELDS = {"type", "elements", "default", "required", "choices", "aliases", "returned"}


def _contract(value: dict[str, Any]) -> dict[str, Any]:
    result = {key: item for key, item in value.items() if key in FIELDS}
    for key in ("suboptions", "contains"):
        if key in value:
            result[key] = {name: _contract(item) for name, item in value[key].items()}
    return result


def _return_contract(
    value: dict[str, Any], reference: dict[str, Any]
) -> dict[str, Any]:
    result = _contract(value)
    # An omitted upstream element type does not prohibit more precise metadata.
    if "elements" not in reference:
        result.pop("elements", None)
    if "contains" in result:
        result["contains"] = {
            name: _return_contract(item, reference.get("contains", {}).get(name, {}))
            for name, item in result["contains"].items()
        }
    return result


def _fragment(path: Path) -> dict[str, Any]:
    tree = ast.parse(path.read_text())
    fragment = next(
        node
        for node in tree.body
        if isinstance(node, ast.ClassDef) and node.name == "ModuleDocFragment"
    )
    document = next(
        ast.literal_eval(node.value)
        for node in fragment.body
        if isinstance(node, ast.Assign)
        and any(
            isinstance(target, ast.Name) and target.id == "DOCUMENTATION"
            for target in node.targets
        )
    )
    return cast(dict[str, Any], yaml.safe_load(document))


def _module_document(name: str) -> dict[str, Any]:
    path = AD / "plugins/modules" / (name + ".yml")
    if path.exists():
        return cast(dict[str, Any], yaml.safe_load(path.read_text()))
    tree = ast.parse(path.with_suffix(".py").read_text())
    return {
        target.id: yaml.safe_load(ast.literal_eval(node.value))
        for node in tree.body
        if isinstance(node, ast.Assign)
        for target in node.targets
        if isinstance(target, ast.Name) and target.id in {"DOCUMENTATION", "RETURN"}
    }


@pytest.mark.parametrize("name", REFERENCE["fragments"])
def test_common_option_contract_matches_released_reference(name: str) -> None:
    document = _fragment(AD / "plugins/doc_fragments" / (name + ".py"))
    assert {
        key: _contract(value) for key, value in document.get("options", {}).items()
    } == REFERENCE["fragments"][name]


@pytest.mark.parametrize("name", REFERENCE["modules"])
def test_module_arguments_and_returns_match_released_reference(name: str) -> None:
    document = _module_document(name)
    options = document["DOCUMENTATION"]
    actual = {
        "options": {
            key: _contract(value) for key, value in options.get("options", {}).items()
        },
        "fragments": [
            name.rsplit(".", 1)[1]
            for name in options.get("extends_documentation_fragment", [])
            if name.startswith("sustainablelobster.legacy_ad.")
        ],
        "returns": {
            key: _return_contract(
                value, REFERENCE["modules"][name]["returns"].get(key, {})
            )
            for key, value in document.get("RETURN", {}).items()
        },
    }
    assert actual == REFERENCE["modules"][name]


@pytest.mark.parametrize(
    "name",
    [
        "kds_root_key",
        "kds_root_key_info",
        "service_account",
        "fs_trust",
        "fs_claim_rule",
    ],
)
def test_actions_stage_every_declared_helper_once_and_resolve_modules(
    name: str, monkeypatch: pytest.MonkeyPatch
) -> None:
    fqcn = "sustainablelobster.legacy_ad." + name
    action_class = action_loader.get(fqcn, class_only=True)
    assert action_class is not None
    assert module_loader.find_plugin(fqcn) is not None
    action, _, events = _action(action_class, monkeypatch)
    action.run()
    actual = [Path(str(event[1])) for event in events if event[0] == "transfer"]
    expected = [HELPER]
    expected.extend(
        HELPER.parent / filename for filename in action_class.EXTRA_MODULE_UTILS
    )
    expected.extend(action_class.COLLECTION_MODULE_UTILS)
    assert actual == expected
    assert len({path.name.casefold() for path in actual}) == len(actual)
