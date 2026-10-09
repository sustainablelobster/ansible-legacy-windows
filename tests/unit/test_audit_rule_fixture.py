"""Verify maintained audit fixture ownership, journal persistence, and guards."""

# SPDX-License-Identifier: GPL-3.0-or-later

import ast
import json
import ntpath
import os
from pathlib import Path
from typing import Any
from unittest.mock import Mock

import pytest
import yaml  # type: ignore[import-untyped]

from tests.unit.payload_support import ROOT


@pytest.fixture(name="source")
def fixture_source() -> str:
    """Read the maintained independent Python target fixture.

    :returns: Embedded fixture source.
    """
    return str(
        yaml.safe_load(
            (ROOT / "tests/integration/vars/audit_rule_fixture.yml").read_text()
        )["audit_rule_fixture"]
    )


def _function(source: str, name: str, namespace: dict[str, Any]) -> Any:
    definition = next(
        node
        for node in ast.parse(source).body
        if isinstance(node, ast.FunctionDef) and node.name == name
    )
    # Run the maintained routine with only its platform boundaries substituted.
    # pylint: disable-next=exec-used
    exec(
        compile(
            ast.Module(body=[definition], type_ignores=[]), "audit_rule_fixture", "exec"
        ),
        namespace,
    )
    return namespace[name]


def test_fixture_is_python34_native_and_independent(source: str) -> None:
    ast.parse(source, feature_version=(3, 4))
    assert "GetSecurityInfo" in source and "ConvertSidToStringSidW" in source
    assert not any(
        text in source
        for text in (
            "legacy_windows_audit_rule",
            "legacy_windows_acl",
            "powershell",
            "subprocess",
            "pywin32",
        )
    )
    assert source.index("save(journal)") < source.index("winreg.CreateKeyEx")
    assert 'journal["paths"] == owned_paths(journal["suffix"])' in source


def test_journal_is_atomic_and_flushed(source: str, tmp_path: Path) -> None:
    path = tmp_path / "journal.json"
    save = _function(
        source, "save", {"os": os, "json": json, "journal_path": str(path)}
    )
    journal = {"initial_absence": True, "paths": {"file": "owned"}}
    save(journal)
    assert json.loads(path.read_text()) == journal
    assert not (tmp_path / "journal.json.new").exists()


@pytest.mark.parametrize("suffix", ["", "a" * 31, "g" * 32, "../" * 11, "A" * 32])
def test_owned_paths_reject_unbound_resource_names(source: str, suffix: str) -> None:
    function = _function(
        source, "owned_paths", {"os": Mock(path=ntpath), "workspace": r"C:\private"}
    )
    with pytest.raises(AssertionError):
        function(suffix)


def test_owned_paths_are_exactly_scoped(source: str) -> None:
    function = _function(
        source, "owned_paths", {"os": Mock(path=ntpath), "workspace": r"C:\private"}
    )
    suffix = "a" * 32
    paths = function(suffix)
    assert len(paths) == 23 and len(set(paths.values())) == 23
    assert paths["directory"] == r"C:\private\audit_" + suffix
    assert paths["child_file"] == paths["directory"] + r"\child.txt"
    assert paths["registry"] == r"HKCU:\Software\legacy_audit_rule_" + suffix
    assert paths["child_registry"] == paths["registry"] + r"\child"
    assert paths["provider_file"] == r"C:\private\audit_" + suffix + "[.]txt"
    assert paths["provider_registry_sibling"] == paths["registry"] + "_selecta"
    assert paths["provider_escaped_file"].endswith(suffix + "``[.]txt")
    assert paths["provider_single_escape_registry"].endswith("_select`[a]")
    assert paths["provider_range_file"].endswith("_range[Ö-Ø].txt")
    assert paths["provider_range_file_sibling"].endswith("_range÷.txt")
    assert paths["provider_invalid_range_registry"].endswith("_invalid[@-[]")
    assert paths["provider_invalid_range_registry_sibling"].endswith("_invalidA")


@pytest.mark.parametrize("code", [2, 5])
def test_registry_absence_never_hides_access_denial(source: str, code: int) -> None:
    registry = Mock()
    error = OSError("native error")
    setattr(error, "winerror", code)
    registry.OpenKey.side_effect = error
    function = _function(
        source,
        "exists",
        {"os": os, "winreg": registry, "registry_path": lambda path: path[6:]},
    )
    if code == 2:
        assert not function(r"HKCU:\Software\legacy_audit_rule_owned")
    else:
        with pytest.raises(OSError, match="native error"):
            function(r"HKCU:\Software\legacy_audit_rule_owned")


def test_cases_capture_before_assert_and_cleanup_retains_failure_journal() -> None:
    case = (ROOT / "tests/integration/tasks/win_audit_rule_case.yml").read_text()
    main = (ROOT / "tests/integration/win_audit_rule.yml").read_text()
    assert case.index(
        "Save raw public and native evidence before assertion"
    ) < case.index("Verify public results")
    assert "always:" in case and "validated: '{{ audit_rule_validated }}'" in case
    assert main.index("Require verified resource and journal absence") < main.index(
        "Remove the verified empty workspace"
    )
    assert "staging_before.stdout | from_json" in main
