"""Reject weakened public equality and unknown files in the signature path test."""

# SPDX-License-Identifier: GPL-3.0-or-later
# These private fixture boundaries protect actual input/proof ownership.
# pylint: disable=protected-access

import base64
import json
import sys
from pathlib import Path
from types import SimpleNamespace
from typing import Any

import pytest
import yaml  # type: ignore[import-untyped]

from tests.unit.integration_selection import assert_local_selection
from tests.unit.payload_support import ROOT, load_module


@pytest.fixture(name="fixture")
def path_fixture(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> Any:
    """Load the concrete fixture with scoped native file observations.

    :param monkeypatch: Scoped argument and native-observation substitutions.
    :param tmp_path: Exclusively owned temporary workspace.
    :returns: Concrete fixture for public-equality and ownership regressions.
    """
    monkeypatch.setattr(sys, "argv", ["fixture", str(tmp_path), "compare"])
    monkeypatch.setitem(sys.modules, "package_msp_fixture", SimpleNamespace())
    return load_module(
        ROOT / "tests/integration/fixtures/package_signature_paths.py",
        "tested_signature_paths_fixture",
    )


@pytest.mark.parametrize("native_value", [False, 0, None, "false"])
def test_complete_comparison_retains_json_types_and_all_public_fields(
    fixture: Any, monkeypatch: pytest.MonkeyPatch, native_value: Any
) -> None:
    original = [{"item": name, "changed": False} for name in fixture.CASES]
    native = [dict(value) for value in original]
    native[0]["changed"] = native_value
    encoded = base64.b64encode(
        json.dumps(
            {"native": {"results": native}, "original": {"results": original}}
        ).encode()
    ).decode()
    monkeypatch.setattr(sys, "argv", ["fixture", fixture.ROOT, "compare", encoded])
    if native_value is False:
        assert fixture._compare() == {"complete_typed_public_equal": True, "cases": 10}
    else:
        with pytest.raises(AssertionError):
            fixture._compare()


def test_unknown_owned_tree_file_blocks_protection_claim(
    fixture: Any, monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    record = {
        "workspace": str(tmp_path),
        "system": "protected.exe",
        "protected": {"sha256": "original"},
        "files": {},
        "directories": ["."],
    }
    (tmp_path / "signature-paths-journal.json").write_text(json.dumps(record))
    monkeypatch.setattr(fixture.base, "_decode", lambda value: value, raising=False)
    monkeypatch.setattr(fixture, "_metadata", lambda _path: record["protected"])
    monkeypatch.setattr(
        fixture, "_files", lambda: {"unknown.txt": {"sha256": "unknown"}}
    )
    with pytest.raises(AssertionError):
        fixture._observe()


@pytest.mark.parametrize("difference", ["missing", "extra", "order", "count"])
def test_complete_comparison_rejects_omitted_fields_cases_and_changed_order(
    fixture: Any, monkeypatch: pytest.MonkeyPatch, difference: str
) -> None:
    original = [{"item": name, "changed": False} for name in fixture.CASES]
    native = [dict(value) for value in original]
    if difference == "missing":
        native[0].pop("changed")
    elif difference == "extra":
        native[0]["new_public_field"] = 1
    elif difference == "order":
        native.reverse()
    else:
        native.pop()
    encoded = base64.b64encode(
        json.dumps(
            {"native": {"results": native}, "original": {"results": original}}
        ).encode()
    ).decode()
    monkeypatch.setattr(sys, "argv", ["fixture", fixture.ROOT, "compare", encoded])
    with pytest.raises(AssertionError):
        fixture._compare()


@pytest.mark.parametrize("compare", [False, True])
@pytest.mark.parametrize("indices", [None, [1, 2, 6, 7, 8, 9]])
def test_effective_case_selection_before_windows_access(
    tmp_path: Path, compare: bool, indices: list[int] | None
) -> None:
    integration = ROOT / "tests/integration"
    play = yaml.safe_load(
        (integration / "win_package_signature_paths.yml").read_text()
    )[0]
    cases = [f"case{index}.exe" for index in range(10)]
    variables = dict(play["vars"])
    variables.update(
        signature_paths_setup={"stdout": json.dumps({"cases": cases})},
        package_signature_paths_compare=compare,
        expected_compare=compare,
        expected_cases=(
            cases if indices is None else [cases[index] for index in indices]
        ),
    )
    if indices is not None:
        variables["package_signature_paths_case_indices"] = indices
    assert_local_selection(
        tmp_path,
        variables,
        [
            "signature_paths_cases == expected_cases",
            "(package_signature_paths_compare | default(true) | bool) == expected_compare",
        ],
        [],
    )


@pytest.mark.parametrize("supplied", [False, True])
def test_setup_uses_identical_supplied_sample_without_changing_system_command(
    fixture: Any,
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    supplied: bool,
) -> None:
    system = tmp_path / "system"
    (system / "System32").mkdir(parents=True)
    system_command = system / "System32/cmd.exe"
    original = b"MZ" + b"original" * 40
    recorded = b"MZ" + b"recorded modern bytes" * 40
    system_command.write_bytes(original)
    workspace = tmp_path / "workspace"
    workspace.mkdir()
    monkeypatch.setattr(fixture, "ROOT", str(workspace))
    monkeypatch.setattr(
        fixture, "JOURNAL", str(workspace / "signature-paths-journal.json")
    )
    monkeypatch.setenv("SystemRoot", str(system))
    monkeypatch.setattr(fixture, "SIGNED", ("plain.exe",))
    monkeypatch.setattr(fixture, "INVALID", ())
    monkeypatch.setattr(
        fixture, "_metadata", lambda path: {"size": len(Path(path).read_bytes())}
    )
    monkeypatch.setattr(fixture.base, "_encode", str, raising=False)
    monkeypatch.setattr(
        sys,
        "argv",
        [
            "fixture",
            str(workspace),
            "setup",
            "",
            base64.b64encode(recorded).decode() if supplied else "",
        ],
    )
    result = fixture._setup()
    expected = recorded if supplied else original
    assert (workspace / "plain.exe").read_bytes() == expected
    assert system_command.read_bytes() == original
    assert result["original"]["files"]["plain.exe"] == {"size": len(expected)}
