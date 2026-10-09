"""Check the focused regex fixture's ownership and minimum target syntax."""

# SPDX-License-Identifier: GPL-3.0-or-later

import ast
import importlib.util
import ntpath
from pathlib import Path
from types import ModuleType

import pytest
import yaml  # type: ignore[import-untyped]

from tests.unit.payload_support import ROOT


@pytest.fixture(name="fixture")
def owned_fixture() -> ModuleType:
    """Load the fixture's portable file operations without Windows calls.

    :returns: The unchanged target fixture module.
    """
    source = ROOT / "tests/integration/fixtures/regex_contract.py"
    spec = importlib.util.spec_from_file_location("regex_contract_fixture", source)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def test_fixture_and_embedded_observer_use_minimum_target_syntax() -> None:
    source = ROOT / "tests/integration/fixtures/regex_contract.py"
    ast.parse(source.read_text(encoding="utf-8"), feature_version=(3, 4))
    play = yaml.safe_load(
        (ROOT / "tests/integration/regex_contract.yml").read_text(encoding="utf-8")
    )[0]
    ast.parse(play["vars"]["regex_contract_staging"], feature_version=(3, 4))
    assert len(play["vars"]["regex_contract_wait_cases"]) == 9
    assert len(play["vars"]["regex_contract_find_cases"]) == 3


def test_owned_names_are_distinct_on_case_insensitive_windows(
    fixture: ModuleType,
) -> None:
    assert len({ntpath.normcase(name) for name in fixture.NAMES}) == len(fixture.NAMES)


def test_journal_observation_detects_file_changes(
    fixture: ModuleType, tmp_path: Path
) -> None:
    root = tmp_path / "legacy-windows-regex-contract-unit"
    (root / "helpers").mkdir(parents=True)
    # Deliberately inspect the fixture's ownership/hash boundary, not Windows APIs.
    # pylint: disable=protected-access
    before = fixture._prepare(str(root))
    assert fixture._observe(str(root), before["nonce"]) == before
    assert (root / "texts" / "lf").read_bytes() == b"done\n"
    assert (root / "texts" / "crlf").read_bytes() == b"done\r\n"
    (root / "texts" / "lf").write_bytes(b"changed")
    assert fixture._observe(str(root), before["nonce"]) != before
    with pytest.raises(AssertionError):
        fixture._observe(str(root), "not-owned")
    # pylint: enable=protected-access


def test_fixture_refuses_adopting_existing_files(
    fixture: ModuleType, tmp_path: Path
) -> None:
    root = tmp_path / "legacy-windows-regex-contract-unit"
    (root / "helpers").mkdir(parents=True)
    (root / "foreign.txt").write_text("not owned", encoding="utf-8")
    with pytest.raises(AssertionError):
        fixture._prepare(str(root))  # pylint: disable=protected-access
