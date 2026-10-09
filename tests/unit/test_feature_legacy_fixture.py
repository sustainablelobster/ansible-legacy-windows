"""Exercise older feature journal ownership and literal recovery evidence."""

# SPDX-License-Identifier: GPL-3.0-or-later
# These fixture substitutes do not establish Windows execution support.
# pylint: disable=exec-used

import ast
import copy
import sys
from pathlib import Path
from types import ModuleType
from typing import Any
from unittest.mock import Mock

import pytest

# PyYAML is provided by the pinned developer environment without typing stubs.
import yaml  # type: ignore[import-untyped]

from tests.unit.payload_support import ROOT


@pytest.fixture(name="fixture")
def feature_fixture(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> dict[str, Any]:
    """Load the maintained fixture with private paths and controller substitutes.

    :param tmp_path: Private owned recovery directory.
    :param monkeypatch: Scoped Windows imports, runtime and arguments.
    :returns: Fixture functions with independent observation substitutes.
    """
    monkeypatch.setitem(sys.modules, "winreg", ModuleType("winreg"))
    monkeypatch.setenv("SystemRoot", str(tmp_path / "windows"))
    monkeypatch.setenv("COMPUTERNAME", "fixture")
    monkeypatch.setattr(sys, "argv", ["fixture", str(tmp_path), "setup"])
    monkeypatch.setattr(sys, "getwindowsversion", lambda: (6, 1, 7601), raising=False)
    source = yaml.safe_load(
        (ROOT / "tests/integration/vars/feature_legacy_fixture.yml").read_text()
    )["feature_legacy_fixture"]
    ast.parse(source, feature_version=(3, 4))
    namespace: dict[str, Any] = {"__name__": "fixture"}
    exec(compile(source, "feature_legacy_fixture.py", "exec"), namespace)
    namespace["observe"] = Mock(
        return_value={
            "catalogue": {
                "Telnet-Client": {"Installed": "false"},
                "TFTP-Client": {"Installed": "false"},
                "Other": {"Installed": "true"},
            },
            "pending": {"CBS": False},
            "services": {"TrustedInstaller": {"State": "Stopped"}},
            "binaries": {"telnet.exe": None},
        }
    )
    return namespace


def test_durable_journal_keeps_every_original_feature_service_and_file(
    fixture: dict[str, Any],
) -> None:
    record = fixture["setup"]()
    assert fixture["journal"]() == record
    assert record["before"] == fixture["observe"]()
    assert record["targets"] == ["Telnet-Client", "TFTP-Client"]


def test_existing_journal_cannot_be_overwritten(fixture: dict[str, Any]) -> None:
    fixture["setup"]()
    path = Path(fixture["JOURNAL"])
    before = path.read_bytes()
    with pytest.raises(FileExistsError):
        fixture["setup"]()
    assert path.read_bytes() == before


@pytest.mark.parametrize("field", ["catalogue", "services", "binaries", "pending"])
def test_recovery_retains_both_snapshots_when_any_observed_field_differs(
    fixture: dict[str, Any], field: str
) -> None:
    before = fixture["setup"]()["before"]
    after = copy.deepcopy(before)
    after[field]["unrelated"] = "different"
    fixture["observe"].return_value = after
    result = fixture["verify"]()
    assert not result["restored"]
    assert result["before"] == before and result["after"] == after
    assert Path(fixture["JOURNAL"]).exists()


def test_original_enabled_owned_feature_prevents_journal_authorization(
    fixture: dict[str, Any],
) -> None:
    fixture["observe"].return_value["catalogue"]["Telnet-Client"]["Installed"] = "true"
    with pytest.raises(AssertionError, match="must be disabled"):
        fixture["setup"]()
    assert not Path(fixture["JOURNAL"]).exists()


def test_verification_without_journal_never_reads_or_changes_system_state(
    fixture: dict[str, Any],
) -> None:
    assert fixture["verify"]() == {"restored": True, "journal_absent": True}
    fixture["observe"].assert_not_called()
