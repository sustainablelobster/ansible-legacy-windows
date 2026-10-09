"""Verify Event Log journals, retained files, and retryable recovery."""

# SPDX-License-Identifier: GPL-3.0-or-later
# The fixture is executed with isolated native and runtime substitutes.
# pylint: disable=exec-used

import json
import sys
from pathlib import Path
from types import ModuleType, SimpleNamespace
from typing import Any
from unittest.mock import Mock

import pytest

# PyYAML is supplied by the pinned developer environment without typing stubs.
import yaml  # type: ignore[import-untyped]

from tests.unit.payload_support import ROOT


@pytest.fixture(name="fixture")
def recovery_fixture(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> dict[str, Any]:
    """Load the maintained target fixture with isolated paths and native APIs.

    :param tmp_path: Owned local recovery workspace.
    :param monkeypatch: Scoped native/runtime substitutes.
    :returns: Fixture functions and globals.
    """
    monkeypatch.setitem(sys.modules, "winreg", ModuleType("winreg"))
    import ctypes  # pylint: disable=import-outside-toplevel

    monkeypatch.setattr(ctypes, "WinDLL", Mock(return_value=Mock()), raising=False)
    source = yaml.safe_load(
        (ROOT / "tests/integration/vars/eventlog_fixture.yml").read_text(
            encoding="utf-8"
        )
    )["eventlog_fixture"]
    monkeypatch.setattr(sys, "argv", ["fixture", str(tmp_path), "cleanup"])
    namespace: dict[str, Any] = {"__name__": "fixture"}
    exec(compile(source, "eventlog_fixture.py", "exec"), namespace)
    namespace["sys"] = SimpleNamespace(
        version_info=(3, 4, 4), argv=["fixture", str(tmp_path), "cleanup", "Probe"]
    )
    namespace["registered"] = Mock(return_value=None)
    namespace["file_paths"] = lambda name: [str(tmp_path / (name + ".evt"))]
    return namespace


def make_journal(fixture: dict[str, Any]) -> dict[str, Any]:
    """Create one owned test journal with exact expected file paths.

    :param fixture: Loaded isolated recovery fixture.
    :returns: Persisted journal record.
    """
    record = {
        "workspace": fixture["workspace"],
        "log": "12345678LegacyEventLog",
        "missing": "87654321Missing EventLog",
        "sources": [
            "12345678LegacyEventLog" + suffix
            for suffix in ("Source1", "Source2", "Partial")
        ],
        "originally_absent": True,
    }
    record["files"] = fixture["file_paths"](record["log"]) + fixture["file_paths"](
        record["missing"]
    )
    Path(fixture["journal_path"]).write_text(json.dumps(record), encoding="utf-8")
    return record


def test_cleanup_without_journal_does_not_mutate_logs(fixture: dict[str, Any]) -> None:
    assert fixture["main"]() == {"restored": True, "requires_reboot": False}
    fixture["registered"].assert_not_called()


# This workflow keeps an independent fixture and expected-result oracle.
# pylint: disable=duplicate-code
def test_existing_journal_is_not_overwritten(fixture: dict[str, Any]) -> None:
    make_journal(fixture)
    before = Path(fixture["journal_path"]).read_bytes()
    with pytest.raises(ValueError, match="must not be overwritten"):
        fixture["setup"]()
    assert Path(fixture["journal_path"]).read_bytes() == before


# pylint: enable=duplicate-code


# This workflow keeps an independent fixture and expected-result oracle.
# pylint: disable=duplicate-code
def test_file_lock_retains_journal_and_cleanup_retry_removes_it(
    fixture: dict[str, Any], monkeypatch: pytest.MonkeyPatch
) -> None:
    record = make_journal(fixture)
    owned = Path(record["files"][0])
    owned.write_bytes(b"owned log")
    actual_remove = fixture["os"].remove
    error = OSError(32, "sharing violation")
    error.winerror = 32  # type: ignore[attr-defined]

    def _remove(path: str) -> None:
        if path == str(owned):
            raise error
        actual_remove(path)

    monkeypatch.setattr(fixture["os"], "remove", _remove)
    assert fixture["main"]() == {
        "restored": False,
        "requires_reboot": True,
        "retained": [str(owned)],
    }
    assert Path(fixture["journal_path"]).exists() and owned.exists()
    monkeypatch.setattr(fixture["os"], "remove", actual_remove)
    assert fixture["main"]() == {"restored": True, "requires_reboot": False}
    assert not owned.exists() and not Path(fixture["journal_path"]).exists()


# pylint: enable=duplicate-code


@pytest.mark.parametrize(
    "field,value",
    [
        ("workspace", "another-workspace"),
        ("originally_absent", False),
        ("files", ["C:\\unowned.evt"]),
        ("sources", ["Application"]),
    ],
)
def test_unowned_journal_is_rejected_before_mutation(
    fixture: dict[str, Any], field: str, value: Any
) -> None:
    record = make_journal(fixture)
    record[field] = value
    Path(fixture["journal_path"]).write_text(json.dumps(record), encoding="utf-8")
    with pytest.raises(ValueError, match="does not own"):
        fixture["main"]()
    fixture["registered"].assert_not_called()


def test_recovery_requires_registration_absence_before_journal_deletion(
    fixture: dict[str, Any],
) -> None:
    make_journal(fixture)
    fixture["registered"].side_effect = [None, None, {"remaining": True}, None]
    with pytest.raises(ValueError, match="registration remains"):
        fixture["main"]()
    assert Path(fixture["journal_path"]).exists()


def test_journal_cannot_authorize_a_builtin_log_even_with_matching_file_paths(
    fixture: dict[str, Any],
) -> None:
    record = make_journal(fixture)
    record["log"] = "Application"
    record["files"] = fixture["file_paths"](record["log"]) + fixture["file_paths"](
        record["missing"]
    )
    Path(fixture["journal_path"]).write_text(json.dumps(record), encoding="utf-8")
    with pytest.raises(ValueError, match="does not own these log names"):
        fixture["main"]()
    fixture["registered"].assert_not_called()


def test_spaced_owned_log_is_journaled_and_recovered_without_clear_fallback(
    fixture: dict[str, Any],
) -> None:
    record = make_journal(fixture)
    assert fixture["journal"]()["missing"] == "87654321Missing EventLog"
    root = Mock()
    root.__enter__ = Mock(return_value=root)
    root.__exit__ = Mock(return_value=False)
    registry = Mock(HKEY_LOCAL_MACHINE=1, KEY_READ=1, KEY_WRITE=2)
    registry.OpenKey.return_value = root
    fixture["winreg"] = registry
    fixture["registered"].side_effect = [None, {"owned": True}, None, None]
    delete = Mock()
    fixture["delete_tree"] = delete
    assert fixture["main"]() == {"restored": True, "requires_reboot": False}
    delete.assert_called_once_with(root, record["missing"])
    fixture["api"].ClearEventLogW.assert_not_called()


def test_protected_observation_reads_builtins_without_mutation(
    fixture: dict[str, Any],
) -> None:
    make_journal(fixture)
    fixture["operation"] = "observe_protected"
    fixture["probe_registration"] = Mock(return_value=False)
    fixture["registered"].side_effect = [
        None,
        None,
        {"entries": 10},
        {"entries": 20},
        {"entries": 30},
    ]
    assert fixture["main"]() == {
        "log": None,
        "missing": None,
        "rejected_registered": False,
        "protected": {
            "Application": {"entries": 10},
            "Security": {"entries": 20},
            "System": {"entries": 30},
        },
    }
    fixture["api"].ClearEventLogW.assert_not_called()


def test_registry_binary_observation_is_lossless_and_json_serializable(
    fixture: dict[str, Any],
) -> None:
    registry = Mock()
    registry.QueryInfoKey.return_value = (0, 2, 0)
    registry.EnumValue.side_effect = [
        ("Binary", b"\x07\x00\xff\x00", 3),
        ("Text", "Unchanged", 1),
    ]
    fixture["winreg"] = registry
    observed = fixture["values"]("key")
    assert json.loads(json.dumps(observed)) == {
        "Binary": [{"hex": "0700ff00"}, 3],
        "Text": ["Unchanged", 1],
    }
    assert (
        fixture["binascii"].unhexlify(observed["Binary"][0]["hex"])
        == b"\x07\x00\xff\x00"
    )


# This workflow keeps an independent fixture and expected-result oracle.
# pylint: disable=duplicate-code
@pytest.mark.parametrize(
    "filename", ["win_eventlog.yml", "tasks/win_eventlog_case.yml"]
)
def test_owned_assertions_are_conditions_not_yaml_mappings(filename: str) -> None:
    document = yaml.safe_load(
        (ROOT / "tests/integration" / filename).read_text(encoding="utf-8")
    )
    conditions: list[Any] = []

    def _visit(value: Any) -> None:
        if isinstance(value, dict):
            if "ansible.builtin.assert" in value:
                conditions.extend(value["ansible.builtin.assert"]["that"])
            for child in value.values():
                _visit(child)
        elif isinstance(value, list):
            for child in value:
                _visit(child)

    _visit(document)
    assert conditions and all(isinstance(item, (str, bool)) for item in conditions)


# pylint: enable=duplicate-code
