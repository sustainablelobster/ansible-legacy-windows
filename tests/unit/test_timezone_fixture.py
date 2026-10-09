"""Verify timezone fixture journaling, native readback, and recovery."""

# SPDX-License-Identifier: GPL-3.0-or-later

import ast
import base64
import copy
import ctypes
import datetime
import json
import os
from pathlib import Path
from types import SimpleNamespace
from typing import Any
from unittest.mock import MagicMock, Mock

import pytest

# The pinned Nix environment supplies PyYAML without its optional typing stubs.
import yaml  # type: ignore[import-untyped]

from tests.unit.payload_support import ROOT


@pytest.fixture(name="fixture")
def timezone_fixture(tmp_path: Path) -> Any:
    """Load native layouts and recovery contracts without Windows initialization.

    :param tmp_path: Disposable controller-only recovery directory.
    :returns: Real fixture contracts with observable native-operation stand-ins.
    """
    source = yaml.safe_load(
        (ROOT / "tests/integration/vars/timezone_fixture.yml").read_text()
    )["timezone_fixture"]
    source = source.replace("{{ timezone_helper_sources | to_json | to_json }}", "'{}'")
    names = {
        "SystemTime",
        "Zone",
        "DynamicZone",
        "encoded",
        "text",
        "transition",
        "observe",
        "save_journal",
        "read_journal",
        "backup",
        "setup",
        "restore_native",
        "cleanup",
    }
    definitions: list[ast.stmt] = [
        node
        for node in ast.parse(source).body
        if isinstance(node, (ast.FunctionDef, ast.ClassDef)) and node.name in names
    ]
    namespace: dict[str, Any] = {
        "base64": base64,
        "ctypes": ctypes,
        "datetime": datetime,
        "json": json,
        "os": os,
        "WORD": ctypes.c_uint16,
        "LONG": ctypes.c_int32,
        "JOURNAL": str(tmp_path / "timezone-recovery.json"),
        "BASELINE": "Pacific Standard Time",
    }
    # Load only isolated contracts; helper-source injection and main never run.
    # pylint: disable-next=exec-used
    exec(
        compile(
            ast.Module(body=definitions, type_ignores=[]), "<timezone fixture>", "exec"
        ),
        namespace,
    )
    zone = namespace["Zone"]()
    zone.bias, zone.daylight_bias = 300, -60
    unusual_name = "Eastern Standard Time"
    for index, character in enumerate(unusual_name):
        zone.standard_name[index] = ord(character)
        zone.daylight_name[index] = ord(character)
    initial = {
        "raw": base64.b64encode(bytes(zone)).decode("ascii"),
        "dynamic": None,
        "offsets": [-300, -240],
        "daylight_name": unusual_name,
    }
    helper = SimpleNamespace(
        get_timezone=Mock(return_value="Eastern Standard Time"), set_timezone=Mock()
    )
    privilege_context = MagicMock()
    owner = SimpleNamespace(ownership_privileges=Mock(return_value=privilege_context))
    api = SimpleNamespace(
        functions=namespace,
        initial=copy.deepcopy(initial),
        current=copy.deepcopy(initial),
        journal=tmp_path / "timezone-recovery.json",
        helper=helper,
        owner=owner,
        privilege_context=privilege_context,
        native_restore=namespace["restore_native"],
        native_observe=namespace["observe"],
    )

    def _restore(state: dict[str, Any]) -> None:
        api.current = copy.deepcopy(state["native"])

    namespace.update(
        {
            "observe": Mock(side_effect=lambda year: copy.deepcopy(api.current)),
            "restore_native": Mock(side_effect=_restore),
            "load_timezone_helper": Mock(return_value=helper),
            "sys": SimpleNamespace(modules={"legacy_windows_owner": owner}),
            "set_zone": Mock(return_value=True),
            "require": Mock(),
        }
    )
    return api


def test_backup_preserves_raw_native_state_before_timezone_writes(fixture: Any) -> None:
    state = fixture.functions["backup"]()
    assert state["native"] == fixture.initial
    assert state["timezone"] == "Eastern Standard Time"
    assert state["restored"] is False
    assert json.loads(fixture.journal.read_text()) == state
    fixture.helper.set_timezone.assert_not_called()
    fixture.functions["restore_native"].assert_not_called()


def test_existing_recovery_journal_cannot_be_replaced(fixture: Any) -> None:
    fixture.journal.write_text("earlier native backup")
    with pytest.raises(AssertionError, match="already exists"):
        fixture.functions["setup"]()
    assert fixture.journal.read_text() == "earlier native backup"
    fixture.helper.get_timezone.assert_not_called()
    fixture.helper.set_timezone.assert_not_called()


def test_failed_journal_creation_prevents_baseline_write(fixture: Any) -> None:
    fixture.functions["save_journal"] = Mock(side_effect=OSError("disk full"))
    with pytest.raises(OSError, match="disk full"):
        fixture.functions["setup"]()
    fixture.helper.set_timezone.assert_not_called()
    assert fixture.current == fixture.initial


def test_partial_setup_failure_keeps_native_backup_for_cleanup(fixture: Any) -> None:
    def _fail_after_change(requested: str) -> None:
        assert requested == "Pacific Standard Time"
        fixture.current["offsets"] = [-480, -420]
        raise OSError("timezone setting failed after mutation")

    fixture.helper.set_timezone.side_effect = _fail_after_change
    with pytest.raises(OSError, match="after mutation"):
        fixture.functions["setup"]()
    state = fixture.functions["read_journal"]()
    assert state["native"] == fixture.initial
    assert state["restored"] is False
    fixture.functions["cleanup"](state)
    assert fixture.current == fixture.initial
    assert json.loads(fixture.journal.read_text())["restored"] is True


def test_failed_cleanup_retains_backup_and_can_be_retried(fixture: Any) -> None:
    state = fixture.functions["backup"]()
    fixture.current["offsets"] = [330, 330]
    restore = fixture.functions["restore_native"]
    fixture.functions["restore_native"] = Mock(side_effect=OSError("privilege denied"))
    with pytest.raises(OSError, match="privilege denied"):
        fixture.functions["cleanup"](state)
    assert json.loads(fixture.journal.read_text()) == state
    assert state["restored"] is False
    fixture.functions["restore_native"] = restore
    fixture.functions["cleanup"](fixture.functions["read_journal"]())
    assert fixture.current == fixture.initial


def test_failed_native_verification_does_not_mark_restored(fixture: Any) -> None:
    state = fixture.functions["backup"]()
    fixture.current["daylight_name"] = "Different native daylight name"
    fixture.functions["restore_native"] = Mock()
    with pytest.raises(AssertionError, match="Restored native timezone differs"):
        fixture.functions["cleanup"](state)
    assert json.loads(fixture.journal.read_text()) == state
    assert state["restored"] is False


def test_unchanged_native_state_is_not_rewritten(fixture: Any) -> None:
    fixture.functions["cleanup"](fixture.functions["backup"]())
    fixture.functions["restore_native"].assert_not_called()


def test_legacy_restore_uses_exact_raw_state_under_bounded_privilege(
    fixture: Any,
) -> None:
    state = fixture.functions["backup"]()
    fixture.native_restore(state)
    fixture.owner.ownership_privileges.assert_called_once_with(
        ("SeSystemtimePrivilege",)
    )
    arguments = fixture.functions["set_zone"].call_args.args
    restored = ctypes.cast(
        arguments[0], ctypes.POINTER(fixture.functions["Zone"])
    ).contents
    assert bytes(restored) == base64.b64decode(fixture.initial["raw"])
    fixture.helper.set_timezone.assert_not_called()
    fixture.privilege_context.__exit__.assert_called_once()


def test_legacy_restore_failure_releases_privilege_context(fixture: Any) -> None:
    state = fixture.functions["backup"]()
    fixture.functions["require"] = Mock(side_effect=OSError("native restore denied"))
    with pytest.raises(OSError, match="native restore denied"):
        fixture.native_restore(state)
    fixture.privilege_context.__exit__.assert_called_once()
    assert json.loads(fixture.journal.read_text())["restored"] is False


def test_modern_restore_uses_original_identifier_without_legacy_setter(
    fixture: Any,
) -> None:
    state = fixture.functions["backup"]()
    state["native"]["dynamic"] = {"key_name": "Pacific Standard Time"}
    fixture.native_restore(state)
    fixture.helper.set_timezone.assert_called_once_with("Eastern Standard Time")
    fixture.functions["set_zone"].assert_not_called()
    fixture.owner.ownership_privileges.assert_not_called()


def test_observer_reads_native_rules_and_offsets_without_loading_helpers(
    fixture: Any,
) -> None:
    native = fixture.functions

    def _convert(unused_zone: Any, universal: Any, local: Any) -> bool:
        record = native["SystemTime"]
        source = ctypes.cast(universal, ctypes.POINTER(record)).contents
        target = ctypes.cast(local, ctypes.POINTER(record)).contents
        target.year, target.month, target.day = source.year, source.month, source.day
        target.hour = source.hour + 1
        return True

    native.update(
        {
            "get_zone": Mock(return_value=1),
            "get_dynamic": None,
            "convert": Mock(side_effect=_convert),
        }
    )
    actual = fixture.native_observe(2026)
    assert actual["offsets"] == [60, 60]
    assert actual["dynamic"] is None
    assert actual["standard_date"] == [0] * 8
    assert len(base64.b64decode(actual["raw"])) == 172
    native["load_timezone_helper"].assert_not_called()
    assert native["convert"].call_count == 2
