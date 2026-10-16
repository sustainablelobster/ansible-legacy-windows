"""Verify SNMP registry behavior through the public JSON request interface."""

# Copyright 2026 sustainablelobster
# SPDX-License-Identifier: GPL-3.0-or-later

import json
import sys
from pathlib import Path
from types import SimpleNamespace
from typing import Any
from unittest.mock import MagicMock, Mock

import pytest

from tests.unit.payload_support import HELPER, ROOT, invoke_payload, load_module


@pytest.fixture(name="fixture")
def snmp_request(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
) -> Any:
    """Expose independent registry values and an actual JSON request callable.

    :param monkeypatch: Scoped imports and native-registry replacements.
    :param tmp_path: Owned request file location.
    :param capsys: JSON response capture.
    :returns: Request callable, registry values and observed native operations.
    """
    monkeypatch.syspath_prepend(str(HELPER.parent))
    payload = load_module(
        ROOT / "legacy_community_windows/plugins/modules/win_snmp.py", "tested_snmp"
    )
    values: dict[str, dict[str, tuple[Any, int]]] = {
        "PermittedManagers": {"": ("default", 1), "1": ("manager", 1)},
        "ValidCommunities": {"public": (4, 4), "private": (8, 4)},
    }

    def _open_key(_root: str, path: str, _reserved: int, access: int) -> MagicMock:
        name = path.rsplit("\\", 1)[-1]
        assert access in (1, 3)
        if name not in values:
            raise FileNotFoundError("SNMP configuration missing")
        context = MagicMock()
        context.__enter__.return_value = name
        return context

    def set_value(key: str, name: str, _reserved: int, kind: int, value: Any) -> None:
        values[key][name] = (value, kind)

    native = SimpleNamespace(
        HKEY_LOCAL_MACHINE="machine",
        KEY_READ=1,
        KEY_SET_VALUE=2,
        REG_SZ=1,
        REG_DWORD=4,
        OpenKey=Mock(side_effect=_open_key),
        QueryInfoKey=lambda key: (0, len(values[key]), 0),
        EnumValue=lambda key, index: (
            list(values[key])[index],
            *list(values[key].values())[index],
        ),
        SetValueEx=Mock(side_effect=set_value),
        DeleteValue=Mock(side_effect=lambda key, name: values[key].pop(name)),
    )
    monkeypatch.setattr(payload, "winreg", native)
    request = tmp_path / "request.json"

    def execute(arguments: dict[str, Any]) -> tuple[int, dict[str, Any]]:
        """Execute the public JSON request against an independent registry.

        :param arguments: Module inputs, including controller check-mode flag.
        :returns: Payload exit status and decoded result.
        """
        request.write_text(json.dumps(arguments), encoding="utf-8")
        monkeypatch.setattr(sys, "argv", [str(payload.__file__), str(request)])
        return invoke_payload(payload, capsys)

    return SimpleNamespace(execute=execute, values=values, native=native)


def test_omitted_lists_return_existing_configuration(fixture: Any) -> None:
    assert fixture.execute({}) == (
        0,
        {
            "changed": False,
            "failed": False,
            "permitted_managers": ["manager"],
            "community_strings": ["public", "private"],
        },
    )
    fixture.native.SetValueEx.assert_not_called()
    fixture.native.DeleteValue.assert_not_called()


def test_set_preview_apply_and_repeat(fixture: Any) -> None:
    arguments = {"permitted_managers": ["new"], "community_strings": ["new-community"]}
    _, preview = fixture.execute(dict(arguments, _ansible_check_mode=True))
    assert preview["changed"] is True
    assert preview["permitted_managers"] == ["new"]
    assert preview["community_strings"] == ["new-community"]
    fixture.native.SetValueEx.assert_not_called()
    fixture.native.DeleteValue.assert_not_called()
    assert fixture.execute(arguments)[1] == preview
    assert fixture.values["PermittedManagers"] == {"": ("default", 1), "1": ("new", 1)}
    assert fixture.values["ValidCommunities"] == {"new-community": (4, 4)}
    assert fixture.execute(arguments)[1]["changed"] is False


def test_add_preserves_existing_community_permissions_and_fills_manager_gap(
    fixture: Any,
) -> None:
    fixture.values["PermittedManagers"]["3"] = ("third", 1)
    _, result = fixture.execute(
        {
            "action": "add",
            "permitted_managers": ["manager", "new"],
            "community_strings": ["private", "new-community"],
        }
    )
    assert result["permitted_managers"] == ["manager", "third", "new"]
    assert fixture.values["PermittedManagers"]["2"] == ("new", 1)
    assert fixture.values["ValidCommunities"]["private"] == (8, 4)
    assert fixture.values["ValidCommunities"]["new-community"] == (4, 4)


def test_remove_does_not_add_absent_values(fixture: Any) -> None:
    _, result = fixture.execute(
        {
            "action": "remove",
            "permitted_managers": ["absent"],
            "community_strings": ["public", "absent"],
        }
    )
    assert result["permitted_managers"] == ["manager"]
    assert result["community_strings"] == ["private"]
    assert result["changed"] is True
    fixture.native.SetValueEx.assert_not_called()


def test_empty_set_clears_only_supplied_list(fixture: Any) -> None:
    _, result = fixture.execute({"permitted_managers": []})
    assert result["permitted_managers"] == []
    assert result["community_strings"] == ["public", "private"]
    assert fixture.values["PermittedManagers"] == {"": ("default", 1)}


def test_missing_second_key_does_not_mutate_first(fixture: Any) -> None:
    del fixture.values["ValidCommunities"]
    status, result = fixture.execute({"permitted_managers": []})
    assert status == 1 and result["changed"] is False
    fixture.native.DeleteValue.assert_not_called()
    fixture.native.SetValueEx.assert_not_called()


@pytest.mark.parametrize(
    "arguments",
    [
        {"action": "invalid"},
        {"community_strings": {}},
        {"permitted_managers": [None]},
        {"permitted_managers": False},
    ],
)
def test_invalid_options_fail_before_read_or_write(
    fixture: Any, arguments: dict[str, Any]
) -> None:
    status, result = fixture.execute(arguments)
    assert status == 1 and result["changed"] is False
    fixture.native.OpenKey.assert_not_called()


def test_native_write_failure_returns_actionable_error(fixture: Any) -> None:
    fixture.native.SetValueEx.side_effect = PermissionError("native access denied")
    status, result = fixture.execute({"permitted_managers": ["different"]})
    assert status == 1
    assert result["failed"] is True
    assert result["msg"] == "native access denied"
