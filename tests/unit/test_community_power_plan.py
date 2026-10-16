"""Verify power-plan requests and both native power-policy API boundaries."""

# Copyright 2026 sustainablelobster
# SPDX-License-Identifier: GPL-3.0-or-later

import ctypes
import json
import sys
import uuid
from pathlib import Path
from types import SimpleNamespace
from typing import Any
from unittest.mock import Mock

import pytest

from tests.unit.payload_support import HELPER, ROOT, invoke_payload, load_module

SOURCE = ROOT / "legacy_community_windows/plugins"
GUID_A = "381b4222-f694-41f0-9685-ff5bb260df2e"
GUID_B = "8c5e7fda-e8bf-4a96-9a85-a6e23a8c635c"


@pytest.fixture(name="execute")
def power_request(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
) -> Any:
    """Run the public request with independent power-policy observations.

    :param monkeypatch: Scoped import and native-boundary replacements.
    :param tmp_path: Owned JSON request directory.
    :param capsys: JSON result capture.
    :returns: Request callable and native catalogue/setter observations.
    """
    monkeypatch.syspath_prepend(str(HELPER.parent))
    monkeypatch.syspath_prepend(str(SOURCE / "module_utils"))
    payload = load_module(SOURCE / "modules/win_power_plan.py", "tested_power_plan")
    native = SimpleNamespace(
        read_plans=Mock(return_value=({"First": 1, "Second": 2}, 1, False)),
        activate=Mock(),
    )
    monkeypatch.setattr(payload, "native", native)
    filename = tmp_path / "request.json"

    def _run(arguments: dict[str, Any]) -> tuple[int, dict[str, Any]]:
        filename.write_text(json.dumps(arguments), encoding="utf-8")
        monkeypatch.setattr(sys, "argv", [str(payload.__file__), str(filename)])
        return invoke_payload(payload, capsys)

    return _run, native


@pytest.mark.parametrize("check", [False, True])
def test_name_selection_predicts_or_activates(execute: Any, check: bool) -> None:
    run, native = execute
    assert run({"name": "sEcOnD", "_ansible_check_mode": check}) == (
        0,
        {
            "changed": True,
            "power_plan_name": "sEcOnD",
            "power_plan_enabled": True,
            "all_available_plans": {"First": False, "Second": True},
        },
    )
    assert native.activate.call_count == (0 if check else 1)
    if not check:
        native.activate.assert_called_once_with(2, False)


def test_active_plan_is_unchanged(execute: Any) -> None:
    run, native = execute
    assert run({"name": "First"})[1]["changed"] is False
    native.activate.assert_not_called()


def test_guid_selects_real_catalogue_identifier(execute: Any) -> None:
    run, native = execute
    native.read_plans.return_value = ({"First": GUID_A, "Second": GUID_B}, GUID_A, True)
    status, result = run({"guid": "{" + GUID_B.upper() + "}"})
    assert status == 0
    assert result["power_plan_name"] is None
    assert result["all_available_plans"] == {"First": False, "Second": True}
    native.activate.assert_called_once_with(GUID_B, True)


@pytest.mark.parametrize("arguments", [{"name": "missing"}, {"guid": GUID_B}])
def test_legacy_capability_failure_retains_catalogue(
    execute: Any, arguments: dict[str, Any]
) -> None:
    run, native = execute
    status, result = run(arguments)
    assert status == 1 and result["changed"] is False
    assert result["all_available_plans"] == {"First": True, "Second": False}
    native.activate.assert_not_called()


def test_native_activation_failure_preserves_observed_state(execute: Any) -> None:
    run, native = execute
    native.activate.side_effect = OSError("native power-policy access denied")
    status, result = run({"name": "Second"})
    assert status == 1 and result["changed"] is False
    assert result["power_plan_enabled"] is False
    assert result["all_available_plans"] == {"First": True, "Second": False}
    assert "access denied" in result["msg"]


def test_missing_selection_is_rejected_before_native_calls(execute: Any) -> None:
    run, native = execute
    assert run({})[0] == 1
    native.read_plans.assert_not_called()


# These checks isolate native ABI calls that cannot be made by Linux unit tests.
# pylint: disable=protected-access
def test_legacy_catalogue_callback_and_activation(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    helper = load_module(
        SOURCE / "module_utils/legacy_community_windows_power.py", "power_legacy"
    )

    def _enumerate(callback: Any, data: int) -> int:
        assert data == 0
        assert callback(3, 12, "First", 0, "", None, 0) == 1
        assert callback(7, 14, "Second", 0, "", None, 0) == 1
        return 1

    def _active(pointer: Any) -> int:
        pointer._obj.value = 7
        return 1

    power = SimpleNamespace(
        EnumPwrSchemes=Mock(side_effect=_enumerate),
        GetActivePwrScheme=Mock(side_effect=_active),
        SetActivePwrScheme=Mock(return_value=1),
    )
    monkeypatch.setattr(helper.ctypes, "WINFUNCTYPE", ctypes.CFUNCTYPE, raising=False)
    monkeypatch.setattr(
        helper.ctypes, "WinDLL", lambda *_args, **_kwargs: power, raising=False
    )
    assert helper.read_plans() == ({"First": 3, "Second": 7}, 7, False)
    helper.activate(3, False)
    power.SetActivePwrScheme.assert_called_once_with(3, None, None)


def test_modern_catalogue_frees_owned_active_guid(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    helper = load_module(
        SOURCE / "module_utils/legacy_community_windows_power.py", "power_modern"
    )
    active_guid = helper._Guid.from_buffer_copy(uuid.UUID(GUID_A).bytes_le)

    def _active(_root: Any, pointer: Any) -> int:
        pointer._obj.value = ctypes.addressof(active_guid)
        return 0

    def _enumerate(*arguments: Any) -> int:
        index = arguments[4]
        buffer = arguments[5]
        if index == 2:
            return 259
        identity = [GUID_A, GUID_B][index]
        ctypes.memmove(buffer, uuid.UUID(identity).bytes_le, 16)
        return 0

    def _name(
        _root: Any, guid: Any, _subgroup: Any, _setting: Any, buffer: Any, size: Any
    ) -> int:
        label = "First" if helper._identity(guid._obj) == GUID_A else "Second"
        native = ctypes.create_unicode_buffer(label)
        size._obj.value = ctypes.sizeof(native)
        if buffer is None:
            return 234
        ctypes.memmove(buffer, native, ctypes.sizeof(native))
        return 0

    power = SimpleNamespace(
        PowerGetActiveScheme=Mock(side_effect=_active),
        PowerEnumerate=Mock(side_effect=_enumerate),
        PowerReadFriendlyName=Mock(side_effect=_name),
        PowerSetActiveScheme=Mock(return_value=0),
    )
    kernel = SimpleNamespace(LocalFree=Mock())
    monkeypatch.setattr(
        helper.ctypes,
        "WinDLL",
        lambda name, **_kwargs: kernel if name == "kernel32" else power,
        raising=False,
    )
    assert helper.read_plans() == ({"First": GUID_A, "Second": GUID_B}, GUID_A, True)
    kernel.LocalFree.assert_called_once()
    helper.activate(GUID_B, True)
    assert helper._identity(power.PowerSetActiveScheme.call_args.args[1]._obj) == GUID_B
