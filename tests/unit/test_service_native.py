"""Check service setter ABI, resource lifetimes, and native failure boundaries."""

# SPDX-License-Identifier: GPL-3.0-or-later
# ABI tests deliberately inspect the private ctypes records.
# pylint: disable=protected-access

import ctypes
from types import ModuleType, SimpleNamespace
from typing import Any
from unittest.mock import Mock

import pytest

from tests.unit.payload_support import ROOT, load_module


@pytest.fixture(name="helper")
def service_helper() -> ModuleType:
    """Load the native helper without calling Windows APIs.

    :returns: Imported service helper.
    """
    return load_module(
        ROOT / "legacy_windows/plugins/module_utils/legacy_windows_service.py",
        "tested_service_native",
    )


@pytest.fixture(name="native")
def native_library(helper: ModuleType, monkeypatch: pytest.MonkeyPatch) -> Any:
    """Replace only the DLL and error boundary.

    :param helper: Helper being exercised.
    :param monkeypatch: Scoped native substitutions.
    :returns: Native mock and mutable Windows error code.
    """
    state = SimpleNamespace(library=Mock(), error=5)
    state.library.OpenSCManagerW.return_value = 1
    state.library.OpenServiceW.return_value = 2
    state.library.CreateServiceW.return_value = 3
    monkeypatch.setattr(helper, "_library", lambda: state.library)
    monkeypatch.setattr(
        helper.ctypes, "get_last_error", lambda: state.error, raising=False
    )

    def _error(code: int) -> OSError:
        error = OSError("Windows error " + str(code))
        error.winerror = code  # type: ignore[attr-defined]
        return error

    monkeypatch.setattr(helper.ctypes, "WinError", _error, raising=False)
    return state


def test_native_records_preserve_windows_dword_and_pointer_width(
    helper: ModuleType,
) -> None:
    width = ctypes.sizeof(ctypes.c_void_p)
    assert ctypes.sizeof(helper._Status) == 36
    assert ctypes.sizeof(helper._Action) == 8
    assert helper._Config.path.offset == (16 if width == 8 else 12)
    assert helper._Failures.actions.offset == (32 if width == 8 else 16)


@pytest.mark.parametrize("major,expected", [(5, False), (6, True), (10, True)])
def test_delayed_start_boundary_uses_actual_os_version(
    helper: ModuleType, monkeypatch: pytest.MonkeyPatch, major: int, expected: bool
) -> None:
    monkeypatch.setattr(
        helper.sys,
        "getwindowsversion",
        lambda: SimpleNamespace(major=major),
        raising=False,
    )
    assert helper.supports_delayed_start() is expected


def test_creation_defaults_and_handles_close(helper: ModuleType, native: Any) -> None:
    helper.create("owned", '"owned.exe"')
    assert native.library.CreateServiceW.call_args.args == (
        1,
        "owned",
        "owned",
        1,
        16,
        2,
        1,
        '"owned.exe"',
        None,
        None,
        None,
        None,
        None,
    )
    assert [
        call.args[0] for call in native.library.CloseServiceHandle.call_args_list
    ] == [3, 1]


@pytest.mark.parametrize("query_error", [2, 5, 124])
def test_unreadable_description_returns_null_without_hiding_service(
    helper: ModuleType, native: Any, monkeypatch: pytest.MonkeyPatch, query_error: int
) -> None:
    config = helper._Config(service_type=16, start_type=3, display_name="owned")
    status = helper._Status(state=1)

    def _buffer(function: Any, unused_service: Any, level: int | None = None) -> Any:
        if function is native.library.QueryServiceConfigW:
            return ctypes.create_string_buffer(bytes(config))
        if function is native.library.QueryServiceStatusEx:
            return ctypes.create_string_buffer(bytes(status))
        if level == 1:
            raise helper.ctypes.WinError(query_error)
        return ctypes.create_string_buffer(128)

    monkeypatch.setattr(helper, "_buffer", _buffer)
    monkeypatch.setattr(helper, "_dependents", lambda *_arguments: [])
    warnings: list[str] = []
    actual = helper.read("owned", warnings)
    assert actual["description"] is None
    assert actual["name"] == "owned" and actual["display_name"] == "owned"
    assert actual["state"] == "stopped" and actual["start_mode"] == "manual"
    assert actual["failure_actions"] == [] and actual["required_privileges"] == []
    assert not warnings
    assert [
        call.args[0] for call in native.library.CloseServiceHandle.call_args_list
    ] == [2, 1]


def test_other_required_configuration_failure_remains_an_error(
    helper: ModuleType, native: Any, monkeypatch: pytest.MonkeyPatch
) -> None:
    config = helper._Config(service_type=16, start_type=3)
    status = helper._Status(state=1)

    def _buffer(function: Any, unused_service: Any, level: int | None = None) -> Any:
        if function is native.library.QueryServiceConfigW:
            return ctypes.create_string_buffer(bytes(config))
        if function is native.library.QueryServiceStatusEx:
            return ctypes.create_string_buffer(bytes(status))
        if level == 5:
            raise helper.ctypes.WinError(2)
        return ctypes.create_string_buffer(128)

    monkeypatch.setattr(helper, "_buffer", _buffer)
    monkeypatch.setattr(helper, "_dependents", lambda *_arguments: [])
    with pytest.raises(OSError) as error:
        helper.read("owned", [])
    assert error.value.winerror == 2  # type: ignore[attr-defined]
    assert [
        call.args[0] for call in native.library.CloseServiceHandle.call_args_list
    ] == [2, 1]


def test_basic_setter_preserves_unrequested_fields_and_empty_dependencies(
    helper: ModuleType, native: Any
) -> None:
    helper.change("owned", dependencies=[])
    assert native.library.ChangeServiceConfigW.call_args.args == (
        2,
        0xFFFFFFFF,
        0xFFFFFFFF,
        0xFFFFFFFF,
        None,
        None,
        None,
        None,
        None,
        None,
        None,
    )
    assert [
        call.args[0] for call in native.library.CloseServiceHandle.call_args_list
    ] == [2, 1]


@pytest.mark.parametrize("access", [0, 16])
def test_extended_setter_requests_only_the_callers_additional_rights(
    helper: ModuleType, native: Any, access: int
) -> None:
    helper.set_extended("owned", "failures", {"failure_actions": []}, access=access)
    assert native.library.OpenServiceW.call_args.args == (1, "owned", 2 | access)


def test_forced_restart_restores_only_previously_active_dependents(
    helper: ModuleType, native: Any, monkeypatch: pytest.MonkeyPatch
) -> None:
    services = {"companion": 4, "primary": 4, "stopped": 1}
    operations: list[tuple[str, str]] = []
    native.library.OpenServiceW.side_effect = (
        lambda unused_manager, name, unused_access: name
    )

    def _buffer(unused_function: Any, name: str, unused_level: int) -> Any:
        status = helper._Status()
        status.state = services[name]
        return ctypes.create_string_buffer(bytes(status))

    def _control(name: str, code: int, unused_status: Any) -> int:
        assert code == 1
        services[name] = 1
        operations.append((name, "stop"))
        return 1

    def _start(name: str, unused_count: int, unused_arguments: Any) -> int:
        services[name] = 4
        operations.append((name, "start"))
        return 1

    monkeypatch.setattr(helper, "_buffer", _buffer)
    monkeypatch.setattr(
        helper,
        "_dependents",
        lambda unused_library, name: (
            ["primary", "stopped"] if name == "companion" else []
        ),
    )
    native.library.ControlService.side_effect = _control
    native.library.StartServiceW.side_effect = _start
    helper.control("companion", "restarted", True)
    assert operations == [
        ("primary", "stop"),
        ("companion", "stop"),
        ("companion", "start"),
        ("primary", "start"),
    ]
    assert services == {"companion": 4, "primary": 4, "stopped": 1}


def test_failed_setter_closes_service_then_manager(
    helper: ModuleType, native: Any
) -> None:
    native.library.ChangeServiceConfig2W.return_value = 0
    native.error = 124
    with pytest.raises(OSError, match="Windows error 124"):
        helper.set_extended("owned", "sid_info", 1)
    assert [
        call.args[0] for call in native.library.CloseServiceHandle.call_args_list
    ] == [2, 1]


def test_failure_actions_keep_order_buffers_and_zero_length_pointer(
    helper: ModuleType, native: Any
) -> None:
    records: list[dict[str, Any]] = []

    def _write(unused_service: int, level: int, pointer: Any) -> int:
        assert level == 2
        value = pointer._obj
        records.append(
            {
                "period": value.reset_period,
                "command": value.command,
                "count": value.count,
                "pointer": bool(value.actions),
                "actions": [
                    (entry.type, entry.delay) for entry in value.actions[: value.count]
                ],
            }
        )
        return 1

    native.library.ChangeServiceConfig2W.side_effect = _write
    helper.set_extended(
        "owned",
        "failures",
        {
            "failure_actions": [
                {"type": "restart", "delay_ms": 0xFFFFFFFF},
                {"type": "none", "delay_ms": 0},
            ],
            "failure_reset_period_sec": 0xFFFFFFFF,
            "failure_command": "command",
        },
    )
    helper.set_extended("owned", "failures", {"failure_actions": []})
    helper.set_extended("owned", "failures", {"failure_command": ""})
    assert records == [
        {
            "period": 0xFFFFFFFF,
            "command": "command",
            "count": 2,
            "pointer": True,
            "actions": [(1, 0xFFFFFFFF), (0, 0)],
        },
        {"period": 0, "command": None, "count": 0, "pointer": True, "actions": []},
        {"period": 0, "command": "", "count": 0, "pointer": False, "actions": []},
    ]


def test_privilege_multisz_contains_final_double_nul(
    helper: ModuleType, native: Any
) -> None:
    def _write(unused_service: int, level: int, pointer: Any) -> int:
        assert level == 6
        address = pointer._obj.value
        assert ctypes.wstring_at(address, 21) == "SeChangeNotifyPrivilege"[:21]
        assert ctypes.wstring_at(address, 25).endswith("\0\0")
        return 1

    native.library.ChangeServiceConfig2W.side_effect = _write
    helper.set_extended("owned", "required_privileges", ["SeChangeNotifyPrivilege"])


@pytest.mark.parametrize("write_succeeds", [True, False])
def test_reboot_setter_restores_token_privilege_and_closes_it_even_on_failure(
    helper: ModuleType,
    native: Any,
    monkeypatch: pytest.MonkeyPatch,
    write_succeeds: bool,
) -> None:
    kernel = Mock()
    kernel.GetCurrentProcess.return_value = 10
    monkeypatch.setattr(
        helper.ctypes,
        "WinDLL",
        lambda *unused, **unused_keywords: kernel,
        raising=False,
    )
    adjustments: list[int] = []

    def _open(unused_process: int, access: int, output: Any) -> int:
        assert access == 0x28
        output._obj.value = 99
        return 1

    def _adjust(
        token: Any,
        unused_disable_all: bool,
        requested: Any,
        unused_size: int,
        previous: Any,
        unused_needed: Any,
    ) -> int:
        assert token.value == 99
        adjustments.append(requested._obj.attributes)
        if previous is not None:
            previous._obj.count = 1
            previous._obj.attributes = 0
        return 1

    native.library.OpenProcessToken.side_effect = _open
    native.library.AdjustTokenPrivileges.side_effect = _adjust
    native.library.ChangeServiceConfig2W.return_value = int(write_succeeds)
    native.error = 124 if not write_succeeds else 0
    parameters = {"failure_actions": [{"type": "reboot", "delay_ms": 1}]}
    if write_succeeds:
        helper.set_extended("owned", "failures", parameters)
    else:
        with pytest.raises(OSError, match="Windows error 124"):
            helper.set_extended("owned", "failures", parameters)
    assert adjustments == [2, 0]
    kernel.CloseHandle.assert_called_once()
    assert kernel.CloseHandle.call_args.args[0].value == 99
