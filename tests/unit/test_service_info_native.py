"""Exercise read-only service queries without contacting Windows hosts."""

# SPDX-License-Identifier: GPL-3.0-or-later
# The native substitutes inspect ABI structures and borrowed buffer lifetimes.
# pylint: disable=protected-access

import ctypes
import json
import sys
from collections.abc import Callable
from types import ModuleType, SimpleNamespace
from typing import Any
from unittest.mock import Mock, call

import pytest

from tests.unit.payload_support import HELPER, ROOT, load_module, native_error

SERIALIZATION = json.loads(
    (ROOT / "tests/fixtures/service_info_serialization.json").read_text(
        encoding="utf-8"
    )
)


@pytest.fixture(name="helper")
def service_helper(monkeypatch: pytest.MonkeyPatch) -> ModuleType:
    """Load the target helper without opening a native library.

    :param monkeypatch: Scoped import path override.
    :returns: Imported service helper.
    """
    monkeypatch.syspath_prepend(str(HELPER.parent))
    return load_module(
        ROOT / "legacy_windows/plugins/module_utils/legacy_windows_service_info.py",
        "tested_service_info_native",
    )


@pytest.fixture(name="native")
def native_boundary(helper: ModuleType, monkeypatch: pytest.MonkeyPatch) -> Mock:
    """Provide observable Windows calls and native errors.

    :param helper: Imported service helper.
    :param monkeypatch: Scoped Windows library substitutions.
    :returns: Parent mock containing the native library and last-error function.
    """
    native = Mock()
    native.load.return_value = native.library
    native.library.OpenSCManagerW.return_value = 101
    native.library.OpenServiceW.return_value = 202
    native.library.CloseServiceHandle.return_value = 1
    native.last_error.return_value = 122
    native.sid_to_name.return_value = "NT AUTHORITY\\SYSTEM"
    monkeypatch.setattr(helper, "os", SimpleNamespace(name="nt"))
    monkeypatch.setattr(ctypes, "WinDLL", native.load, raising=False)
    monkeypatch.setattr(ctypes, "WinError", native_error, raising=False)
    monkeypatch.setattr(ctypes, "get_last_error", native.last_error, raising=False)
    monkeypatch.setattr(helper, "sid_to_name", native.sid_to_name)
    return native


def _set_dword(pointer: Any, value: int) -> None:
    ctypes.cast(pointer, ctypes.POINTER(ctypes.c_uint32))[0] = value


def _query_structure(structure: Any, native: Mock) -> Callable[..., int]:
    def _query(*arguments: Any) -> int:
        buffer, size, needed = arguments[-3], arguments[-2], arguments[-1]
        _set_dword(needed, ctypes.sizeof(structure))
        if size < ctypes.sizeof(structure):
            native.last_error.return_value = 122
            return 0
        ctypes.memmove(buffer, ctypes.byref(structure), ctypes.sizeof(structure))
        return 1

    return _query


def _service_fixture(helper: ModuleType, native: Mock) -> SimpleNamespace:
    dependencies = ctypes.create_string_buffer(
        "RpcSs\0+Network\0Unicode_雪_😀\0\0".encode("utf-16-le")
    )
    config = helper._ServiceConfig(
        0x110,
        2,
        1,
        '"C:\\Program Files\\service.exe" --run',
        "group",
        9,
        ctypes.cast(dependencies, ctypes.c_void_p),
        "LocalSystem",
        "Service 雪",
    )
    status = helper._ServiceStatusProcess(0x110, 4, 0x1FF, 5, 6, 7, 8000, 99, 1)
    actions = (helper.configuration._FailureAction * 4)(
        (0, 0), (1, 1000), (2, 60000), (3, 0xFFFFFFFF)
    )
    failures = helper.configuration._FailureActions(
        0xFFFFFFFF, "reboot 雪", "command", len(actions), actions
    )
    description = helper.configuration._Description("Description 雪")
    dependents = (helper._EnumServiceStatus * 2)()
    dependents[0].name = "Zulu"
    dependents[1].name = "Alpha"
    native.library.QueryServiceConfigW.side_effect = _query_structure(config, native)
    native.library.QueryServiceStatusEx.side_effect = _query_structure(status, native)
    modern = {
        3: ctypes.c_uint32(0),
        4: ctypes.c_uint32(1),
        5: ctypes.c_uint32(1),
        6: ctypes.c_void_p(),
        7: ctypes.c_uint32(10000),
        8: helper.configuration._Triggers(),
        9: ctypes.c_uint16(2),
        12: ctypes.c_uint32(2),
    }

    def _config2(*arguments: Any) -> int:
        structure = {1: description, 2: failures, **modern}[arguments[1]]
        return _query_structure(structure, native)(*arguments)

    def _dependents(*arguments: Any) -> int:
        assert arguments[:2] == (202, 3)
        buffer, size = arguments[-4], arguments[-3]
        needed, count = arguments[-2], arguments[-1]
        _set_dword(needed, ctypes.sizeof(dependents))
        if size < ctypes.sizeof(dependents):
            native.last_error.return_value = 234
            return 0
        _set_dword(count, len(dependents))
        ctypes.memmove(buffer, ctypes.byref(dependents), ctypes.sizeof(dependents))
        return 1

    native.library.QueryServiceConfig2W.side_effect = _config2
    native.library.EnumDependentServicesW.side_effect = _dependents
    return SimpleNamespace(
        config=config,
        status=status,
        description=description,
        failures=failures,
        dependencies=dependencies,
        dependents=dependents,
        actions=actions,
    )


def test_query_copies_all_31_fields_and_closes_handles(
    helper: ModuleType, native: Mock
) -> None:
    fixture = _service_fixture(helper, native)
    result = helper.query_service("Service\0suffix", [])
    assert result == {
        "name": "Service\0suffix",
        "dependencies": ["RpcSs", "+Network", "Unicode_雪_😀"],
        "dependency_of": ["Zulu", "Alpha"],
        "desktop_interact": True,
        "display_name": "Service 雪",
        "description": "Description 雪",
        "error_control": "normal",
        "load_order_group": "group",
        "path": '"C:\\Program Files\\service.exe" --run',
        "service_type": "win32_own_process",
        "start_mode": "auto",
        "username": "NT AUTHORITY\\SYSTEM",
        "checkpoint": 7,
        "controls_accepted": [
            "stop",
            "pause_continue",
            "shutdown",
            "param_change",
            "netbind_change",
            "hardware_profile_change",
            "power_event",
            "session_change",
            "pre_shutdown",
        ],
        "process_id": 99,
        "service_exit_code": 6,
        "service_flags": ["runs_in_system_process"],
        "state": "started",
        "wait_hint_ms": 8000,
        "win32_exit_code": 5,
        "failure_actions": [
            {"type": "none", "delay_ms": 0},
            {"type": "restart", "delay_ms": 1000},
            {"type": "reboot", "delay_ms": 60000},
            {"type": "run_command", "delay_ms": 0xFFFFFFFF},
        ],
        "failure_command": "command",
        "failure_reboot_msg": "reboot 雪",
        "failure_reset_period_sec": 0xFFFFFFFF,
        "failure_actions_on_non_crash_failure": True,
        "sid_info": "unrestricted",
        "required_privileges": [],
        "pre_shutdown_timeout_ms": 10000,
        "triggers": [],
        "preferred_node": 2,
        "launch_protection": "windows_light",
    }
    native.library.OpenSCManagerW.assert_called_once_with(None, None, 1)
    native.library.OpenServiceW.assert_called_once_with(101, "Service\0suffix", 13)
    assert native.library.CloseServiceHandle.call_args_list == [call(202), call(101)]
    assert {
        entry.args[1] for entry in native.library.QueryServiceConfig2W.call_args_list
    } == {1, 2, 3, 4, 5, 6, 7, 8, 9, 12}
    native.sid_to_name.assert_called_once_with("S-1-5-18")
    fixture.config.display_name = "changed"
    fixture.description.description = "changed"
    fixture.actions[0].delay = 999
    fixture.dependents[0].name = "changed"
    assert result["display_name"] == "Service 雪"
    assert result["description"] == "Description 雪"
    assert result["failure_actions"][0]["delay_ms"] == 0
    assert result["dependency_of"] == ["Zulu", "Alpha"]


@pytest.mark.parametrize(
    "username", [None, "localSystem", "NT AUTHORITY\\NetworkService"]
)
def test_only_exact_local_system_is_translated(
    helper: ModuleType, native: Mock, username: str | None
) -> None:
    fixture = _service_fixture(helper, native)
    fixture.config.username = username
    assert helper.query_service("name", [])["username"] == username
    native.sid_to_name.assert_not_called()


def test_empty_stored_account_is_null_like_reference_driver_account(
    helper: ModuleType, native: Mock
) -> None:
    fixture = _service_fixture(helper, native)
    fixture.config.username = ""
    assert helper.query_service("Tcpip", [])["username"] is None
    native.sid_to_name.assert_not_called()


@pytest.mark.parametrize("empty", [None, ""])
def test_nullable_load_order_group_and_empty_dependencies(
    helper: ModuleType, native: Mock, empty: str | None
) -> None:
    fixture = _service_fixture(helper, native)
    fixture.config.load_order_group = empty
    fixture.config.dependencies = None
    result = helper.query_service("name", [])
    assert result["load_order_group"] == empty
    assert result["dependencies"] == []


@pytest.mark.parametrize(
    ("value", "expected"),
    [
        (1, "kernel_driver"),
        (2, "file_system_driver"),
        (4, "adapter"),
        (8, "recognizer_driver"),
        (16, "win32_own_process"),
        (32, "win32_share_process"),
        (0x50, "user_own_process"),
        (0x60, "user_share_process"),
        (0x200, "pkg_service"),
        (0x30, {}),
        (0x400, {}),
    ],
)
def test_service_types_strip_only_interactive_and_instance_flags(
    helper: ModuleType, value: int, expected: str | dict[str, str]
) -> None:
    for flags in (0, 0x80, 0x100, 0x180):
        config = helper._ServiceConfig()
        config.service_type = value | flags
        fields = helper._configuration_fields(config)
        assert fields["service_type"] == expected
        assert fields["desktop_interact"] == bool(flags & 0x100)


@pytest.mark.parametrize("value", [0, 1, 0x55, 0x1FF, 0x200, 0x201, 0xFFFFFFFF])
def test_controls_discard_whole_unknown_flag_combinations(
    helper: ModuleType, value: int
) -> None:
    status = helper._ServiceStatusProcess()
    status.controls = value
    expected = (
        []
        if value & ~0x1FF
        else [
            name
            for index, name in enumerate(helper._CONTROL_NAMES)
            if value & (1 << index)
        ]
    )
    assert helper._status_fields(status)["controls_accepted"] == expected


@pytest.mark.parametrize("value", [0, 1, 2, 3, 0xFFFFFFFF])
def test_service_flags_discard_unknown_combinations(
    helper: ModuleType, value: int
) -> None:
    status = helper._ServiceStatusProcess()
    status.flags = value
    assert helper._status_fields(status)["service_flags"] == (
        ["runs_in_system_process"] if value == 1 else []
    )


@pytest.mark.parametrize("state", range(9))
def test_all_states_and_unknown_state(helper: ModuleType, state: int) -> None:
    status = helper._ServiceStatusProcess()
    status.state = state
    expected = [
        {},
        "stopped",
        "start_pending",
        "stop_pending",
        "started",
        "continue_pending",
        "pause_pending",
        "paused",
        {},
    ][state]
    assert helper._status_fields(status)["state"] == expected


@pytest.mark.parametrize("start", range(6))
def test_base_start_modes(helper: ModuleType, start: int) -> None:
    config = helper._ServiceConfig()
    config.start_type = start
    assert (
        helper._configuration_fields(config)["start_mode"]
        == ["boot", "system", "auto", "manual", "disabled", {}][start]
    )


def test_unknown_error_control_keeps_numeric_text(
    helper: ModuleType, native: Mock
) -> None:
    fixture = _service_fixture(helper, native)
    fixture.config.error_control = 0xFFFFFFFF
    result = helper.query_service("name", [])
    assert result["error_control"] == "4294967295"


def test_unknown_service_enums_match_recorded_assigned_switch_results(
    helper: ModuleType, native: Mock
) -> None:
    observation = next(row for row in SERIALIZATION["switches"] if row["input"] == 99)
    fixture = _service_fixture(helper, native)
    fixture.config.service_type = 99
    fixture.config.start_type = 99
    fixture.status.state = 99
    result = helper.query_service("name", [])
    assert result["service_type"] == observation["assigned_string"]["type"]
    assert result["start_mode"] == observation["assigned"]["type"]
    assert result["state"] == observation["assigned"]["type"]


@pytest.mark.parametrize(
    "operation",
    ["OpenSCManagerW", "OpenServiceW", "QueryServiceConfigW", "QueryServiceStatusEx"],
)
@pytest.mark.parametrize("code", [2, 5, 1060])
def test_initial_read_errors_are_distinct_and_close_acquired_handles(
    helper: ModuleType, native: Mock, operation: str, code: int
) -> None:
    _service_fixture(helper, native)
    function = getattr(native.library, operation)

    def _failure(*_arguments: Any) -> int:
        native.last_error.return_value = code
        return 0

    function.side_effect = _failure
    with pytest.raises(helper.ServiceOpenError) as caught:
        helper.query_service("name", [])
    assert caught.value.winerror == code
    assert str(caught.value) == str(native_error(code))
    expected = [] if operation == "OpenSCManagerW" else [call(101)]
    if operation.startswith("Query"):
        expected.insert(0, call(202))
    assert native.library.CloseServiceHandle.call_args_list == expected


@pytest.mark.parametrize(
    ("getter", "code"),
    [("description", 2), ("failure_actions", 5), ("dependency_of", 5), ("username", 5)],
)
def test_post_constructor_getter_errors_preserve_other_fields_and_recover(
    helper: ModuleType, native: Mock, getter: str, code: int
) -> None:
    _service_fixture(helper, native)
    expected = helper.query_service("name", [])
    original_config2: Callable[..., int] = (
        native.library.QueryServiceConfig2W.side_effect
    )
    original_dependents = native.library.EnumDependentServicesW.side_effect
    original_account = native.sid_to_name.side_effect

    def _config2(*arguments: Any) -> int:
        failing_level = {"description": 1, "failure_actions": 2}.get(getter)
        if arguments[1] == failing_level:
            native.last_error.return_value = code
            return 0
        return original_config2(*arguments)

    def _dependents(*_arguments: Any) -> int:
        native.last_error.return_value = code
        return 0

    native.library.QueryServiceConfig2W.side_effect = _config2
    if getter == "dependency_of":
        native.library.EnumDependentServicesW.side_effect = _dependents
    if getter == "username":
        native.sid_to_name.side_effect = native_error(code)
    fields = (
        [
            "failure_actions",
            "failure_command",
            "failure_reboot_msg",
            "failure_reset_period_sec",
        ]
        if getter == "failure_actions"
        else [getter]
    )
    failure_result = expected.copy()
    failure_result.update({field: SERIALIZATION["getters"][field] for field in fields})
    assert helper.query_service("name", []) == failure_result
    assert helper.query_service("name", []) == failure_result
    native.library.QueryServiceConfig2W.side_effect = original_config2
    native.library.EnumDependentServicesW.side_effect = original_dependents
    native.sid_to_name.side_effect = original_account
    assert helper.query_service("name", []) == expected
    assert (
        native.library.CloseServiceHandle.call_args_list == [call(202), call(101)] * 4
    )


def test_conversion_error_closes_both_handles(helper: ModuleType, native: Mock) -> None:
    _service_fixture(helper, native)
    native.sid_to_name.side_effect = ValueError("conversion failed")
    with pytest.raises(ValueError, match="conversion failed"):
        helper.query_service("name", [])
    assert native.library.CloseServiceHandle.call_args_list == [call(202), call(101)]


def test_query_buffer_retries_growth_and_preserves_arguments(
    helper: ModuleType, native: Mock
) -> None:
    seen = []

    def _query(*arguments: Any) -> int:
        assert arguments[:2] == (202, 1)
        buffer, size, needed = arguments[-3], arguments[-2], arguments[-1]
        seen.append(size)
        if len(seen) < 3:
            _set_dword(needed, 8 * len(seen))
            return 0
        buffer[0] = b"x"
        return 1

    result = helper._query_buffer(_query, 202, 1)
    assert seen == [0, 8, 16]
    assert result[0] == b"x"
    assert native.last_error.call_count == 2


def test_empty_dependent_enumeration_returns_empty_list(
    helper: ModuleType, native: Mock
) -> None:
    def _enumerate(*arguments: Any) -> int:
        _set_dword(arguments[-1], 0)
        return 1

    native.library.EnumDependentServicesW.side_effect = _enumerate
    assert helper._dependent_names(native.library, 202) == []


def test_dependent_enumeration_retries_growing_native_buffer(
    helper: ModuleType, native: Mock
) -> None:
    entries = (helper._EnumServiceStatus * 1)()
    entries[0].name = "Dependent"
    seen = []

    def _enumerate(*arguments: Any) -> int:
        buffer, size = arguments[2], arguments[3]
        needed, count = arguments[4], arguments[5]
        seen.append(size)
        if len(seen) < 3:
            _set_dword(needed, ctypes.sizeof(entries) * len(seen))
            native.last_error.return_value = 234
            return 0
        ctypes.memmove(buffer, ctypes.byref(entries), ctypes.sizeof(entries))
        _set_dword(count, 1)
        return 1

    native.library.EnumDependentServicesW.side_effect = _enumerate
    assert helper._dependent_names(native.library, 202) == ["Dependent"]
    assert seen == [0, ctypes.sizeof(entries), ctypes.sizeof(entries) * 2]


def test_service_enumeration_consumes_pages_in_native_order(
    helper: ModuleType, native: Mock
) -> None:
    pages = []
    for names in (("Zulu", "雪"), ("Alpha",)):
        records = (helper._EnumServiceStatusProcess * len(names))()
        for index, name in enumerate(names):
            records[index].name = name
        pages.append(records)
    resumes = []

    def _enumerate(*arguments: Any) -> int:
        assert arguments[:4] == (101, 0, 0x30, 3)
        buffer, size = arguments[4], arguments[5]
        needed, count = arguments[6], arguments[7]
        resume, group = arguments[8], arguments[9]
        assert size == 65536
        assert group is None
        resumes.append(ctypes.cast(resume, ctypes.POINTER(ctypes.c_uint32))[0])
        records = pages[len(resumes) - 1]
        ctypes.memmove(buffer, ctypes.byref(records), ctypes.sizeof(records))
        _set_dword(count, len(records))
        _set_dword(needed, 99999)
        _set_dword(resume, 42)
        native.last_error.return_value = 234
        return int(len(resumes) == 2)

    native.library.EnumServicesStatusExW.side_effect = _enumerate
    assert helper.enumerate_names() == ["Zulu", "雪", "Alpha"]
    assert resumes == [0, 42]
    native.library.OpenSCManagerW.assert_called_once_with(None, None, 4)
    native.library.CloseServiceHandle.assert_called_once_with(101)


@pytest.mark.parametrize("success", [True, False])
def test_empty_service_enumeration_and_errors_close_manager(
    helper: ModuleType, native: Mock, success: bool
) -> None:
    native.library.EnumServicesStatusExW.return_value = int(success)
    native.last_error.return_value = 5
    if success:
        assert helper.enumerate_names() == []
    else:
        with pytest.raises(OSError) as caught:
            helper.enumerate_names()
        assert caught.value.errno == 5
    native.library.CloseServiceHandle.assert_called_once_with(101)


def test_service_enumeration_does_not_hide_manager_access_error(
    helper: ModuleType, native: Mock
) -> None:
    native.library.OpenSCManagerW.return_value = 0
    native.last_error.return_value = 5
    with pytest.raises(OSError) as caught:
        helper.enumerate_names()
    assert caught.value.errno == 5
    native.library.EnumServicesStatusExW.assert_not_called()
    native.library.CloseServiceHandle.assert_not_called()


def _name_lookup(value: str | None, native: Mock) -> Any:
    def _lookup(_manager: int, _name: str, buffer: Any, count: Any) -> int:
        if value is None:
            native.last_error.return_value = 1060
            return 0
        if buffer is None or len(buffer) <= len(value):
            _set_dword(count, len(value))
            native.last_error.return_value = 122
            return 0
        buffer.value = value
        return 1

    return _lookup


@pytest.mark.parametrize(
    "case",
    [
        ("Display", "Service", None, "Service"),
        ("TCPIP", None, "TCP/IP Protocol Driver", "TCPIP"),
        ("RpcSs\0ignored", None, "Remote Procedure Call (RPC)", "RpcSs\0ignored"),
        ("missing", None, None, None),
    ],
)
def test_exact_name_resolution_preserves_native_fallback_spelling(
    helper: ModuleType,
    native: Mock,
    case: tuple[str, str | None, str | None, str | None],
) -> None:
    name, key, display, expected = case
    _service_fixture(helper, native)
    native.library.GetServiceKeyNameW.side_effect = _name_lookup(key, native)
    native.library.GetServiceDisplayNameW.side_effect = _name_lookup(display, native)
    assert helper.resolve_name(name) == expected
    if key is not None:
        native.library.GetServiceDisplayNameW.assert_not_called()
    assert all(
        entry.args[:2] == (101, name)
        for entry in native.library.GetServiceKeyNameW.call_args_list
    )
    assert native.library.CloseServiceHandle.call_args_list == (
        [call(202), call(101)] if expected is not None else [call(101)]
    )
    if expected is not None:
        native.library.OpenServiceW.assert_called_once_with(101, expected, 4)


def test_name_lookup_error_closes_manager(helper: ModuleType, native: Mock) -> None:
    native.library.GetServiceKeyNameW.return_value = 0
    native.last_error.return_value = 5
    assert helper.resolve_name("name") is None
    native.library.GetServiceDisplayNameW.assert_not_called()
    native.library.CloseServiceHandle.assert_called_once_with(101)


def test_display_lookup_retries_name_growth_and_copies_the_result(
    helper: ModuleType, native: Mock
) -> None:
    sizes = []

    def _lookup(_manager: int, _name: str, buffer: Any, count: Any) -> int:
        sizes.append(ctypes.cast(count, ctypes.POINTER(ctypes.c_uint32))[0])
        if len(sizes) < 3:
            _set_dword(count, len(sizes) * 4)
            native.last_error.return_value = 122
            return 0
        buffer.value = "Service"
        return 1

    result = helper._lookup_service_name(_lookup, 101, "Display")
    assert result == "Service"
    assert sizes == [0, 5, 9]


@pytest.mark.parametrize(
    "operation", ["OpenSCManagerW", "OpenServiceW", "QueryServiceStatusEx"]
)
def test_name_resolution_suppresses_status_failures_and_closes_handles(
    helper: ModuleType, native: Mock, operation: str
) -> None:
    _service_fixture(helper, native)
    native.library.GetServiceKeyNameW.side_effect = _name_lookup("Service", native)

    def _failure(*_arguments: Any) -> int:
        native.last_error.return_value = 5
        return 0

    getattr(native.library, operation).side_effect = _failure
    assert helper.resolve_name("name") is None
    expected = [] if operation == "OpenSCManagerW" else [call(101)]
    if operation == "QueryServiceStatusEx":
        expected.insert(0, call(202))
    assert native.library.CloseServiceHandle.call_args_list == expected


@pytest.mark.parametrize(
    "operation", ["query_service", "enumerate_names", "resolve_name"]
)
def test_requires_windows(helper: ModuleType, operation: str) -> None:
    arguments: dict[str, tuple[Any, ...]] = {
        "query_service": ("name", []),
        "enumerate_names": (),
        "resolve_name": ("name",),
    }
    with pytest.raises(ValueError, match="Windows target"):
        getattr(helper, operation)(*arguments[operation])


def test_native_structures_keep_windows_widths(helper: ModuleType) -> None:
    assert ctypes.sizeof(helper._ServiceStatus) == 28
    assert ctypes.sizeof(helper._ServiceStatusProcess) == 36
    width = ctypes.sizeof(ctypes.c_void_p)
    assert ctypes.sizeof(helper._ServiceConfig) == (64 if width == 8 else 36)
    assert helper._ServiceConfig.dependencies.offset == (40 if width == 8 else 24)


def test_native_signatures_preserve_pointer_width_and_read_only_surface(
    helper: ModuleType, native: Mock
) -> None:
    library = helper._advapi()
    native.load.assert_called_once_with("advapi32", use_last_error=True)
    assert library.OpenSCManagerW.restype is ctypes.c_void_p
    assert library.OpenServiceW.restype is ctypes.c_void_p
    assert library.CloseServiceHandle.argtypes == [ctypes.c_void_p]
    assert library.EnumServicesStatusExW.argtypes == [
        ctypes.c_void_p,
        ctypes.c_uint32,
        ctypes.c_uint32,
        ctypes.c_uint32,
        ctypes.c_void_p,
        ctypes.c_uint32,
        ctypes.POINTER(ctypes.c_uint32),
        ctypes.POINTER(ctypes.c_uint32),
        ctypes.POINTER(ctypes.c_uint32),
        ctypes.c_wchar_p,
    ]
    assert set(library._mock_children) == {
        "OpenSCManagerW",
        "OpenServiceW",
        "CloseServiceHandle",
        "QueryServiceConfigW",
        "QueryServiceConfig2W",
        "QueryServiceStatusEx",
        "EnumDependentServicesW",
        "EnumServicesStatusExW",
        "GetServiceKeyNameW",
        "GetServiceDisplayNameW",
    }


@pytest.fixture(name="selector")
def service_selector(helper: ModuleType, monkeypatch: pytest.MonkeyPatch) -> Mock:
    """Substitute native enumeration/culture while retaining wildcard parsing.

    :param helper: Imported service helper.
    :param monkeypatch: Scoped native-boundary substitutions.
    :returns: Observable enumeration, literal lookup, equality, and sorting calls.
    """
    boundary = Mock()
    boundary.enumerate.return_value = ["Zulu", "RpcSs", "RpcLocator", "RpcEptMapper"]
    boundary.resolve.return_value = None

    # These are the measured Server 2025 case/NUL/soft-hyphen equivalences;
    # XP/2003 do not ignore the tested soft hyphen. Windows execution, not this
    # substitute, establishes each target's native collation.
    def _key(value: str) -> str:
        return value.replace("\0", "").replace("\u00ad", "").lower()

    boundary.equal.side_effect = lambda left, right: _key(left) == _key(right)
    boundary.compare.side_effect = lambda left, right: (
        (_key(left) > _key(right)) - (_key(left) < _key(right))
    )
    monkeypatch.setattr(helper, "enumerate_names", boundary.enumerate)
    monkeypatch.setattr(helper, "resolve_name", boundary.resolve)
    monkeypatch.setattr(helper, "_invariant_equal", boundary.equal)
    monkeypatch.setattr(helper, "compare_service_names", boundary.compare)
    matching = sys.modules["legacy_windows_find_match"]
    monkeypatch.setattr(matching, "_current_lower", lambda: str.lower)
    return boundary


@pytest.mark.parametrize("name", [None, ""])
def test_absent_filter_selects_every_ordinary_name_in_culture_order(
    helper: ModuleType, selector: Mock, name: str | None
) -> None:
    assert helper.select_names(name) == ["RpcEptMapper", "RpcLocator", "RpcSs", "Zulu"]
    selector.equal.assert_not_called()
    selector.resolve.assert_not_called()
    selector.enumerate.assert_called_once_with()


@pytest.mark.parametrize("name", ["rpcss", "RPCSS", "RpcSs\0", "Rpc\u00adSs"])
def test_exact_invariant_match_returns_canonical_ordinary_name(
    helper: ModuleType, selector: Mock, name: str
) -> None:
    assert helper.select_names(name) == ["RpcSs"]
    selector.resolve.assert_not_called()
    assert selector.equal.call_args_list == [
        call(candidate, name) for candidate in selector.enumerate.return_value
    ]


@pytest.mark.parametrize("literal", ["Rpc*", "Rpc[S]s", "[", "Rpc`S*", "RpcSs]"])
def test_exact_literal_service_name_precedes_wildcard_interpretation(
    helper: ModuleType, selector: Mock, monkeypatch: pytest.MonkeyPatch, literal: str
) -> None:
    selector.enumerate.return_value.append(literal)
    wildcard = Mock(side_effect=AssertionError("literal match must not parse wildcard"))
    monkeypatch.setattr(helper, "matches_service_name", wildcard)
    assert helper.select_names(literal) == [literal]
    wildcard.assert_not_called()
    selector.resolve.assert_not_called()


@pytest.mark.parametrize(
    ("pattern", "expected"),
    [
        ("Rpc*", ["RpcEptMapper", "RpcLocator", "RpcSs"]),
        ("RpcS?", ["RpcSs"]),
        ("Rpc[S]s", ["RpcSs"]),
        ("Rpc[sS]s", ["RpcSs"]),
        ("Rpc[A-Z]s", ["RpcSs"]),
        ("Rpc[!S]s", ["RpcSs"]),
        ("Rpc[^S]s", ["RpcSs"]),
        ("Rpc[ŚS]s", ["RpcSs"]),
        ("Rpc`S*", ["RpcSs"]),
        ("`RpcS*", ["RpcSs"]),
        ("Remote Procedure*", []),
        ("Tcpi*", []),
        ("RpcSs]", []),
        ("Missing*", []),
    ],
)
def test_reference_wildcard_selection_uses_only_ordinary_key_names(
    helper: ModuleType, selector: Mock, pattern: str, expected: list[str]
) -> None:
    assert helper.select_names(pattern) == expected
    assert selector.enumerate.call_count == 2
    selector.resolve.assert_not_called()


@pytest.mark.parametrize("name", [None, "", "Rpc*"])
def test_fallback_reenumerates_services_that_changed_after_first_lookup(
    helper: ModuleType, selector: Mock, name: str | None
) -> None:
    selector.enumerate.side_effect = [
        [] if not name else ["RpcOld"],
        ["RpcNewB", "RpcNewA"],
    ]
    assert helper.select_names(name) == ["RpcNewA", "RpcNewB"]
    assert selector.enumerate.call_count == 2
    selector.resolve.assert_not_called()


def test_failed_second_enumeration_does_not_return_stale_names(
    helper: ModuleType, selector: Mock
) -> None:
    selector.enumerate.side_effect = [["RpcOld"], native_error(5)]
    with pytest.raises(OSError) as caught:
        helper.select_names("Rpc*")
    assert caught.value.errno == 5
    assert selector.enumerate.call_count == 2


@pytest.mark.parametrize("pattern", ["[", "[]", "[z-a]", "System.Object[]"])
def test_invalid_wildcard_errors_are_not_hidden_by_literal_fallback(
    helper: ModuleType, selector: Mock, pattern: str
) -> None:
    with pytest.raises(ValueError, match="wildcard character pattern is not valid"):
        helper.select_names(pattern)
    selector.resolve.assert_not_called()


@pytest.mark.parametrize("pattern", ["Rpc[A-Ž]s", "Rpc[a-ž]s"])
def test_non_ascii_wildcard_ranges_select_reference_service(
    helper: ModuleType, selector: Mock, pattern: str
) -> None:
    assert helper.select_names(pattern) == ["RpcSs"]
    assert selector.enumerate.call_count == 2
    selector.resolve.assert_not_called()


@pytest.mark.parametrize(
    "name",
    [
        "Rpc`Ss",
        "Rpc`*",
        "RpcSs`",
        "`RpcSs",
        "RpcSs`]",
        " RpcSs",
        "RpcSs ",
        "RpcSs\0ignored",
        "TCPIP",
        "Remote Procedure Call (RPC)",
        "Rpc/Ss",
        "Rpc\\Ss",
    ],
)
def test_literal_fallback_receives_the_whole_unmodified_request(
    helper: ModuleType, selector: Mock, name: str
) -> None:
    selector.resolve.return_value = "resolved"
    assert helper.select_names(name) == ["resolved"]
    selector.resolve.assert_called_once_with(name)


def test_missing_literal_fallback_returns_no_matches(
    helper: ModuleType, selector: Mock
) -> None:
    assert helper.select_names("Missing") == []
    selector.resolve.assert_called_once_with("Missing")


@pytest.mark.parametrize(
    ("name", "expected"),
    [
        ("literal", False),
        ("*", True),
        ("?", True),
        ("[", True),
        ("]", True),
        ("`*", False),
        ("`?", False),
        ("`[", False),
        ("`]", False),
        ("`", False),
        ("``*", True),
        ("```*", False),
        ("`[*", True),
        ("a`b", False),
        ("a`b?", True),
    ],
)
def test_wildcard_detection_skips_escaped_characters(
    helper: ModuleType, name: str, expected: bool
) -> None:
    assert helper._contains_wildcards(name) is expected


def test_selector_uses_current_culture_comparer_and_preserves_equal_key_order(
    helper: ModuleType, selector: Mock
) -> None:
    selector.enumerate.return_value = ["z", "A", "a", "ä"]
    rank = {"A": 0, "a": 0, "ä": 1, "z": 2}
    selector.compare.side_effect = lambda left, right: rank[left] - rank[right]
    assert helper.select_names(None) == ["A", "a", "ä", "z"]
    assert selector.compare.call_count > 0


@pytest.mark.parametrize("operation", ["enumerate", "equal", "compare", "resolve"])
def test_selector_propagates_native_boundary_errors(
    helper: ModuleType, selector: Mock, operation: str
) -> None:
    getattr(selector, operation).side_effect = native_error(5)
    with pytest.raises(OSError) as caught:
        helper.select_names(None if operation == "compare" else "Missing")
    assert caught.value.errno == 5


def test_selector_propagates_wildcard_casing_error(
    helper: ModuleType, selector: Mock, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(
        helper, "matches_service_name", Mock(side_effect=native_error(5))
    )
    with pytest.raises(OSError) as caught:
        helper.select_names("Rpc*")
    assert caught.value.errno == 5
    selector.resolve.assert_not_called()


@pytest.mark.parametrize("name", [True, False, 0, 1.5, [], {}])
def test_selector_requires_preconverted_string_or_none(
    helper: ModuleType, selector: Mock, name: Any
) -> None:
    with pytest.raises(ValueError, match="Service name must be a string or None"):
        helper.select_names(name)
    selector.enumerate.assert_not_called()


@pytest.mark.parametrize("result", [1, 2, 3])
def test_invariant_equality_uses_counted_utf16_and_invariant_locale(
    helper: ModuleType, native: Mock, result: int
) -> None:
    native.library.CompareStringW.return_value = result
    assert helper._invariant_equal("Rpc😀Ss", "Rpc\0😀Ss\u00ad") is (result == 2)
    native.load.assert_called_once_with("kernel32", use_last_error=True)
    native.library.CompareStringW.assert_called_once_with(
        0x7F, 0x08000001, "Rpc😀Ss", 7, "Rpc\0😀Ss\u00ad", 9
    )
    assert native.library.CompareStringW.argtypes == [
        ctypes.c_uint32,
        ctypes.c_uint32,
        ctypes.c_wchar_p,
        ctypes.c_int,
        ctypes.c_wchar_p,
        ctypes.c_int,
    ]
    assert native.library.CompareStringW.restype is ctypes.c_int


def test_invariant_equality_falls_back_only_for_invalid_linguistic_flags(
    helper: ModuleType, native: Mock
) -> None:
    native.library.CompareStringW.side_effect = [0, 2]
    native.last_error.return_value = 1004
    assert helper._invariant_equal("RpcSs", "rpcss") is True
    assert native.library.CompareStringW.call_args_list == [
        call(0x7F, 0x08000001, "RpcSs", 5, "rpcss", 5),
        call(0x7F, 1, "RpcSs", 5, "rpcss", 5),
    ]


@pytest.mark.parametrize("fallback", [False, True])
def test_invariant_equality_preserves_native_failure(
    helper: ModuleType, native: Mock, fallback: bool
) -> None:
    native.library.CompareStringW.return_value = 0
    native.last_error.side_effect = [1004, 87] if fallback else [87, 87]
    with pytest.raises(OSError) as caught:
        helper._invariant_equal("RpcSs", "rpcss")
    assert caught.value.errno == 87
    assert native.library.CompareStringW.call_count == (2 if fallback else 1)


def test_invariant_equality_requires_windows(helper: ModuleType) -> None:
    with pytest.raises(ValueError, match="Windows target"):
        helper._invariant_equal("RpcSs", "rpcss")
