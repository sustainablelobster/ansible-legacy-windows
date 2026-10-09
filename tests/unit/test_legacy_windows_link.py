"""Exercise native link inspection and privilege ownership without Windows."""

# SPDX-License-Identifier: GPL-3.0-or-later
# Tests inspect native memory layouts and bindings using substitutes, not hosts.
# pylint: disable=protected-access

import ctypes
import importlib.util
import struct
from types import ModuleType, SimpleNamespace
from typing import Any
from unittest.mock import Mock

import pytest

from tests.unit.payload_support import ROOT


@pytest.fixture(name="helper")
def link_helper() -> ModuleType:
    """Import the target helper using the developer interpreter.

    :returns: The isolated helper module without invoking Windows APIs.
    """
    source = ROOT / "plugins/module_utils/legacy_windows_link.py"
    spec = importlib.util.spec_from_file_location("tested_link_native", source)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


@pytest.fixture(name="native")
def native_libraries(helper: ModuleType, monkeypatch: pytest.MonkeyPatch) -> Any:
    """Replace native libraries with controllable calls and last-error state.

    :param helper: The imported link helper.
    :param monkeypatch: Fixture restoring Windows-only ctypes substitutions.
    :returns: Kernel, security, and last-error values shared by substitutes.
    """
    native = SimpleNamespace(kernel=Mock(), security=Mock(), error=5)
    native.kernel.GetFileAttributesW.return_value = 0x20
    native.kernel.CreateFileW.return_value = 123
    native.kernel.GetCurrentProcess.return_value = ctypes.c_void_p(-1).value
    # This workflow keeps an independent fixture and expected-result oracle.
    # pylint: disable=duplicate-code
    monkeypatch.setattr(helper, "os", SimpleNamespace(name="nt"))
    monkeypatch.setattr(
        helper.ctypes,
        "WinDLL",
        Mock(
            side_effect=lambda name, **_: (
                native.kernel if name == "kernel32" else native.security
            )
        ),
        raising=False,
    )
    # pylint: enable=duplicate-code
    monkeypatch.setattr(
        helper.ctypes, "get_last_error", lambda: native.error, raising=False
    )
    # This platform stub is kept with its fixture so independent native API
    # tests do not need a shared Windows-error mocking layer.
    # pylint: disable=duplicate-code
    monkeypatch.setattr(
        helper.ctypes,
        "WinError",
        lambda code: OSError(code, "native failure"),
        raising=False,
    )
    return native
    # pylint: enable=duplicate-code


def _put_uint(pointer: Any, value: int) -> None:
    ctypes.cast(pointer, ctypes.POINTER(ctypes.c_uint32)).contents.value = value


def _reparse_data(tag: int, target: str, flags: int = 0) -> bytes:
    print_name = "unused display name\0".encode("utf-16-le")
    name = target.encode("utf-16-le", "surrogatepass")
    offsets = struct.pack("<HHHH", len(print_name), len(name), 0, len(print_name) - 2)
    body = offsets + (struct.pack("<I", flags) if tag == 0xA000000C else b"")
    body += print_name + name
    return struct.pack("<IHH", tag, len(body), 0) + body


def _return_reparse(native: Any, data: bytes) -> None:
    native.kernel.GetFileAttributesW.return_value = 0x410

    def _read(*args: Any) -> int:
        assert args[:4] == (123, 0x900A8, None, 0)
        assert args[5] == 16384
        assert args[7] is None
        ctypes.memmove(args[4], data, len(data))
        _put_uint(args[6], len(data))
        return 1

    native.kernel.DeviceIoControl.side_effect = _read


def _return_hardlinks(native: Any, volume: str, names: list[str]) -> None:
    entries = iter(names)

    def _volume(_path: str, buffer: Any, length: int) -> int:
        assert length == 260
        buffer.value = volume
        return 1

    def _first(_path: str, flags: int, length: Any, buffer: Any) -> int:
        assert flags == 0
        assert (
            ctypes.cast(length, ctypes.POINTER(ctypes.c_uint32)).contents.value == 260
        )
        assert len(buffer) == 260
        buffer.value = next(entries)
        _put_uint(length, len(buffer.value) + 1)
        return 456

    def _next(handle: int, length: Any, buffer: Any) -> int:
        assert handle == 456
        assert (
            ctypes.cast(length, ctypes.POINTER(ctypes.c_uint32)).contents.value == 260
        )
        name = next(entries, None)
        if name is None:
            native.error = 38
            return 0
        buffer.value = name
        _put_uint(length, len(name) + 1)
        return 1

    native.kernel.GetVolumePathNameW.side_effect = _volume
    native.kernel.FindFirstFileNameW.side_effect = _first
    native.kernel.FindNextFileNameW.side_effect = _next


def _return_privileges(helper: ModuleType, native: Any, attributes: int | None) -> None:
    # Include unrelated privileges before and after SeBackupPrivilege so that
    # selecting the requested LUID cannot accidentally depend on token order.
    records = [(4, 0, 2), (9, 0, 0)]
    if attributes is not None:
        records.insert(1, (17, 1, attributes))
    data = struct.pack("<I", len(records)) + b"".join(
        struct.pack("<IiI", *record) for record in records
    )
    tokens = iter([101, 102])

    def _lookup(system: Any, name: str, pointer: Any) -> int:
        assert system is None
        assert name == "SeBackupPrivilege"
        luid = ctypes.cast(pointer, ctypes.POINTER(helper._Luid)).contents
        luid.low, luid.high = 17, 1
        return 1

    def _open(process: int, _access: int, pointer: Any) -> int:
        assert process == ctypes.c_void_p(-1).value
        ctypes.cast(pointer, ctypes.POINTER(ctypes.c_void_p)).contents.value = next(
            tokens
        )
        return 1

    def _query(token: Any, kind: int, buffer: Any, length: int, required: Any) -> int:
        assert token.value == 101
        assert kind == 3
        _put_uint(required, len(data))
        if buffer is None:
            assert length == 0
            native.error = 122
            return 0
        assert length == len(data)
        ctypes.memmove(buffer, data, len(data))
        return 1

    def _adjust(*args: Any) -> int:
        assert args[0].value == 102
        assert args[1] is False
        assert args[3:] == (0, None, None)
        state = ctypes.cast(args[2], ctypes.POINTER(helper._TokenPrivilege)).contents
        assert (state.count, state.luid.low, state.luid.high, state.attributes) == (
            1,
            17,
            1,
            2,
        )
        native.error = 0
        return 1

    native.security.LookupPrivilegeValueW.side_effect = _lookup
    native.security.OpenProcessToken.side_effect = _open
    native.security.GetTokenInformation.side_effect = _query
    native.security.AdjustTokenPrivileges.side_effect = _adjust


def test_plain_directory_never_opens_or_enumerates(
    helper: ModuleType, native: Any
) -> None:
    native.kernel.GetFileAttributesW.return_value = 0x10
    del native.kernel.FindFirstFileNameW

    assert helper.get_link_info("C:\\fixture") is None

    native.kernel.GetFileAttributesW.assert_called_once_with("C:\\fixture")
    native.kernel.CreateFileW.assert_not_called()
    native.kernel.GetVolumePathNameW.assert_not_called()


def test_attribute_failure_precedes_link_inspection(
    helper: ModuleType, native: Any
) -> None:
    native.kernel.GetFileAttributesW.return_value = 0xFFFFFFFF

    with pytest.raises(OSError) as failure:
        helper.get_link_info("C:\\missing")

    assert failure.value.errno == 5
    native.kernel.CreateFileW.assert_not_called()
    native.kernel.GetVolumePathNameW.assert_not_called()


@pytest.mark.parametrize(
    "case",
    [
        (0xA0000003, "\\??\\D:\\target\\雪", 0, "D:\\target\\雪"),
        (0xA000000C, "\\??\\C:\\target", 0, "C:\\target"),
        (0xA000000C, "..\\target", 1, "..\\target"),
        (0xA000000C, "\\rooted", 1, "\\rooted"),
        (0xA000000C, "\\??\\UNC\\server\\share", 0, "UNC\\server\\share"),
        (0xA000000C, "\\\\?\\UNC\\server\\share", 0, "\\\\?\\UNC\\server\\share"),
        (0xA000000C, "part\\??\\target", 0, "part\\??\\target"),
        (0xA000000C, "C:\\unpaired\ud800", 0, "C:\\unpaired\ud800"),
    ],
)
def test_reparse_uses_substitute_name_without_following(
    helper: ModuleType, native: Any, case: tuple[int, str, int, str]
) -> None:
    tag, target, flags, expected = case
    _return_reparse(native, _reparse_data(tag, target, flags))
    del native.kernel.FindFirstFileNameW

    assert helper.get_link_info("C:\\fixture\\[link]") == {
        "type": "symbolic" if tag == 0xA000000C else "junction",
        "target": expected,
        "relative": flags == 1,
    }

    native.kernel.CreateFileW.assert_called_once_with(
        "C:\\fixture\\[link]", 1, 0, None, 3, 0x02200000, None
    )
    native.kernel.GetFileAttributesW.assert_called_once()
    native.kernel.CloseHandle.assert_called_once_with(123)
    native.kernel.GetVolumePathNameW.assert_not_called()


@pytest.mark.parametrize("failure_at", ["open", "read"])
def test_reparse_native_failure_preserves_error_and_closes_only_owned_handle(
    helper: ModuleType, native: Any, failure_at: str
) -> None:
    native.kernel.GetFileAttributesW.return_value = 0x400
    if failure_at == "open":
        native.kernel.CreateFileW.return_value = ctypes.c_void_p(-1).value
    else:
        native.kernel.DeviceIoControl.return_value = 0

    with pytest.raises(OSError) as failure:
        helper.get_link_info("C:\\fixture\\link")

    assert failure.value.errno == 5
    if failure_at == "open":
        native.kernel.CloseHandle.assert_not_called()
        native.kernel.DeviceIoControl.assert_not_called()
    else:
        native.kernel.CloseHandle.assert_called_once_with(123)


def test_unknown_reparse_tag_fails_after_closing(
    helper: ModuleType, native: Any
) -> None:
    _return_reparse(native, struct.pack("<IHH", 0x8000001B, 0, 0))

    with pytest.raises(ValueError, match="Invalid Reparse Tag: 2147483675"):
        helper.get_link_info("C:\\fixture\\cloud")

    native.kernel.CloseHandle.assert_called_once_with(123)


@pytest.mark.parametrize(
    "data", [b"", b"\x0c\0\0\xa0\0\0\0\0", _reparse_data(0xA0000003, "name")[:-1]]
)
def test_truncated_reparse_data_fails_instead_of_returning_truncated_target(
    helper: ModuleType, native: Any, data: bytes
) -> None:
    _return_reparse(native, data)

    with pytest.raises(ValueError, match="Invalid reparse point data"):
        helper.get_link_info("C:\\fixture\\link")

    native.kernel.CloseHandle.assert_called_once_with(123)


def test_hardlinks_preserve_native_order_and_mounted_volume(
    helper: ModuleType, native: Any
) -> None:
    _return_hardlinks(native, "C:\\mounted\\", ["\\last", "\\雪\\first", "middle"])

    assert helper.get_link_info("C:\\mounted\\middle") == {
        "type": "hard",
        "target": [
            "C:\\mounted\\last",
            "C:\\mounted\\雪\\first",
            "C:\\mounted\\middle",
        ],
    }

    native.kernel.FindClose.assert_called_once_with(456)
    assert native.kernel.GetVolumePathNameW.argtypes[2] is ctypes.c_uint32
    native.kernel.CloseHandle.assert_not_called()


def test_single_hardlink_name_is_ordinary(helper: ModuleType, native: Any) -> None:
    _return_hardlinks(native, "C:\\", ["\\only"])

    assert helper.get_link_info("C:\\only") is None

    native.kernel.FindClose.assert_called_once_with(456)


@pytest.mark.parametrize("error", [5, 38, 234])
def test_first_hardlink_enumeration_failure_means_no_link_info(
    helper: ModuleType, native: Any, error: int
) -> None:
    _return_hardlinks(native, "C:\\", ["\\entry"])
    native.kernel.FindFirstFileNameW.side_effect = None
    native.kernel.FindFirstFileNameW.return_value = ctypes.c_void_p(-1).value
    native.error = error

    assert helper.get_link_info("C:\\entry") is None

    native.kernel.FindClose.assert_not_called()
    native.kernel.FindNextFileNameW.assert_not_called()


def test_later_hardlink_failure_retains_partial_names(
    helper: ModuleType, native: Any
) -> None:
    _return_hardlinks(native, "C:\\", ["\\second", "\\first"])
    original = native.kernel.FindNextFileNameW.side_effect

    def _next(*args: Any) -> int:
        result = int(original(*args))
        if not result:
            native.error = 234
        return result

    native.kernel.FindNextFileNameW.side_effect = _next

    assert helper.get_link_info("C:\\first") == {
        "type": "hard",
        "target": ["C:\\second", "C:\\first"],
    }

    native.kernel.FindClose.assert_called_once_with(456)
    assert native.kernel.FindFirstFileNameW.call_count == 1
    assert native.kernel.FindNextFileNameW.call_count == 2


def test_volume_failure_stops_before_enumeration(
    helper: ModuleType, native: Any
) -> None:
    native.kernel.GetVolumePathNameW.return_value = 0

    with pytest.raises(OSError) as failure:
        helper.get_link_info("C:\\entry")

    assert failure.value.errno == 5
    native.kernel.FindFirstFileNameW.assert_not_called()
    native.kernel.FindClose.assert_not_called()


@pytest.mark.parametrize("missing", ["FindFirstFileNameW", "FindNextFileNameW"])
def test_missing_hardlink_api_reports_legacy_limit_without_searching(
    helper: ModuleType, native: Any, missing: str
) -> None:
    delattr(native.kernel, missing)

    with pytest.raises(
        NotImplementedError, match="Windows Vista or Windows Server 2008"
    ):
        helper.get_link_info("C:\\entry")

    native.kernel.GetVolumePathNameW.assert_not_called()
    native.kernel.CreateFileW.assert_not_called()


@pytest.mark.parametrize("attributes", [None, 2, 3])
def test_absent_or_enabled_backup_privilege_is_not_adjusted(
    helper: ModuleType, native: Any, attributes: int | None
) -> None:
    _return_privileges(helper, native, attributes)

    assert helper.enable_backup_privilege() is None

    native.security.OpenProcessToken.assert_called_once()
    assert native.security.OpenProcessToken.call_args.args[1] == 8
    native.security.AdjustTokenPrivileges.assert_not_called()
    assert [
        call.args[0].value for call in native.kernel.CloseHandle.call_args_list
    ] == [101]


@pytest.mark.parametrize("attributes", [0, 1])
def test_present_disabled_backup_privilege_is_enabled_and_handles_closed(
    helper: ModuleType, native: Any, attributes: int
) -> None:
    _return_privileges(helper, native, attributes)

    assert helper.enable_backup_privilege() is None

    assert [
        call.args[1] for call in native.security.OpenProcessToken.call_args_list
    ] == [8, 0x28]
    native.security.AdjustTokenPrivileges.assert_called_once()
    assert [
        call.args[0].value for call in native.kernel.CloseHandle.call_args_list
    ] == [101, 102]


@pytest.mark.parametrize(
    "failure_at", ["lookup", "open", "query_size", "query", "adjust"]
)
def test_privilege_failures_preserve_error_and_close_tokens(
    helper: ModuleType, native: Any, failure_at: str
) -> None:
    _return_privileges(helper, native, 0)
    function = {
        "lookup": native.security.LookupPrivilegeValueW,
        "open": native.security.OpenProcessToken,
        "query_size": native.security.GetTokenInformation,
        "query": native.security.GetTokenInformation,
        "adjust": native.security.AdjustTokenPrivileges,
    }[failure_at]
    original = function.side_effect

    def _fail(*args: Any) -> int:
        if failure_at == "query" and args[2] is None:
            return int(original(*args))
        native.error = 5
        return 0

    function.side_effect = _fail

    with pytest.raises(OSError) as failure:
        helper.enable_backup_privilege()

    assert failure.value.errno == 5
    expected = [] if failure_at in ("lookup", "open") else [101]
    if failure_at == "adjust":
        expected.append(102)
    assert [
        call.args[0].value for call in native.kernel.CloseHandle.call_args_list
    ] == expected


def test_successful_adjustment_with_not_all_assigned_is_failure(
    helper: ModuleType, native: Any
) -> None:
    _return_privileges(helper, native, 0)

    def _not_assigned(*_args: Any) -> int:
        native.error = 1300
        return 1

    native.security.AdjustTokenPrivileges.side_effect = _not_assigned

    with pytest.raises(OSError) as failure:
        helper.enable_backup_privilege()

    assert failure.value.errno == 1300
    assert [
        call.args[0].value for call in native.kernel.CloseHandle.call_args_list
    ] == [101, 102]
