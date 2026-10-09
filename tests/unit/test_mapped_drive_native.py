"""Check mapped-drive ABI, impersonation boundaries, and resource cleanup."""

# SPDX-License-Identifier: GPL-3.0-or-later
# Native tests inspect the private ABI records and lifecycle boundaries.
# pylint: disable=protected-access

import ctypes
from types import ModuleType, SimpleNamespace
from typing import Any
from unittest.mock import Mock

import pytest

from tests.unit.payload_support import ROOT, load_module


@pytest.fixture(name="helper")
def native_helper(monkeypatch: pytest.MonkeyPatch) -> ModuleType:
    """Load the helper without invoking Windows.

    :param monkeypatch: Scoped module path and native error formatter.
    :returns: Loaded target helper.
    """
    monkeypatch.syspath_prepend(str(ROOT / "plugins/module_utils"))
    module = load_module(
        ROOT / "plugins/module_utils/legacy_windows_mapped_drive.py",
        "tested_mapped_drive_native",
    )
    monkeypatch.setattr(
        module.ctypes, "FormatError", lambda _code: "Native error.\r\n", raising=False
    )
    return module


def test_resource_alignment_and_api_bindings(
    helper: ModuleType, monkeypatch: pytest.MonkeyPatch
) -> None:
    network, kernel, security = Mock(), Mock(), Mock()
    monkeypatch.setattr(helper, "os", SimpleNamespace(name="nt"))
    monkeypatch.setattr(
        helper.ctypes,
        "WinDLL",
        Mock(side_effect=[network, kernel, security]),
        raising=False,
    )
    assert helper._libraries() == (network, kernel, security)
    assert helper._Resource.local.offset == 16
    assert ctypes.sizeof(helper._Resource) == 16 + 4 * ctypes.sizeof(ctypes.c_void_p)
    assert network.WNetAddConnection2W.restype is ctypes.c_uint32
    assert network.WNetCancelConnection2W.argtypes[-1] is ctypes.c_int
    assert kernel.GetCurrentProcess.restype is ctypes.c_void_p


def test_enumeration_closes_handle_and_reverts_on_failure(helper: ModuleType) -> None:
    network, security = Mock(), Mock()
    network.WNetOpenEnumW.return_value = 0
    network.WNetEnumResourceW.return_value = 5
    with pytest.raises(OSError, match="WNetEnumResourceW"):
        helper.Mappings(network, security, 42).remembered()
    network.WNetCloseEnum.assert_called_once()
    security.ImpersonateLoggedOnUser.assert_called_once_with(42)
    security.RevertToSelf.assert_called_once()


def test_enumeration_copies_native_order_before_buffer_release(
    helper: ModuleType,
) -> None:
    network, security = Mock(), Mock()
    network.WNetOpenEnumW.return_value = 0
    entries = (helper._Resource * 2)(
        helper._Resource(local="Z:", remote=r"\\server\z"),
        helper._Resource(local="M:", remote=r"\\server\m"),
    )

    def _fill(_handle: Any, count: Any, buffer: Any, _size: Any) -> int:
        count._obj.value = 2
        ctypes.memmove(buffer, entries, ctypes.sizeof(entries))
        return 0

    calls = iter((0, 259))
    network.WNetEnumResourceW.side_effect = lambda *args: (
        _fill(*args) if next(calls) == 0 else 259
    )
    assert helper.Mappings(network, security, None).remembered() == [
        {"drive": "Z:", "path": r"\\server\z"},
        {"drive": "M:", "path": r"\\server\m"},
    ]
    network.WNetCloseEnum.assert_called_once()
    security.ImpersonateLoggedOnUser.assert_not_called()


def test_add_preserves_null_and_empty_credentials_and_profile_flags(
    helper: ModuleType,
) -> None:
    network, security = Mock(), Mock()
    network.WNetAddConnection2W.return_value = 0
    mappings = helper.Mappings(network, security, 42)
    mappings.add("M:", r"\\server\share", None, "")
    record, password, username, flags = network.WNetAddConnection2W.call_args.args
    assert (record._obj.kind, record._obj.local, record._obj.remote) == (
        1,
        "M:",
        r"\\server\share",
    )
    assert (password, username, flags) == ("", None, 1)
    security.RevertToSelf.assert_called_once()


def test_remove_forces_profile_removal_and_reverts_after_error(
    helper: ModuleType,
) -> None:
    network, security = Mock(), Mock()
    network.WNetCancelConnection2W.return_value = 5
    with pytest.raises(OSError, match="Win32ErrorCode 5"):
        helper.Mappings(network, security, 42).remove("M:")
    network.WNetCancelConnection2W.assert_called_once_with("M:", 1, True)
    security.RevertToSelf.assert_called_once()


@pytest.mark.parametrize(
    "code,message",
    [
        (55, "The specified network resource or device is no longer available."),
        (2250, "This network connection does not exist."),
    ],
)
def test_error_message_matches_measured_original_terminal_punctuation(
    helper: ModuleType, monkeypatch: pytest.MonkeyPatch, code: int, message: str
) -> None:
    monkeypatch.setattr(helper.ctypes, "FormatError", lambda _code: message + "\r\n")
    with pytest.raises(OSError) as error:
        helper._check(code, "Native operation")
    assert error.value.errno == code
    assert error.value.strerror == (
        f"Native operation ({message[:-1]}, Win32ErrorCode {code})"
    )


def test_legacy_token_path_never_queries_unsupported_fields(
    helper: ModuleType, monkeypatch: pytest.MonkeyPatch
) -> None:
    security, kernel = Mock(), Mock()
    monkeypatch.setattr(
        helper.sys, "getwindowsversion", lambda: SimpleNamespace(major=5), raising=False
    )
    assert helper._limited_token(security, kernel) is None
    assert security.mock_calls == kernel.mock_calls == []


def test_owned_linked_token_is_closed_on_consumer_failure(
    helper: ModuleType, monkeypatch: pytest.MonkeyPatch
) -> None:
    network, kernel, security = Mock(), Mock(), Mock()
    monkeypatch.setattr(helper, "_libraries", lambda: (network, kernel, security))
    monkeypatch.setattr(helper, "_limited_token", lambda *_args: 42)
    with pytest.raises(RuntimeError, match="consumer"):
        with helper.open_mappings():
            raise RuntimeError("consumer")
    kernel.CloseHandle.assert_called_once_with(42)


def test_failed_impersonation_never_calls_network_or_reverts(
    helper: ModuleType, monkeypatch: pytest.MonkeyPatch
) -> None:
    network, security = Mock(), Mock()
    security.ImpersonateLoggedOnUser.return_value = 0
    monkeypatch.setattr(helper.ctypes, "get_last_error", lambda: 5, raising=False)
    with pytest.raises(OSError, match="impersonate"):
        helper.Mappings(network, security, 42).remove("M:")
    network.WNetCancelConnection2W.assert_not_called()
    security.RevertToSelf.assert_not_called()


@pytest.mark.parametrize("fails", [False, True])
def test_linked_token_discovery_closes_system_handles_and_reverts(
    helper: ModuleType, monkeypatch: pytest.MonkeyPatch, fails: bool
) -> None:
    security, kernel = Mock(), Mock()
    kernel.OpenProcess.side_effect = [None, 300]

    def _open(_process: Any, access: int, output: Any) -> int:
        assert access == 0xA
        output._obj.value = 200
        return 1

    def _lookup(_system: Any, name: str, output: Any) -> int:
        assert name == "SeTcbPrivilege"
        output._obj.low = 7
        return 1

    def _information(_security: Any, _token: Any, kind: int) -> Any:
        if kind == 3:
            buffer = ctypes.create_string_buffer(4 + ctypes.sizeof(helper._Privilege))
            ctypes.c_uint32.from_buffer(buffer).value = 1
            helper._Privilege.from_buffer(buffer, 4).luid.low = 7
            return buffer
        if kind == 19 and fails:
            raise OSError(5, "Linked token denied")
        buffer = ctypes.create_string_buffer(ctypes.sizeof(ctypes.c_void_p))
        ctypes.c_void_p.from_buffer(buffer).value = 42 if kind == 19 else 77
        return buffer

    security.OpenProcessToken.side_effect = _open
    security.LookupPrivilegeValueW.side_effect = _lookup
    monkeypatch.setattr(helper, "_process_ids", lambda: [1, 2])
    monkeypatch.setattr(helper, "_token_information", _information)
    monkeypatch.setattr(helper.account, "sid_to_string", lambda _pointer: "S-1-5-18")
    if fails:
        with pytest.raises(OSError, match="Linked token denied"):
            helper._linked_token(security, kernel, 100)
    else:
        assert helper._linked_token(security, kernel, 100).value == 42
    assert [
        (
            entry.args[0].value
            if isinstance(entry.args[0], ctypes.c_void_p)
            else entry.args[0]
        )
        for entry in kernel.CloseHandle.call_args_list
    ] == [200, 300]
    security.ImpersonateLoggedOnUser.assert_called_once()
    security.RevertToSelf.assert_called_once()
