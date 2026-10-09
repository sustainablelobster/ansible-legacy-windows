"""Exercise owner API boundaries and privilege restoration without Windows."""

# SPDX-License-Identifier: GPL-3.0-or-later
# These tests inspect native pointers, buffer ownership, and ABI declarations.
# pylint: disable=protected-access

import ctypes
from types import ModuleType, SimpleNamespace
from typing import Any
from unittest.mock import Mock

import pytest

from tests.unit.payload_support import ROOT, load_module, native_error


def _windows_error(code: int) -> OSError:
    error = native_error(code)
    setattr(error, "winerror", code)
    return error


@pytest.fixture(name="helper")
def owner_helper(monkeypatch: pytest.MonkeyPatch) -> ModuleType:
    """Load the target helper with its normal adjacent helper imports.

    :param monkeypatch: Scoped import-path changes.
    :returns: Independently loaded owner helper.
    """
    monkeypatch.syspath_prepend(str(ROOT / "plugins/module_utils"))
    return load_module(
        ROOT / "plugins/module_utils/legacy_windows_owner.py", "tested_owner_native"
    )


@pytest.fixture(name="native")
def owner_native(helper: ModuleType, monkeypatch: pytest.MonkeyPatch) -> Any:
    """Expose security buffers and native calls while keeping operations local.

    :param helper: Loaded owner helper.
    :param monkeypatch: Scoped library and last-error replacements.
    :returns: Native stand-in with configurable errors and security pointers.
    """
    state = SimpleNamespace(
        security=Mock(),
        kernel=Mock(),
        error=0,
        descriptor=ctypes.create_string_buffer(b"security descriptor"),
        owner=ctypes.create_string_buffer(b"owner SID"),
        group=ctypes.create_string_buffer(b"group SID"),
        dacl=ctypes.create_string_buffer(b"existing DACL"),
        control=0x8004,
    )
    state.kernel.GetCurrentProcess.return_value = -1
    state.kernel.CreateFileW.return_value = 41
    state.security.SetSecurityInfo.return_value = 0

    def _get_security(*args: Any) -> int:
        for index, value in enumerate((state.owner, state.group, state.dacl), 3):
            if args[index] is not None:
                args[index]._obj.value = ctypes.addressof(value) if value else None
        args[7]._obj.value = ctypes.addressof(state.descriptor)
        return 0

    def _get_control(_descriptor: Any, control: Any, revision: Any) -> int:
        control._obj.value = state.control
        revision._obj.value = 1
        return 1

    def _open_token(_process: Any, _access: Any, token: Any) -> int:
        token._obj.value = 51
        return 1

    def _lookup(_system: Any, name: str, pointer: Any) -> int:
        pointer._obj.low = helper._PRIVILEGES.index(name) + 10
        return 1

    def _adjust(*args: Any) -> int:
        state.error = 0
        if args[4] is not None:
            previous = args[4]._obj
            previous.count = 2
            previous.privileges[0].luid.low = 10
            previous.privileges[0].attributes = 0
            previous.privileges[1].luid.low = 12
            previous.privileges[1].attributes = 1
            args[5]._obj.value = ctypes.sizeof(previous)
        return 1

    state.security.GetSecurityInfo.side_effect = _get_security
    state.security.GetSecurityDescriptorControl.side_effect = _get_control
    state.security.OpenProcessToken.side_effect = _open_token
    state.security.LookupPrivilegeValueW.side_effect = _lookup
    state.security.AdjustTokenPrivileges.side_effect = _adjust
    monkeypatch.setattr(helper, "_libraries", lambda: (state.security, state.kernel))
    monkeypatch.setattr(ctypes, "get_last_error", lambda: state.error, raising=False)
    monkeypatch.setattr(ctypes, "WinError", _windows_error, raising=False)
    monkeypatch.setattr(helper.account, "sid_bytes", Mock(return_value=b"binary SID"))
    monkeypatch.setattr(helper.account, "sid_to_string", Mock(return_value="S-1-5-18"))
    return state


def test_security_abi_has_pointer_sized_handles_and_fixed_dwords(
    helper: ModuleType, monkeypatch: pytest.MonkeyPatch
) -> None:
    libraries = {"advapi32": Mock(), "kernel32": Mock()}
    monkeypatch.setattr(helper, "os", SimpleNamespace(name="nt"))
    loader = Mock(side_effect=lambda name, **_kwargs: libraries[name])
    monkeypatch.setattr(ctypes, "WinDLL", loader, raising=False)
    security, kernel = helper._libraries()
    assert loader.call_args_list[0].kwargs == {"use_last_error": True}
    assert loader.call_args_list[1].kwargs == {"use_last_error": True}
    assert kernel.CreateFileW.restype is ctypes.c_void_p
    assert kernel.GetCurrentProcess.restype is ctypes.c_void_p
    assert kernel.CloseHandle.argtypes == [ctypes.c_void_p]
    assert kernel.LocalFree.argtypes == [ctypes.c_void_p]
    assert security.OpenProcessToken.argtypes == [
        ctypes.c_void_p,
        ctypes.c_uint32,
        ctypes.POINTER(ctypes.c_void_p),
    ]
    assert security.GetSecurityInfo.restype is ctypes.c_uint32
    assert security.GetSecurityDescriptorControl.argtypes == [
        ctypes.c_void_p,
        ctypes.POINTER(ctypes.c_uint16),
        ctypes.POINTER(ctypes.c_uint32),
    ]
    assert security.GetSecurityDescriptorControl.restype is ctypes.c_int
    assert security.SetSecurityInfo.restype is ctypes.c_uint32
    assert (
        security.GetSecurityInfo.argtypes[3:] == [ctypes.POINTER(ctypes.c_void_p)] * 5
    )
    assert ctypes.sizeof(helper._Luid) == 8
    assert ctypes.sizeof(helper._Privilege) == 12
    assert ctypes.sizeof(helper._OwnershipPrivileges) == 52
    assert helper._OwnershipPrivileges.privileges.offset == 4


def test_non_windows_rejected_before_loading_libraries(
    helper: ModuleType, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(helper, "os", SimpleNamespace(name="posix"))
    with pytest.raises(ValueError, match="Windows target"):
        helper._libraries()


@pytest.mark.parametrize("user", ["S-1-5-18", "SY", "BA"])
def test_raw_sid_and_alias_skip_account_and_group_lookup(
    helper: ModuleType, monkeypatch: pytest.MonkeyPatch, user: str
) -> None:
    parser = Mock(return_value="S-1-5-18")
    lookup, groups = Mock(), Mock()
    monkeypatch.setattr(helper.account, "parse_sid", parser)
    monkeypatch.setattr(helper.account, "account_name_to_sid", lookup)
    monkeypatch.setattr(helper, "list_groups", groups)
    assert helper.resolve_owner(user) == "S-1-5-18"
    parser.assert_called_once_with(user)
    lookup.assert_not_called()
    groups.assert_not_called()


@pytest.mark.parametrize(
    "user,expected,enumerates",
    [
        (r".\Administrators", "Administrators", True),
        (r"HOST\administrators", "administrators", True),
        (r"host\Administrators", "Administrators", True),
        (r".\normal", r"HOST\normal", True),
        (r"HOST\normal", r"HOST\normal", True),
        (r"DOMAIN\Administrators", r"DOMAIN\Administrators", False),
        (r"NT AUTHORITY\SYSTEM", r"NT AUTHORITY\SYSTEM", False),
        ("Administrators", "Administrators", False),
        (r"\Administrators", "Administrators", False),
        (r"DOMAIN\name\tail", r"DOMAIN\name\tail", False),
    ],
)
def test_account_lookup_retains_domain_except_machine_local_groups(
    helper: ModuleType,
    monkeypatch: pytest.MonkeyPatch,
    user: str,
    expected: str,
    enumerates: bool,
) -> None:
    parser = Mock(side_effect=_windows_error(1337))
    lookup = Mock(return_value="S-1-5-32-544")
    groups = Mock(return_value=[{"name": "Administrators", "description": ""}])
    monkeypatch.setattr(helper.account, "parse_sid", parser)
    monkeypatch.setattr(helper.account, "account_name_to_sid", lookup)
    monkeypatch.setattr(helper, "list_groups", groups)
    monkeypatch.setattr(helper, "os", SimpleNamespace(environ={"COMPUTERNAME": "HOST"}))
    assert helper.resolve_owner(user) == "S-1-5-32-544"
    lookup.assert_called_once_with(expected)
    assert groups.call_count == int(enumerates)


@pytest.mark.parametrize("code", [5, 8, 87])
def test_unexpected_sid_parse_error_does_not_turn_into_account_lookup(
    helper: ModuleType, monkeypatch: pytest.MonkeyPatch, code: int
) -> None:
    monkeypatch.setattr(
        helper.account, "parse_sid", Mock(side_effect=_windows_error(code))
    )
    lookup = Mock()
    monkeypatch.setattr(helper.account, "account_name_to_sid", lookup)
    with pytest.raises(OSError) as error:
        helper.resolve_owner("invalid")
    assert error.value.errno == code
    lookup.assert_not_called()


def test_failed_local_group_enumeration_is_not_silently_ignored(
    helper: ModuleType, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(
        helper.account, "parse_sid", Mock(side_effect=_windows_error(1337))
    )
    monkeypatch.setattr(helper, "list_groups", Mock(side_effect=_windows_error(5)))
    monkeypatch.setattr(helper, "os", SimpleNamespace(environ={"COMPUTERNAME": "HOST"}))
    with pytest.raises(OSError) as error:
        helper.resolve_owner(r".\Administrators")
    assert error.value.errno == 5


def test_get_owner_uses_backup_handle_and_frees_descriptor_not_borrowed_sid(
    helper: ModuleType, native: Any
) -> None:
    assert helper.get_owner(r"C:\雪 [owner].txt") == "S-1-5-18"
    native.kernel.CreateFileW.assert_called_once_with(
        r"C:\雪 [owner].txt", 0x20000, 7, None, 3, 0x02000000, None
    )
    args = native.security.GetSecurityInfo.call_args.args
    assert args[:3] == (41, 1, 1)
    assert args[4:7] == (None, None, None)
    assert helper.account.sid_to_string.call_args.args[0].value == ctypes.addressof(
        native.owner
    )
    assert native.kernel.LocalFree.call_args.args[0].value == ctypes.addressof(
        native.descriptor
    )
    native.kernel.LocalFree.assert_called_once()
    native.kernel.CloseHandle.assert_called_once_with(41)


def test_missing_owner_is_returned_as_none_without_sid_conversion(
    helper: ModuleType, native: Any
) -> None:
    native.security.GetSecurityInfo.side_effect = None
    native.security.GetSecurityInfo.return_value = 0
    assert helper.get_owner("file") is None
    helper.account.sid_to_string.assert_not_called()
    native.kernel.LocalFree.assert_not_called()
    native.kernel.CloseHandle.assert_called_once_with(41)


@pytest.mark.parametrize("failure", ["security", "conversion"])
def test_read_failure_releases_descriptor_and_handle_then_recovers(
    helper: ModuleType, native: Any, failure: str
) -> None:
    original = native.security.GetSecurityInfo.side_effect
    if failure == "security":

        def _fail(*args: Any) -> int:
            original(*args)
            return 5

        native.security.GetSecurityInfo.side_effect = _fail
    else:
        helper.account.sid_to_string.side_effect = _windows_error(5)
    with pytest.raises(OSError) as error:
        helper.get_owner("file")
    assert error.value.errno == 5
    native.kernel.LocalFree.assert_called_once()
    native.kernel.CloseHandle.assert_called_once_with(41)
    native.security.GetSecurityInfo.side_effect = original
    helper.account.sid_to_string.side_effect = None
    assert helper.get_owner("file") == "S-1-5-18"
    assert native.kernel.CloseHandle.call_count == 2
    assert native.kernel.LocalFree.call_count == 2


@pytest.mark.parametrize("protected", [False, True])
@pytest.mark.parametrize("null_dacl", [False, True])
def test_set_owner_preserves_group_dacl_and_protection_with_backup_semantics(
    helper: ModuleType, native: Any, protected: bool, null_dacl: bool
) -> None:
    if protected:
        native.control |= 0x1000
    if null_dacl:
        native.dacl = None
    helper.set_owner(r"C:\directory", "S-1-5-18")
    helper.account.sid_bytes.assert_called_once_with("S-1-5-18")
    native.kernel.CreateFileW.assert_called_once_with(
        r"C:\directory", 0xE0000, 7, None, 3, 0x02000000, None
    )
    read = native.security.GetSecurityInfo.call_args.args
    assert read[:4] == (41, 1, 6, None)
    assert read[6] is None
    control_descriptor = native.security.GetSecurityDescriptorControl.call_args.args[0]
    assert control_descriptor.value == ctypes.addressof(native.descriptor)
    args = native.security.SetSecurityInfo.call_args.args
    assert args[:3] == (41, 1, 7 | (0x80000000 if protected else 0x20000000))
    assert ctypes.string_at(args[3], len(b"binary SID")) == b"binary SID"
    assert args[4].value == ctypes.addressof(native.group)
    assert args[5].value == (None if null_dacl else ctypes.addressof(native.dacl))
    assert args[6] is None
    assert native.kernel.LocalFree.call_args.args[0].value == ctypes.addressof(
        native.descriptor
    )
    native.kernel.LocalFree.assert_called_once()
    native.kernel.CloseHandle.assert_called_once_with(41)


@pytest.mark.parametrize("failure", ["security", "control"])
def test_set_owner_read_failure_releases_buffers_without_writing_then_recovers(
    helper: ModuleType, native: Any, failure: str
) -> None:
    operation = (
        native.security.GetSecurityInfo
        if failure == "security"
        else native.security.GetSecurityDescriptorControl
    )
    original = operation.side_effect

    def _fail(*args: Any) -> int:
        original(*args)
        native.error = 5
        return 5 if failure == "security" else 0

    operation.side_effect = _fail
    with pytest.raises(OSError) as error:
        helper.set_owner("file", "S-1-5-18")
    assert error.value.errno == 5
    native.security.SetSecurityInfo.assert_not_called()
    native.kernel.LocalFree.assert_called_once()
    native.kernel.CloseHandle.assert_called_once_with(41)
    operation.side_effect = original
    helper.set_owner("file", "S-1-5-18")
    native.security.SetSecurityInfo.assert_called_once()
    assert native.kernel.LocalFree.call_count == 2
    assert native.kernel.CloseHandle.call_count == 2


@pytest.mark.parametrize("operation", ["get", "set"])
def test_open_failure_does_not_close_invalid_handle(
    helper: ModuleType, native: Any, operation: str
) -> None:
    native.error = 32
    native.kernel.CreateFileW.return_value = ctypes.c_void_p(-1).value
    with pytest.raises(OSError) as error:
        if operation == "get":
            helper.get_owner("locked")
        else:
            helper.set_owner("locked", "S-1-5-18")
    assert error.value.errno == 32
    native.security.GetSecurityInfo.assert_not_called()
    native.security.SetSecurityInfo.assert_not_called()
    native.kernel.CloseHandle.assert_not_called()


@pytest.mark.parametrize("code", [5, 1307, 1314])
def test_set_failure_frees_descriptor_closes_handle_and_preserves_native_status(
    helper: ModuleType, native: Any, code: int
) -> None:
    native.security.SetSecurityInfo.return_value = code
    native.error = 999
    with pytest.raises(OSError) as error:
        helper.set_owner("file", "S-1-5-18")
    assert error.value.errno == code
    native.kernel.LocalFree.assert_called_once()
    native.kernel.CloseHandle.assert_called_once_with(41)
    native.security.SetSecurityInfo.return_value = 0
    helper.set_owner("file", "S-1-5-18")
    assert native.kernel.LocalFree.call_count == 2
    assert native.kernel.CloseHandle.call_count == 2


def test_invalid_sid_fails_before_opening_file(helper: ModuleType, native: Any) -> None:
    helper.account.sid_bytes.side_effect = _windows_error(1337)
    with pytest.raises(OSError):
        helper.set_owner("file", "invalid")
    native.kernel.CreateFileW.assert_not_called()


@pytest.mark.parametrize("raise_in_body", [False, True])
def test_privileges_restore_exact_previous_state_on_success_and_body_failure(
    helper: ModuleType, native: Any, raise_in_body: bool
) -> None:
    def _operation() -> None:
        with helper.ownership_privileges():
            assert native.security.AdjustTokenPrivileges.call_count == 1
            native.kernel.CloseHandle.assert_not_called()
            if raise_in_body:
                raise RuntimeError("operation failed")

    if raise_in_body:
        with pytest.raises(RuntimeError, match="operation failed"):
            _operation()
    else:
        _operation()
    native.security.OpenProcessToken.assert_called_once()
    opening = native.security.OpenProcessToken.call_args.args
    assert opening[:2] == (-1, 0x28)
    calls = native.security.AdjustTokenPrivileges.call_args_list
    enabled = calls[0].args[2]._obj
    assert enabled.count == 4
    assert [item.luid.low for item in enabled.privileges] == [10, 11, 12, 13]
    assert [item.attributes for item in enabled.privileges] == [2, 2, 2, 2]
    restored = calls[1].args[2]._obj
    assert restored.count == 2
    assert [(item.luid.low, item.attributes) for item in restored.privileges[:2]] == [
        (10, 0),
        (12, 1),
    ]
    assert calls[1].args[3:] == (0, None, None)
    assert native.kernel.CloseHandle.call_args.args[0].value == 51
    native.kernel.CloseHandle.assert_called_once()


def test_explicit_privilege_subset_uses_same_restoration(
    helper: ModuleType, native: Any
) -> None:
    names = ("SeRestorePrivilege", "SeBackupPrivilege", "SeTakeOwnershipPrivilege")
    with helper.ownership_privileges(names):
        pass
    assert [
        call.args[1] for call in native.security.LookupPrivilegeValueW.call_args_list
    ] == list(names)
    calls = native.security.AdjustTokenPrivileges.call_args_list
    requested = calls[0].args[2]._obj
    assert requested.count == 3
    assert [item.luid.low for item in requested.privileges[:3]] == [12, 10, 13]
    assert calls[1].args[2]._obj.count == 2
    native.kernel.CloseHandle.assert_called_once()


def test_oversized_privilege_request_fails_before_native_calls(
    helper: ModuleType, native: Any
) -> None:
    with pytest.raises(ValueError, match="At most four"):
        with helper.ownership_privileges(("name",) * 5):
            pass
    native.security.LookupPrivilegeValueW.assert_not_called()
    native.security.OpenProcessToken.assert_not_called()
    native.kernel.CloseHandle.assert_not_called()


@pytest.mark.parametrize("changed", [False, True])
def test_missing_privileges_are_ignored_and_only_changed_privileges_restored(
    helper: ModuleType, native: Any, changed: bool
) -> None:
    original = native.security.AdjustTokenPrivileges.side_effect

    def _adjust(*args: Any) -> int:
        result = original(*args)
        if args[4] is not None:
            native.error = 1300
            if not changed:
                args[4]._obj.count = 0
        return int(result)

    native.security.AdjustTokenPrivileges.side_effect = _adjust
    with helper.ownership_privileges():
        pass
    assert native.security.AdjustTokenPrivileges.call_count == (2 if changed else 1)
    native.kernel.CloseHandle.assert_called_once()


@pytest.mark.parametrize("failure", ["lookup", "open", "adjust", "restore"])
def test_privilege_api_failure_is_reported_without_leaking_token(
    helper: ModuleType, native: Any, failure: str
) -> None:
    native.error = 5
    if failure == "lookup":
        native.security.LookupPrivilegeValueW.side_effect = None
        native.security.LookupPrivilegeValueW.return_value = 0
    elif failure == "open":
        native.security.OpenProcessToken.side_effect = None
        native.security.OpenProcessToken.return_value = 0
    else:
        original = native.security.AdjustTokenPrivileges.side_effect

        def _adjust(*args: Any) -> int:
            enabling = args[4] is not None
            if enabling == (failure == "adjust"):
                native.error = 5
                return 0
            return int(original(*args))

        native.security.AdjustTokenPrivileges.side_effect = _adjust
    with pytest.raises(OSError) as error:
        with helper.ownership_privileges():
            pass
    assert error.value.errno == 5
    assert native.kernel.CloseHandle.call_count == int(failure in ("adjust", "restore"))


def test_unexpected_success_error_restores_changed_privileges_before_failure(
    helper: ModuleType, native: Any
) -> None:
    original = native.security.AdjustTokenPrivileges.side_effect

    def _adjust(*args: Any) -> int:
        result = original(*args)
        if args[4] is not None:
            native.error = 87
        return int(result)

    native.security.AdjustTokenPrivileges.side_effect = _adjust
    with pytest.raises(OSError) as error:
        with helper.ownership_privileges():
            pytest.fail("A failed enable must not execute the body")
    assert error.value.errno == 87
    assert native.security.AdjustTokenPrivileges.call_count == 2
    native.kernel.CloseHandle.assert_called_once()
