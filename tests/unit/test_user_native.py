"""Exercise local-user native boundaries without contacting Windows hosts."""

# Copyright 2026 sustainablelobster
# SPDX-License-Identifier: GPL-3.0-or-later
# Native substitutes inspect private ABI records and buffer ownership directly.
# pylint: disable=protected-access

import ctypes
from types import ModuleType, SimpleNamespace
from typing import Any
from unittest.mock import Mock

import pytest

from tests.unit.payload_support import HELPER, ROOT, load_module


@pytest.fixture(name="helper")
def user_helper(monkeypatch: pytest.MonkeyPatch) -> ModuleType:
    """Import the native helper without loading Windows libraries.

    :param monkeypatch: Scoped source-import path.
    :returns: Imported target helper.
    """
    monkeypatch.syspath_prepend(str(HELPER.parent))
    return load_module(
        ROOT / "legacy_windows/plugins/module_utils/legacy_windows_user.py",
        "tested_user_native",
    )


@pytest.fixture(name="native")
def native_boundary(helper: ModuleType, monkeypatch: pytest.MonkeyPatch) -> Mock:
    """Substitute native functions while keeping real ctypes buffer ownership.

    :param helper: Imported user helper.
    :param monkeypatch: Scoped Windows substitutions.
    :returns: Mock exposing the libraries and native error state.
    """
    native = Mock()
    for name in (
        "NetUserGetInfo",
        "NetUserAdd",
        "NetUserSetInfo",
        "NetUserDel",
        "NetUserGetLocalGroups",
        "NetWkstaGetInfo",
        "NetApiBufferFree",
    ):
        getattr(native.netapi, name).return_value = 0
    native.security.LogonUserW.return_value = 0
    native.kernel.CloseHandle.return_value = 1
    native.last_error.return_value = 1326
    native.load.side_effect = lambda name, **_kwargs: {
        "netapi32": native.netapi,
        "advapi32": native.security,
        "kernel32": native.kernel,
    }[name]
    monkeypatch.setattr(helper, "os", SimpleNamespace(name="nt"))
    monkeypatch.setattr(ctypes, "WinDLL", native.load, raising=False)
    monkeypatch.setattr(ctypes, "get_last_error", native.last_error, raising=False)
    monkeypatch.setattr(
        ctypes, "FormatError", lambda _code: "native failure", raising=False
    )
    monkeypatch.setattr(ctypes, "WinError", OSError, raising=False)
    native.sid_to_string.return_value = "S-1-5-21-1-2-3-1001"
    monkeypatch.setattr(helper, "sid_to_string", native.sid_to_string)
    return native


def _publish(buffer: Any, record: Any) -> None:
    ctypes.cast(buffer, ctypes.POINTER(ctypes.c_void_p))[0] = ctypes.addressof(record)


def test_read_copies_borrowed_fields_before_free(
    helper: ModuleType, native: Mock
) -> None:
    name = ctypes.create_unicode_buffer("Owned_雪")
    full_name = ctypes.create_unicode_buffer("Display 雪")
    record = helper._UserInfo4()
    record.name = ctypes.cast(name, ctypes.c_wchar_p)
    record.full_name = ctypes.cast(full_name, ctypes.c_wchar_p)
    record.comment = "Description"
    record.home_dir = "C:\\Home"
    record.script_path = "login.cmd"
    record.flags = 0x10201
    record.acct_expires = 0xFFFFFFFF
    record.password_expired = 1
    record.password = "must not be returned"
    record.password_age = 999
    record.user_sid = 1234

    def _read(_server: Any, requested: str, level: int, buffer: Any) -> int:
        assert requested == "Owned_雪" and level == 4
        _publish(buffer, record)
        return 0

    def _convert(pointer: int) -> str:
        assert pointer == 1234
        native.netapi.NetApiBufferFree.assert_not_called()
        return "S-1-5-21-1-2-3-1001"

    def _free(_buffer: Any) -> int:
        name.value = "freed"
        full_name.value = "freed"
        return 0

    native.netapi.NetUserGetInfo.side_effect = _read
    native.sid_to_string.side_effect = _convert
    native.netapi.NetApiBufferFree.side_effect = _free
    assert helper.read_user("Owned_雪") == {
        "name": "Owned_雪",
        "full_name": "Display 雪",
        "comment": "Description",
        "home_dir": "C:\\Home",
        "script_path": "login.cmd",
        "profile": None,
        "flags": 0x10201,
        "acct_expires": 0xFFFFFFFF,
        "password_expired": 1,
        "sid": "S-1-5-21-1-2-3-1001",
    }
    assert native.netapi.NetApiBufferFree.call_count == 1


@pytest.mark.parametrize("status", [2221, 5, 87])
@pytest.mark.parametrize("allocated", [False, True])
def test_read_missing_and_failed_accounts_release_buffers(
    helper: ModuleType, native: Mock, status: int, allocated: bool
) -> None:
    record = helper._UserInfo4()

    def _read(*arguments: Any) -> int:
        if allocated:
            _publish(arguments[-1], record)
        return status

    native.netapi.NetUserGetInfo.side_effect = _read
    if status == 2221:
        assert helper.read_user("Missing") is None
    else:
        with pytest.raises(OSError) as caught:
            helper.read_user("Owned")
        assert caught.value.errno == status
    assert native.netapi.NetApiBufferFree.call_count == int(allocated)
    native.sid_to_string.assert_not_called()


def test_sid_conversion_failure_releases_user_buffer(
    helper: ModuleType, native: Mock
) -> None:
    record = helper._UserInfo4()

    def _read(*arguments: Any) -> int:
        _publish(arguments[-1], record)
        return 0

    native.netapi.NetUserGetInfo.side_effect = _read
    native.sid_to_string.side_effect = OSError(1337, "invalid SID")
    with pytest.raises(OSError, match="invalid SID"):
        helper.read_user("Owned")
    assert native.netapi.NetApiBufferFree.call_count == 1


@pytest.mark.parametrize("status", [0, 87])
def test_update_preserves_password_and_unrelated_borrowed_fields(
    helper: ModuleType, native: Mock, status: int
) -> None:
    hours = ctypes.create_string_buffer(b"\xff" * 21)
    reserved = ctypes.create_unicode_buffer("Unrelated application data")
    record = helper._UserInfo4()
    record.name = "Owned"
    record.full_name = "Before"
    record.profile = "C:\\Profile"
    record.parameters = ctypes.cast(reserved, ctypes.c_wchar_p)
    record.logon_hours = ctypes.addressof(hours)
    record.flags = 0x10241
    record.primary_group_id = 513
    record.acct_expires = 0xFFFFFFFF
    record.password_expired = 0

    def _read(*arguments: Any) -> int:
        _publish(arguments[-1], record)
        return 0

    def _set(_server: Any, name: str, level: int, buffer: Any, parameter: Any) -> int:
        assert name == "Owned" and level == 4
        native.netapi.NetApiBufferFree.assert_not_called()
        updated = ctypes.cast(buffer, ctypes.POINTER(helper._UserInfo4)).contents
        assert ctypes.addressof(updated) == ctypes.addressof(record)
        assert updated.full_name == "After 雪"
        assert updated.comment == ""
        assert updated.password is None
        assert updated.password_expired == 0
        assert updated.flags == 0x10241
        assert updated.acct_expires == 0xFFFFFFFF
        assert updated.primary_group_id == 513
        assert updated.profile == "C:\\Profile"
        assert updated.parameters == "Unrelated application data"
        assert updated.logon_hours == ctypes.addressof(hours)
        assert ctypes.string_at(updated.logon_hours, 21) == b"\xff" * 21
        ctypes.cast(parameter, ctypes.POINTER(ctypes.c_uint32))[0] = 10
        return status

    native.netapi.NetUserGetInfo.side_effect = _read
    native.netapi.NetUserSetInfo.side_effect = _set
    if status:
        with pytest.raises(OSError, match=r"NetUserSetInfo\(4\).*parameter 10"):
            helper.update_user("Owned", {"full_name": "After 雪", "comment": ""})
    else:
        helper.update_user("Owned", {"full_name": "After 雪", "comment": ""})
    assert native.netapi.NetUserGetInfo.call_count == 1
    assert native.netapi.NetUserSetInfo.call_count == 1
    assert native.netapi.NetApiBufferFree.call_count == 1


def test_update_rejects_password_field_before_native_access(
    helper: ModuleType, native: Mock
) -> None:
    with pytest.raises(ValueError, match="Unsupported local user property"):
        helper.update_user("Owned", {"password": "private value"})
    native.load.assert_not_called()


def test_failed_update_read_does_not_write(helper: ModuleType, native: Mock) -> None:
    native.netapi.NetUserGetInfo.return_value = 2221
    with pytest.raises(OSError) as caught:
        helper.update_user("Gone", {"full_name": "After"})
    assert caught.value.errno == 2221
    native.netapi.NetUserSetInfo.assert_not_called()
    native.netapi.NetApiBufferFree.assert_not_called()


@pytest.mark.parametrize("password", [None, "", "private 雪 value"])
def test_create_assigns_only_explicit_flags_and_initial_password(
    helper: ModuleType, native: Mock, password: str | None
) -> None:
    def _add(_server: Any, level: int, buffer: Any, _parameter: Any) -> int:
        assert level == 1
        record = ctypes.cast(buffer, ctypes.POINTER(helper._UserInfo1)).contents
        assert record.name == "Owned"
        assert record.password == password
        assert record.flags == 0x201
        assert record.priv == 1
        assert record.home_dir is None and record.comment is None
        assert record.script_path is None
        return 0

    native.netapi.NetUserAdd.side_effect = _add
    helper.create_user("Owned", password, 0x201)
    native.netapi.NetUserSetInfo.assert_not_called()


@pytest.mark.parametrize("creating", [False, True])
def test_password_failures_report_status_and_parameter_without_password(
    helper: ModuleType, native: Mock, creating: bool
) -> None:
    password = "Private password 雪"

    def _fail(*arguments: Any) -> int:
        ctypes.cast(arguments[-1], ctypes.POINTER(ctypes.c_uint32))[0] = 2
        if not creating:
            assert arguments[2] == 1003
            record = ctypes.cast(
                arguments[3], ctypes.POINTER(helper._UserInfo1003)
            ).contents
            assert record.password == password
        return 2245

    operation = native.netapi.NetUserAdd if creating else native.netapi.NetUserSetInfo
    operation.side_effect = _fail
    with pytest.raises(OSError) as caught:
        if creating:
            helper.create_user("Owned", password, 0x201)
        else:
            helper.set_password("Owned", password)
    assert caught.value.errno == 2245
    assert "parameter 2" in str(caught.value)
    assert password not in str(caught.value)


@pytest.mark.parametrize("status", [0, 2221, 5])
def test_delete_targets_only_supplied_name(
    helper: ModuleType, native: Mock, status: int
) -> None:
    native.netapi.NetUserDel.return_value = status
    if status:
        with pytest.raises(OSError) as caught:
            helper.delete_user("Owned")
        assert caught.value.errno == status
    else:
        helper.delete_user("Owned")
    native.netapi.NetUserDel.assert_called_once_with(None, "Owned")


@pytest.mark.parametrize("total", [0, 1, 2, 3])
def test_memberships_copy_actual_entries_in_native_order(
    helper: ModuleType, native: Mock, total: int
) -> None:
    first = ctypes.create_unicode_buffer("Zulu 雪")
    entries = (helper._LocalGroupUsersInfo0 * 2)(
        (ctypes.cast(first, ctypes.c_wchar_p),), ("Alpha",)
    )

    def _groups(*arguments: Any) -> int:
        assert arguments[:4] == (None, "Owned", 0, 0)
        assert arguments[5] == 0xFFFFFFFF
        _publish(arguments[4], entries)
        ctypes.cast(arguments[6], ctypes.POINTER(ctypes.c_uint32))[0] = 2
        ctypes.cast(arguments[7], ctypes.POINTER(ctypes.c_uint32))[0] = total
        return 0

    def _free(_buffer: Any) -> int:
        first.value = "freed"
        return 0

    native.netapi.NetUserGetLocalGroups.side_effect = _groups
    native.netapi.NetApiBufferFree.side_effect = _free
    assert helper.local_group_names("Owned") == ["Zulu 雪", "Alpha"]
    assert native.netapi.NetApiBufferFree.call_count == 1


def test_empty_memberships_do_not_need_a_buffer(
    helper: ModuleType, native: Mock
) -> None:
    assert helper.local_group_names("Owned") == []
    native.netapi.NetApiBufferFree.assert_not_called()


@pytest.mark.parametrize("status", [234, 5, 2221])
def test_membership_failures_free_even_partial_buffers(
    helper: ModuleType, native: Mock, status: int
) -> None:
    entries = (helper._LocalGroupUsersInfo0 * 1)(("Partial",))

    def _groups(*arguments: Any) -> int:
        _publish(arguments[4], entries)
        ctypes.cast(arguments[6], ctypes.POINTER(ctypes.c_uint32))[0] = 1
        return status

    native.netapi.NetUserGetLocalGroups.side_effect = _groups
    with pytest.raises(OSError) as caught:
        helper.local_group_names("Owned")
    assert caught.value.errno == status
    assert native.netapi.NetApiBufferFree.call_count == 1


def test_password_logon_closes_token(helper: ModuleType, native: Mock) -> None:
    token_value = (1 << (ctypes.sizeof(ctypes.c_void_p) * 8 - 1)) + 123

    def _logon(*arguments: Any) -> int:
        assert arguments[:5] == ("Owned", ".", "private value", 3, 0)
        ctypes.cast(arguments[5], ctypes.POINTER(ctypes.c_void_p))[0] = token_value
        return 1

    native.security.LogonUserW.side_effect = _logon
    assert helper.password_matches("Owned", "private value") is True
    assert native.kernel.CloseHandle.call_args.args[0].value == token_value
    assert native.kernel.CloseHandle.call_count == 1
    native.last_error.assert_not_called()


@pytest.mark.parametrize("code", [1326, 1327, 1328, 1329, 1385, 1330, 1331, 1909, 5])
def test_password_validation_matches_upstream_restriction_codes(
    helper: ModuleType, native: Mock, code: int
) -> None:
    native.last_error.return_value = code
    if code in (1326, 1327, 1328, 1329, 1385):
        assert helper.password_matches("Owned", "private value") is (code != 1326)
    else:
        with pytest.raises(OSError) as caught:
            helper.password_matches("Owned", "private value")
        assert caught.value.errno == code
        assert "private value" not in str(caught.value)
    native.kernel.CloseHandle.assert_not_called()


def test_token_close_failure_is_reported(helper: ModuleType, native: Mock) -> None:
    native.security.LogonUserW.return_value = 1
    native.kernel.CloseHandle.return_value = 0
    native.last_error.return_value = 6
    with pytest.raises(OSError, match="CloseHandle") as caught:
        helper.password_matches("Owned", "private value")
    assert caught.value.errno == 6


def test_account_path_copies_workstation_identity_before_free(
    helper: ModuleType, native: Mock
) -> None:
    computer = ctypes.create_unicode_buffer("COMPUTER")
    langroup = ctypes.create_unicode_buffer("WORKGROUP")
    record = helper._WorkstationInfo100(
        500,
        ctypes.cast(computer, ctypes.c_wchar_p),
        ctypes.cast(langroup, ctypes.c_wchar_p),
        5,
        1,
    )

    def _identity(server: Any, level: int, buffer: Any) -> int:
        assert server is None and level == 100
        _publish(buffer, record)
        return 0

    def _free(_buffer: Any) -> int:
        computer.value = "freed"
        langroup.value = "freed"
        return 0

    native.netapi.NetWkstaGetInfo.side_effect = _identity
    native.netapi.NetApiBufferFree.side_effect = _free
    assert helper.account_path("Owned_雪") == "WinNT://WORKGROUP/COMPUTER/Owned_雪"
    assert native.netapi.NetApiBufferFree.call_count == 1


def test_account_path_failure_releases_allocated_buffer(
    helper: ModuleType, native: Mock
) -> None:
    record = helper._WorkstationInfo100()

    def _identity(*arguments: Any) -> int:
        _publish(arguments[-1], record)
        return 5

    native.netapi.NetWkstaGetInfo.side_effect = _identity
    with pytest.raises(OSError) as caught:
        helper.account_path("Owned")
    assert caught.value.errno == 5
    assert native.netapi.NetApiBufferFree.call_count == 1
