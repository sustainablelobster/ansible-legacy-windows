"""Exercise token result fields, native buffer ownership, and failure recovery."""

# SPDX-License-Identifier: GPL-3.0-or-later
# Native substitutes expose buffer layout and calls for ownership assertions.
# pylint: disable=protected-access

import ctypes
import json
import weakref
from collections.abc import Callable
from types import ModuleType, SimpleNamespace
from typing import Any
from unittest.mock import Mock

import pytest

from tests.unit.payload_support import ROOT, load_module, native_error


@pytest.fixture(name="helper")
def token_helper(monkeypatch: pytest.MonkeyPatch) -> ModuleType:
    """Import the token helper with its adjacent account dependency.

    :param monkeypatch: Scoped helper import path.
    :returns: An isolated token helper module.
    """
    monkeypatch.syspath_prepend(str(ROOT / "plugins/module_utils"))
    return load_module(
        ROOT / "plugins/module_utils/legacy_windows_token.py", "tested_token_native"
    )


def _fill_groups(helper: ModuleType, native: Mock, buffer: Any) -> None:
    ctypes.c_uint32.from_buffer(buffer).value = len(native.groups)
    offset = helper._TokenGroups.groups.offset
    tail = offset + len(native.groups) * ctypes.sizeof(helper._SidAndAttributes)
    for sid, attributes in native.groups:
        entry = helper._SidAndAttributes.from_buffer(buffer, offset)
        entry.sid = ctypes.addressof(buffer) + tail
        entry.attributes = attributes
        data = sid.encode("ascii") + b"\0"
        ctypes.memmove(entry.sid, data, len(data))
        tail += len(data)
        offset += ctypes.sizeof(entry)


def _fill_privileges(helper: ModuleType, native: Mock, buffer: Any) -> None:
    ctypes.c_uint32.from_buffer(buffer).value = len(native.privileges)
    offset = helper._TokenPrivileges.privileges.offset
    for identifier, attributes in native.privileges:
        entry = helper._LuidAndAttributes.from_buffer(buffer, offset)
        entry.luid.low, entry.luid.high = identifier, -1
        entry.attributes = attributes
        offset += ctypes.sizeof(entry)


def _token_query(helper: ModuleType, native: Mock) -> Callable[..., int]:
    def _query(
        token: Any, information_class: int, buffer: Any, size: int, needed: Any
    ) -> int:
        assert token.value == 0x12345678
        if information_class == native.failure_class:
            native.error = native.query_error
            return 0
        required = 1024
        if (information_class == 2 and not native.groups) or (
            information_class == 3 and not native.privileges
        ):
            required = 4
        if size < required:
            needed._obj.value = required
            native.error = 122
            return 0
        native.buffers.append(weakref.ref(buffer))
        if information_class == 2:
            _fill_groups(helper, native, buffer)
        elif information_class == 3:
            _fill_privileges(helper, native, buffer)
        elif information_class == 25:
            label = helper._SidAndAttributes.from_buffer(buffer)
            label.sid = ctypes.addressof(buffer) + ctypes.sizeof(label)
            ctypes.memmove(label.sid, b"S-1-16-12288\0", 13)
        else:
            assert information_class == 10
            stats = helper._TokenStatistics.from_buffer(buffer)
            stats.authentication_id.low = 0xF0000001
            stats.authentication_id.high = -2
            stats.token_type = native.token_type
            stats.impersonation_level = native.impersonation
        return 1

    return _query


@pytest.fixture(name="native")
def native_token(helper: ModuleType, monkeypatch: pytest.MonkeyPatch) -> Mock:
    """Supply Windows calls that place all SID data inside their owning buffers.

    :param helper: Imported token helper.
    :param monkeypatch: Scoped native-boundary replacements.
    :returns: Inspectable libraries, query buffers, token contents, and errors.
    """
    native = Mock()
    native.error = 0
    native.failure_class = None
    native.query_error = 5
    native.buffers = []
    native.groups = [
        ("S-1-5-32-544", 0xF),
        ("S-1-1-0", 4),
        ("S-1-5-5-12-34", 0xC0000004),
        ("S-1-5-21-9-513", 0x20000072),
        ("S-1-5-99", 0x80000004),
    ]
    native.privileges = [(1, 1), (2, 2), (3, 3), (4, 0), (5, 0x80000000)]
    native.token_type = 1
    native.impersonation = 0
    native.windows_major = 6
    native.admin = True
    native.closed = []
    native.kernel.GetCurrentProcess.return_value = 0xFFFFFFFFFFFFFFFF
    native.kernel.CloseHandle.side_effect = lambda handle: native.closed.append(
        handle.value
    )

    def _open(process: int, access: int, token: Any) -> int:
        assert process == 0xFFFFFFFFFFFFFFFF
        assert access == 8
        token._obj.value = 0x12345678
        return 1

    def _lookup(_system: Any, luid: Any, name: Any, length: Any) -> int:
        assert luid._obj.high == -1
        value = "Privilege" + str(luid._obj.low)
        if name is None or length._obj.value <= len(value):
            length._obj.value = len(value)
            native.error = 122
            return 0
        name.value = value
        return 1

    def _membership(token: Any, sid: Any, member: Any) -> int:
        assert token is None
        assert sid.value == b"administrators"
        member._obj.value = int(native.admin)
        return 1

    def _describe(pointer: int) -> dict[str, Any]:
        sid = ctypes.string_at(pointer).decode("ascii")
        return {
            "sid": sid,
            "account_name": "name:" + sid,
            "domain_name": "domain",
            "type": "Label" if sid.startswith("S-1-16-") else "Group",
        }

    native.security.OpenProcessToken.side_effect = _open
    native.security.GetTokenInformation.side_effect = _token_query(helper, native)
    native.security.LookupPrivilegeNameW.side_effect = _lookup
    native.security.CheckTokenMembership.side_effect = _membership
    monkeypatch.setattr(helper, "os", SimpleNamespace(name="nt"))
    monkeypatch.setattr(
        helper,
        "sys",
        SimpleNamespace(
            getwindowsversion=lambda: SimpleNamespace(major=native.windows_major)
        ),
    )
    monkeypatch.setattr(
        ctypes,
        "WinDLL",
        lambda name, **_kwargs: {
            "advapi32": native.security,
            "kernel32": native.kernel,
        }[name],
        raising=False,
    )
    monkeypatch.setattr(ctypes, "get_last_error", lambda: native.error, raising=False)

    def _error(code: int) -> OSError:
        error = native_error(code)
        error.__dict__["winerror"] = code
        return error

    monkeypatch.setattr(ctypes, "WinError", _error, raising=False)
    monkeypatch.setattr(helper.account, "describe_sid", _describe, raising=False)
    monkeypatch.setattr(
        helper.account,
        "sid_to_string",
        lambda pointer: ctypes.string_at(pointer).decode("ascii"),
    )
    native.sid_bytes = Mock(return_value=b"administrators")
    monkeypatch.setattr(helper.account, "sid_bytes", native.sid_bytes)
    return native


@pytest.mark.parametrize("administrator", [False, True])
def test_token_result_copies_fields_order_and_effective_membership(
    helper: ModuleType, native: Mock, administrator: bool
) -> None:
    native.admin = administrator
    warnings: list[str] = []
    result, identifier, enabled, admin = helper.token_information(warnings)
    assert set(result) == {
        "groups",
        "privileges",
        "label",
        "token_type",
        "impersonation_level",
    }
    assert [entry["sid"] for entry in result["groups"]] == [
        "S-1-5-32-544",
        "S-1-1-0",
        "S-1-5-21-9-513",
        "S-1-5-99",
    ]
    assert [entry["attributes"] for entry in result["groups"]] == [
        ["Mandatory", "Enabled by default", "Enabled", "Owner"],
        ["Enabled"],
        [
            "Enabled by default",
            "Use for deny only",
            "Integrity",
            "Integrity enabled",
            "Resource",
        ],
        ["Enabled"],
    ]
    assert enabled == ["S-1-5-32-544", "S-1-1-0", "S-1-5-5-12-34", "S-1-5-99"]
    assert result["privileges"] == {
        "Privilege1": "enabled-by-default",
        "Privilege2": "enabled",
        "Privilege3": "enabled-by-default",
        "Privilege4": "disabled",
        "Privilege5": "disabled",
    }
    assert result["label"] == {
        "sid": "S-1-16-12288",
        "account_name": "name:S-1-16-12288",
        "domain_name": "domain",
        "type": "Label",
    }
    assert result["token_type"] == "TokenPrimary"
    assert result["impersonation_level"] == "SecurityAnonymous"
    assert identifier == 0xFFFFFFFEF0000001
    assert admin is administrator
    assert not warnings
    assert native.closed == [0x12345678]
    native.sid_bytes.assert_called_once_with("S-1-5-32-544")
    # Call histories themselves retain pointer arguments and their owning buffers.
    native.reset_mock()
    assert all(reference() is None for reference in native.buffers)
    json.dumps((result, identifier, enabled, admin))


@pytest.mark.parametrize(
    "case",
    [
        (2, 1, "TokenImpersonation", "SecurityIdentification"),
        (2, 2, "TokenImpersonation", "SecurityImpersonation"),
        (2, 3, "TokenImpersonation", "SecurityDelegation"),
        (7, -1, "7", "-1"),
    ],
)
def test_enum_names_and_numeric_fallbacks(
    helper: ModuleType, native: Mock, case: tuple[int, int, str, str]
) -> None:
    kind, level, expected_kind, expected_level = case
    native.token_type, native.impersonation = kind, level
    result = helper.token_information([])[0]
    assert result["token_type"] == expected_kind
    assert result["impersonation_level"] == expected_level


def test_empty_group_and_privilege_lists(helper: ModuleType, native: Mock) -> None:
    native.groups, native.privileges = [], []
    result, _identifier, enabled, _admin = helper.token_information([])
    assert result["groups"] == enabled == []
    assert result["privileges"] == {}
    native.security.LookupPrivilegeNameW.assert_not_called()


def test_unsupported_label_is_named_null_and_retains_other_information(
    helper: ModuleType, native: Mock
) -> None:
    native.failure_class, native.query_error = 25, 87
    native.windows_major = 5
    warnings: list[str] = []
    result, identifier, enabled, _admin = helper.token_information(warnings)
    assert result["label"] is None
    assert result["groups"] and result["privileges"] and enabled and identifier
    assert warnings == [
        "label is unavailable: Windows does not support TokenIntegrityLevel "
        "(Win32 error 87)."
    ]
    assert native.closed == [0x12345678]


def test_invalid_parameter_on_modern_windows_is_not_an_unsupported_label(
    helper: ModuleType, native: Mock
) -> None:
    native.failure_class, native.query_error = 25, 87
    warnings: list[str] = []
    with pytest.raises(OSError) as caught:
        helper.token_information(warnings)
    assert caught.value.errno == 87
    assert not warnings
    assert native.closed == [0x12345678]


@pytest.mark.parametrize("information_class", [2, 3, 10])
def test_invalid_parameter_for_required_fields_is_not_treated_as_unsupported_label(
    helper: ModuleType, native: Mock, information_class: int
) -> None:
    native.failure_class, native.query_error = information_class, 87
    warnings: list[str] = []
    with pytest.raises(OSError) as caught:
        helper.token_information(warnings)
    assert caught.value.errno == 87
    assert not warnings
    assert native.closed == [0x12345678]


@pytest.mark.parametrize("information_class", [2, 3, 10, 25])
def test_query_failure_closes_token_and_subsequent_call_recovers(
    helper: ModuleType, native: Mock, information_class: int
) -> None:
    native.failure_class = information_class
    warnings: list[str] = []
    with pytest.raises(OSError) as caught:
        helper.token_information(warnings)
    assert caught.value.errno == 5
    assert not warnings
    assert native.closed == [0x12345678]
    native.failure_class = None
    assert helper.token_information([])[0]["label"]["sid"] == "S-1-16-12288"
    assert native.closed == [0x12345678, 0x12345678]


@pytest.mark.parametrize("operation", ["LookupPrivilegeNameW", "CheckTokenMembership"])
def test_secondary_lookup_failure_closes_token(
    helper: ModuleType, native: Mock, operation: str
) -> None:
    def _failure(*_arguments: Any) -> int:
        native.error = 5
        return 0

    getattr(native.security, operation).side_effect = _failure
    with pytest.raises(OSError) as caught:
        helper.token_information([])
    assert caught.value.errno == 5
    assert native.closed == [0x12345678]


def test_sid_failure_closes_token(
    helper: ModuleType, native: Mock, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(
        helper.account, "describe_sid", Mock(side_effect=native_error(8))
    )
    with pytest.raises(OSError) as caught:
        helper.token_information([])
    assert caught.value.errno == 8
    assert native.closed == [0x12345678]


def test_open_failure_does_not_query_or_close_unowned_handle(
    helper: ModuleType, native: Mock
) -> None:
    native.security.OpenProcessToken.side_effect = None
    native.security.OpenProcessToken.return_value = 0
    native.error = 5
    with pytest.raises(OSError) as caught:
        helper.token_information([])
    assert caught.value.errno == 5
    assert native.closed == []
    native.security.GetTokenInformation.assert_not_called()


def test_query_retries_growth_with_same_token_and_class(
    helper: ModuleType, native: Mock
) -> None:
    seen = []

    def _query(
        token: int, information_class: int, buffer: Any, size: int, needed: Any
    ) -> int:
        assert token == 123 and information_class == 2
        seen.append(size)
        if len(seen) < 3:
            needed._obj.value = len(seen) * 16
            native.error = 122
            return 0
        buffer[0] = b"x"
        return 1

    native.security.GetTokenInformation.side_effect = _query
    buffer = helper._query_information(native.security, 123, 2)
    assert buffer[0] == b"x"
    assert seen == [0, 16, 32]


def test_structures_use_windows_field_widths_and_alignment(helper: ModuleType) -> None:
    width = ctypes.sizeof(ctypes.c_void_p)
    assert ctypes.sizeof(helper._Luid) == 8
    assert ctypes.sizeof(helper._LuidAndAttributes) == 12
    assert ctypes.sizeof(helper._TokenStatistics) == 56
    assert helper._TokenStatistics.authentication_id.offset == 8
    assert helper._TokenStatistics.token_type.offset == 24
    assert helper._TokenStatistics.modified_id.offset == 48
    assert helper._TokenGroups.groups.offset == width
    assert ctypes.sizeof(helper._SidAndAttributes) == (16 if width == 8 else 8)
    assert helper._TokenPrivileges.privileges.offset == 4


def test_native_signatures_retain_handle_and_output_pointer_widths(
    helper: ModuleType, native: Mock
) -> None:
    security, kernel = helper._libraries()
    assert security is native.security and kernel is native.kernel
    assert kernel.GetCurrentProcess.restype is ctypes.c_void_p
    assert kernel.CloseHandle.argtypes == [ctypes.c_void_p]
    assert security.OpenProcessToken.argtypes[-1] == ctypes.POINTER(ctypes.c_void_p)
    assert security.GetTokenInformation.argtypes == [
        ctypes.c_void_p,
        ctypes.c_int,
        ctypes.c_void_p,
        ctypes.c_uint32,
        ctypes.POINTER(ctypes.c_uint32),
    ]
    assert security.CheckTokenMembership.argtypes == [
        ctypes.c_void_p,
        ctypes.c_void_p,
        ctypes.POINTER(ctypes.c_int),
    ]


def test_token_information_requires_windows(helper: ModuleType) -> None:
    with pytest.raises(ValueError, match="Windows target"):
        helper.token_information([])
