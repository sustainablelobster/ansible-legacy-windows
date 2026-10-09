"""Verify native LSA ABI, assignment scope, and allocation ownership."""

# SPDX-License-Identifier: GPL-3.0-or-later
# Native boundary tests deliberately inspect the private C records.
# pylint: disable=protected-access

import ctypes
from types import ModuleType, SimpleNamespace
from typing import Any
from unittest.mock import Mock

import pytest

from tests.unit.payload_support import ROOT, load_module


@pytest.fixture(name="helper")
def rights_helper(monkeypatch: pytest.MonkeyPatch) -> ModuleType:
    """Load the target helper without loading native libraries.

    :param monkeypatch: Scoped helper import path.
    :returns: Fresh helper module.
    """
    monkeypatch.syspath_prepend(str(ROOT / "plugins/module_utils"))
    return load_module(
        ROOT / "plugins/module_utils/legacy_windows_user_right.py", "tested_lsa_rights"
    )


@pytest.fixture(name="native")
def native_api(helper: ModuleType, monkeypatch: pytest.MonkeyPatch) -> Any:
    """Replace native functions with policy and SID allocation stand-ins.

    :param helper: Loaded native helper.
    :param monkeypatch: Scoped native substitutions.
    :returns: Policy, API call recorders, and retained enumeration buffers.
    """
    library, kernel = Mock(), Mock()
    for name in (
        "LsaOpenPolicy",
        "LsaAddAccountRights",
        "LsaRemoveAccountRights",
        "LsaEnumerateAccountsWithUserRight",
        "LsaClose",
        "LsaFreeMemory",
    ):
        getattr(library, name).return_value = 0
    library.LsaNtStatusToWinError.return_value = 5

    def _open(_system: Any, _attributes: Any, _access: int, handle: Any) -> int:
        handle._obj.value = 100
        return 0

    def _sid(_text: str, pointer: Any) -> int:
        pointer._obj.value = 200
        return 1

    library.LsaOpenPolicy.side_effect = _open
    library.ConvertStringSidToSidW.side_effect = _sid
    monkeypatch.setattr(helper, "_libraries", lambda: (library, kernel))
    monkeypatch.setattr(
        helper.ctypes, "WinError", lambda code: OSError(code, "denied"), raising=False
    )
    monkeypatch.setattr(helper.ctypes, "get_last_error", lambda: 5, raising=False)
    monkeypatch.setattr(
        helper.accounts, "sid_to_string", lambda pointer: "SID-" + str(pointer)
    )
    return SimpleNamespace(library=library, kernel=kernel, buffers=[])


def _enumeration(native: Any, values: list[int], status: int = 0) -> Any:
    array = (ctypes.c_void_p * len(values))(*values)
    native.buffers.append(array)

    def _fill(_policy: Any, _right: Any, output: Any, count: Any) -> int:
        output._obj.value = ctypes.addressof(array)
        count._obj.value = len(values)
        return status

    return _fill


def test_exact_native_signatures(
    helper: ModuleType, monkeypatch: pytest.MonkeyPatch
) -> None:
    library, kernel = Mock(), Mock()
    monkeypatch.setattr(helper, "os", SimpleNamespace(name="nt"))
    monkeypatch.setattr(
        helper.ctypes, "WinDLL", Mock(side_effect=[library, kernel]), raising=False
    )
    assert helper._libraries() == (library, kernel)
    assert library.LsaRemoveAccountRights.argtypes[2] is ctypes.c_ubyte
    assert library.LsaEnumerateAccountsWithUserRight.argtypes[-1] == ctypes.POINTER(
        ctypes.c_uint32
    )
    assert library.LsaNtStatusToWinError.argtypes == [ctypes.c_int32]
    assert library.LsaOpenPolicy.restype is ctypes.c_uint32
    assert kernel.LocalFree.restype is ctypes.c_void_p
    width = ctypes.sizeof(ctypes.c_void_p)
    assert ctypes.sizeof(helper._ObjectAttributes) == (48 if width == 8 else 24)
    assert helper._UnicodeString.buffer.offset == (8 if width == 8 else 4)


def test_non_windows_fails_without_loading_libraries(
    helper: ModuleType, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(helper, "os", SimpleNamespace(name="posix"))
    loader = Mock()
    monkeypatch.setattr(helper.ctypes, "WinDLL", loader, raising=False)
    with pytest.raises(OSError, match="require a Windows target"):
        with helper.open_policy():
            pytest.fail("policy must not open")
    loader.assert_not_called()


def test_counted_strings_use_utf16_units_and_preserve_embedded_null(
    helper: ModuleType,
) -> None:
    value = "Se雪😀\0Right"
    right = helper._right_string(value)
    assert right.length == len(value.encode("utf-16-le"))
    assert right.maximum_length == right.length + 2
    assert helper._right_string("a" * 0x7FFE).length == 0xFFFC
    with pytest.raises(ValueError, match="String too long"):
        helper._right_string("a" * 0x7FFF)


def test_policy_access_and_close_on_consumer_failure(
    helper: ModuleType, native: Any
) -> None:
    with pytest.raises(RuntimeError, match="consumer"):
        with helper.open_policy():
            raise RuntimeError("consumer")
    arguments = native.library.LsaOpenPolicy.call_args.args
    assert arguments[0] is None
    assert arguments[1]._obj.length == ctypes.sizeof(helper._ObjectAttributes)
    assert arguments[2] == 0xF0FFF
    assert native.library.LsaClose.call_args.args[0].value == 100


def test_failed_open_releases_any_returned_handle(
    helper: ModuleType, native: Any
) -> None:
    def _failed(_system: Any, _attributes: Any, _access: int, handle: Any) -> int:
        handle._obj.value = 100
        return 0xC0000022

    native.library.LsaOpenPolicy.side_effect = _failed
    with pytest.raises(OSError):
        with helper.open_policy():
            pytest.fail("failed policy must not be yielded")
    assert native.library.LsaClose.call_args.args[0].value == 100
    native.library.LsaNtStatusToWinError.assert_called_once_with(-1073741790)


def test_enumeration_preserves_native_order_and_frees_buffer(
    helper: ModuleType, native: Any
) -> None:
    native.library.LsaEnumerateAccountsWithUserRight.side_effect = _enumeration(
        native, [40, 20, 90]
    )
    with helper.open_policy() as policy:
        assert policy.accounts("SeCreatePagefilePrivilege") == [
            "SID-40",
            "SID-20",
            "SID-90",
        ]
    native.library.LsaFreeMemory.assert_called_once()
    assert native.library.LsaFreeMemory.call_args.args[0].value == ctypes.addressof(
        native.buffers[0]
    )


@pytest.mark.parametrize("status", [0x8000001A, -2147483622])
def test_empty_enumeration_accepts_signed_status_and_frees_buffer(
    helper: ModuleType, native: Any, status: int
) -> None:
    native.library.LsaEnumerateAccountsWithUserRight.side_effect = _enumeration(
        native, [], status
    )
    with helper.open_policy() as policy:
        assert policy.accounts("SeCreatePagefilePrivilege") == []
    native.library.LsaFreeMemory.assert_called_once()


@pytest.mark.parametrize(
    "status,error",
    [(0xC0000060, ValueError), (-1073741728, ValueError), (0xC0000022, OSError)],
)
def test_enumeration_failure_frees_buffer(
    helper: ModuleType, native: Any, status: int, error: type[Exception]
) -> None:
    native.library.LsaEnumerateAccountsWithUserRight.side_effect = _enumeration(
        native, [10], status
    )
    with helper.open_policy() as policy, pytest.raises(error):
        policy.accounts("NoRight")
    native.library.LsaFreeMemory.assert_called_once()


def test_sid_conversion_failure_still_frees_enumeration(
    helper: ModuleType, native: Any, monkeypatch: pytest.MonkeyPatch
) -> None:
    native.library.LsaEnumerateAccountsWithUserRight.side_effect = _enumeration(
        native, [10]
    )
    monkeypatch.setattr(
        helper.accounts, "sid_to_string", Mock(side_effect=OSError("SID failed"))
    )
    with helper.open_policy() as policy, pytest.raises(OSError, match="SID failed"):
        policy.accounts("SeCreatePagefilePrivilege")
    native.library.LsaFreeMemory.assert_called_once()


@pytest.mark.parametrize("operation", ["add", "remove"])
@pytest.mark.parametrize("fails", [False, True])
def test_mutations_change_only_one_right_and_free_sid(
    helper: ModuleType, native: Any, operation: str, fails: bool
) -> None:
    function = getattr(
        native.library,
        "LsaAddAccountRights" if operation == "add" else "LsaRemoveAccountRights",
    )
    function.return_value = 0xC0000022 if fails else 0
    with helper.open_policy() as policy:
        if fails:
            with pytest.raises(OSError):
                getattr(policy, operation)("S-1-5-18", "SeCreatePagefilePrivilege")
        else:
            getattr(policy, operation)("S-1-5-18", "SeCreatePagefilePrivilege")
    arguments = function.call_args.args
    assert arguments[1].value == 200
    assert arguments[-1] == 1
    assert arguments[-2]._obj.buffer == "SeCreatePagefilePrivilege"
    if operation == "remove":
        assert arguments[2] == 0
    assert native.kernel.LocalFree.call_args.args[0].value == 200


def test_failed_sid_allocation_is_freed_before_propagating(
    helper: ModuleType, native: Any
) -> None:
    def _failed(_text: str, pointer: Any) -> int:
        pointer._obj.value = 200
        return 0

    native.library.ConvertStringSidToSidW.side_effect = _failed
    with helper.open_policy() as policy, pytest.raises(OSError):
        policy.add("S-1-5-18", "SeCreatePagefilePrivilege")
    native.library.LsaAddAccountRights.assert_not_called()
    assert native.kernel.LocalFree.call_args.args[0].value == 200
