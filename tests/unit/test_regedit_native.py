"""Exercise registry writes and hive privileges without contacting Windows."""

# SPDX-License-Identifier: GPL-3.0-or-later
# Native substitutes expose the exact buffers and handle lifetime.
# pylint: disable=protected-access

import ctypes
from types import ModuleType, SimpleNamespace
from typing import Any
from unittest.mock import MagicMock, Mock

import pytest

from tests.unit.payload_support import HELPER, ROOT, load_module, native_error


@pytest.fixture(name="helper")
def registry_helper(monkeypatch: pytest.MonkeyPatch) -> ModuleType:
    """Import the helper without loading Windows libraries.

    :param monkeypatch: Scoped import path.
    :returns: Imported target helper.
    """
    monkeypatch.syspath_prepend(str(HELPER.parent))
    return load_module(
        ROOT / "legacy_windows/plugins/module_utils/legacy_windows_regedit.py",
        "tested_regedit_native",
    )


@pytest.fixture(name="native")
def native_boundary(helper: ModuleType, monkeypatch: pytest.MonkeyPatch) -> Mock:
    """Supply observable Windows registry and token APIs.

    :param helper: Imported helper.
    :param monkeypatch: Scoped Windows substitutions.
    :returns: Mock containing registry, token, and kernel libraries.
    """
    native = Mock()
    native.registry = MagicMock()
    native.registry.KEY_READ = 0x20019
    native.registry.KEY_WRITE = 0x20006
    for suffix, value in (("CURRENT_USER", 0x80000001), ("LOCAL_MACHINE", 0x80000002)):
        setattr(native.registry, "HKEY_" + suffix, value)
    native.advapi.RegSetValueExW.return_value = 0
    native.advapi.RegDeleteValueW.return_value = 0
    native.advapi.RegUnLoadKeyW.return_value = 0
    native.advapi.OpenProcessToken.return_value = 1
    native.advapi.LookupPrivilegeValueW.return_value = 1
    native.advapi.AdjustTokenPrivileges.return_value = 1
    native.kernel.GetCurrentProcess.return_value = -1
    native.kernel.CloseHandle.return_value = 1
    native.error = 0
    monkeypatch.setattr(helper, "winreg", native.registry)
    monkeypatch.setattr(helper, "os", SimpleNamespace(name="nt"))
    monkeypatch.setattr(
        ctypes,
        "WinDLL",
        lambda name, **_kwargs: native.advapi if name == "advapi32" else native.kernel,
        raising=False,
    )
    monkeypatch.setattr(ctypes, "WinError", native_error, raising=False)
    monkeypatch.setattr(ctypes, "get_last_error", lambda: native.error, raising=False)
    monkeypatch.setattr(
        ctypes,
        "set_last_error",
        lambda value: setattr(native, "error", value),
        raising=False,
    )
    return native


@pytest.mark.parametrize(
    "kind,value,expected",
    [
        ("string", "snowman \u2603", "snowman \u2603\0".encode("utf-16-le")),
        ("string", True, "True\0".encode("utf-16-le")),
        ("string", [1, 2], "System.Object[]\0".encode("utf-16-le")),
        ("string", {"a": 1}, "System.Collections.Hashtable\0".encode("utf-16-le")),
        ("expandstring", "%TEMP%", "%TEMP%\0".encode("utf-16-le")),
        ("multistring", ["one", "", "two"], "one\0\0two\0\0".encode("utf-16-le")),
        ("multistring", [], b"\0\0"),
        ("dword", -1, b"\xff" * 4),
        ("dword", 0, b"\0" * 4),
        ("qword", -1, b"\xff" * 8),
        ("qword", 1, b"\x01" + b"\0" * 7),
        ("binary", [0, 255], b"\0\xff"),
        ("none", [], b""),
    ],
)
def test_exact_native_value_encoding(
    helper: ModuleType, native: Mock, kind: str, value: Any, expected: bytes
) -> None:
    captured = []

    def _set(*arguments: Any) -> int:
        key, name, reserved, number, data, size = arguments
        captured.append(
            (key, name, reserved, number, ctypes.string_at(data, size), size)
        )
        return 0

    native.advapi.RegSetValueExW.side_effect = _set
    helper.set_value(123, "name", kind, value)
    assert captured == [(123, "name", 0, helper.KINDS[kind], expected, len(expected))]


@pytest.mark.parametrize(
    "kind,value",
    [("binary", True), ("binary", 1.5), ("none", {"a": 1}), ("binary", [256])],
)
def test_invalid_binary_data_does_not_write(
    helper: ModuleType, native: Mock, kind: str, value: Any
) -> None:
    with pytest.raises(ValueError):
        helper.set_value(123, "name", kind, value)
    native.advapi.RegSetValueExW.assert_not_called()


def test_long_value_name_fails_before_write(helper: ModuleType, native: Mock) -> None:
    with pytest.raises(ValueError, match="16383"):
        helper.set_value(123, "\U0001f600" * 8192, "string", "value")
    native.advapi.RegSetValueExW.assert_not_called()


@pytest.mark.parametrize("operation", ["set", "delete", "unload"])
def test_registry_error_codes_propagate(
    helper: ModuleType, native: Mock, operation: str
) -> None:
    native.advapi.RegSetValueExW.return_value = 5
    native.advapi.RegDeleteValueW.return_value = 5
    native.advapi.RegUnLoadKeyW.return_value = 5
    with pytest.raises(OSError) as caught:
        if operation == "set":
            helper.set_value(123, "name", "string", "value")
        elif operation == "delete":
            helper.delete_value(123, "name")
        else:
            helper.unload_hive()
    assert caught.value.errno == 5


@pytest.mark.parametrize("create", [False, True])
def test_opens_writable_default_view_and_normalizes_subkey(
    helper: ModuleType, native: Mock, create: bool
) -> None:
    helper.open_key("HKCU", "Software\\\\Owned\\\0ignored", create=create)
    operation = native.registry.CreateKeyEx if create else native.registry.OpenKey
    operation.assert_called_once_with(0x80000001, "Software\\Owned\\", 0, 0x2001F)


@pytest.mark.parametrize("code", [2, 3, 5, 1346, 161])
def test_open_errors_follow_reference_missing_and_access_rules(
    helper: ModuleType, native: Mock, code: int
) -> None:
    error = OSError(code, "native failure")
    error.winerror = code  # type: ignore[attr-defined]
    native.registry.OpenKey.side_effect = error
    if code in (5, 1346):
        with pytest.raises(OSError):
            helper.open_key("HKCU", "Owned")
    else:
        assert helper.open_key("HKCU", "Owned") is None


def test_key_component_limit_is_utf16_before_nul_truncation(
    helper: ModuleType, native: Mock
) -> None:
    with pytest.raises(ValueError, match="255"):
        helper.open_key("HKCU", "Owned\0" + "x" * 256)
    native.registry.OpenKey.assert_not_called()


def test_delete_tree_closes_keys_before_removing_them(
    helper: ModuleType, native: Mock
) -> None:
    events = []
    parent, child = MagicMock(), MagicMock()
    for label, key in (("parent", parent), ("child", child)):
        key.__enter__.return_value = key
        key.__exit__.side_effect = lambda *_args, label=label: events.append(
            "close " + label
        )
    native.registry.OpenKey.side_effect = [parent, child]
    native.registry.QueryInfoKey.side_effect = lambda key: (
        1 if key is parent else 0,
        0,
        0,
    )
    native.registry.EnumKey.return_value = "Child"
    native.registry.DeleteKey.side_effect = lambda _hive, path: events.append(
        "delete " + path
    )
    helper.delete_tree("HKCU", "Owned")
    assert events == [
        "close child",
        "delete Owned\\Child",
        "close parent",
        "delete Owned",
    ]


def test_delete_tree_rejects_root(helper: ModuleType, native: Mock) -> None:
    with pytest.raises(ValueError, match="root"):
        helper.delete_tree("HKCU", "")
    native.registry.OpenKey.assert_not_called()
    native.registry.DeleteKey.assert_not_called()


def test_mount_probe_opens_read_only_and_closes_handle(
    helper: ModuleType, native: Mock
) -> None:
    assert helper.hive_mount_exists() is True
    native.registry.OpenKey.assert_called_once_with(0x80000002, "ANSIBLE", 0, 0x20019)
    native.registry.OpenKey.return_value.__exit__.assert_called_once_with(
        None, None, None
    )


@pytest.mark.parametrize("code", [2, 3, 5, 1346, 161])
def test_mount_probe_treats_access_denial_as_occupied(
    helper: ModuleType, native: Mock, code: int
) -> None:
    error = OSError(code, "native failure")
    error.winerror = code  # type: ignore[attr-defined]
    native.registry.OpenKey.side_effect = error
    assert helper.hive_mount_exists() is (code in (5, 1346))


def test_load_and_unload_use_fixed_mount(helper: ModuleType, native: Mock) -> None:
    helper.load_hive(r"C:\owned.hive")
    helper.unload_hive()
    native.registry.LoadKey.assert_called_once_with(
        0x80000002, "ANSIBLE", r"C:\owned.hive"
    )
    native.advapi.RegUnLoadKeyW.assert_called_once_with(0x80000002, "ANSIBLE")


@pytest.mark.parametrize("failure", [None, "open", "lookup", "adjust", "missing"])
def test_privilege_enabling_checks_not_all_assigned_and_closes_token(
    helper: ModuleType, native: Mock, failure: str | None
) -> None:
    snapshots = []

    def _open(_process: Any, access: int, token: Any) -> int:
        assert access == 0x28
        if failure == "open":
            native.error = 5
            return 0
        token._obj.value = 456
        return 1

    def _lookup(_system: Any, name: str, _luid: Any) -> int:
        snapshots.append(name)
        if failure == "lookup":
            native.error = 5
            return 0
        return 1

    def _adjust(*arguments: Any) -> int:
        token, disable, privilege, size, previous, length = arguments
        assert token.value == 456 and not disable and size == 0
        assert previous is None and length is None
        assert privilege._obj.count == 1 and privilege._obj.attributes == 2
        if failure in ("adjust", "missing"):
            native.error = 1300 if failure == "missing" else 5
        return 0 if failure == "adjust" else 1

    native.advapi.OpenProcessToken.side_effect = _open
    native.advapi.LookupPrivilegeValueW.side_effect = _lookup
    native.advapi.AdjustTokenPrivileges.side_effect = _adjust
    if failure == "missing":
        with pytest.raises(
            ValueError, match="SeBackupPrivilege.*removed from the token"
        ):
            helper.enable_hive_privileges()
    elif failure:
        with pytest.raises(OSError) as caught:
            helper.enable_hive_privileges()
        assert caught.value.errno == 5
    else:
        helper.enable_hive_privileges()
        assert snapshots == ["SeBackupPrivilege", "SeRestorePrivilege"]
    assert native.kernel.CloseHandle.call_count == (0 if failure == "open" else 1)
    if failure != "open":
        assert native.kernel.CloseHandle.call_args.args[0].value == 456
