"""Check native log ABI, handle cleanup, and setter ordering."""

# SPDX-License-Identifier: GPL-3.0-or-later
# Tests exercise private native boundary functions without requiring Windows.
# pylint: disable=protected-access

import ctypes
from types import ModuleType, SimpleNamespace
from typing import Any
from unittest.mock import MagicMock, Mock

import pytest

from tests.unit.payload_support import ROOT, load_module


@pytest.fixture(name="helper")
def native_helper(monkeypatch: pytest.MonkeyPatch) -> ModuleType:
    """Load the target helper for portable native-boundary tests.

    :param monkeypatch: Scoped helper import path.
    :returns: Loaded target helper.
    """
    monkeypatch.syspath_prepend(str(ROOT / "legacy_windows/plugins/module_utils"))
    return load_module(
        ROOT / "legacy_windows/plugins/module_utils/legacy_windows_eventlog.py",
        "tested_eventlog_native",
    )


def test_api_bindings_keep_pointer_width_and_native_integer_width(
    helper: ModuleType, monkeypatch: pytest.MonkeyPatch
) -> None:
    library = Mock()
    monkeypatch.setattr(
        helper.ctypes, "WinDLL", Mock(return_value=library), raising=False
    )
    assert helper._api() is library
    assert library.OpenEventLogW.restype is ctypes.c_void_p
    assert library.ClearEventLogW.argtypes == [ctypes.c_void_p, ctypes.c_wchar_p]
    assert library.GetNumberOfEventLogRecords.argtypes[1] == ctypes.POINTER(
        ctypes.c_uint32
    )
    assert library.CloseEventLog.argtypes == [ctypes.c_void_p]


def test_log_handle_closes_on_count_or_clear_failure(
    helper: ModuleType, monkeypatch: pytest.MonkeyPatch
) -> None:
    library = Mock()
    library.OpenEventLogW.return_value = 42
    monkeypatch.setattr(helper, "_api", lambda: library)
    monkeypatch.setattr(helper, "_log_name", lambda _name: "Owned")
    with pytest.raises(ValueError, match="observed failure"):
        helper._with_log("Owned", Mock(side_effect=ValueError("observed failure")))
    library.CloseEventLog.assert_called_once_with(42)


def test_clear_never_creates_a_backup_file(
    helper: ModuleType, monkeypatch: pytest.MonkeyPatch
) -> None:
    library = Mock()
    library.OpenEventLogW.return_value = 42
    library.ClearEventLogW.return_value = 1
    monkeypatch.setattr(helper, "_api", lambda: library)
    monkeypatch.setattr(helper, "_log_name", lambda _name: "Owned")
    helper.clear_log("Owned")
    library.ClearEventLogW.assert_called_once_with(42, None)
    library.CloseEventLog.assert_called_once_with(42)


def test_limit_changes_overflow_before_size_and_size_only_preserves_retention(
    helper: ModuleType, monkeypatch: pytest.MonkeyPatch
) -> None:
    key = MagicMock()
    key.__enter__.return_value = key
    registry = Mock(KEY_READ=1, KEY_WRITE=2, REG_DWORD=4)
    monkeypatch.setattr(helper, "winreg", registry)
    monkeypatch.setattr(helper, "_log_key", lambda *_args: key)
    monkeypatch.setattr(helper, "_value", lambda *_args: 604800)
    helper.limit_log("Owned", 131072, "DoNotOverwrite", None)
    assert [
        (call.args[1], call.args[-1]) for call in registry.SetValueEx.call_args_list
    ] == [("Retention", 4294967295), ("MaxSize", 131072)]
    registry.SetValueEx.reset_mock()
    helper.limit_log("Owned", 131072, None, None)
    assert [call.args[1] for call in registry.SetValueEx.call_args_list] == ["MaxSize"]


def test_check_mode_binding_validates_range_but_skips_overflow_compatibility(
    helper: ModuleType, monkeypatch: pytest.MonkeyPatch
) -> None:
    key = MagicMock()
    key.__enter__.return_value = key
    monkeypatch.setattr(helper, "_log_key", lambda *_args: key)
    monkeypatch.setattr(helper, "_value", lambda *_args: 0)
    with pytest.raises(ValueError, match="between 1 and 365"):
        helper.validate_limit("Owned", None, 366, True)
    helper.validate_limit("Owned", None, 7, True)
    with pytest.raises(ValueError) as failure:
        helper.validate_limit("Owned", None, 7, False)
    assert str(failure.value) == (
        'Retention days is valid only if the overflow action is "OverwriteOlder". '
        "Please change  and try again."
    )


def test_limit_check_mode_does_not_require_an_existing_log(
    helper: ModuleType, monkeypatch: pytest.MonkeyPatch
) -> None:
    missing_log = Mock(side_effect=FileNotFoundError(2, "Log is absent"))
    monkeypatch.setattr(helper, "_log_key", missing_log)
    helper.validate_limit("Owned", "OverwriteAsNeeded", None, True)
    missing_log.assert_not_called()


def test_limit_missing_log_failure_is_preserved_outside_check_mode(
    helper: ModuleType, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(
        helper, "_log_key", Mock(side_effect=FileNotFoundError(2, "Log is absent"))
    )
    with pytest.raises(ValueError) as failure:
        helper.validate_limit("Owned", "OverwriteAsNeeded", None, False)
    assert str(failure.value) == (
        'The Log name "Owned" does not exist in the computer "localhost".'
    )


def test_source_resource_values_use_expandable_strings_and_zero_categories(
    helper: ModuleType, monkeypatch: pytest.MonkeyPatch
) -> None:
    key = MagicMock()
    child = MagicMock()
    child.__enter__.return_value = child
    registry = Mock(KEY_READ=1, KEY_WRITE=2, REG_EXPAND_SZ=2, REG_DWORD=4)
    registry.CreateKeyEx.return_value = child
    monkeypatch.setattr(helper, "winreg", registry)
    monkeypatch.setattr(
        helper, "_default_message_file", lambda: "C:\\DefaultMessages.dll"
    )
    helper._write_source(key, "Source", {"category_file": "C:\\Category.dll"})
    values = [
        (call.args[1], call.args[3], call.args[4])
        for call in registry.SetValueEx.call_args_list
    ]
    assert values == [
        ("CategoryMessageFile", 2, "C:\\Category.dll"),
        ("CategoryCount", 4, 0),
        ("EventMessageFile", 2, "C:\\DefaultMessages.dll"),
    ]
    registry.FlushKey.assert_called_once_with(child)


def test_remove_log_suppresses_only_file_failure_and_still_removes_registration(
    helper: ModuleType, monkeypatch: pytest.MonkeyPatch
) -> None:
    key = MagicMock()
    key.__enter__.return_value = key
    registry = Mock(HKEY_LOCAL_MACHINE=1, KEY_READ=1, KEY_WRITE=2)
    registry.OpenKey.return_value = key
    monkeypatch.setattr(helper, "winreg", registry)
    monkeypatch.setattr(helper, "_log_key", lambda *_args: key)
    monkeypatch.setattr(helper, "_log_name", lambda _name: "Owned")
    monkeypatch.setattr(helper, "_value", lambda *_args: "C:\\Owned.evt")
    clear, remove = Mock(), Mock()
    monkeypatch.setattr(helper, "clear_log", clear)
    monkeypatch.setattr(helper, "_delete_tree", remove)
    monkeypatch.setattr(
        helper.os, "remove", Mock(side_effect=OSError(32, "sharing violation"))
    )
    helper.remove_log("Owned")
    clear.assert_called_once_with("Owned")
    remove.assert_called_once_with(key, "Owned")


def test_classic_source_list_patch_is_not_used_on_modern_windows(
    helper: ModuleType, monkeypatch: pytest.MonkeyPatch
) -> None:
    key = MagicMock()
    key.__enter__.return_value = key
    registry = Mock(KEY_READ=1, KEY_WRITE=2)
    monkeypatch.setattr(helper, "winreg", registry)
    monkeypatch.setattr(helper, "_log_key", lambda *_args: key)
    monkeypatch.setattr(helper, "_delete_tree", Mock())
    monkeypatch.setattr(
        helper.sys,
        "getwindowsversion",
        lambda: SimpleNamespace(major=10),
        raising=False,
    )
    helper.remove_source("Owned", "Source")
    registry.SetValueEx.assert_not_called()


def test_entry_count_copies_output_before_closing_handle(helper: ModuleType) -> None:
    library = Mock()

    def _count(_handle: Any, value: Any) -> int:
        value._obj.value = 17
        return 1

    library.GetNumberOfEventLogRecords.side_effect = _count
    assert helper._count(library, 42) == 17


@pytest.mark.parametrize("legacy", [False, True])
def test_default_resource_uses_existing_native_case_or_absent_legacy_metadata(
    helper: ModuleType, monkeypatch: pytest.MonkeyPatch, legacy: bool
) -> None:
    library = Mock()
    monkeypatch.setenv("SystemRoot", "C:\\WINDOWS")
    monkeypatch.setattr(helper, "_legacy_windows", lambda: legacy)
    monkeypatch.setattr(helper.ctypes, "sizeof", lambda _kind: 4 if legacy else 8)
    monkeypatch.setattr(
        helper.ctypes, "WinDLL", Mock(return_value=library), raising=False
    )
    version = "v2.0.50727" if legacy else "v4.0.30319"
    directory = "Framework" if legacy else "Framework64"
    path = "C:\\WINDOWS\\Microsoft.NET\\" + directory + "\\" + version
    path += "\\EventLogMessages.dll"
    actual = path if legacy else path.replace("WINDOWS", "Windows")

    def _long_path(filename: str, buffer: Any, capacity: int) -> int:
        assert filename == path
        if legacy:
            return 0
        if library.GetLongPathNameW.call_count == 1:
            return capacity + 1
        buffer.value = actual
        return len(actual)

    library.GetLongPathNameW.side_effect = _long_path
    assert helper._default_message_file() == actual
    assert library.GetLongPathNameW.argtypes == [
        ctypes.c_wchar_p,
        ctypes.c_wchar_p,
        ctypes.c_uint32,
    ]
    assert library.GetLongPathNameW.restype is ctypes.c_uint32
    assert library.GetLongPathNameW.call_count == (1 if legacy else 2)


@pytest.mark.parametrize(
    "name", [r"Application\Application", r"Application\Missing", "Missing"]
)
def test_nested_or_missing_log_never_opens_native_fallback_or_deletes(
    helper: ModuleType, monkeypatch: pytest.MonkeyPatch, name: str
) -> None:
    root = MagicMock()
    root.__enter__.return_value = root
    registry = Mock(HKEY_LOCAL_MACHINE=1, KEY_READ=1, KEY_WRITE=2)
    registry.OpenKey.return_value = root
    monkeypatch.setattr(helper, "winreg", registry)
    monkeypatch.setattr(helper, "_names", lambda _key: ["Application", "Owned Log"])
    monkeypatch.setattr(
        helper.environment,
        "values_equal",
        lambda left, right: left.lower() == right.lower(),
    )
    native, delete, remove = Mock(), Mock(), Mock()
    monkeypatch.setattr(helper, "_api", native)
    monkeypatch.setattr(helper, "_delete_tree", delete)
    monkeypatch.setattr(helper.os, "remove", remove)
    assert helper.log_details(name) == {"name": name, "exists": False}
    for operation in (helper.clear_log, helper.remove_log):
        with pytest.raises(OSError) as failure:
            operation(name)
        assert failure.value.errno == 2
    native.assert_not_called()
    delete.assert_not_called()
    remove.assert_not_called()
    assert all(
        call.args == (1, helper.ROOT) for call in registry.OpenKey.call_args_list
    )


def test_actual_immediate_log_resolves_case_without_registry_path_traversal(
    helper: ModuleType, monkeypatch: pytest.MonkeyPatch
) -> None:
    root = MagicMock()
    root.__enter__.return_value = root
    child = Mock()
    registry = Mock(HKEY_LOCAL_MACHINE=1, KEY_READ=1, KEY_WRITE=2)
    registry.OpenKey.side_effect = [root, child]
    monkeypatch.setattr(helper, "winreg", registry)
    monkeypatch.setattr(helper, "_names", lambda _key: ["Application", "Owned Log"])
    monkeypatch.setattr(
        helper.environment,
        "values_equal",
        lambda left, right: left.lower() == right.lower(),
    )
    assert helper._log_key("owned log", 3) is child
    assert [call.args for call in registry.OpenKey.call_args_list] == [
        (1, helper.ROOT),
        (1, helper.ROOT + "\\Owned Log", 0, 3),
    ]


@pytest.mark.parametrize("prefix", ["AppEvent", "sEcEvEnT", "SYSEVENT"])
def test_reserved_file_prefix_rejected_before_any_registration_write(
    helper: ModuleType, monkeypatch: pytest.MonkeyPatch, prefix: str
) -> None:
    registry = Mock(KEY_READ=1, KEY_WRITE=2)
    monkeypatch.setattr(helper, "winreg", registry)
    monkeypatch.setattr(helper, "_log_key", Mock(side_effect=OSError(2, "missing")))
    defaults, source_lookup = Mock(), Mock()
    monkeypatch.setattr(helper, "_log_defaults", defaults)
    monkeypatch.setattr(helper, "source_log", source_lookup)
    name = prefix + "Owned"
    with pytest.raises(ValueError) as failure:
        helper.create_source(name, "OwnedSource", {})
    assert str(failure.value) == (
        "The log name: '" + name + "' is invalid for customer log creation."
    )
    registry.CreateKeyEx.assert_not_called()
    defaults.assert_not_called()
    source_lookup.assert_not_called()


@pytest.mark.parametrize("character", ["\x00", "\x1f", "\x7f", "\x9f", "\\", "*", "?"])
def test_invalid_log_characters_fail_before_opening_or_creating_a_log(
    helper: ModuleType, monkeypatch: pytest.MonkeyPatch, character: str
) -> None:
    opening = Mock()
    monkeypatch.setattr(helper, "_open_or_create_log", opening)
    with pytest.raises(ValueError, match="printable characters"):
        helper.create_source("Owned" + character + "Log", "OwnedSource", {})
    opening.assert_not_called()


@pytest.mark.parametrize("name", ["Owned Log", "Owned\u200bLog", "Owned\u2028Log"])
def test_spaces_and_non_control_unicode_reach_source_registration(
    helper: ModuleType, monkeypatch: pytest.MonkeyPatch, name: str
) -> None:
    key = MagicMock()
    key.__enter__.return_value = key
    opening, defaults, writing = Mock(return_value=(key, False)), Mock(), Mock()
    monkeypatch.setattr(helper, "_open_or_create_log", opening)
    monkeypatch.setattr(helper, "_log_defaults", defaults)
    monkeypatch.setattr(helper, "_write_source", writing)
    monkeypatch.setattr(helper, "winreg", Mock())
    helper.create_source(name, "Owned Source", {})
    opening.assert_called_once_with(name)
    defaults.assert_called_once_with(key, name, "Owned Source")
    writing.assert_called_once_with(key, "Owned Source", {})
