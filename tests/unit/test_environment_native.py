"""Exercise environment native boundaries without accessing Windows hosts."""

# SPDX-License-Identifier: GPL-3.0-or-later
# Tests substitute native calls so that resource ownership and errors are visible.
# pylint: disable=protected-access

import ctypes
from types import ModuleType, SimpleNamespace
from typing import Any
from unittest.mock import MagicMock, Mock

import pytest

from tests.unit.payload_support import ROOT, load_module


@pytest.fixture(name="helper")
def environment_helper() -> ModuleType:
    """Import the helper without loading Windows libraries.

    :returns: Imported target helper.
    """
    path = ROOT / "legacy_windows/plugins/module_utils/legacy_windows_environment.py"
    return load_module(path, "tested_environment_native")


@pytest.fixture(name="native")
def native_environment(helper: ModuleType, monkeypatch: pytest.MonkeyPatch) -> Mock:
    """Replace process, registry, and notification APIs with controllable mocks.

    :param helper: Imported target helper.
    :param monkeypatch: Scoped native replacements.
    :returns: Parent mock exposing native libraries, registry, and last error.
    """
    native = Mock()
    native.kernel.SetEnvironmentVariableW.return_value = 1
    native.user.SendMessageTimeoutW.return_value = 1
    native.error = 0
    registry = MagicMock()
    registry.HKEY_CURRENT_USER = 0x80000001
    registry.HKEY_LOCAL_MACHINE = 0x80000002
    registry.KEY_READ = 0x20019
    registry.KEY_WRITE = 0x20006
    registry.REG_SZ = 1
    registry.REG_EXPAND_SZ = 2
    native.registry = registry
    monkeypatch.setattr(helper, "winreg", registry)
    monkeypatch.setattr(helper, "os", SimpleNamespace(name="nt"))
    monkeypatch.setattr(
        helper.ctypes,
        "WinDLL",
        lambda name, **_kwargs: {"kernel32": native.kernel, "user32": native.user}[
            name
        ],
        raising=False,
    )
    monkeypatch.setattr(
        helper.ctypes, "get_last_error", lambda: native.error, raising=False
    )
    monkeypatch.setattr(
        helper.ctypes,
        "set_last_error",
        lambda value: setattr(native, "error", value),
        raising=False,
    )
    monkeypatch.setattr(helper.ctypes, "WinError", _windows_error, raising=False)
    return native


def _windows_error(code: int) -> OSError:
    error = OSError(code, "native failure")
    error.winerror = code  # type: ignore[attr-defined]
    return error


@pytest.mark.parametrize("invariant,locale", [(True, 0x7F), (False, 0x400)])
def test_comparison_selects_invariant_or_user_culture(
    helper: ModuleType, native: Mock, invariant: bool, locale: int
) -> None:
    native.kernel.CompareStringW.return_value = 2
    assert helper.values_equal("A", "a", invariant=invariant)
    native.kernel.CompareStringW.assert_called_once_with(locale, 1, "A", 1, "a", 1)


def test_process_get_reads_unicode_and_case_without_environment_snapshot(
    helper: ModuleType, native: Mock
) -> None:
    def _get(name: str, buffer: Any, capacity: int) -> int:
        assert name == "mixed_雪"
        assert capacity == 128
        buffer.value = "native 雪"
        return 8

    native.kernel.GetEnvironmentVariableW.side_effect = _get
    assert helper.get_value("mixed_雪", "process") == "native 雪"
    native.registry.OpenKey.assert_not_called()


@pytest.mark.parametrize(("error", "expected"), [(203, None), (0, "")])
def test_process_get_distinguishes_missing_from_empty_and_clears_stale_error(
    helper: ModuleType, native: Mock, error: int, expected: str | None
) -> None:
    native.error = 5

    def _get(_name: str, _buffer: Any, _capacity: int) -> int:
        assert native.error == 0
        native.error = error
        return 0

    native.kernel.GetEnvironmentVariableW.side_effect = _get
    assert helper.get_value("fixture", "process") == expected


def test_process_get_retries_when_value_grows_between_reads(
    helper: ModuleType, native: Mock
) -> None:
    capacities = []

    def _get(_name: str, buffer: Any, capacity: int) -> int:
        capacities.append(capacity)
        if len(capacities) == 1:
            return 256
        if len(capacities) == 2:
            return 512
        buffer.value = "x" * 511
        return 511

    native.kernel.GetEnvironmentVariableW.side_effect = _get
    assert helper.get_value("fixture", "process") == "x" * 511
    assert capacities == [128, 257, 513]


def test_process_get_matches_reference_empty_result_for_other_native_errors(
    helper: ModuleType, native: Mock
) -> None:
    def _get(_name: str, _buffer: Any, _capacity: int) -> int:
        native.error = 5
        return 0

    native.kernel.GetEnvironmentVariableW.side_effect = _get
    assert helper.get_value("fixture", "process") == ""


@pytest.mark.parametrize(
    "location",
    [
        ("user", 0x80000001, "Environment"),
        (
            "machine",
            0x80000002,
            r"SYSTEM\CurrentControlSet\Control\Session Manager\Environment",
        ),
    ],
)
@pytest.mark.parametrize("value", ["", "%DO_NOT_EXPAND%", "literal 雪"])
def test_registry_get_reads_string_and_closes_key(
    helper: ModuleType, native: Mock, location: tuple[str, int, str], value: str
) -> None:
    level, hive, path = location
    native.registry.QueryValueEx.return_value = (value, 1)
    assert helper.get_value("Fixture", level) == value
    native.registry.OpenKey.assert_called_once_with(hive, path, 0, 0x20019)
    key = native.registry.OpenKey.return_value.__enter__.return_value
    native.registry.QueryValueEx.assert_called_once_with(key, "Fixture")
    native.registry.OpenKey.return_value.__exit__.assert_called_once()
    native.kernel.ExpandEnvironmentStringsW.assert_not_called()


@pytest.mark.parametrize("kind", [0, 3, 4, 7, 11, 999])
def test_registry_non_string_is_not_an_environment_value(
    helper: ModuleType, native: Mock, kind: int
) -> None:
    native.registry.QueryValueEx.return_value = (123, kind)
    assert helper.get_value("fixture", "user") is None


@pytest.mark.parametrize("operation", ["OpenKey", "QueryValueEx"])
@pytest.mark.parametrize("code", [2, 3, 5])
def test_registry_read_missing_is_absent_but_access_denied_fails(
    helper: ModuleType, native: Mock, operation: str, code: int
) -> None:
    getattr(native.registry, operation).side_effect = _windows_error(code)
    if code == 5:
        with pytest.raises(OSError) as failure:
            helper.get_value("fixture", "user")
        assert failure.value.errno == 5
    else:
        assert helper.get_value("fixture", "user") is None
    if operation == "QueryValueEx":
        native.registry.OpenKey.return_value.__exit__.assert_called_once()


def test_registry_expansion_reads_native_process_and_retries_buffer(
    helper: ModuleType, native: Mock
) -> None:
    native.registry.QueryValueEx.return_value = ("%NATIVE_FIXTURE%", 2)
    capacities = []

    def _expand(value: str, buffer: Any, capacity: int) -> int:
        assert value == "%NATIVE_FIXTURE%"
        capacities.append(capacity)
        if capacity < 501:
            return 501
        buffer.value = "x" * 500
        return 501

    native.kernel.ExpandEnvironmentStringsW.side_effect = _expand
    assert helper.get_value("fixture", "user") == "x" * 500
    assert capacities == [256, 501]


def test_registry_expansion_failure_keeps_native_error(
    helper: ModuleType, native: Mock
) -> None:
    native.registry.QueryValueEx.return_value = ("%NATIVE_FIXTURE%", 2)
    native.kernel.ExpandEnvironmentStringsW.return_value = 0
    native.error = 8
    with pytest.raises(OSError) as failure:
        helper.get_value("fixture", "user")
    assert failure.value.errno == 8


@pytest.mark.parametrize(
    ("value", "native_value"),
    [(None, None), ("", None), ("\0x", None), ("snow 雪", "snow 雪")],
)
def test_process_set_normalizes_framework_deletion_values_without_broadcast(
    helper: ModuleType, native: Mock, value: str | None, native_value: str | None
) -> None:
    helper.set_value("fixture", value, "process")
    native.kernel.SetEnvironmentVariableW.assert_called_once_with(
        "fixture", native_value
    )
    native.user.SendMessageTimeoutW.assert_not_called()
    native.registry.OpenKey.assert_not_called()


@pytest.mark.parametrize("code", [5, 203])
def test_process_set_allows_already_absent_removal_only(
    helper: ModuleType, native: Mock, code: int
) -> None:
    native.kernel.SetEnvironmentVariableW.return_value = 0
    native.error = code
    if code == 203:
        helper.set_value("fixture", None, "process")
    else:
        with pytest.raises(OSError) as failure:
            helper.set_value("fixture", None, "process")
        assert failure.value.errno == 5


@pytest.mark.parametrize("level", ["user", "machine"])
@pytest.mark.parametrize("value", [None, "%LITERAL%"])
def test_persisted_set_uses_reg_sz_and_separate_unchecked_notification(
    helper: ModuleType, native: Mock, level: str, value: str | None
) -> None:
    helper.set_value("fixture", value, level)
    assert native.registry.OpenKey.call_args.args[3] == 0x2001F
    key = native.registry.OpenKey.return_value
    if value is None:
        native.registry.DeleteValue.assert_called_once_with(key, "fixture")
        native.registry.SetValueEx.assert_not_called()
    else:
        native.registry.SetValueEx.assert_called_once_with(key, "fixture", 0, 1, value)
        native.registry.DeleteValue.assert_not_called()
    native.registry.OpenKey.return_value.__exit__.assert_called_once()
    native.kernel.SetEnvironmentVariableW.assert_not_called()
    assert native.user.SendMessageTimeoutW.call_args.args[:6] == (
        0xFFFF,
        0x1A,
        0,
        "Environment",
        0,
        1000,
    )


@pytest.mark.parametrize("operation", ["OpenKey", "DeleteValue"])
@pytest.mark.parametrize("code", [2, 3, 5])
def test_persisted_missing_delete_still_notifies_and_access_failure_does_not(
    helper: ModuleType, native: Mock, operation: str, code: int
) -> None:
    getattr(native.registry, operation).side_effect = _windows_error(code)
    if code == 5 or (code == 3 and operation == "DeleteValue"):
        with pytest.raises(OSError):
            helper.set_value("fixture", None, "user")
        native.user.SendMessageTimeoutW.assert_not_called()
    else:
        helper.set_value("fixture", None, "user")
        native.user.SendMessageTimeoutW.assert_called_once()
    native.registry.CreateKey.assert_not_called()


@pytest.mark.parametrize("code", [2, 3, 5, 1018])
def test_persisted_write_failure_is_never_hidden_as_missing_key(
    helper: ModuleType, native: Mock, code: int
) -> None:
    native.registry.SetValueEx.side_effect = _windows_error(code)
    with pytest.raises(OSError) as failure:
        helper.set_value("fixture", "value", "user")
    assert failure.value.errno == code
    native.registry.OpenKey.return_value.__exit__.assert_called_once()
    native.user.SendMessageTimeoutW.assert_not_called()


def test_persisted_set_ignores_first_broadcast_failure(
    helper: ModuleType, native: Mock
) -> None:
    native.user.SendMessageTimeoutW.return_value = 0
    helper.set_value("fixture", "value", "user")


@pytest.mark.parametrize("name", [None, "", "\0fixture", "fixture=invalid"])
def test_set_rejects_invalid_name_before_native_mutation(
    helper: ModuleType, native: Mock, name: str | None
) -> None:
    with pytest.raises(ValueError):
        helper.set_value(name, "value", "process")
    native.kernel.SetEnvironmentVariableW.assert_not_called()
    native.registry.OpenKey.assert_not_called()


@pytest.mark.parametrize(
    ("level", "limit"), [("user", 255), ("machine", 1024), ("process", 32767)]
)
def test_set_name_limits_count_utf16_characters(
    helper: ModuleType, native: Mock, level: str, limit: int
) -> None:
    name = "a" * (limit - 2) + "😀"
    with pytest.raises(ValueError, match="UTF-16"):
        helper.set_value(name, "value", level)
    helper.set_value("a" * (limit - 1), "value", level)
    if level == "process":
        native.kernel.SetEnvironmentVariableW.assert_called_once()
    else:
        native.registry.SetValueEx.assert_called_once()


def test_set_value_length_limit_is_process_only(
    helper: ModuleType, native: Mock
) -> None:
    with pytest.raises(ValueError, match="Process environment value"):
        helper.set_value("fixture", "a" * 32765 + "😀", "process")
    helper.set_value("fixture", "a" * 32766, "process")
    helper.set_value("fixture", "a" * 32767, "user")
    assert native.kernel.SetEnvironmentVariableW.call_count == 1
    assert native.registry.SetValueEx.call_count == 1


def test_get_does_not_apply_set_name_validation(
    helper: ModuleType, native: Mock
) -> None:
    native.registry.QueryValueEx.return_value = ("value", 1)
    assert helper.get_value("fixture=read", "user") == "value"
    assert helper.get_value("", "user") == "value"


def test_broadcast_uses_pointer_sized_result_and_abort_if_hung(
    helper: ModuleType, native: Mock
) -> None:
    def _send(*args: Any) -> int:
        assert args[:6] == (0xFFFF, 0x1A, 0, "Environment", 2, 5000)
        result = ctypes.cast(args[6], ctypes.POINTER(ctypes.c_size_t))
        result.contents.value = 0xABCD
        return 1

    native.user.SendMessageTimeoutW.side_effect = _send
    helper.broadcast_change()
    assert native.user.SendMessageTimeoutW.restype is ctypes.c_ssize_t


@pytest.mark.parametrize("code", [0, 5, 1460])
def test_broadcast_failures_are_actionable_even_without_error_code(
    helper: ModuleType, native: Mock, code: int
) -> None:
    native.error = 123

    def _send(*_args: Any) -> int:
        assert native.error == 0
        native.error = code
        return 0

    native.user.SendMessageTimeoutW.side_effect = _send
    with pytest.raises(OSError) as failure:
        helper.broadcast_change()
    if code:
        assert failure.value.errno == code
    else:
        assert "Windows did not report an error code" in str(failure.value)


@pytest.mark.parametrize(
    ("left", "right", "expected"),
    [(None, None, True), (None, "", False), ("", None, False)],
)
def test_comparison_distinguishes_none_and_empty_without_native_call(
    helper: ModuleType,
    native: Mock,
    left: str | None,
    right: str | None,
    expected: bool,
) -> None:
    assert helper.values_equal(left, right) is expected
    native.kernel.CompareStringW.assert_not_called()


@pytest.mark.parametrize(("result", "expected"), [(1, False), (2, True), (3, False)])
def test_comparison_uses_invariant_case_insensitive_utf16_lengths(
    helper: ModuleType, native: Mock, result: int, expected: bool
) -> None:
    native.kernel.CompareStringW.return_value = result
    assert helper.values_equal("A\0😀", "a\0😀") is expected
    native.kernel.CompareStringW.assert_called_once_with(
        0x7F, 1, "A\0😀", 4, "a\0😀", 4
    )


def test_comparison_reports_native_failure(helper: ModuleType, native: Mock) -> None:
    native.error = 87
    native.kernel.CompareStringW.return_value = 0
    with pytest.raises(OSError) as failure:
        helper.values_equal("one", "two")
    assert failure.value.errno == 87


def test_name_key_uses_simple_uppercase_not_linguistic_collation(
    helper: ModuleType, native: Mock
) -> None:
    def _uppercase(*args: Any) -> int:
        locale, flags, character, length, buffer, capacity = args
        assert (locale, flags, length, capacity) == (0x7F, 0x200, 1, 1)
        buffer[0] = {"a": "A", "s": "S"}.get(character, character)
        return 1

    native.kernel.LCMapStringW.side_effect = _uppercase
    assert helper.name_key("aAa") == "AAA"
    assert helper.name_key("ß") != helper.name_key("ss")
    native.kernel.CompareStringW.assert_not_called()


def test_name_key_preserves_nul_surrogate_halves_and_supplementary_characters(
    helper: ModuleType, native: Mock
) -> None:
    assert helper.name_key("\0\ud800\udfff\U00010400") == "\0\ud800\udfff\ud801\udc00"
    assert helper.name_key("") == ""
    native.kernel.LCMapStringW.assert_not_called()


def test_name_key_accepts_long_unvalidated_names_without_native_length_limit(
    helper: ModuleType, native: Mock
) -> None:
    def _uppercase(*args: Any) -> int:
        assert args[2:4] == ("a", 1)
        args[4][0] = "A"
        assert args[5] == 1
        return 1

    native.kernel.LCMapStringW.side_effect = _uppercase
    assert helper.name_key("a" * 65536) == "A" * 65536
    native.kernel.LCMapStringW.assert_called_once()


@pytest.mark.parametrize("code", [87, 122])
def test_name_key_reports_failed_mapping_instead_of_expanding_or_falling_back(
    helper: ModuleType, native: Mock, code: int
) -> None:
    native.error = code
    native.kernel.LCMapStringW.return_value = 0
    with pytest.raises(OSError) as failure:
        helper.name_key("a")
    assert failure.value.errno == code


def test_name_key_requires_windows(
    helper: ModuleType, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(helper, "os", SimpleNamespace(name="posix"))
    with pytest.raises(ValueError, match="Windows target"):
        helper.name_key("fixture")


@pytest.mark.parametrize("operation", ["get", "set", "broadcast", "compare"])
def test_non_windows_operations_fail_before_library_load(
    helper: ModuleType, monkeypatch: pytest.MonkeyPatch, operation: str
) -> None:
    monkeypatch.setattr(helper, "os", SimpleNamespace(name="posix"))
    with pytest.raises(ValueError, match="Windows target"):
        if operation == "get":
            helper.get_value("fixture", "user")
        elif operation == "set":
            helper.set_value("fixture", "value", "process")
        elif operation == "broadcast":
            helper.broadcast_change()
        else:
            helper.values_equal("one", "two")


@pytest.mark.parametrize("operation", ["get", "set"])
def test_invalid_level_is_rejected(
    helper: ModuleType, native: Mock, operation: str
) -> None:
    with pytest.raises(ValueError, match="level"):
        if operation == "get":
            helper.get_value("fixture", "other")
        else:
            helper.set_value("fixture", "value", "other")
    native.registry.OpenKey.assert_not_called()


def test_null_get_name_is_rejected(helper: ModuleType) -> None:
    with pytest.raises(ValueError, match="null"):
        helper.get_value(None, "process")
