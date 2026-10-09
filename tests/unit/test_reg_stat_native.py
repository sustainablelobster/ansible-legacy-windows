"""Exercise registry reads and native failures without contacting Windows."""

# SPDX-License-Identifier: GPL-3.0-or-later
# Native substitutes make resource ownership and byte-level input observable.
# pylint: disable=protected-access

import ctypes
from types import ModuleType, SimpleNamespace
from typing import Any
from unittest.mock import MagicMock, Mock

import pytest

from tests.unit.payload_support import ROOT, load_module


@pytest.fixture(name="helper")
def registry_helper() -> ModuleType:
    """Load the registry helper without importing Windows libraries.

    :returns: The isolated helper module.
    """
    source = ROOT / "plugins/module_utils/legacy_windows_reg_stat.py"
    return load_module(source, "tested_reg_stat_native")


def _windows_error(code: int) -> OSError:
    error = OSError(code, "native failure")
    error.winerror = code  # type: ignore[attr-defined]
    return error


@pytest.fixture(name="native")
def native_registry(helper: ModuleType, monkeypatch: pytest.MonkeyPatch) -> Mock:
    """Provide deterministic registry contents and native API substitutes.

    :param helper: Imported target helper.
    :param monkeypatch: Scoped substitutions for Windows APIs.
    :returns: Mock exposing registry contents and callable native boundaries.
    """
    native = Mock()
    native.values = {}
    native.subkeys = []
    native.error = 5
    registry = MagicMock()
    for offset, hive in [
        (0, "CLASSES_ROOT"),
        (1, "CURRENT_USER"),
        (2, "LOCAL_MACHINE"),
        (3, "USERS"),
        (5, "CURRENT_CONFIG"),
    ]:
        setattr(registry, "HKEY_" + hive, 0x80000000 + offset)
    registry.KEY_READ = 0x20019
    registry.OpenKey.return_value.__int__.return_value = 123
    registry.QueryInfoKey.side_effect = lambda _key: (
        len(native.subkeys),
        len(native.values),
        0,
    )
    registry.EnumKey.side_effect = lambda _key, index: native.subkeys[index]

    # The six parameters match the Win32 function being substituted.
    # pylint: disable-next=too-many-arguments,too-many-positional-arguments
    def _query(
        key: int, name: str, reserved: Any, kind: Any, data: Any, size: Any
    ) -> int:
        assert key == 123 and reserved is None
        name = name.split("\0")[0]
        selected = next(
            (item for item in native.values if item.lower() == name.lower()), None
        )
        if selected is None:
            return 2
        value_kind, raw = native.values[selected]
        kind._obj.value = value_kind
        capacity = size._obj.value
        size._obj.value = len(raw)
        if data is not None:
            if capacity < len(raw):
                return 234
            ctypes.memmove(data, raw, len(raw))
        return 0

    def _enum(key: int, index: int, buffer: Any, size: Any, *unused: Any) -> int:
        assert key == 123 and all(item is None for item in unused)
        assert size._obj.value == 16384
        buffer.value = list(native.values)[index]
        size._obj.value = len(buffer.value)
        return 0

    def _expand(value: str, buffer: Any, capacity: int) -> int:
        value = value.split("\0")[0].replace("%SystemRoot%", r"C:\Windows")
        required = len(value) + 1
        if capacity >= required:
            buffer.value = value
        return required

    # The six parameters match the Win32 function being substituted.
    # pylint: disable-next=too-many-arguments,too-many-positional-arguments
    def _compare(
        locale: int, flags: int, left: str, left_size: int, right: str, right_size: int
    ) -> int:
        assert locale == 0x7F and flags == 1
        assert left_size == len(left.encode("utf-16-le", "surrogatepass")) // 2
        assert right_size == len(right.encode("utf-16-le", "surrogatepass")) // 2
        return (
            2
            if left.replace("\0", "").casefold() == right.replace("\0", "").casefold()
            else 1
        )

    native.registry = registry
    native.advapi.RegQueryValueExW.side_effect = _query
    native.advapi.RegEnumValueW.side_effect = _enum
    native.kernel.ExpandEnvironmentStringsW.side_effect = _expand
    native.kernel.CompareStringW.side_effect = _compare
    # The environment fixture uses the same few substitutions. Keeping each
    # library loader local makes this fixture's distinct API fakes visible.
    # pylint: disable=duplicate-code
    monkeypatch.setattr(helper, "winreg", registry)
    monkeypatch.setattr(helper, "os", SimpleNamespace(name="nt"))
    monkeypatch.setattr(
        helper.ctypes,
        "WinDLL",
        lambda name, **_kwargs: {
            "advapi32": native.advapi,
            "kernel32": native.kernel,
        }[name],
        raising=False,
    )
    # pylint: enable=duplicate-code
    monkeypatch.setattr(helper.ctypes, "WinError", _windows_error, raising=False)
    monkeypatch.setattr(
        helper.ctypes, "get_last_error", lambda: native.error, raising=False
    )
    return native


def _text(value: str) -> bytes:
    return value.encode("utf-16-le", "surrogatepass")


@pytest.mark.parametrize(
    "case",
    [
        (0, b"\x00\xff", [0, 255], ["0x00", "0xff"], "REG_NONE"),
        (0, b"", [], [], "REG_NONE"),
        (1, _text("hello 雪\0"), "hello 雪", "hello 雪", "REG_SZ"),
        (1, b"", "", "", "REG_SZ"),
        (1, _text("\0"), "", "", "REG_SZ"),
        (1, _text("unterminated"), "unterminated", "unterminated", "REG_SZ"),
        (1, b"A", "A", "A", "REG_SZ"),
        (1, _text("A\0B\0\0"), "A\0B\0", "A\0B\0", "REG_SZ"),
        (1, _text("\ud800\0"), "\ud800", "\ud800", "REG_SZ"),
        (2, _text("%SystemRoot%\0"), r"C:\Windows", "%SystemRoot%", "REG_EXPAND_SZ"),
        (2, _text("%UNSET%\0"), "%UNSET%", "%UNSET%", "REG_EXPAND_SZ"),
        (2, b"", "", "", "REG_EXPAND_SZ"),
        (2, _text("A\0B\0"), "A", "A\0B", "REG_EXPAND_SZ"),
        (3, b"\x01\x0a\xff", [1, 10, 255], ["0x01", "0x0a", "0xff"], "REG_BINARY"),
        (3, b"", [], [], "REG_BINARY"),
        (4, b"", 0, 0, "REG_DWORD"),
        (4, b"\xff", 255, 255, "REG_DWORD"),
        (4, b"\xff" * 4, 4294967295, 4294967295, "REG_DWORD"),
        (4, b"\x01" + b"\0" * 4, 1, 1, "REG_DWORD"),
        (5, b"\x01\x02\x03\x04", [1, 2, 3, 4], [1, 2, 3, 4], "Unknown - Unknown"),
        (7, b"", [], [], "REG_MULTI_SZ"),
        (7, _text("\0"), [], [], "REG_MULTI_SZ"),
        (7, _text("\0\0"), [""], [""], "REG_MULTI_SZ"),
        (7, _text("\0\0\0"), ["", ""], ["", ""], "REG_MULTI_SZ"),
        (7, _text("one\0two\0\0"), ["one", "two"], ["one", "two"], "REG_MULTI_SZ"),
        (
            7,
            _text("one\0\0two\0"),
            ["one", "", "two"],
            ["one", "", "two"],
            "REG_MULTI_SZ",
        ),
        (7, _text("one\0two"), ["one", "two"], ["one", "two"], "REG_MULTI_SZ"),
        (7, b"A", ["A"], ["A"], "REG_MULTI_SZ"),
        (11, b"", 0, 0, "REG_QWORD"),
        (11, b"\xff", 255, 255, "REG_QWORD"),
        (11, b"\xff" * 8, 18446744073709551615, 18446744073709551615, "REG_QWORD"),
    ],
)
def test_named_value_preserves_framework_decoding(
    helper: ModuleType,
    native: Mock,
    case: tuple[int, bytes, Any, Any, str],
) -> None:
    kind, data, value, raw, label = case
    native.values["Fixture"] = (kind, data)
    assert helper.query_key("HKCU", r"Software\Fixture", "fixture") == {
        "exists": True,
        "type": label,
        "value": value,
        "raw_value": raw,
    }
    native.registry.OpenKey.assert_called_once_with(
        native.registry.HKEY_CURRENT_USER, r"Software\Fixture", 0, 0x20019
    )
    native.registry.OpenKey.return_value.__exit__.assert_called_once()


@pytest.mark.parametrize(
    "case",
    [
        (0, b"\x01", [1], [1]),
        (3, b"\x00\xff", [0, 255], [0, 255]),
        (4, b"\xff" * 4, -1, -1),
        (11, b"\xff" * 8, -1, -1),
        (4, b"\xff" * 9, [255] * 9, [255] * 9),
        (7, _text("one\0two\0\0"), ["one", "two"], ["one", "two"]),
        (2, _text("%SystemRoot%\0"), r"C:\Windows", "%SystemRoot%"),
    ],
)
def test_default_always_reports_string_kind_without_named_value_conversion(
    helper: ModuleType,
    native: Mock,
    case: tuple[int, bytes, Any, Any],
) -> None:
    kind, data, value, raw = case
    native.values[""] = (kind, data)
    expected = {"type": "REG_SZ", "value": value, "raw_value": raw}
    assert helper.query_key("HKCU", "Fixture", "") == dict(expected, exists=True)
    assert helper.query_key("HKCU", "Fixture") == {
        "exists": True,
        "properties": {"": expected},
        "sub_keys": [],
    }


@pytest.mark.parametrize(
    ("kind", "data", "expected"),
    [(4, b"\xff" * 4, -1), (11, b"\xff" * 8, -1), (3, b"\x01\xff", [1, 255])],
)
def test_nul_only_name_uses_default_format_like_reference(
    helper: ModuleType, native: Mock, kind: int, data: bytes, expected: Any
) -> None:
    native.values[""] = (kind, data)
    assert helper.query_key("HKCU", "Fixture", "\0") == {
        "exists": True,
        "type": "REG_SZ",
        "value": expected,
        "raw_value": expected,
    }


@pytest.mark.parametrize(
    ("stored", "requested"), [("", "\0tail"), ("Name", "Name\0tail")]
)
def test_nul_with_non_ignorable_text_uses_named_value_format(
    helper: ModuleType, native: Mock, stored: str, requested: str
) -> None:
    native.values[stored] = (4, b"\xff" * 4)
    assert helper.query_key("HKCU", "Fixture", requested) == {
        "exists": True,
        "type": "REG_DWORD",
        "value": 4294967295,
        "raw_value": 4294967295,
    }


@pytest.mark.parametrize("kind", [6, 8, 9, 10, 12345])
def test_unsupported_value_is_absent_when_named_but_null_in_listing(
    helper: ModuleType, native: Mock, kind: int
) -> None:
    native.values["Unsupported"] = (kind, b"fixture")
    assert helper.query_key("HKLM", "Fixture", "Unsupported") == {"exists": False}
    assert helper.query_key("HKLM", "Fixture") == {
        "exists": True,
        "properties": {"Unsupported": None},
        "sub_keys": [],
    }


@pytest.mark.parametrize(
    ("kind", "data"),
    [(4, b"\xff" * 5), (4, b"\xff" * 8), (4, b"\xff" * 9), (11, b"\xff" * 9)],
)
def test_unrepresentable_named_integer_fails_and_closes_handle(
    helper: ModuleType, native: Mock, kind: int, data: bytes
) -> None:
    native.values["Broken"] = (kind, data)
    with pytest.raises(ValueError, match="Registry integer value"):
        helper.query_key("HKLM", "Fixture", "Broken")
    native.registry.OpenKey.return_value.__exit__.assert_called_once()
    native.values["Broken"] = (4, b"\x01\0\0\0")
    assert helper.query_key("HKLM", "Fixture", "Broken")["value"] == 1


def test_all_values_and_immediate_subkeys_preserve_native_enumeration(
    helper: ModuleType, native: Mock
) -> None:
    native.values.update({"Two": (1, _text("second\0")), "One": (3, b"\x01")})
    native.subkeys = ["Z child", "A child"]
    result = helper.query_key("HKCU", "Fixture")
    assert result == {
        "exists": True,
        "properties": {
            "Two": {"type": "REG_SZ", "value": "second", "raw_value": "second"},
            "One": {"type": "REG_BINARY", "value": [1], "raw_value": ["0x01"]},
        },
        "sub_keys": ["Z child", "A child"],
    }
    native.registry.EnumValue.assert_not_called()
    native.registry.QueryValueEx.assert_not_called()


def test_listing_collapses_invariant_equivalent_names_but_direct_reads_do_not(
    helper: ModuleType, native: Mock
) -> None:
    native.values.update({"ß": (1, _text("first\0")), "ss": (1, _text("last\0"))})
    assert helper.query_key("HKCU", "Fixture")["properties"] == {
        "ß": {"type": "REG_SZ", "value": "last", "raw_value": "last"}
    }
    assert helper.query_key("HKCU", "Fixture", "ß")["value"] == "first"
    assert helper.query_key("HKCU", "Fixture", "ss")["value"] == "last"


@pytest.mark.parametrize("name", [None, "", "missing"])
def test_empty_key_is_existing_but_missing_values_are_absent(
    helper: ModuleType, native: Mock, name: str | None
) -> None:
    expected = (
        {"exists": True, "properties": {}, "sub_keys": []}
        if name is None
        else {"exists": False}
    )
    assert helper.query_key("HKCU", "Fixture", name) == expected
    native.registry.OpenKey.return_value.__exit__.assert_called_once()


@pytest.mark.parametrize("code", [2, 3, 6, 87, 123, 1018])
def test_non_security_open_errors_match_reference_absent_result(
    helper: ModuleType, native: Mock, code: int
) -> None:
    native.registry.OpenKey.side_effect = _windows_error(code)
    assert helper.query_key("HKCU", "Fixture") == {"exists": False}
    native.advapi.RegQueryValueExW.assert_not_called()


@pytest.mark.parametrize("code", [5, 1346])
def test_open_security_error_is_not_hidden(
    helper: ModuleType, native: Mock, code: int
) -> None:
    native.registry.OpenKey.side_effect = _windows_error(code)
    with pytest.raises(OSError) as failure:
        helper.query_key("HKCU", "Fixture")
    assert failure.value.errno == code


@pytest.mark.parametrize("code", [2, 5, 6, 87])
def test_initial_value_query_errors_match_reference_missing_result(
    helper: ModuleType, native: Mock, code: int
) -> None:
    native.advapi.RegQueryValueExW.side_effect = None
    native.advapi.RegQueryValueExW.return_value = code
    assert helper.query_key("HKCU", "Fixture", "Value") == {"exists": False}
    native.registry.OpenKey.return_value.__exit__.assert_called_once()


@pytest.mark.parametrize("operation", ["QueryInfoKey", "EnumKey", "RegEnumValueW"])
def test_enumeration_failures_close_the_key_and_do_not_return_partial_results(
    helper: ModuleType, native: Mock, operation: str
) -> None:
    native.values["First"] = (1, _text("first\0"))
    native.subkeys = ["Child"]
    if operation == "RegEnumValueW":
        native.advapi.RegEnumValueW.side_effect = None
        native.advapi.RegEnumValueW.return_value = 5
    else:
        getattr(native.registry, operation).side_effect = _windows_error(5)
    with pytest.raises(OSError) as failure:
        helper.query_key("HKCU", "Fixture")
    assert failure.value.errno == 5
    native.registry.OpenKey.return_value.__exit__.assert_called_once()


def test_value_kind_query_failure_after_read_is_not_hidden(
    helper: ModuleType, native: Mock
) -> None:
    native.values["Value"] = (1, _text("first\0"))
    original = native.advapi.RegQueryValueExW.side_effect

    def _query(*args: Any) -> int:
        if native.advapi.RegQueryValueExW.call_count == 5:
            return 2
        return int(original(*args))

    native.advapi.RegQueryValueExW.side_effect = _query
    with pytest.raises(OSError) as failure:
        helper.query_key("HKCU", "Fixture", "Value")
    assert failure.value.errno == 2
    native.registry.OpenKey.return_value.__exit__.assert_called_once()


def test_more_data_from_metadata_query_is_allowed(
    helper: ModuleType, native: Mock
) -> None:
    native.values["Value"] = (1, _text("fixture\0"))
    original = native.advapi.RegQueryValueExW.side_effect

    def _query(*args: Any) -> int:
        error = int(original(*args))
        return 234 if native.advapi.RegQueryValueExW.call_count == 1 else error

    native.advapi.RegQueryValueExW.side_effect = _query
    assert helper.query_key("HKCU", "Fixture", "Value")["value"] == "fixture"


@pytest.mark.parametrize(("kind", "expected"), [(1, "\0"), (7, []), (4, 0)])
def test_second_read_failure_preserves_reference_zero_buffer_without_retry(
    helper: ModuleType, native: Mock, kind: int, expected: Any
) -> None:
    native.values["Value"] = (kind, b"\x01\0\x02\0")
    original = native.advapi.RegQueryValueExW.side_effect

    def _query(*args: Any) -> int:
        if args[4] is not None:
            return 234
        return int(original(*args))

    native.advapi.RegQueryValueExW.side_effect = _query
    result = helper.query_key("HKCU", "Fixture", "Value")
    assert result["value"] == result["raw_value"] == expected
    assert native.advapi.RegQueryValueExW.call_count == 5


def test_expanded_and_raw_value_are_separate_reference_reads(
    helper: ModuleType, native: Mock
) -> None:
    native.values["Value"] = (1, _text("first\0"))
    original = native.advapi.RegQueryValueExW.side_effect

    def _query(*args: Any) -> int:
        if native.advapi.RegQueryValueExW.call_count == 3:
            native.values["Value"] = (1, _text("second\0"))
        return int(original(*args))

    native.advapi.RegQueryValueExW.side_effect = _query
    result = helper.query_key("HKCU", "Fixture", "Value")
    assert result["value"] == "first"
    assert result["raw_value"] == "second"


def test_expansion_retries_required_capacity_and_preserves_raw_value(
    helper: ModuleType, native: Mock
) -> None:
    text = "%SystemRoot%" + "x" * 300
    native.values["Value"] = (2, _text(text + "\0"))
    result = helper.query_key("HKCU", "Fixture", "Value")
    assert result["value"] == r"C:\Windows" + "x" * 300
    assert result["raw_value"] == text
    calls = native.kernel.ExpandEnvironmentStringsW.call_args_list
    assert [call.args[2] for call in calls] == [128, 311]


@pytest.mark.parametrize("operation", ["ExpandEnvironmentStringsW", "CompareStringW"])
def test_conversion_failure_closes_handle(
    helper: ModuleType, native: Mock, operation: str
) -> None:
    native.values.update({"First": (2, _text("%SystemRoot%\0")), "Second": (1, b"")})
    getattr(native.kernel, operation).side_effect = None
    getattr(native.kernel, operation).return_value = 0
    with pytest.raises(OSError) as failure:
        helper.query_key("HKCU", "Fixture")
    assert failure.value.errno == 5
    native.registry.OpenKey.return_value.__exit__.assert_called_once()


@pytest.mark.parametrize(
    ("path", "opened"),
    [
        ("", ""),
        ("Fixture\\", "Fixture"),
        ("Fixture\\\\Child\\\\", "Fixture\\Child"),
        ("\\Fixture", "\\Fixture"),
        ("\\\\Fixture", "\\\\Fixture"),
        ("Fixture\0tail", "Fixture"),
        ("Fixture\\\\Child\0tail", "Fixture\\Child"),
        ("A" * 255, "A" * 255),
        ("A" * 255 + "\\" + "B" * 255, "A" * 255 + "\\" + "B" * 255),
    ],
)
def test_subkey_cleanup_matches_framework_without_resolving_dot_segments(
    helper: ModuleType, native: Mock, path: str, opened: str
) -> None:
    assert helper.query_key("HKLM", path, "missing") == {"exists": False}
    assert native.registry.OpenKey.call_args.args[1] == opened


@pytest.mark.parametrize(
    "path",
    [
        None,
        "x" * 256,
        "A\\" + "x" * 256,
        "𐐀" * 128,
        "Fixture\0" + "x" * 256,
        "Fixture\0tail\\" + "x" * 256,
    ],
)
def test_oversized_component_fails_before_opening_key(
    helper: ModuleType, native: Mock, path: str | None
) -> None:
    with pytest.raises(ValueError, match="255 UTF-16"):
        helper.query_key("HKCU", path)
    native.registry.OpenKey.assert_not_called()


@pytest.mark.parametrize("hive", ["HKCU", "HKLM", "HKCR", "HKCC", "HKU"])
def test_each_supported_hive_opens_only_target_process_default_view(
    helper: ModuleType, native: Mock, hive: str
) -> None:
    helper.query_key(hive, "Fixture", "missing")
    assert native.registry.OpenKey.call_args.args[2:] == (0, 0x20019)


def test_invalid_hive_and_non_windows_target_fail_actionably(
    helper: ModuleType, native: Mock, monkeypatch: pytest.MonkeyPatch
) -> None:
    with pytest.raises(ValueError, match="Unknown registry hive"):
        helper.query_key("HKPD", "")
    monkeypatch.setattr(helper, "os", SimpleNamespace(name="posix"))
    with pytest.raises(ValueError, match="require a Windows target"):
        helper.query_key("HKCU", "")
    native.registry.OpenKey.assert_not_called()


@pytest.mark.parametrize(
    "case",
    [
        ("", 4, b"\xff" * 4, -1),
        ("integer", 11, b"\xff" * 8, -1),
        ("bytes", 3, b"\x00\xff", [0, 255]),
        ("multi", 7, "one\0\0two\0\0".encode("utf-16-le"), ["one", "", "two"]),
    ],
)
def test_edit_reader_retains_actual_kind_and_signed_value(
    helper: ModuleType, native: Mock, case: tuple[str, int, bytes, object]
) -> None:
    name, kind, raw, expected = case
    native.values[name] = (kind, raw)
    assert helper.read_value(123, name) == (expected, kind)


def test_edit_reader_reports_absent_value(helper: ModuleType, native: Mock) -> None:
    native.values = {}
    assert helper.read_value(123, "absent") == (None, None)
