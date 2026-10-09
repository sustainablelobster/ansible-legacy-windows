"""Check registry conversions and comparisons without contacting Windows."""

# SPDX-License-Identifier: GPL-3.0-or-later
# Native substitutions keep these conversion tests independent of Windows.
# pylint: disable=protected-access

from types import ModuleType, SimpleNamespace
from unittest.mock import Mock

import pytest

from tests.unit.payload_support import HELPER, load_module


@pytest.fixture(name="helper")
def registry_data_helper(monkeypatch: pytest.MonkeyPatch) -> ModuleType:
    """Load data conversion with deterministic Windows number symbols.

    :param monkeypatch: Scoped module-path and culture substitutions.
    :returns: The registry data helper.
    """
    monkeypatch.syspath_prepend(str(HELPER.parent))
    module = load_module(
        HELPER.parent / "legacy_windows_regedit_data.py", "tested_regedit_data"
    )
    monkeypatch.setattr(module.module, "_number_symbols", lambda: (".", "+", "-"))
    return module


@pytest.mark.parametrize("kind", ["string", "expandstring"])
@pytest.mark.parametrize("named", [False, True])
def test_null_strings_distinguish_named_and_default_values(
    helper: ModuleType, kind: str, named: bool
) -> None:
    assert helper.convert_data(None, kind, named) == ("" if named else None)


@pytest.mark.parametrize("value", ["", "%SystemRoot%", 12, True, [1, 2], {"a": 1}])
@pytest.mark.parametrize("kind", ["string", "expandstring"])
def test_nonnull_strings_preserve_raw_data_for_diff(
    helper: ModuleType, value: object, kind: str
) -> None:
    assert helper.convert_data(value, kind, True) is value
    assert helper.diff_value(kind, value)["value"] is value


@pytest.mark.parametrize("kind", ["binary", "none"])
@pytest.mark.parametrize(
    ("value", "expected"),
    [
        (None, []),
        ("", []),
        ([], []),
        ("hex:00,01,EE,ff", [0, 1, 238, 255]),
        ("beef", [190, 239]),
        ("1", [1]),
        ("a", [10]),
        ("abc", []),
        ("gg", []),
        ("01::02", [1, 2]),
        ([0, 1, 238, 255], [0, 1, 238, 255]),
        (255, [255]),
    ],
)
def test_binary_forms(
    helper: ModuleType, kind: str, value: object, expected: list[int]
) -> None:
    assert helper.convert_data(value, kind, True) == expected
    assert helper.diff_value(kind, expected) == {
        "type": "Binary" if kind == "binary" else "None",
        "value": [f"0x{byte:02x}" for byte in expected],
    }


@pytest.mark.parametrize("value", [256, 2147483647])
def test_binary_int32_overflow_preserves_explicit_validation(
    helper: ModuleType, value: int
) -> None:
    with pytest.raises(helper.DataValidationError, match="yaml byte array"):
        helper.convert_data(value, "binary", True)


@pytest.mark.parametrize("value", [True, False, 2147483648, 1.0, {"a": 1}])
def test_binary_unconverted_types_reach_the_native_setter(
    helper: ModuleType, value: object
) -> None:
    assert helper.convert_data(value, "binary", True) is value


@pytest.mark.parametrize("value", ["0x01", ":01", "01:", "100:", [-1], [256], -1])
def test_invalid_binary_conversion_is_not_explicit_validation(
    helper: ModuleType, value: object
) -> None:
    with pytest.raises(ValueError) as raised:
        helper.convert_data(value, "binary", True)
    assert not isinstance(raised.value, helper.DataValidationError)


@pytest.mark.parametrize("kind,bits", [("dword", 32), ("qword", 64)])
@pytest.mark.parametrize(
    "value,expected",
    [
        (None, 0),
        (0, 0),
        (1, 1),
        (-1, -1),
        ("0", 0),
        ("1", 1),
        ("0xff", 255),
        (42.0, 42),
        ("1.0", 1),
        (" 1 ", 1),
        (True, 1),
        ("1.5", 2),
        ("2.5", 2),
        ("1e2", 100),
        ("1,000", 1000),
        ("", 0),
        ("+1", 1),
        ("-0.5", 0),
    ],
)
def test_integer_scalar_forms(
    helper: ModuleType, kind: str, bits: int, value: object, expected: int
) -> None:
    assert helper.convert_data(value, kind, True) == expected
    assert helper.diff_value(kind, expected) == {
        "type": "DWord" if kind == "dword" else "QWord",
        "value": f"0x{int(expected) & ((1 << bits) - 1):0{bits // 4}x}",
    }


@pytest.mark.parametrize("kind,bits", [("dword", 32), ("qword", 64)])
def test_unsigned_integer_limits_use_signed_storage_values(
    helper: ModuleType, kind: str, bits: int
) -> None:
    maximum = (1 << bits) - 1
    assert helper.convert_data(maximum, kind, True) == -1
    assert helper.convert_data(str(maximum), kind, True) == -1
    assert helper.convert_data(1 << (bits - 1), kind, True) == -(1 << (bits - 1))
    with pytest.raises(helper.DataValidationError, match=f"0x{'f' * (bits // 4)}"):
        helper.convert_data(maximum + 1, kind, True)


@pytest.mark.parametrize("kind", ["dword", "qword"])
def test_fractional_integer_has_the_reference_failure(
    helper: ModuleType, kind: str
) -> None:
    with pytest.raises(helper.DataValidationError) as raised:
        helper.convert_data(1.1, kind, True)
    assert str(raised.value) == (
        "data '1.1' cannot be a decimal or float value with a remainder when type "
        "is dword or qword"
    )


@pytest.mark.parametrize(
    "value,expected",
    [
        (None, []),
        ("one", ["one"]),
        (["one", 2], ["one", "2"]),
        ([""], [""]),
        (["", "two", ""], ["", "two", ""]),
        ([1, True, 2.5], ["1", "True", "2.5"]),
    ],
)
def test_multistring_known_forms(
    helper: ModuleType, value: object, expected: list[str]
) -> None:
    assert helper.convert_data(value, "multistring", True) == expected
    assert helper.diff_value("multistring", expected) == {
        "type": "MultiString",
        "value": expected,
    }


def test_multistring_number_format_is_invariant(
    helper: ModuleType, monkeypatch: pytest.MonkeyPatch
) -> None:
    symbols = Mock(
        side_effect=AssertionError("Invariant formatting must not read locale")
    )
    monkeypatch.setattr(helper.module, "_number_symbols", symbols)
    assert helper.convert_data([1.25, -2, 1e20], "multistring", True) == [
        "1.25",
        "-2",
        "1E+20",
    ]
    symbols.assert_not_called()


def test_explicit_empty_multistring_leaves_the_value_untouched(
    helper: ModuleType,
) -> None:
    assert helper.convert_data([], "multistring", True) is None


def test_binary_array_cast_rounds_and_accepts_null_and_boolean(
    helper: ModuleType,
) -> None:
    assert helper.convert_data([1.5, None, True], "binary", True) == [2, 0, 1]
    assert helper.convert_data(["1.5", "2.5", "0xff", ""], "binary", True) == [
        2,
        2,
        255,
        0,
    ]


@pytest.mark.parametrize("value", ["   ", "18446744073709551615.0", "-1"])
def test_integer_string_fallback_failures_keep_unhandled_classification(
    helper: ModuleType, value: str
) -> None:
    with pytest.raises(ValueError, match="System.UInt64") as raised:
        helper.convert_data(value, "qword", True)
    assert not isinstance(raised.value, helper.DataValidationError)


@pytest.mark.parametrize(
    "value,expected",
    [
        (True, "0xTrue"),
        (2147483648, "0x80000000"),
        ({"a": 1}, "0xSystem.Collections.Hashtable"),
    ],
)
def test_check_mode_binary_diff_formats_values_rejected_by_the_setter(
    helper: ModuleType, value: object, expected: str
) -> None:
    converted = helper.convert_data(value, "binary", True)
    assert helper.diff_value("binary", converted) == {
        "type": "Binary",
        "value": [expected],
    }


def test_readable_legacy_kind_keeps_raw_bytes_in_diff(helper: ModuleType) -> None:
    assert helper.diff_value("unknown", [0, 0, 0, 1]) == {
        "type": "Unknown",
        "value": [0, 0, 0, 1],
    }


def test_binary_float_diff_raises_the_measured_format_error(helper: ModuleType) -> None:
    with pytest.raises(ValueError, match="Format specifier was invalid"):
        helper.diff_value("binary", 1.5)


def test_null_multistring_entry_fails_before_storage(helper: ModuleType) -> None:
    with pytest.raises(ValueError, match="null-valued"):
        helper.convert_data([None], "multistring", True)


@pytest.mark.parametrize("value", [{"a": 1}, [{"a": 1}], [["one"]]])
def test_multistring_objects_lack_the_required_string_overload(
    helper: ModuleType, value: object
) -> None:
    with pytest.raises(ValueError, match="Cannot find an overload"):
        helper.convert_data(value, "multistring", True)


@pytest.mark.parametrize(
    "existing,desired,equal",
    [
        ("System.Object[]", [1, 2], False),
        ("System.Collections.Hashtable", {"a": 1}, True),
        ("4", ["4"], True),
        ("4", 4, True),
        ("True", True, True),
    ],
)
def test_cross_kind_comparisons_follow_measured_powershell_conversion(
    helper: ModuleType,
    monkeypatch: pytest.MonkeyPatch,
    existing: str,
    desired: object,
    equal: bool,
) -> None:
    monkeypatch.setattr(helper, "_strings_equal", lambda a, b, _ignore: a == b)
    assert helper.values_equal(existing, desired) is equal


@pytest.mark.parametrize(
    "left,right,equal", [(1, 1, True), (1, 2, False), (1, "1", True), (1, "x", False)]
)
def test_numeric_value_comparison(
    helper: ModuleType, left: object, right: object, equal: bool
) -> None:
    assert helper.values_equal(left, right) is equal


def test_arrays_compare_positions_and_ignore_case(
    helper: ModuleType, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(
        helper,
        "_strings_equal",
        lambda a, b, ignore: a.lower() == b.lower() if ignore else a == b,
    )
    assert helper.values_equal(["one", "two"], ["ONE", "TWO"])
    assert not helper.values_equal(["one", "two"], ["two", "one"])
    assert not helper.values_equal(["one"], ["one", "two"])
    assert helper.values_equal(["one"], "ONE")
    assert not helper.values_equal("one", "ONE")


@pytest.mark.parametrize("ignore_case", [False, True])
def test_text_comparison_uses_native_invariant_utf16_lengths(
    helper: ModuleType, monkeypatch: pytest.MonkeyPatch, ignore_case: bool
) -> None:
    compare = Mock(return_value=2)
    monkeypatch.setattr(
        helper.ctypes,
        "WinDLL",
        Mock(return_value=SimpleNamespace(CompareStringW=compare)),
        raising=False,
    )
    assert helper._strings_equal("a😀", "A😀", ignore_case)
    compare.assert_called_once_with(0x7F, int(ignore_case), "a😀", 3, "A😀", 3)


def test_native_comparison_failure_is_reported(
    helper: ModuleType, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(
        helper.ctypes,
        "WinDLL",
        Mock(return_value=SimpleNamespace(CompareStringW=Mock(return_value=0))),
        raising=False,
    )
    monkeypatch.setattr(helper.ctypes, "get_last_error", lambda: 87, raising=False)
    monkeypatch.setattr(
        helper.ctypes,
        "WinError",
        lambda code: OSError(code, "comparison failed"),
        raising=False,
    )
    with pytest.raises(OSError, match="comparison failed"):
        helper.values_equal("a", "b")
