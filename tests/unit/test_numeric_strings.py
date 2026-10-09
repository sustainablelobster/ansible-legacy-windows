"""Check measured .NET numeric conversions without connecting to Windows."""

# SPDX-License-Identifier: GPL-3.0-or-later
# Pure formatting and a mocked Windows locale boundary keep these checks local.
# pylint: disable=protected-access

import ctypes
import importlib
from types import SimpleNamespace
from unittest.mock import Mock

import pytest

helper = importlib.import_module("plugins.module_utils.legacy_windows_module")


@pytest.mark.parametrize(
    ("value", "expected"),
    [
        (27, "27"),
        (-12, "-12"),
        (1.25, "1.25"),
        (-1.25, "-1.25"),
        (1.0, "1.0"),
        (-0.0, "0.0"),
        (1.2345678901234567, "1.2345678901234567"),
        (0.0001, "0.0001"),
        (1e-5, "1E-05"),
        (1e15, "1000000000000000.0"),
        (1e16, "1E+16"),
        (1.2345678901234567e20, "1.23456789012346E+20"),
        (5e-324, "4.94065645841247E-324"),
        (1.000000000000025e16, "1.00000000000003E+16"),
        (1.000000000000035e16, "1.00000000000004E+16"),
        (-1.000000000000025e16, "-1.00000000000003E+16"),
        (9.999999999999999e-5, "0.0001"),
        (9999999999999998.0, "9999999999999998.0"),
        (2.2250738585072014e-308, "2.2250738585072E-308"),
        (1.7976931348623157e308, "1.79769313486232E+308"),
        (79228162514264337593543950335, "79228162514264337593543950335"),
        (79228162514264337593543950336, "7.92281625142643E+28"),
    ],
)
def test_numeric_text_matches_reference(
    monkeypatch: pytest.MonkeyPatch, value: int | float, expected: str
) -> None:
    # The reference used CLR 4.0.30319.42000, CurrentCulture en-US.
    monkeypatch.setattr(helper, "_number_symbols", lambda: (".", "+", "-"))
    assert helper.as_string(value, "data") == expected


@pytest.mark.parametrize(
    ("value", "expected"),
    [
        (1.25, "1,25"),
        (-1.25, "minus1,25"),
        (1.25e20, "1,25Eplus20"),
        (-1.25e-20, "minus1,25Eminus20"),
        (-42, "minus42"),
    ],
)
def test_numeric_symbols_are_applied_without_rewriting_the_symbols(
    monkeypatch: pytest.MonkeyPatch, value: int | float, expected: str
) -> None:
    monkeypatch.setattr(helper, "_number_symbols", lambda: (",", "plus", "minus"))
    assert helper.as_string(value, "data") == expected


@pytest.mark.parametrize("value", [float("inf"), -float("inf"), float("nan"), 10**400])
def test_out_of_range_numbers_are_validation_errors(value: int | float) -> None:
    with pytest.raises(ValueError, match="data"):
        helper.as_string(value, "data")


def test_text_and_booleans_do_not_depend_on_windows_numeric_settings(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    read_symbols = Mock(side_effect=AssertionError("Numeric settings not needed"))
    monkeypatch.setattr(helper, "_number_symbols", read_symbols)
    assert helper.as_string("-1.25e+20", "data") == "-1.25e+20"
    assert helper.as_string(True, "data") == "True"
    assert helper.as_string(False, "data") == "False"
    read_symbols.assert_not_called()


@pytest.mark.parametrize("positive", ["", "plus"])
def test_windows_numeric_settings_include_the_framework_positive_sign_default(
    monkeypatch: pytest.MonkeyPatch, positive: str
) -> None:
    values = {0xE: ",", 0x50: positive, 0x51: "minus"}

    def _read_info(
        locale: int, field: int, buffer: ctypes.Array[ctypes.c_wchar] | None, size: int
    ) -> int:
        assert locale == 0x400
        text = values[field]
        if buffer is not None:
            assert size == len(text) + 1
            buffer.value = text
        return len(text) + 1

    library = SimpleNamespace(GetLocaleInfoW=Mock(side_effect=_read_info))
    monkeypatch.setattr(
        helper.ctypes, "WinDLL", Mock(return_value=library), raising=False
    )
    assert helper._number_symbols() == (",", positive or "+", "minus")


@pytest.mark.parametrize("responses", [[0], [2, 0]])
def test_windows_locale_failure_is_not_silently_replaced_with_english(
    monkeypatch: pytest.MonkeyPatch, responses: list[int]
) -> None:
    library = SimpleNamespace(GetLocaleInfoW=Mock(side_effect=responses))
    monkeypatch.setattr(
        helper.ctypes, "WinDLL", Mock(return_value=library), raising=False
    )
    monkeypatch.setattr(
        helper.ctypes,
        "WinError",
        Mock(return_value=OSError("Locale unavailable")),
        raising=False,
    )
    with pytest.raises(OSError, match="Locale unavailable"):
        helper.as_string(1.25, "data")
