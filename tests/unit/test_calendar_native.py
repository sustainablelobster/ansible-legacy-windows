"""Check calendar arithmetic and NLS metadata without contacting Windows."""

# SPDX-License-Identifier: GPL-3.0-or-later
# Native boundary tests inspect the private structures passed through ctypes.
# pylint: disable=protected-access

import ctypes
import datetime
import importlib.util
from types import ModuleType
from typing import Any
from unittest.mock import Mock

import pytest

from tests.unit.payload_support import ROOT, native_error


@pytest.mark.parametrize("failure_step", [None, "size", "write"])
@pytest.mark.parametrize(
    "case",
    [
        (8, 1037, datetime.date(2040, 10, 27), "תת\"א-ב'-כ'"),
        (3, 1041, datetime.date(2040, 10, 27), "22-10-27"),
        (3, 1041, datetime.date(2040, 10, 27), "52-10-27"),
        # The fixed yyyy-MM-dd picture requires numeric era years, including
        # year one; these API substitutes do not prove native gannen behavior.
        (3, 1041, datetime.date(1868, 9, 8), "01-09-08"),
        (3, 1041, datetime.date(1912, 7, 30), "01-07-30"),
        (3, 1041, datetime.date(1926, 12, 25), "01-12-25"),
        (3, 1041, datetime.date(1989, 1, 8), "01-01-08"),
        (3, 1041, datetime.date(2019, 5, 1), "01-05-01"),
        (3, 1041, datetime.date(2019, 5, 1), "31-05-01"),
    ],
)
def test_date_formatting_uses_native_alternative_calendar(
    helper: ModuleType,
    monkeypatch: pytest.MonkeyPatch,
    failure_step: str | None,
    case: tuple[int, int, datetime.date, str],
) -> None:
    calendar_id, locale_id, date, expected = case

    def _format(*arguments: Any) -> int:
        locale, flags, pointer, pattern, buffer, size = arguments
        assert (locale, flags, pattern) == (locale_id, 4, "yyyy-MM-dd")
        native_date = ctypes.cast(pointer, ctypes.POINTER(helper._SystemTime)).contents
        assert (native_date.year, native_date.month, native_date.day) == (
            date.year,
            date.month,
            date.day,
        )
        if size == 0:
            assert buffer is None
            return 0 if failure_step == "size" else len(expected) + 1
        if failure_step == "write":
            return 0
        assert size == len(expected) + 1
        buffer.value = expected
        return int(size)

    formatter = Mock(side_effect=_format)
    kernel = Mock(spec=["GetDateFormatW"], GetDateFormatW=formatter)
    monkeypatch.setattr(helper, "_kernel", lambda: kernel)
    monkeypatch.setattr(ctypes, "get_last_error", lambda: 87, raising=False)
    monkeypatch.setattr(ctypes, "WinError", native_error, raising=False)
    if failure_step:
        with pytest.raises(OSError) as raised:
            helper.format_alternative_date(calendar_id, date)
        assert raised.value.errno == 87
    else:
        assert helper.format_alternative_date(calendar_id, date) == expected
    assert formatter.call_count == (1 if failure_step == "size" else 2)


@pytest.mark.parametrize(
    ("calendar_id", "date", "message"),
    [
        (8, datetime.date(1582, 12, 31), "Hebrew calendar"),
        (8, datetime.date(2239, 9, 30), "Hebrew calendar"),
        (3, datetime.date(1868, 9, 7), "Japanese calendar"),
        (1, datetime.date(2040, 10, 27), "requires Japanese or Hebrew"),
        (4, datetime.date(2040, 10, 27), "requires Japanese or Hebrew"),
    ],
)
def test_alternative_formatter_rejects_invalid_dates_before_native_call(
    helper: ModuleType,
    monkeypatch: pytest.MonkeyPatch,
    calendar_id: int,
    date: datetime.date,
    message: str,
) -> None:
    native = Mock()
    monkeypatch.setattr(helper, "_kernel", native)
    with pytest.raises(ValueError, match=message):
        helper.format_alternative_date(calendar_id, date)
    native.assert_not_called()


@pytest.mark.parametrize(
    ("calendar_id", "date"),
    [
        (3, datetime.date(1868, 9, 8)),
        (3, datetime.date.max),
        (8, datetime.date(1583, 1, 1)),
        (8, datetime.date(2239, 9, 29)),
    ],
)
def test_alternative_formatter_accepts_calendar_boundary_dates(
    helper: ModuleType,
    monkeypatch: pytest.MonkeyPatch,
    calendar_id: int,
    date: datetime.date,
) -> None:
    def _format(*arguments: Any) -> int:
        _, _, pointer, _, buffer, size = arguments
        native_date = ctypes.cast(pointer, ctypes.POINTER(helper._SystemTime)).contents
        assert (native_date.year, native_date.month, native_date.day) == (
            date.year,
            date.month,
            date.day,
        )
        if size:
            buffer.value = "native date"
        return len("native date") + 1

    kernel = Mock(spec=["GetDateFormatW"], GetDateFormatW=Mock(side_effect=_format))
    monkeypatch.setattr(helper, "_kernel", lambda: kernel)

    assert helper.format_alternative_date(calendar_id, date) == "native date"


@pytest.fixture(name="helper")
def calendar_helper() -> ModuleType:
    """Load the target helper with the developer interpreter.

    :returns: Target helper module without accessing Windows.
    """
    source = ROOT / "plugins/module_utils/legacy_windows_calendar.py"
    spec = importlib.util.spec_from_file_location("tested_calendar_native", source)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


@pytest.mark.parametrize(
    ("calendar_id", "year", "gregorian_year"),
    [
        (1, 2024, 2024),
        (2, 2024, 2024),
        (9, 2024, 2024),
        (10, 2024, 2024),
        (11, 2024, 2024),
        (12, 2024, 2024),
        (4, 113, 2024),
        (5, 4357, 2024),
        (7, 2567, 2024),
        (7, 544, 1),
        (7, 10542, 9999),
        (4, 1, 1912),
        (4, 8088, 9999),
    ],
)
def test_solar_calendar_roundtrip(
    helper: ModuleType, calendar_id: int, year: int, gregorian_year: int
) -> None:
    culture = {"calendar_id": calendar_id}
    expected = datetime.date(gregorian_year, 6, 9)
    assert helper.calendar_date(culture, year, 6, 9) == expected
    assert helper.calendar_fields(culture, expected) == (year, 6, 9, 1)


@pytest.mark.parametrize(
    ("calendar_id", "fields"),
    [
        (7, (543, 1, 1, 0)),
        (7, (10543, 1, 1, 0)),
        (4, (0, 1, 1, 0)),
        (4, (8089, 1, 1, 0)),
        (1, (2023, 2, 29, 0)),
        (7, (2566, 2, 29, 0)),
        (5, (2333, 1, 1, 0)),
        (1, (2024, 1, 1, 2)),
    ],
)
def test_solar_calendar_rejects_invalid_dates(
    helper: ModuleType, calendar_id: int, fields: tuple[int, int, int, int]
) -> None:
    with pytest.raises(ValueError):
        helper.calendar_date({"calendar_id": calendar_id}, *fields)


def test_taiwan_calendar_rejects_dates_before_its_first_year(
    helper: ModuleType,
) -> None:
    with pytest.raises(ValueError, match="first year"):
        helper.calendar_fields({"calendar_id": 4}, datetime.date(1911, 12, 31))


@pytest.mark.parametrize(
    ("calendar_id", "cutoff", "year", "expected"),
    [
        (1, 2049, 49, 2049),
        (1, 2049, 50, 1950),
        (1, 2049, 0, 2000),
        (1, 2029, 30, 1930),
        (1, 2029, 100, 100),
        (7, 2592, 92, 2592),
        (7, 2592, 93, 2493),
        (23, 1451, 51, 1451),
        (23, 1451, 52, 1352),
        (3, 99, 6, 6),
        (4, 99, 24, 24),
    ],
)
def test_year_expansion_uses_calendar_specific_cutoff(
    helper: ModuleType, calendar_id: int, cutoff: int, year: int, expected: int
) -> None:
    culture = {"calendar_id": calendar_id, "two_digit_year_max": cutoff}
    assert helper.expand_year(culture, year) == expected


@pytest.fixture(name="nls")
def native_metadata(
    helper: ModuleType, monkeypatch: pytest.MonkeyPatch
) -> dict[str, Any]:
    """Provide account data through native API substitutes.

    :param helper: Imported target helper.
    :param monkeypatch: Scoped Windows-only API substitutions.
    :returns: Locale and calendar mappings that individual tests can change.
    """
    kernel = Mock(spec=["GetLocaleInfoW", "GetCalendarInfoW", "GetUserDefaultLCID"])
    locale_values = {
        1: "0409",
        0x1009: "1",
        0x5C: "en-US",
        0x28: "AM",
        0x29: "PM",
        0x1003: "h:mm:ss tt",
        0x79: "h:mm tt",
        0x1F: "M/d/yyyy",
        0x20: "dddd, MMMM d, yyyy",
        0x1006: "MMMM yyyy",
    }
    calendar_values = {
        0x30: "2049",
        0x38: "MMMM d",
        4: "A.D.",
        0x39: "AD",
        5: "MM-dd-yyyy",
        6: "dddd dd MMMM yyyy",
        0x2F: "yyyy MMMM",
    }
    for index in range(13):
        calendar_values[0x15 + index] = f"Month{index + 1}"
        calendar_values[0x22 + index] = f"M{index + 1}"
        calendar_values[0x10000015 + index] = f"Genitive{index + 1}"
        calendar_values[0x10000022 + index] = f"G{index + 1}"
    for index, name in enumerate(("Mon", "Tue", "Wed", "Thu", "Fri", "Sat", "Sun")):
        calendar_values[7 + index] = name + "day"
        calendar_values[0xE + index] = name

    def _write(value: str | None, buffer: Any, length: int) -> int:
        if value is None:
            return 0
        if length:
            buffer.value = value
        return len(value) + 1

    def _locale(_selected: int, info: int, buffer: Any, length: int) -> int:
        return _write(locale_values[info], buffer, length)

    def _calendar(
        _selected: int,
        _calendar_id: int,
        info: int,
        buffer: Any,
        length: int,
        _number: Any,
    ) -> int:
        return _write(calendar_values[info], buffer, length)

    kernel.GetLocaleInfoW.side_effect = _locale
    kernel.GetCalendarInfoW.side_effect = _calendar
    monkeypatch.setattr(helper, "_kernel", lambda: kernel)
    monkeypatch.setattr(helper.ctypes, "get_last_error", lambda: 87, raising=False)
    return {"locale": locale_values, "calendar": calendar_values}


def test_account_metadata_preserves_names_and_default_patterns(
    helper: ModuleType, nls: dict[str, Any]
) -> None:
    culture = helper.get_culture()
    assert culture["name"] == "en-US"
    assert culture["lcid"] == 1033
    assert culture["calendar_id"] == 1
    assert culture["short_date"] == nls["locale"][0x1F]
    assert culture["full_datetime"] == "dddd, MMMM d, yyyy h:mm:ss tt"
    assert culture["day_abbreviations"] == [
        "Sun",
        "Mon",
        "Tue",
        "Wed",
        "Thu",
        "Fri",
        "Sat",
    ]
    assert culture["month_names"][0] == "Month1"
    assert culture["month_genitive"][0] == "Genitive1"
    assert culture["eras"] == [{"number": 1, "name": "A.D.", "abbreviation": "AD"}]


def test_calendar_override_refreshes_calendar_patterns(
    helper: ModuleType, nls: dict[str, Any]
) -> None:
    nls["locale"][0x1009] = "7"
    culture = helper.get_culture(calendar_id=1)
    assert culture["calendar_id"] == 1
    assert culture["short_date"] == "MM-dd-yyyy"
    assert culture["full_datetime"] == "dddd dd MMMM yyyy h:mm:ss tt"
    assert culture["date_separator"] == "-"


def test_unavailable_metadata_is_explicit(
    helper: ModuleType, nls: dict[str, Any]
) -> None:
    nls["locale"][0x79] = None
    nls["calendar"][0x38] = None
    nls["calendar"][0x39] = None
    nls["calendar"][0x10000015] = None
    culture = helper.get_culture()
    assert culture["short_time"] is None
    assert culture["month_day"] is None
    assert culture["month_genitive"] is None
    assert culture["eras"][0]["abbreviation"] is None


def test_native_quoted_patterns_and_separators_preserve_literal_text(
    helper: ModuleType, nls: dict[str, Any]
) -> None:
    nls["locale"][0x1F] = "yyyy'年'M'月'd'日'"
    nls["locale"][0x20] = "dddd 'l''anniversaire' d MMMM yyyy"
    nls["locale"][0x1003] = "HH'::'mm\\ss"
    culture = helper.get_culture()
    assert culture["date_separator"] == "年"
    assert culture["time_separator"] == "::"
    assert culture["long_date"] == "dddd 'l\\'anniversaire' d MMMM yyyy"
    assert culture["long_time"] == "HH'::'mm\\\\ss"


def test_thai_era_and_genitive_names_follow_calendar_contract(
    helper: ModuleType, nls: dict[str, Any]
) -> None:
    nls["locale"][0x1009] = "7"
    culture = helper.get_culture()
    assert culture["eras"] == [{"number": 1, "name": "พ.ศ.", "abbreviation": "พ.ศ."}]
    assert culture["month_genitive"] == culture["month_names"]


@pytest.mark.parametrize(
    ("calendar_id", "fields", "gregorian"),
    [
        (6, (1, 1, 1), (622, 7, 18)),
        (6, (990, 12, 7), (1583, 1, 1)),
        (6, (1445, 12, 3), (2024, 6, 9)),
        (6, (1448, 4, 16), (2026, 9, 28)),
        (6, (9666, 4, 3), (9999, 12, 31)),
        (8, (5343, 4, 7), (1583, 1, 1)),
        (8, (5361, 4, 27), (1601, 1, 1)),
        (8, (5784, 1, 1), (2023, 9, 16)),
        (8, (5784, 10, 3), (2024, 6, 9)),
        (8, (5787, 1, 17), (2026, 9, 28)),
        (8, (5999, 13, 29), (2239, 9, 29)),
    ],
)
def test_lunar_arithmetic_matches_recorded_dates_and_documented_boundaries(
    helper: ModuleType,
    calendar_id: int,
    fields: tuple[int, int, int],
    gregorian: tuple[int, int, int],
) -> None:
    culture = {"calendar_id": calendar_id, "hijri_adjustment": 0}
    expected = datetime.date(*gregorian)
    assert helper.calendar_date(culture, *fields) == expected
    assert helper.calendar_fields(culture, expected) == (*fields, 1)


@pytest.mark.parametrize(
    ("calendar_id", "fields"),
    [
        (6, (1445, 2, 30)),
        (6, (9666, 5, 1)),
        (6, (1444, 12, 30)),
        (8, (5784, 2, 30)),
        (8, (5783, 13, 1)),
        (8, (5343, 4, 6)),
        (8, (6000, 1, 1)),
    ],
)
def test_lunar_invalid_days_are_not_normalized(
    helper: ModuleType, calendar_id: int, fields: tuple[int, int, int]
) -> None:
    with pytest.raises(ValueError):
        helper.calendar_date(
            {"calendar_id": calendar_id, "hijri_adjustment": 0}, *fields
        )


@pytest.mark.parametrize("adjustment", [-2, -1, 0, 1, 2])
def test_hijri_adjustment_moves_dates_without_changing_calendar_fields(
    helper: ModuleType, adjustment: int
) -> None:
    culture = {"calendar_id": 6, "hijri_adjustment": adjustment}
    expected = datetime.date(2024, 6, 9) - datetime.timedelta(days=adjustment)
    assert helper.calendar_date(culture, 1445, 12, 3) == expected
    assert helper.calendar_fields(culture, expected) == (1445, 12, 3, 1)


@pytest.mark.parametrize("result", [1, 2, 3])
def test_name_comparison_uses_locale_and_utf16_lengths(
    helper: ModuleType, monkeypatch: pytest.MonkeyPatch, result: int
) -> None:
    kernel = Mock()
    kernel.CompareStringW.return_value = result
    monkeypatch.setattr(helper, "_kernel", lambda: kernel)
    assert helper.names_equal({"lcid": 1055}, "I\U0001f600", "ı\U0001f600") == (
        result == 2
    )
    kernel.CompareStringW.assert_called_once_with(
        1055, 1, "I\U0001f600", 3, "ı\U0001f600", 3
    )


def test_empty_names_do_not_require_a_native_comparison(helper: ModuleType) -> None:
    assert helper.names_equal({"lcid": 1033}, "", "")
    assert not helper.names_equal({"lcid": 1033}, "", "AM")
