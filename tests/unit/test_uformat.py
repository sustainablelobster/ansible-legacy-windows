"""Compare process-date formatting with saved PowerShell 5.1 observations."""

# SPDX-License-Identifier: GPL-3.0-or-later

import copy
import datetime
import json
from types import ModuleType
from typing import Any
from unittest.mock import Mock

import pytest

from tests.unit.payload_support import ROOT, load_module

REFERENCE = json.loads(
    (ROOT / "tests/fixtures/listen_ports_uformat_reference.json").read_text(
        encoding="utf-8"
    )
)
CALENDARS = json.loads(
    (ROOT / "tests/fixtures/file_datetime.json").read_text(encoding="utf-8")
)


@pytest.fixture(name="helper")
def uformat_helper(monkeypatch: pytest.MonkeyPatch) -> ModuleType:
    """Load the formatter without substituting its formatting implementation.

    :param monkeypatch: Scoped target import path.
    :returns: Fresh target formatter with native boundaries left explicit.
    """
    monkeypatch.syspath_prepend(str(ROOT / "plugins/module_utils"))
    return load_module(
        ROOT / "plugins/module_utils/legacy_windows_uformat.py", "tested_uformat"
    )


@pytest.mark.parametrize(
    "case",
    REFERENCE["cases"],
    ids=lambda case: f"{case['culture']}:{case['date']}:{case['format']}",
)
def test_formatting_matches_recorded_reference(
    helper: ModuleType, monkeypatch: pytest.MonkeyPatch, case: dict[str, Any]
) -> None:
    culture_name = case["culture"]

    def _culture(name: str | None = None, calendar_id: int | None = None) -> Any:
        selected = copy.deepcopy(CALENDARS["cultures"][name or culture_name])
        if calendar_id is not None and calendar_id != selected["calendar_id"]:
            selected = copy.deepcopy(
                CALENDARS["calendar_overrides"][f"{selected['name']}:{calendar_id}"]
            )
        return selected

    native_fields = helper.calendar.calendar_fields

    def _fields(culture: dict[str, Any], date: datetime.date) -> Any:
        if culture["calendar_id"] != 23:
            return native_fields(culture, date)
        key = f"{culture['name']}:{date.isoformat()}"
        if key not in REFERENCE["calendar_fields"]:
            # The two probed year boundaries lie outside UmAlQura's range.
            assert date.year in (1, 9999)
            raise ValueError("Reference calendar cannot represent this date.")
        return tuple(REFERENCE["calendar_fields"][key])

    def _offset(value: datetime.datetime) -> int:
        return int(REFERENCE["offsets"][value.date().isoformat()])

    def _file_time(ticks: int) -> int:
        value = helper._datetime_from_ticks(ticks)  # pylint: disable=protected-access
        return ticks - _offset(value) * 600000000 - 504911232000000000

    symbols = REFERENCE["cultures"][culture_name]
    monkeypatch.setattr(helper.calendar, "get_culture", _culture)
    monkeypatch.setattr(helper.calendar, "calendar_fields", _fields)
    monkeypatch.setattr(helper, "_offset", _offset)
    monkeypatch.setattr(
        helper,
        "_number_symbols",
        lambda: (
            symbols["decimal_separator"],
            symbols["positive_sign"],
            symbols["negative_sign"],
        ),
    )
    monkeypatch.setattr(helper.native_time, "local_ticks_to_file_time", _file_time)
    current = datetime.datetime(2026, 9, 3, 4, 5, 6)
    monkeypatch.setattr(
        helper.native_time,
        "current_local_ticks",
        lambda: helper._local_ticks(current),  # pylint: disable=protected-access
    )
    value = datetime.datetime.fromisoformat(case["date"]).replace(tzinfo=None)
    if "error" in case:
        with pytest.raises(ValueError) as raised:
            helper.format_date(value, case["format"])
        if case["error_type"] != "System.ArgumentOutOfRangeException":
            assert str(raised.value) == case["error"]
    else:
        assert helper.format_date(value, case["format"]) == case["value"]


def test_submicrosecond_observations_are_not_claimed_as_process_date_matches() -> None:
    cases = REFERENCE["outside_input_domain"]
    assert len(cases) == 8
    assert all("%s" in case["format"] and case["date"][26] != "0" for case in cases)


def test_missing_date_does_not_read_culture_or_validate_format(
    helper: ModuleType, monkeypatch: pytest.MonkeyPatch
) -> None:
    read = Mock(side_effect=AssertionError("no date requires no culture"))
    monkeypatch.setattr(helper.calendar, "get_culture", read)
    assert helper.format_date(None, "") is None
    assert helper.format_date(None, None) is None
    read.assert_not_called()


@pytest.mark.parametrize(
    "ticks, expected", [(0, 0), (9999, 0), (-9999, 0), (10001, 1), (-10001, -1)]
)
def test_null_format_preserves_ajax_date_and_truncates_milliseconds_toward_zero(
    helper: ModuleType, monkeypatch: pytest.MonkeyPatch, ticks: int, expected: int
) -> None:
    monkeypatch.setattr(
        helper.native_time,
        "local_ticks_to_file_time",
        lambda _: ticks + 116444736000000000,
    )
    monkeypatch.setattr(
        helper.calendar, "get_culture", Mock(side_effect=AssertionError("not needed"))
    )
    assert (
        helper.format_date(datetime.datetime(1970, 1, 1), None) == f"/Date({expected})/"
    )


@pytest.mark.parametrize(
    "value",
    ["2026-09-03", 1, datetime.datetime(2026, 9, 3, tzinfo=datetime.timezone.utc)],
)
def test_non_local_datetime_input_fails(helper: ModuleType, value: object) -> None:
    with pytest.raises(ValueError, match="naive local datetime"):
        helper.format_date(value, "%Y")


def test_native_error_is_not_replaced_with_an_approximate_date(
    helper: ModuleType, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(
        helper.calendar, "get_culture", Mock(side_effect=OSError("locale denied"))
    )
    with pytest.raises(OSError, match="locale denied"):
        helper.format_date(datetime.datetime(2026, 9, 3), "%Y")


@pytest.mark.parametrize(
    ("field", "pattern"),
    [
        ("short_time", "{0:t}"),
        ("short_time", "{0:f}"),
        ("short_time", "{0:g}"),
        ("month_day", "{0:m}"),
        ("month_day", "{0:M}"),
        ("month_genitive", "{0:D}"),
        ("month_genitive", "{0:F}"),
        ("month_genitive", "{0:MMMM d}"),
    ],
)
def test_unavailable_legacy_locale_field_is_named(
    helper: ModuleType, monkeypatch: pytest.MonkeyPatch, field: str, pattern: str
) -> None:
    culture = copy.deepcopy(CALENDARS["cultures"]["en-US"])
    culture[field] = None
    monkeypatch.setattr(helper.calendar, "get_culture", lambda: culture)
    with pytest.raises(NotImplementedError, match=field + " locale field"):
        helper.format_date(datetime.datetime(2026, 9, 3, 4, 5, 6), pattern)


@pytest.mark.parametrize(
    ("pattern", "expected"),
    [
        ("%c", "Thu Sep  3 04:05:06 2026"),
        ("%B", "September"),
        ("%R", "04:05"),
        ("{0:yyyy-MM-dd}", "2026-09-03"),
    ],
)
def test_available_formats_do_not_require_optional_legacy_fields(
    helper: ModuleType,
    monkeypatch: pytest.MonkeyPatch,
    pattern: str,
    expected: str,
) -> None:
    culture = copy.deepcopy(CALENDARS["cultures"]["en-US"])
    for field in ("short_time", "month_day", "month_genitive"):
        culture[field] = None
    monkeypatch.setattr(helper.calendar, "get_culture", lambda: culture)
    assert (
        helper.format_date(datetime.datetime(2026, 9, 3, 4, 5, 6), pattern) == expected
    )
