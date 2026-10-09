"""Compare account expiration parsing and formatting with Windows observations."""

# SPDX-License-Identifier: GPL-3.0-or-later

import datetime
import json
from types import ModuleType
from typing import Any
from unittest.mock import Mock

import pytest

from tests.unit.payload_support import ROOT, load_module

REFERENCE = json.loads(
    (ROOT / "tests/fixtures/user_expiration.json").read_text(encoding="utf-8")
)
SECOND = 10000000
MAX_TICKS = 3155378975999999999
# Account expiration uses Local desired dates and Unspecified ADSI readback.
# The saved Utc-kind formatter controls are outside this helper's interface.
FORMAT_CASES = [case for case in REFERENCE["formatting"] if case["kind"] != "Utc"]


def _culture(name: str = "en-US") -> dict[str, Any]:
    return {
        "name": name,
        "calendar_id": {"th-TH": 7, "ar-SA": 23}.get(name, 1),
        "time_separator": ":",
    }


@pytest.fixture(name="helper")
def datetime_helper(monkeypatch: pytest.MonkeyPatch) -> ModuleType:
    """Load the helper with finite recorded native timezone and calendar results.

    These substitutions exercise parser and formatter behavior locally; they
    do not establish native Windows timezone or calendar conversion support.

    :param monkeypatch: Scoped replacements of native target boundaries.
    :returns: Imported helper using the recorded Pacific timezone observations.
    """
    source = ROOT / "plugins/module_utils/legacy_windows_datetime.py"
    monkeypatch.syspath_prepend(str(source.parent))
    helper = load_module(source, "tested_user_expiration")
    conversions: dict[int, int] = {}
    for case in REFERENCE["cases"]:
        if "utc_input_ticks" not in case:
            continue
        utc_ticks = case["utc_input_ticks"]
        offset = (
            case["parsed"]["local_offset_minutes"]
            if case["success"]
            else REFERENCE["provenance"]["base_utc_offset_minutes"]
        )
        local_ticks = utc_ticks + offset * 60 * SECOND
        assert conversions.get(utc_ticks, local_ticks) == local_ticks
        conversions[utc_ticks] = local_ticks

    def _local_ticks(utc_ticks: int) -> int:
        assert utc_ticks in conversions, f"Unrecorded UTC conversion: {utc_ticks}"
        return conversions[utc_ticks]

    real_fields = helper.calendar.calendar_fields

    def _calendar_fields(culture: dict[str, Any], date: datetime.date) -> Any:
        if culture["calendar_id"] != 23:
            return real_fields(culture, date)
        # This one recorded native conversion isolates formatting from the
        # separately tested Windows UmAlQura calendar boundary.
        assert date == datetime.date(2040, 10, 27)
        return 1462, 10, 21, 1

    monkeypatch.setattr(helper.native_time, "utc_ticks_to_local_ticks", _local_ticks)
    monkeypatch.setattr(helper.calendar, "calendar_fields", _calendar_fields)
    monkeypatch.setattr(helper.calendar, "get_culture", _culture)
    return helper


@pytest.mark.parametrize("case", REFERENCE["cases"], ids=lambda case: case["id"])
def test_parser_matches_saved_reference(helper: ModuleType, case: Any) -> None:
    if not case["success"]:
        with pytest.raises(ValueError):
            helper.parse_account_expiration(case["value"])
        return
    expected = case["parsed"]

    actual = helper.parse_account_expiration(case["value"])

    assert actual == (expected["ticks"], expected["local_offset_minutes"])
    assert helper.format_account_expiration(*actual) == expected["fixed_invariant"]


@pytest.mark.parametrize(
    "case",
    FORMAT_CASES,
    ids=lambda case: f"{case['requested_culture']}-{case['kind']}-{case['ticks']}",
)
def test_formatter_matches_saved_reference(helper: ModuleType, case: Any) -> None:
    culture = (
        None if case["requested_culture"] == "current" else _culture(case["culture"])
    )
    offset = -420 if case["kind"] == "Local" else None

    assert (
        helper.format_account_expiration(case["ticks"], offset, culture)
        == case["rendered"]
    )


def test_parser_is_invariant_but_formatter_uses_the_account_calendar(
    helper: ModuleType, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(helper.calendar, "get_culture", lambda: _culture("th-TH"))

    ticks, offset = helper.parse_account_expiration("2040-10-27T14:30:00Z")

    assert (
        helper.format_account_expiration(ticks, offset) == "2583-10-27T07:30:00-07:00"
    )


@pytest.mark.parametrize(
    ("calendar_id", "expected"),
    [
        (3, "22-10-27"),
        (3, "52-10-27"),
        (4, "129-10-27"),
        (8, "תת\"א-ב'-כ'"),
    ],
)
def test_optional_calendars_preserve_recorded_numeric_formatting(
    helper: ModuleType,
    monkeypatch: pytest.MonkeyPatch,
    calendar_id: int,
    expected: str,
) -> None:
    fields = Mock(return_value=(129, 10, 27, 1))
    monkeypatch.setattr(helper.calendar, "calendar_fields", fields)

    def _alternative(identifier: int, date: datetime.date) -> str:
        assert identifier == calendar_id
        assert date == datetime.date(2040, 10, 27)
        return expected

    formatter = Mock(side_effect=_alternative)
    monkeypatch.setattr(helper.calendar, "format_alternative_date", formatter)
    culture = {"calendar_id": calendar_id, "time_separator": ":"}
    assert helper.format_account_expiration(643705578000000000, None, culture) == (
        expected + "T14:30:00"
    )
    if calendar_id in (3, 8):
        formatter.assert_called_once()
        fields.assert_not_called()
    else:
        formatter.assert_not_called()
        fields.assert_called_once()


@pytest.mark.parametrize(
    ("offset", "suffix"), [(None, ""), (0, "+00:00"), (330, "+05:30"), (-210, "-03:30")]
)
def test_formatter_distinguishes_missing_and_signed_offsets(
    helper: ModuleType, offset: int | None, suffix: str
) -> None:
    assert (
        helper.format_account_expiration(643705578000000001, offset)
        == "2040-10-27T14:30:00.0000001" + suffix
    )


def test_account_time_separator_does_not_change_offset_separator(
    helper: ModuleType,
) -> None:
    culture = _culture()
    culture["time_separator"] = "::"

    assert (
        helper.format_account_expiration(643705578001200000, 330, culture)
        == "2040-10-27T14::30::00.12+05:30"
    )


@pytest.mark.parametrize("value", [None, True, 123, [], {}])
def test_parser_rejects_non_string_values(helper: ModuleType, value: Any) -> None:
    with pytest.raises(ValueError, match="Invalid account expiration date"):
        helper.parse_account_expiration(value)


@pytest.mark.parametrize("ticks", [None, "0", -1, MAX_TICKS + 1, 0.5])
def test_formatter_rejects_invalid_ticks(helper: ModuleType, ticks: Any) -> None:
    with pytest.raises(ValueError, match="between years 1 and 9999"):
        helper.format_account_expiration(ticks)


@pytest.mark.parametrize("offset", ["0", 0.5, [], {}])
def test_formatter_rejects_non_integer_offsets(helper: ModuleType, offset: Any) -> None:
    with pytest.raises(ValueError, match="integer minutes"):
        helper.format_account_expiration(643705578000000000, offset)


def test_native_conversion_failure_is_not_reported_as_a_parse_error(
    helper: ModuleType, monkeypatch: pytest.MonkeyPatch
) -> None:
    def _failure(_ticks: int) -> int:
        raise OSError(5, "Native timezone conversion failed.")

    monkeypatch.setattr(helper.native_time, "utc_ticks_to_local_ticks", _failure)

    with pytest.raises(OSError) as failed:
        helper.parse_account_expiration("2040-10-27T14:30:00Z")

    assert failed.value.errno == 5


def test_missing_native_time_separator_is_explicit(helper: ModuleType) -> None:
    culture = _culture()
    culture["time_separator"] = None

    with pytest.raises(NotImplementedError, match="time_separator"):
        helper.format_account_expiration(643705578000000000, culture=culture)
