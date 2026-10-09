"""Compare timestamp parsing with saved reference observations, entirely locally."""

# SPDX-License-Identifier: GPL-3.0-or-later

import copy
import datetime
import importlib.util
import json
from types import ModuleType
from typing import Any, cast
from unittest.mock import Mock

import pytest

from tests.unit.payload_support import ROOT

REFERENCE = json.loads(
    (ROOT / "tests/fixtures/file_datetime.json").read_text(encoding="utf-8")
)
TODAY = datetime.date.fromisoformat(REFERENCE["provenance"]["local_today"])


@pytest.fixture(name="helper")
def datetime_helper(monkeypatch: pytest.MonkeyPatch) -> ModuleType:
    """Load the target parser with recorded culture data and local substitutions.

    :param monkeypatch: Scoped substitutions for native calendar boundaries.
    :returns: The imported parser, without contacting a Windows host.
    """
    source = ROOT / "plugins/module_utils/legacy_windows_datetime.py"
    monkeypatch.syspath_prepend(str(source.parent))
    spec = importlib.util.spec_from_file_location("tested_datetime", source)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)

    def _culture(name: str | None = None, calendar_id: int | None = None) -> Any:
        culture = copy.deepcopy(REFERENCE["cultures"][name or "en-US"])
        if calendar_id is not None and calendar_id != culture["calendar_id"]:
            key = f"{culture['name']}:{calendar_id}"
            return copy.deepcopy(REFERENCE["calendar_overrides"][key])
        return culture

    def _names_equal(culture: Any, left: str, right: str) -> bool:
        # Only this corpus's case comparisons are modeled. Native NLS comparison
        # requires its separate Windows checks, including additional alphabets.
        if culture["name"] == "tr-TR":
            left = left.replace("I", "ı").replace("İ", "i")
            right = right.replace("I", "ı").replace("İ", "i")
        return left.casefold() == right.casefold()

    real_date = module.calendar.calendar_date
    real_fields = module.calendar.calendar_fields

    def _calendar_date(
        culture: Any, year: int, month: int, day: int, era: int = 0
    ) -> datetime.date:
        if culture["calendar_id"] != 23:
            return cast(datetime.date, real_date(culture, year, month, day, era))
        # These finite recorded conversions isolate parsing, not calendar math.
        assert era in (0, 1)
        key = f"{year}-{month}-{day}"
        assert key in REFERENCE["umalqura_dates"], "Unrecorded calendar date: " + key
        value = REFERENCE["umalqura_dates"][key]
        if value is None:
            raise ValueError("Reference rejected this calendar date.")
        return datetime.date.fromisoformat(value)

    def _calendar_fields(culture: Any, value: datetime.date) -> Any:
        if culture["calendar_id"] != 23:
            return real_fields(culture, value)
        assert value == TODAY
        return tuple(REFERENCE["umalqura_today"])

    monkeypatch.setattr(module.calendar, "get_culture", _culture)
    monkeypatch.setattr(module.calendar, "names_equal", _names_equal)
    monkeypatch.setattr(module.calendar, "calendar_date", _calendar_date)
    monkeypatch.setattr(module.calendar, "calendar_fields", _calendar_fields)
    return module


@pytest.mark.parametrize("case", REFERENCE["cases"], ids=lambda case: case["id"])
def test_parser_matches_saved_reference(helper: ModuleType, case: Any) -> None:
    if "native_only_reason" in case:
        pytest.skip(case["native_only_reason"])
    culture = copy.deepcopy(REFERENCE["cultures"][case["culture"] or "en-US"])
    arguments = case["value"], case["format"], culture, TODAY

    if not case["accepted"]:
        with pytest.raises(ValueError):
            helper.parse_timestamp(*arguments)
        return

    expected = case["expected"]
    assert helper.parse_timestamp(*arguments) == (
        datetime.datetime(*expected["components"]),
        expected["fractional_tick"],
        expected["offset_minutes"],
    )


@pytest.mark.parametrize(
    ("field", "pattern", "value"),
    [
        ("short_time", "t", "1:14 PM"),
        ("month_day", "M", "June 9"),
        ("month_genitive", "dd MMMM yyyy", "09 June 2024"),
        ("abbreviated_genitive", "dd MMM yyyy", "09 Jun 2024"),
    ],
)
def test_missing_native_metadata_names_the_unsupported_field(
    helper: ModuleType, field: str, pattern: str, value: str
) -> None:
    culture = copy.deepcopy(REFERENCE["cultures"]["en-US"])
    culture[field] = None

    with pytest.raises(NotImplementedError, match=field):
        helper.parse_timestamp(value, pattern, culture, TODAY)


@pytest.mark.parametrize("field", ["name", "abbreviation"])
def test_incomplete_native_era_names_are_explicitly_unsupported(
    helper: ModuleType, field: str
) -> None:
    culture = copy.deepcopy(REFERENCE["cultures"]["en-US"])
    culture["eras"][0][field] = None

    with pytest.raises(NotImplementedError, match="era names"):
        helper.parse_timestamp("2024-06-09 AD", "yyyy-MM-dd gg", culture, TODAY)


def test_numeric_format_does_not_need_unrelated_native_metadata(
    helper: ModuleType,
) -> None:
    culture = copy.deepcopy(REFERENCE["cultures"]["en-US"])
    for field in ("short_time", "month_day", "month_genitive", "abbreviated_genitive"):
        culture[field] = None
    culture["eras"] = [{"number": 1, "name": None, "abbreviation": None}]

    assert helper.parse_timestamp(
        "2024-06-09 13:14:15", "yyyy-MM-dd HH:mm:ss", culture, TODAY
    ) == (datetime.datetime(2024, 6, 9, 13, 14, 15), 0, None)


@pytest.mark.parametrize(
    ("value", "pattern"),
    [("24 024-06-09", "yy yyy-MM-dd"), ("024 24-06-09", "yyy yy-MM-dd")],
)
def test_repeated_year_retains_two_digit_expansion(
    helper: ModuleType, value: str, pattern: str
) -> None:
    # Source-backed regression, separate from the saved empirical fixture:
    # referencesource/mscorlib/system/globalization/datetimeparse.cs retains
    # fUseTwoDigitYear once a short year token has appeared.
    culture = copy.deepcopy(REFERENCE["cultures"]["en-US"])
    assert helper.parse_timestamp(value, pattern, culture, TODAY) == (
        datetime.datetime(2024, 6, 9),
        0,
        None,
    )


@pytest.mark.parametrize(
    "case",
    [
        ("time_separator", "::", "13::14::15", "HH:mm:ss", True),
        ("time_separator", "::", "13:14:15", "HH:mm:ss", False),
        ("date_separator", "//", "2024//06//09", "yyyy/MM/dd", True),
        ("date_separator", "//", "2024/06/09", "yyyy/MM/dd", False),
        ("time_separator", ".", "13.14.15", "HH:mm:ss", True),
        ("time_separator", ".", "13:14:15", "HH:mm:ss", True),
        ("date_separator", ".", "2024.06.09", "yyyy/MM/dd", True),
        ("date_separator", ".", "2024/06/09", "yyyy/MM/dd", True),
        ("time_separator", "::", "13:14:15", "HH':'mm':'ss", True),
        ("date_separator", "//", "2024/06/09", "yyyy'/'MM'/'dd", True),
    ],
)
def test_localized_separator_precedence(
    helper: ModuleType, case: tuple[str, str, str, str, bool]
) -> None:
    # ParseByFormat's ':' and '/' branches treat same-prefix, multi-character
    # separators as indivisible; other separators also allow literal fallback.
    field, separator, value, pattern, accepted = case
    culture = copy.deepcopy(REFERENCE["cultures"]["en-US"])
    culture[field] = separator
    if not accepted:
        with pytest.raises(ValueError):
            helper.parse_timestamp(value, pattern, culture, TODAY)
        return
    expected = (
        datetime.datetime(2026, 9, 28, 13, 14, 15)
        if field == "time_separator"
        else datetime.datetime(2024, 6, 9)
    )
    assert helper.parse_timestamp(value, pattern, culture, TODAY) == (expected, 0, None)


@pytest.fixture(name="clock")
def native_clock(helper: ModuleType, monkeypatch: pytest.MonkeyPatch) -> Mock:
    """Substitute the native clock; these tests do not verify Windows timezone rules.

    :param helper: Imported parser with recorded culture metadata.
    :param monkeypatch: Scoped replacement of the native time boundary.
    :returns: Clock fixed to noon on the reference observation date.
    """
    clock = Mock()
    clock.current_local_ticks.return_value = 639261936000000000
    monkeypatch.setattr(helper, "native_time", clock)
    return clock


@pytest.mark.parametrize(
    ("offset", "utc_ticks"),
    [
        ("-07:00", 638662194001234567),
        ("-08:00", 638662230001234567),
    ],
)
def test_offsets_keep_seven_digits_and_ambiguous_results_only_keep_wall_ticks(
    helper: ModuleType, clock: Mock, offset: str, utc_ticks: int
) -> None:
    # The saved fall-back observations produce the same clock from two instants.
    # A local wall-clock integer intentionally cannot retain the original DST flag.
    clock.utc_ticks_to_local_ticks.return_value = 638661942001234567

    result = helper.parse_local_ticks("2024-11-03T01:30:00.1234567" + offset, "O")

    assert result == 638661942001234567
    assert isinstance(result, int)
    clock.utc_ticks_to_local_ticks.assert_called_once_with(utc_ticks)


def test_local_value_preserves_every_tick_without_timezone_conversion(
    helper: ModuleType, clock: Mock
) -> None:
    assert (
        helper.parse_local_ticks("2024-06-09T13:14:15.1234567", "O")
        == 638535356551234567
    )
    clock.utc_ticks_to_local_ticks.assert_not_called()


def test_time_only_uses_the_native_local_date(helper: ModuleType, clock: Mock) -> None:
    assert helper.parse_local_ticks("13:14:15", "HH:mm:ss") == 639261980550000000
    clock.current_local_ticks.assert_called_once_with()
    clock.utc_ticks_to_local_ticks.assert_not_called()


def test_reference_lower_boundary_reaches_the_native_converter(
    helper: ModuleType, clock: Mock
) -> None:
    clock.utc_ticks_to_local_ticks.return_value = -792000000000

    assert (
        helper.parse_local_ticks("0001-01-01 00:00:00+14:00", "yyyy-MM-dd HH:mm:sszzz")
        == 72000000000
    )
    clock.utc_ticks_to_local_ticks.assert_called_once_with(-504000000000)


def test_reference_upper_boundary_rejects_native_conversion_overflow(
    helper: ModuleType, clock: Mock
) -> None:
    clock.utc_ticks_to_local_ticks.return_value = 3155378976000000000

    with pytest.raises(ValueError, match="outside years 1 to 9999"):
        helper.parse_local_ticks("9999-12-31 23:59:59-14:00", "yyyy-MM-dd HH:mm:sszzz")

    clock.utc_ticks_to_local_ticks.assert_called_once_with(3155379479990000000)


@pytest.mark.parametrize(
    ("converted", "expected"),
    [(-1, 863999999999), (-864000000000, 0), (-864000000001, None)],
)
def test_negative_local_conversion_wraps_once_only(
    helper: ModuleType, clock: Mock, converted: int, expected: int | None
) -> None:
    clock.utc_ticks_to_local_ticks.return_value = converted
    arguments = "0001-01-01 00:00:00+14:00", "yyyy-MM-dd HH:mm:sszzz"

    if expected is None:
        with pytest.raises(ValueError, match="outside years 1 to 9999"):
            helper.parse_local_ticks(*arguments)
    else:
        assert helper.parse_local_ticks(*arguments) == expected

    clock.utc_ticks_to_local_ticks.assert_called_once_with(-504000000000)
