"""Exercise timestamp arithmetic using substitutes for native Windows calls."""

# SPDX-License-Identifier: GPL-3.0-or-later
# Native substitutes do not establish execution or timezone parity on Windows.
# pylint: disable=protected-access

import ctypes
from datetime import datetime, timedelta, timezone
from types import ModuleType, SimpleNamespace
from typing import Any
from unittest.mock import Mock
from zoneinfo import ZoneInfo

import pytest

from tests.unit.payload_support import ROOT, load_module, native_error

SECOND = 10000000
HOUR = 3600 * SECOND
EPOCH = 504911232000000000
MAX_TICKS = 3155378975999999999


def _ticks(value: datetime) -> int:
    return (
        (value.toordinal() - 1) * 86400 * SECOND
        + (value.hour * 3600 + value.minute * 60 + value.second) * SECOND
        + value.microsecond * 10
    )


@pytest.fixture(name="helper")
def time_helper() -> ModuleType:
    """Import the target helper with the developer interpreter.

    :returns: Loaded module without accessing Windows.
    """
    source = ROOT / "plugins/module_utils/legacy_windows_time.py"
    return load_module(source, "tested_time_native")


@pytest.fixture(name="kernel")
def native_calls(helper: ModuleType, monkeypatch: pytest.MonkeyPatch) -> Mock:
    """Substitute native calls with a developer-only Pacific timezone oracle.

    :param helper: Imported target helper.
    :param monkeypatch: Scoped substitutions for Windows-only ctypes APIs.
    :returns: Kernel mock with configurable timezone and native failures.
    """
    kernel = Mock()
    kernel.timezone = ZoneInfo("America/Los_Angeles")
    kernel.bias = 480
    kernel.daylight = True

    def _zone(pointer: Any) -> int:
        zone = ctypes.cast(
            pointer, ctypes.POINTER(helper._TimeZoneInformation)
        ).contents
        zone.bias = kernel.bias
        zone.standard_date.month = 11 if kernel.daylight else 0
        zone.daylight_date.month = 3 if kernel.daylight else 0
        zone.daylight_bias = -60
        return 1

    def _year_zone(year: int, dynamic: Any, pointer: Any) -> int:
        assert 1 <= year <= 9999
        assert dynamic is None
        return _zone(pointer)

    def _local(_zone_pointer: Any, source: Any, destination: Any) -> int:
        universal = ctypes.cast(source, ctypes.POINTER(helper._SystemTime)).contents
        local = ctypes.cast(destination, ctypes.POINTER(helper._SystemTime)).contents
        assert 1601 <= universal.year <= 9999
        value = datetime(
            universal.year,
            universal.month,
            universal.day,
            universal.hour,
            universal.minute,
            universal.second,
            universal.millisecond * 1000,
            tzinfo=timezone.utc,
        ).astimezone(kernel.timezone)
        for name in ("year", "month", "day", "hour", "minute", "second"):
            setattr(local, name, getattr(value, name))
        local.millisecond = value.microsecond // 1000
        return 1

    kernel.GetTimeZoneInformation.side_effect = _zone
    kernel.GetTimeZoneInformationForYear.side_effect = _year_zone
    kernel.SystemTimeToTzSpecificLocalTime.side_effect = _local
    monkeypatch.setattr(helper, "os", SimpleNamespace(name="nt"))
    monkeypatch.setattr(
        helper.ctypes, "WinDLL", Mock(return_value=kernel), raising=False
    )
    monkeypatch.setattr(
        helper.ctypes, "get_last_error", Mock(return_value=87), raising=False
    )
    monkeypatch.setattr(helper.ctypes, "WinError", native_error, raising=False)
    return kernel


@pytest.mark.parametrize(
    ("local_ticks", "file_time"),
    [
        (638535356551234567, 133624376551234567),
        (638661942000000000, 133750998000000000),
        (638456346000000000, 133545402000000000),
        (632784528000000000, 127873584000000000),
        (0, 8 * HOUR - EPOCH),
        (504911231990000000, 287990000000),
        (504911232000000000, 288000000000),
        (3155378975990000000, MAX_TICKS - EPOCH),
        (MAX_TICKS, MAX_TICKS - EPOCH),
    ],
)
def test_recorded_local_conversion_cases(
    helper: ModuleType, kernel: Mock, local_ticks: int, file_time: int
) -> None:
    assert helper.local_ticks_to_file_time(local_ticks) == file_time
    kernel.GetTimeZoneInformation.assert_not_called()


@pytest.mark.parametrize(
    ("file_time", "expected"),
    [
        (133624376551234567, 638535356551234567),
        (133750962001234567, 638661942001234567),
        (133750998001234567, 638661942001234567),
        (133545366000000000, 638456310000000000),
        (133545402000000000, 638456382000000000),
        (0, EPOCH - 8 * HOUR),
    ],
)
def test_native_utc_conversion_keeps_all_fraction_digits(
    helper: ModuleType, kernel: Mock, file_time: int, expected: int
) -> None:
    assert helper.file_time_to_local_ticks(file_time) == expected
    kernel.SystemTimeToTzSpecificLocalTime.assert_called()


def test_offset_overlap_discards_daylight_identity(
    helper: ModuleType, kernel: Mock
) -> None:
    daylight_occurrence = 133750962001234567
    standard_occurrence = daylight_occurrence + HOUR

    local_ticks = helper.file_time_to_local_ticks(daylight_occurrence)

    assert helper.local_ticks_to_file_time(local_ticks) == standard_occurrence
    kernel.GetTimeZoneInformation.assert_not_called()


@pytest.mark.parametrize("modern", [False, True])
def test_timezone_failures_keep_native_error(
    helper: ModuleType, kernel: Mock, modern: bool
) -> None:
    if modern:
        kernel.GetTimeZoneInformationForYear.side_effect = None
        kernel.GetTimeZoneInformationForYear.return_value = 0
    else:
        del kernel.GetTimeZoneInformationForYear
        kernel.GetTimeZoneInformation.side_effect = None
        kernel.GetTimeZoneInformation.return_value = 0xFFFFFFFF

    with pytest.raises(OSError) as failure:
        helper.local_ticks_to_file_time(638535356551234567)

    assert failure.value.errno == 87
    kernel.SystemTimeToTzSpecificLocalTime.assert_not_called()


def test_native_conversion_failure_is_not_silently_approximated(
    helper: ModuleType, kernel: Mock
) -> None:
    kernel.SystemTimeToTzSpecificLocalTime.side_effect = None
    kernel.SystemTimeToTzSpecificLocalTime.return_value = 0

    with pytest.raises(OSError) as failure:
        helper.local_ticks_to_file_time(638535356551234567)

    assert failure.value.errno == 87


def test_xp_uses_installed_recurring_rule(helper: ModuleType, kernel: Mock) -> None:
    del kernel.GetTimeZoneInformationForYear

    assert helper.local_ticks_to_file_time(638535356551234567) == 133624376551234567
    kernel.GetTimeZoneInformation.assert_called_once()


def test_no_daylight_rule_ignores_standard_and_daylight_adjustments(
    helper: ModuleType, kernel: Mock
) -> None:
    kernel.daylight = False
    kernel.bias = -330

    assert helper.local_ticks_to_file_time(EPOCH) == -330 * 60 * SECOND
    kernel.SystemTimeToTzSpecificLocalTime.assert_not_called()


def test_utc_conversion_rechecks_rules_for_the_local_year(
    helper: ModuleType, kernel: Mock
) -> None:
    utc_ticks = _ticks(datetime(2024, 1, 1, 2))

    assert helper.utc_ticks_to_local_ticks(utc_ticks) == utc_ticks - 8 * HOUR
    assert [
        call.args[0] for call in kernel.GetTimeZoneInformationForYear.call_args_list
    ] == [
        2024,
        2023,
    ]


def test_raw_parser_conversion_preserves_underflow(
    helper: ModuleType, kernel: Mock
) -> None:
    assert helper.utc_ticks_to_local_ticks(-14 * HOUR) == -22 * HOUR
    kernel.SystemTimeToTzSpecificLocalTime.assert_called_once()


def test_eastern_timezone_clamps_utc_and_local_overflow(
    helper: ModuleType, kernel: Mock
) -> None:
    kernel.timezone = timezone(timedelta(hours=14))
    kernel.bias = -840
    kernel.daylight = False

    assert helper.local_ticks_to_file_time(0) == -EPOCH
    assert helper.file_time_to_local_ticks(MAX_TICKS - EPOCH) == MAX_TICKS


@pytest.mark.parametrize("value", [-1, MAX_TICKS + 1, 1.5, "today"])
def test_invalid_local_ticks_fail_before_native_calls(
    helper: ModuleType, kernel: Mock, value: object
) -> None:
    with pytest.raises(ValueError, match="years 1 and 9999"):
        helper.local_ticks_to_file_time(value)
    kernel.GetTimeZoneInformationForYear.assert_not_called()


@pytest.mark.parametrize("value", [-1, MAX_TICKS - EPOCH + 1, 1.5, "today"])
def test_invalid_file_time_fails_before_native_calls(
    helper: ModuleType, kernel: Mock, value: object
) -> None:
    with pytest.raises(ValueError, match="between 1601 and 9999"):
        helper.file_time_to_local_ticks(value)
    kernel.GetTimeZoneInformationForYear.assert_not_called()


def test_current_time_preserves_native_fraction(
    helper: ModuleType, kernel: Mock
) -> None:
    file_time = 133624376551234567

    def _now(pointer: Any) -> None:
        value = ctypes.cast(pointer, ctypes.POINTER(helper._FileTime)).contents
        value.low = file_time & 0xFFFFFFFF
        value.high = file_time >> 32

    kernel.GetSystemTimeAsFileTime.side_effect = _now

    assert helper.current_local_ticks() == 638535356551234567
    kernel.GetSystemTimeAsFileTime.assert_called_once()


def test_windows_records_have_native_sizes(helper: ModuleType) -> None:
    assert ctypes.sizeof(helper._FileTime) == 8
    assert ctypes.sizeof(helper._SystemTime) == 16
    assert ctypes.sizeof(helper._TimeZoneInformation) == 172
