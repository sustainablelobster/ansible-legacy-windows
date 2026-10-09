# -*- coding: utf-8 -*-
# Copyright 2026 Joe Lustri
# SPDX-License-Identifier: GPL-3.0-or-later

"""Convert exact Windows timestamps using the target's native timezone rules."""

import ctypes
import datetime
import os

_SECOND = 10000000
_MINUTE = 60 * _SECOND
_DAY = 86400 * _SECOND
_CYCLE = 146097 * _DAY
_FILETIME_EPOCH = 504911232000000000
_MAX_TICKS = 3155378975999999999


# These records describe Windows memory layouts and need no methods.
class _FileTime(ctypes.Structure):  # pylint: disable=too-few-public-methods
    _fields_ = [("low", ctypes.c_uint32), ("high", ctypes.c_uint32)]


class _SystemTime(ctypes.Structure):  # pylint: disable=too-few-public-methods
    _fields_ = [
        ("year", ctypes.c_uint16),
        ("month", ctypes.c_uint16),
        ("weekday", ctypes.c_uint16),
        ("day", ctypes.c_uint16),
        ("hour", ctypes.c_uint16),
        ("minute", ctypes.c_uint16),
        ("second", ctypes.c_uint16),
        ("millisecond", ctypes.c_uint16),
    ]


class _TimeZoneInformation(ctypes.Structure):  # pylint: disable=too-few-public-methods
    _fields_ = [
        ("bias", ctypes.c_int32),
        ("standard_name", ctypes.c_uint16 * 32),
        ("standard_date", _SystemTime),
        ("standard_bias", ctypes.c_int32),
        ("daylight_name", ctypes.c_uint16 * 32),
        ("daylight_date", _SystemTime),
        ("daylight_bias", ctypes.c_int32),
    ]


def _kernel():
    if os.name != "nt":
        raise ValueError("Timestamp conversion requires a Windows target.")
    kernel = ctypes.WinDLL("kernel32", use_last_error=True)
    kernel.GetSystemTimeAsFileTime.argtypes = [ctypes.POINTER(_FileTime)]
    kernel.GetSystemTimeAsFileTime.restype = None
    kernel.GetTimeZoneInformation.argtypes = [ctypes.POINTER(_TimeZoneInformation)]
    kernel.GetTimeZoneInformation.restype = ctypes.c_uint32
    kernel.SystemTimeToTzSpecificLocalTime.argtypes = [
        ctypes.POINTER(_TimeZoneInformation),
        ctypes.POINTER(_SystemTime),
        ctypes.POINTER(_SystemTime),
    ]
    kernel.SystemTimeToTzSpecificLocalTime.restype = ctypes.c_int
    yearly = getattr(kernel, "GetTimeZoneInformationForYear", None)
    if yearly is not None:
        yearly.argtypes = [
            ctypes.c_uint16,
            ctypes.c_void_p,
            ctypes.POINTER(_TimeZoneInformation),
        ]
        yearly.restype = ctypes.c_int
    return kernel


def _zone_for_year(kernel, year):
    zone = _TimeZoneInformation()
    yearly = getattr(kernel, "GetTimeZoneInformationForYear", None)
    if yearly is None:
        # XP and Server 2003 expose the installed recurring rule, not a history.
        if kernel.GetTimeZoneInformation(ctypes.byref(zone)) == 0xFFFFFFFF:
            raise ctypes.WinError(ctypes.get_last_error())
    elif not yearly(year, None, ctypes.byref(zone)):
        raise ctypes.WinError(ctypes.get_last_error())
    return zone


def _bounded(ticks):
    return min(_MAX_TICKS, max(0, ticks))


def _year(ticks):
    return datetime.date.fromordinal(_bounded(ticks) // _DAY + 1).year


def _system_time(ticks):
    days, within_day = divmod(ticks, _DAY)
    date = datetime.date.fromordinal(days + 1)
    seconds, fraction = divmod(within_day, _SECOND)
    hours, seconds = divmod(seconds, 3600)
    minutes, seconds = divmod(seconds, 60)
    return _SystemTime(
        date.year,
        date.month,
        (date.weekday() + 1) % 7,
        date.day,
        hours,
        minutes,
        seconds,
        fraction // 10000,
    )


def _system_ticks(value):
    days = datetime.date(value.year, value.month, value.day).toordinal() - 1
    seconds = value.hour * 3600 + value.minute * 60 + value.second
    return days * _DAY + seconds * _SECOND + value.millisecond * 10000


def _native_local_ticks(kernel, zone, utc_ticks):
    # SYSTEMTIME starts at 1601; datetime ends at 9999. Move boundary years
    # by whole Gregorian 400-year cycles, preserving weekdays and leap days.
    # The original year's native rule is retained, including absolute dates.
    cycles = 5 if _year(utc_ticks) <= 1601 else -1 if _year(utc_ticks) == 9999 else 0
    shifted_zone = _TimeZoneInformation.from_buffer_copy(zone)
    for transition in (shifted_zone.standard_date, shifted_zone.daylight_date):
        if transition.year:
            transition.year += cycles * 400
    universal = _system_time(utc_ticks + cycles * _CYCLE)
    local = _SystemTime()
    if not kernel.SystemTimeToTzSpecificLocalTime(
        ctypes.byref(shifted_zone), ctypes.byref(universal), ctypes.byref(local)
    ):
        raise ctypes.WinError(ctypes.get_last_error())
    # Native SYSTEMTIME has millisecond precision. Apply only its offset so
    # all seven fractional digits from the original timestamp survive.
    return utc_ticks + _system_ticks(local) - _system_ticks(universal)


def utc_ticks_to_local_ticks(utc_ticks):
    """Convert UTC ticks to local wall-clock ticks without losing fractions.

    :param utc_ticks: Integer 100-nanosecond units since 0001-01-01 UTC.
        Parser offsets may put the value just outside years 1 through 9999.
    :type utc_ticks: int
    :returns: Local ticks in the same units, without date-boundary clamping.
    :rtype: int
    :raises OSError: If Windows cannot retrieve rules or convert the time.
    """
    kernel = _kernel()
    year = _year(utc_ticks)
    zone = _zone_for_year(kernel, year)
    local_ticks = _native_local_ticks(kernel, zone, utc_ticks)
    local_year = _year(local_ticks)
    if local_year != year:
        # Windows documents that historical rules must use the local year.
        zone = _zone_for_year(kernel, local_year)
        local_ticks = _native_local_ticks(kernel, zone, utc_ticks)
    return local_ticks


def file_time_to_local_ticks(file_time):
    """Convert a filesystem's UTC FILETIME to local wall-clock ticks.

    :param file_time: Native integer 100-nanosecond units since 1601-01-01 UTC.
    :type file_time: int
    :returns: Local ticks since year 1, clamped to the DateTime date range.
    :rtype: int
    :raises ValueError: If FILETIME is outside years 1601 through 9999.
    :raises OSError: If Windows cannot retrieve rules or convert the time.
    """
    if not isinstance(file_time, int) or not 0 <= file_time <= (
        _MAX_TICKS - _FILETIME_EPOCH
    ):
        raise ValueError("File timestamp must be between 1601 and 9999.")
    return _bounded(utc_ticks_to_local_ticks(file_time + _FILETIME_EPOCH))


def local_ticks_to_file_time(local_ticks):
    """Resolve local wall-clock ticks using standard time at DST transitions.

    :param local_ticks: Integer 100-nanosecond units since 0001-01-01 local time.
    :type local_ticks: int
    :returns: UTC FILETIME ticks. Negative values remain negative so the
        filesystem setter can validate the date after opening its handle.
        UTC values beyond the DateTime range are clamped before conversion.
    :rtype: int
    :raises ValueError: If local ticks are outside years 1 through 9999.
    :raises OSError: If Windows cannot retrieve rules or convert the time.
    """
    if not isinstance(local_ticks, int) or not 0 <= local_ticks <= _MAX_TICKS:
        raise ValueError("Local timestamp must be between years 1 and 9999.")
    kernel = _kernel()
    zone = _zone_for_year(kernel, _year(local_ticks))
    has_daylight = zone.standard_date.month and zone.daylight_date.month
    standard_bias = zone.bias + (zone.standard_bias if has_daylight else 0)
    standard_utc = local_ticks + standard_bias * _MINUTE
    utc_ticks = standard_utc
    if has_daylight:
        # Try standard first: both candidates match an overlap, neither
        # matches a gap. The upstream local DateTime chooses standard in both.
        for bias in (standard_bias, zone.bias + zone.daylight_bias):
            candidate = local_ticks + bias * _MINUTE
            if _native_local_ticks(kernel, zone, candidate) == local_ticks:
                utc_ticks = candidate
                break
    return _bounded(utc_ticks) - _FILETIME_EPOCH


def current_local_ticks():
    """Read the current local wall-clock time with native FILETIME precision.

    :returns: Integer 100-nanosecond units since 0001-01-01 local time.
    :rtype: int
    :raises OSError: If Windows cannot retrieve rules or convert the time.
    """
    value = _FileTime()
    _kernel().GetSystemTimeAsFileTime(ctypes.byref(value))
    return file_time_to_local_ticks((value.high << 32) | value.low)
