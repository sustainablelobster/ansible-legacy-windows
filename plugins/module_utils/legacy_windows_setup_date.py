# -*- coding: utf-8 -*-
# Copyright 2026 Joe Lustri
# SPDX-License-Identifier: GPL-3.0-or-later

"""Read setup's compound date fact using the installed Windows timezone."""

import ctypes
import datetime
import struct

try:
    import winreg
except ImportError:
    winreg = None

import legacy_windows_uformat as uformat  # pylint: disable=import-error

# The timestamp helper owns the fixed-width Windows time-record layouts.
from legacy_windows_time import _TimeZoneInformation  # pylint: disable=import-error


def _value(path, name):
    try:
        with winreg.OpenKey(
            winreg.HKEY_LOCAL_MACHINE, path, 0, winreg.KEY_READ | winreg.KEY_WOW64_64KEY
        ) as key:
            return winreg.QueryValueEx(key, name)[0]
    except OSError as error:
        if getattr(error, "winerror", None) not in (2, 3):
            raise
        return None


def _timezone_id():
    name = _value(
        r"SYSTEM\CurrentControlSet\Control\TimeZoneInformation", "TimeZoneKeyName"
    )
    if name:
        return name
    zone = _TimeZoneInformation()
    kernel = ctypes.WinDLL("kernel32", use_last_error=True)
    kernel.GetTimeZoneInformation.argtypes = [ctypes.POINTER(_TimeZoneInformation)]
    kernel.GetTimeZoneInformation.restype = ctypes.c_uint32
    if kernel.GetTimeZoneInformation(ctypes.byref(zone)) == 0xFFFFFFFF:
        raise ctypes.WinError(ctypes.get_last_error())
    standard = bytes(zone.standard_name).decode("utf-16-le").split("\0", 1)[0]
    catalogue = r"SOFTWARE\Microsoft\Windows NT\CurrentVersion\Time Zones"
    with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, catalogue) as key:
        for index in range(winreg.QueryInfoKey(key)[0]):
            name = winreg.EnumKey(key, index)
            path = catalogue + "\\" + name
            if _value(path, "Std") != standard:
                continue
            data = _value(path, "TZI")
            if not isinstance(data, bytes) or len(data) != 44:
                raise ValueError("Installed timezone TZI must contain 44 binary bytes.")
            if struct.unpack_from("<l", data)[0] == zone.bias:
                return name
    raise OSError("The current native timezone has no matching installed ID.")


def read_date_time():
    """Read all released setup date fields from one local clock sample.

    :returns: Complete compound date fact, with canonical timezone ID.
    :rtype: dict
    :raises OSError: Windows cannot convert the time or identify its timezone.
    :raises ValueError: Installed timezone metadata is malformed.
    """
    local = datetime.datetime.now()
    # Derive UTC from the same local instant, not a second sample at a boundary.
    local_ticks = (
        (local.toordinal() - 1) * 86400
        + local.hour * 3600
        + local.minute * 60
        + local.second
    ) * 10000000 + local.microsecond * 10
    universal = datetime.datetime(1601, 1, 1) + datetime.timedelta(
        microseconds=uformat.native_time.local_ticks_to_file_time(local_ticks) // 10
    )
    offset_minutes = int((local - universal).total_seconds() // 60)
    epoch = (universal - datetime.datetime(1970, 1, 1)).total_seconds()
    return {
        "date": local.strftime("%Y-%m-%d"),
        "day": local.strftime("%d"),
        "epoch_local": uformat.format_date(local, "+%s"),
        "epoch": uformat.format_date(universal, "+%s"),
        "epoch_int": round(epoch),
        "hour": local.strftime("%H"),
        "iso8601": universal.strftime("%Y-%m-%dT%H:%M:%SZ"),
        "iso8601_basic": local.strftime("%Y%m%dT%H%M%S%f"),
        "iso8601_basic_short": local.strftime("%Y%m%dT%H%M%S"),
        "iso8601_micro": universal.strftime("%Y-%m-%dT%H:%M:%S.%fZ"),
        "minute": local.strftime("%M"),
        "month": local.strftime("%m"),
        "second": local.strftime("%S"),
        "time": local.strftime("%H:%M:%S"),
        "tz": _timezone_id(),
        "tz_offset": "{0}{1:02d}:{2:02d}".format(
            "-" if offset_minutes < 0 else "+",
            abs(offset_minutes) // 60,
            abs(offset_minutes) % 60,
        ),
        "weekday": (
            "Monday",
            "Tuesday",
            "Wednesday",
            "Thursday",
            "Friday",
            "Saturday",
            "Sunday",
        )[local.weekday()],
        "weekday_number": uformat.format_date(local, "%w"),
        "weeknumber": uformat.format_date(local, "%W"),
        "year": local.strftime("%Y"),
    }
