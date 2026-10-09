# -*- coding: utf-8 -*-
# Copyright 2026 Joe Lustri
# SPDX-License-Identifier: GPL-3.0-or-later

"""Convert local user expiration dates with WinNT provider storage semantics."""

import ctypes
import os

_SECOND = 10000000
_DAY = 86400 * _SECOND
_MILLISECONDS_PER_DAY = 86400000
_FILETIME_EPOCH = 504911232000000000
_UNIX_EPOCH = 621355968000000000
_OLE_EPOCH = 599264352000000000
_OLE_MINIMUM = 31241376000000000
_MAX_TICKS = 3155378975999999999
_NEVER = 0xFFFFFFFF


# Keep these fixed Windows layouts beside the expiration API signatures;
# sharing private ctypes records with the timezone helper would couple them.
# pylint: disable=duplicate-code
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


# pylint: enable=duplicate-code


def _kernel():
    if os.name != "nt":
        raise ValueError("Account expiration conversion requires a Windows target.")
    kernel = ctypes.WinDLL("kernel32", use_last_error=True)
    kernel.SystemTimeToFileTime.argtypes = [
        ctypes.POINTER(_SystemTime),
        ctypes.POINTER(_FileTime),
    ]
    kernel.SystemTimeToFileTime.restype = ctypes.c_int
    for name in ("LocalFileTimeToFileTime", "FileTimeToLocalFileTime"):
        function = getattr(kernel, name)
        function.argtypes = [ctypes.POINTER(_FileTime), ctypes.POINTER(_FileTime)]
        function.restype = ctypes.c_int
    return kernel


def _ole_date(local_ticks):
    if not isinstance(local_ticks, int) or not 0 <= local_ticks <= _MAX_TICKS:
        raise ValueError("Local timestamp must be between years 1 and 9999.")
    # DateTime's first day represents a time on the Automation epoch instead.
    if local_ticks < _DAY:
        local_ticks += _OLE_EPOCH
    elif local_ticks < _OLE_MINIMUM:
        raise ValueError("Not a legal OleAut date.")
    distance = local_ticks - _OLE_EPOCH
    # Truncate toward zero before converting to floating point, including
    # negative distances with sub-millisecond fractions.
    milliseconds = abs(distance) // 10000
    if distance < 0:
        milliseconds = -milliseconds
        # Automation's negative dates have a reflected time-of-day fraction.
        milliseconds -= 2 * (milliseconds % _MILLISECONDS_PER_DAY)
    return milliseconds / float(_MILLISECONDS_PER_DAY)


def account_expiration_seconds(local_ticks):
    """Convert a desired local expiration date to the value stored by WinNT.

    Native Automation conversion rounds fractional seconds. The current
    timezone bias, not the desired date's seasonal bias, determines UTC.
    Dates outside the provider's finite range become the never-expire sentinel.
    Call this before deciding whether check mode suppresses an account write:
    invalid Automation and FILETIME dates fail while preparing the property.

    :param local_ticks: Integer 100-nanosecond units since 0001-01-01 local time.
    :type local_ticks: int
    :returns: UTC Unix seconds or the never-expire value ``0xffffffff``.
    :rtype: int
    :raises ValueError: If ticks are invalid or cannot represent an Automation date.
    :raises OSError: If Windows cannot convert the date or apply its current bias.
    """
    automation_date = _ole_date(local_ticks)
    kernel = _kernel()
    automation = ctypes.WinDLL("oleaut32", use_last_error=True)
    automation.VariantTimeToSystemTime.argtypes = [
        ctypes.c_double,
        ctypes.POINTER(_SystemTime),
    ]
    automation.VariantTimeToSystemTime.restype = ctypes.c_int
    system = _SystemTime()
    if not automation.VariantTimeToSystemTime(automation_date, ctypes.byref(system)):
        raise ValueError("Not a legal OleAut date.")
    local = _FileTime()
    if not kernel.SystemTimeToFileTime(ctypes.byref(system), ctypes.byref(local)):
        raise ctypes.WinError(ctypes.get_last_error())
    universal = _FileTime()
    if not kernel.LocalFileTimeToFileTime(ctypes.byref(local), ctypes.byref(universal)):
        raise ctypes.WinError(ctypes.get_last_error())
    ticks = (universal.high << 32) | universal.low
    seconds = (ticks + _FILETIME_EPOCH - _UNIX_EPOCH) // _SECOND
    # WinNT reserves one day at both ends when assigning this property. Reading
    # a value written directly through NetAPI does not apply the same margin.
    return seconds if 86400 < seconds < _NEVER - 86400 else _NEVER


def account_expiration_ticks(seconds):
    """Read a stored expiration as local wall-clock ticks without a UTC suffix.

    The WinNT provider applies the current timezone bias on readback. Only
    ``0xffffffff`` means never; every other unsigned DWORD represents a date,
    including values which the provider would not itself store on assignment.

    :param seconds: Unsigned DWORD UTC Unix seconds returned by NetAPI.
    :type seconds: int
    :returns: Local 100-nanosecond ticks since year 1, or ``None`` for never.
    :rtype: int or None
    :raises ValueError: If seconds are not an unsigned DWORD.
    :raises OSError: If Windows cannot apply its current timezone bias.
    """
    if not isinstance(seconds, int) or not 0 <= seconds <= _NEVER:
        raise ValueError("Account expiration must be an unsigned DWORD.")
    if seconds == _NEVER:
        return None
    ticks = seconds * _SECOND + _UNIX_EPOCH - _FILETIME_EPOCH
    universal = _FileTime(ticks & 0xFFFFFFFF, ticks >> 32)
    local = _FileTime()
    if not _kernel().FileTimeToLocalFileTime(
        ctypes.byref(universal), ctypes.byref(local)
    ):
        raise ctypes.WinError(ctypes.get_last_error())
    return ((local.high << 32) | local.low) + _FILETIME_EPOCH
