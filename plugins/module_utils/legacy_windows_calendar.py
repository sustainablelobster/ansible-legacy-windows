# -*- coding: utf-8 -*-
# Copyright 2026 sustainablelobster
# SPDX-License-Identifier: GPL-3.0-or-later AND MIT

"""Read Windows account calendars and convert or format their dates."""

import ctypes
import datetime
import locale
import os

try:
    import winreg
except ImportError:
    winreg = None

_GREGORIAN_CALENDARS = (1, 2, 9, 10, 11, 12)
_YEAR_OFFSETS = {4: -1911, 5: 2333, 7: 543}
_INVALID_FLAGS = 1004
_INVALID_PARAMETER = 87


# These structures describe the Windows ABI; methods would obscure their layout.
class _SystemTime(ctypes.Structure):  # pylint: disable=too-few-public-methods
    _fields_ = [
        (name, ctypes.c_uint16)
        for name in (
            "year",
            "month",
            "weekday",
            "day",
            "hour",
            "minute",
            "second",
            "millisecond",
        )
    ]


class _CalendarTime(ctypes.Structure):  # pylint: disable=too-few-public-methods
    _fields_ = [
        (name, ctypes.c_uint32)
        for name in (
            "calendar",
            "era",
            "year",
            "month",
            "day",
            "weekday",
            "hour",
            "minute",
            "second",
            "tick",
        )
    ]


def _kernel():
    if os.name != "nt":
        raise ValueError("Account calendar information requires a Windows target.")
    kernel = ctypes.WinDLL("kernel32", use_last_error=True)
    # Keep this independently staged wrapper's native ABI declarations local.
    # pylint: disable=duplicate-code
    kernel.GetUserDefaultLCID.restype = ctypes.c_uint32
    kernel.GetLocaleInfoW.argtypes = [
        ctypes.c_uint32,
        ctypes.c_uint32,
        ctypes.c_wchar_p,
        ctypes.c_int,
    ]
    kernel.GetCalendarInfoW.argtypes = [
        ctypes.c_uint32,
        ctypes.c_uint32,
        ctypes.c_uint32,
        ctypes.c_wchar_p,
        ctypes.c_int,
        ctypes.c_void_p,
    ]
    # pylint: enable=duplicate-code
    if hasattr(kernel, "GetLocaleInfoEx"):
        # Keep this independently staged wrapper's native ABI declarations local.
        # pylint: disable=duplicate-code
        kernel.GetLocaleInfoEx.argtypes = [
            ctypes.c_wchar_p,
            ctypes.c_uint32,
            ctypes.c_wchar_p,
            ctypes.c_int,
        ]
        kernel.GetCalendarInfoEx.argtypes = [
            ctypes.c_wchar_p,
            ctypes.c_uint32,
            ctypes.c_wchar_p,
            ctypes.c_uint32,
            ctypes.c_wchar_p,
            ctypes.c_int,
            ctypes.c_void_p,
        ]
        # pylint: enable=duplicate-code
    return kernel


def _locale_selector(kernel, name):
    if name is None:
        # LOCALE_USER_DEFAULT also identifies supplemental user locales on Vista+.
        return 0x400
    if hasattr(kernel, "GetLocaleInfoEx"):
        return name
    normalized = name.lower().replace("-", "_")
    for locale_id, windows_name in locale.windows_locale.items():
        if windows_name.lower() == normalized:
            return locale_id
    raise ValueError("Windows does not identify locale {0!r}.".format(name))


def _read_string(function, arguments, optional=False, calendar=False):
    suffix = (None,) if calendar else ()
    length = function(*(arguments + (None, 0) + suffix))
    if not length:
        error = ctypes.get_last_error()
        if optional and error in (_INVALID_FLAGS, _INVALID_PARAMETER):
            return None
        raise ctypes.WinError(error)
    value = ctypes.create_unicode_buffer(length)
    if not function(*(arguments + (value, length) + suffix)):
        raise ctypes.WinError(ctypes.get_last_error())
    return value.value


def _locale_value(kernel, selected_locale, info, optional=False):
    function = (
        kernel.GetLocaleInfoEx
        if isinstance(selected_locale, str)
        else kernel.GetLocaleInfoW
    )
    return _read_string(function, (selected_locale, info), optional)


def _calendar_value(kernel, selected_locale, calendar_id, info, optional=False):
    if isinstance(selected_locale, str):
        function = kernel.GetCalendarInfoEx
        arguments = (selected_locale, calendar_id, None, info)
    else:
        function = kernel.GetCalendarInfoW
        arguments = (selected_locale, calendar_id, info)
    return _read_string(function, arguments, optional, calendar=True)


def _pattern(native_pattern):
    if native_pattern is None:
        return None
    result = []
    quoted = False
    index = 0
    while index < len(native_pattern):
        character = native_pattern[index]
        if character == "\\":
            result.append("\\\\")
        elif character == "'":
            if quoted and native_pattern[index : index + 2] == "''":
                result.append("\\'")
                index += 1
            else:
                quoted = not quoted
                result.append(character)
        else:
            result.append(character)
        index += 1
    return "".join(result)


def _separator(pattern, fields):
    quoted = False
    escaped = False
    first = None
    separator = []
    for character in pattern:
        if escaped:
            if first is not None:
                separator.append(character)
            escaped = False
        elif character == "\\":
            escaped = True
        elif character == "'":
            quoted = not quoted
        elif not quoted and character in fields:
            if first is None:
                first = character
            elif character != first or separator:
                return "".join(separator)
        elif first is not None:
            separator.append(character)
    return ""


def _month_names(kernel, selected_locale, calendar_id, abbreviated, genitive):
    first = 0x22 if abbreviated else 0x15
    if genitive:
        first |= 0x10000000
    names = [
        _calendar_value(
            kernel, selected_locale, calendar_id, first + index, optional=genitive
        )
        for index in range(13)
    ]
    return None if any(name is None for name in names) else names


def _era_names(kernel, selected_locale, calendar_id, culture_name):
    if calendar_id == 3:
        # Japanese era numbers increase from the oldest era. The native
        # enumeration supplies names in reverse chronological order.
        callback_type = ctypes.WINFUNCTYPE(ctypes.c_int, ctypes.c_wchar_p)
        eras = []

        @callback_type
        def _collect(value):
            eras.append(value)
            return 1

        kernel.EnumCalendarInfoW.argtypes = [
            callback_type,
            ctypes.c_uint32,
            ctypes.c_uint32,
            ctypes.c_uint32,
        ]
        if not kernel.EnumCalendarInfoW(_collect, 0x411, calendar_id, 4):
            raise ctypes.WinError(ctypes.get_last_error())
        return [
            {"number": index + 1, "name": name, "abbreviation": name[:1]}
            for index, name in enumerate(reversed(eras))
        ]
    name = _calendar_value(kernel, selected_locale, calendar_id, 4, optional=True)
    abbreviation = _calendar_value(
        kernel, selected_locale, calendar_id, 0x39, optional=True
    )
    # These fixed names are part of the upstream calendar's public contract,
    # rather than OS translations (which differ for these calendars).
    if calendar_id in (6, 23):
        name, abbreviation = (
            ("ހިޖްރީ", "ހ.") if culture_name == "dv-MV" else ("بعد الهجرة", "هـ")
        )
    elif calendar_id == 7:
        name = abbreviation = "พ.ศ."
    elif calendar_id == 5:
        name = abbreviation = "단기"
    elif calendar_id == 8:
        name = abbreviation = "C.E."
    elif calendar_id == 2:
        name, abbreviation = "A.D.", "AD"
    elif calendar_id == 9:
        name = abbreviation = "ap. J.-C."
    elif calendar_id in (10, 11, 12):
        name = abbreviation = "م"
    return [{"number": 1, "name": name, "abbreviation": abbreviation}]


def get_culture(name=None, calendar_id=None):
    """Read date parsing metadata from the target account's Windows settings.

    :param name: Windows culture name, or None for the current account.
    :type name: str or None
    :param calendar_id: Native calendar ID, or None for the selected calendar.
    :type calendar_id: int or None
    :returns: Calendar identifiers, patterns, separators, names, eras, and the
        two-digit year cutoff. Fields unavailable through the host's NLS APIs
        are None; they are never filled with a different culture's data.
    :rtype: dict
    :raises ValueError: If the target is not Windows or a locale is unknown.
    :raises OSError: If Windows cannot read required culture information.
    """
    kernel = _kernel()
    selected = _locale_selector(kernel, name)
    default_calendar = int(_locale_value(kernel, selected, 0x1009))
    calendar_id = default_calendar if calendar_id is None else calendar_id
    culture_name = _locale_value(kernel, selected, 0x5C, optional=True)
    if culture_name is None:
        culture_name = "{0}-{1}".format(
            _locale_value(kernel, selected, 0x59),
            _locale_value(kernel, selected, 0x5A),
        )
    result = {
        "name": culture_name,
        "lcid": int(_locale_value(kernel, selected, 1), 16),
        "calendar_id": calendar_id,
        "two_digit_year_max": int(_calendar_value(kernel, selected, calendar_id, 0x30)),
        "am": _locale_value(kernel, selected, 0x28),
        "pm": _locale_value(kernel, selected, 0x29),
        "long_time": _pattern(_locale_value(kernel, selected, 0x1003)),
        "short_time": _pattern(_locale_value(kernel, selected, 0x79, optional=True)),
        "month_day": _pattern(
            _calendar_value(kernel, selected, calendar_id, 0x38, optional=True)
        ),
    }
    for field, locale_info, calendar_info in (
        ("short_date", 0x1F, 5),
        ("long_date", 0x20, 6),
        ("year_month", 0x1006, 0x2F),
    ):
        native_pattern = (
            _locale_value(kernel, selected, locale_info)
            if name is None and calendar_id == default_calendar
            else _calendar_value(kernel, selected, calendar_id, calendar_info)
        )
        result[field] = _pattern(native_pattern)
    result["full_datetime"] = result["long_date"] + " " + result["long_time"]
    result["date_separator"] = (
        "/" if calendar_id == 3 else _separator(result["short_date"], "dyM")
    )
    result["time_separator"] = _separator(result["long_time"], "Hhms")
    for field, abbreviated, genitive in (
        ("month_names", False, False),
        ("month_abbreviations", True, False),
        ("month_genitive", False, True),
        ("abbreviated_genitive", True, True),
    ):
        if genitive and calendar_id != 1:
            source = "month_abbreviations" if abbreviated else "month_names"
            result[field] = list(result[source])
        else:
            result[field] = _month_names(
                kernel, selected, calendar_id, abbreviated, genitive
            )
    for field, first in (("day_names", 7), ("day_abbreviations", 0xE)):
        result[field] = [
            _calendar_value(kernel, selected, calendar_id, first + index)
            for index in (6, 0, 1, 2, 3, 4, 5)
        ]
    result["eras"] = _era_names(kernel, selected, calendar_id, culture_name)
    if calendar_id == 6:
        result["hijri_adjustment"] = _hijri_adjustment()
    return result


def names_equal(culture, left, right):
    """Compare parsed names using the account locale's case-insensitive rules.

    :param culture: Metadata returned by get_culture.
    :type culture: dict
    :param left: Parsed substring to compare.
    :type left: str
    :param right: Calendar name to compare against.
    :type right: str
    :returns: Whether Windows considers the names equal ignoring case.
    :rtype: bool
    :raises OSError: If Windows cannot perform the comparison.
    """
    if not left or not right:
        return left == right
    compare = _kernel().CompareStringW
    # This fixed NLS signature is also used by filename matching; declaring it
    # locally keeps calendar parsing independent of that separately staged helper.
    # pylint: disable=duplicate-code
    compare.argtypes = [
        ctypes.c_uint32,
        ctypes.c_uint32,
        ctypes.c_wchar_p,
        ctypes.c_int,
        ctypes.c_wchar_p,
        ctypes.c_int,
    ]
    # pylint: enable=duplicate-code
    # Windows counts UTF-16 units, including both halves of supplementary text.
    left_length = len(left.encode("utf-16-le", "surrogatepass")) // 2
    right_length = len(right.encode("utf-16-le", "surrogatepass")) // 2
    result = compare(culture["lcid"], 1, left, left_length, right, right_length)
    if result == 0:
        raise ctypes.WinError(ctypes.get_last_error())
    return result == 2


def expand_year(culture, year):
    """Expand a two-digit year using the selected calendar's account cutoff.

    :param culture: Metadata returned by get_culture.
    :type culture: dict
    :param year: Parsed nonnegative year.
    :type year: int
    :returns: Calendar year after two-digit expansion, if applicable.
    :rtype: int
    :raises ValueError: If the year is negative.
    """
    if year < 0:
        raise ValueError("Calendar year cannot be negative.")
    if year >= 100 or culture["calendar_id"] in (3, 4):
        return year
    cutoff = culture["two_digit_year_max"]
    return (cutoff // 100 - int(year > cutoff % 100)) * 100 + year


def _hijri_adjustment():
    try:
        with winreg.OpenKey(
            winreg.HKEY_CURRENT_USER, "Control Panel\\International"
        ) as key:
            value, _ = winreg.QueryValueEx(key, "AddHijriDate")
    except FileNotFoundError:
        return 0
    value = str(value).lower()
    if value == "addhijridate":
        return -1
    if not value.startswith("addhijridate"):
        return 0
    try:
        adjustment = int(value[12:])
    except ValueError:
        return 0
    return adjustment if -2 <= adjustment <= 2 else 0


def _hijri_first_day(year):
    # Eleven leap days occur in each 30-year cycle. The epoch is 622-07-18.
    return 227014 + 354 * (year - 1) + (3 + 11 * year) // 30


def _hijri_date(culture, year, month, day, era):
    if era not in (0, 1) or not 1 <= year <= 9666 or not 1 <= month <= 12:
        raise ValueError("Hijri calendar year, month, or era is invalid.")
    if year == 9666 and month > 4:
        raise ValueError("The date exceeds the Hijri calendar's last month.")
    days_in_month = 30 if month % 2 else 29
    if month == 12 and (year * 11 + 14) % 30 < 11:
        days_in_month = 30
    if not 1 <= day <= days_in_month:
        raise ValueError("The Hijri calendar day is invalid.")
    ordinal = _hijri_first_day(year) + 29 * (month - 1) + month // 2 + day - 1
    return datetime.date.fromordinal(ordinal - culture["hijri_adjustment"])


def _hijri_fields(culture, value):
    if value < datetime.date(622, 7, 18):
        raise ValueError("The date precedes the Hijri calendar's first day.")
    ordinal = value.toordinal() + culture["hijri_adjustment"]
    year = ((ordinal - 227014) * 30) // 10631 + 1
    while ordinal < _hijri_first_day(year):
        year -= 1
    while ordinal >= _hijri_first_day(year + 1):
        year += 1
    remaining = ordinal - _hijri_first_day(year)
    month = min(12, remaining * 2 // 59 + 1)
    while 29 * (month - 1) + month // 2 > remaining:
        month -= 1
    return year, month, remaining - 29 * (month - 1) - month // 2 + 1, 1


# The Hebrew postponement equations below adapt convertdate 2.4.0 hebrew.py,
# commit 5bccce4c5329340e09594ab8405c953d83130bb5, using integer ordinals.
# Copyright (c) 2014-2022 Neil Freeman; Copyright (c) 2016 fitnr.
# This adapted portion is MIT-licensed; see LICENSES/convertdate-MIT.txt.
def _hebrew_elapsed_days(year):
    months = (235 * year - 234) // 19
    parts = 12084 + 13753 * months
    days = 29 * months + parts // 25920
    return days + int(3 * (days + 1) % 7 < 3)


def _hebrew_first_day(year):
    days = _hebrew_elapsed_days(year)
    if _hebrew_elapsed_days(year + 1) - days == 356:
        days += 2
    elif days - _hebrew_elapsed_days(year - 1) == 382:
        days += 1
    return days - 1373427


def _hebrew_month_lengths(year):
    days_in_year = _hebrew_first_day(year + 1) - _hebrew_first_day(year)
    lengths = [
        30,
        30 if days_in_year % 10 == 5 else 29,
        29 if days_in_year % 10 == 3 else 30,
        29,
        30,
    ]
    if (year * 7 + 1) % 19 < 7:
        lengths.append(30)
    return lengths + [29, 30, 29, 30, 29, 30, 29]


def _hebrew_range(value):
    if not datetime.date(1583, 1, 1) <= value <= datetime.date(2239, 9, 29):
        raise ValueError("The date is outside the Hebrew calendar's supported range.")
    return value


def _hebrew_date(year, month, day, era):
    if era not in (0, 1) or not 5343 <= year <= 5999:
        raise ValueError("Hebrew calendar year or era is invalid.")
    lengths = _hebrew_month_lengths(year)
    if not 1 <= month <= len(lengths) or not 1 <= day <= lengths[month - 1]:
        raise ValueError("Hebrew calendar month or day is invalid.")
    ordinal = _hebrew_first_day(year) + sum(lengths[: month - 1]) + day - 1
    return _hebrew_range(datetime.date.fromordinal(ordinal))


def _hebrew_fields(value):
    ordinal = _hebrew_range(value).toordinal()
    year = value.year + 3760
    if ordinal >= _hebrew_first_day(year + 1):
        year += 1
    remaining = ordinal - _hebrew_first_day(year)
    for month, length in enumerate(_hebrew_month_lengths(year), 1):
        if remaining < length:
            return year, month, remaining + 1, 1
        remaining -= length
    raise ValueError("The date is outside the Hebrew calendar's supported range.")


def calendar_date(culture, year, month, day, era=0):
    """Convert a date in the selected calendar into a Gregorian date.

    :param culture: Metadata returned by get_culture.
    :type culture: dict
    :param year: Year in the selected calendar, already expanded if necessary.
    :type year: int
    :param month: Calendar month starting at one.
    :type month: int
    :param day: Calendar day starting at one.
    :type day: int
    :param era: Native era number, or zero for the current era.
    :type era: int
    :returns: The corresponding Gregorian date.
    :rtype: datetime.date
    :raises ValueError: If date fields or era are invalid.
    :raises NotImplementedError: If the host lacks native calendar conversion.
    """
    calendar_id = culture["calendar_id"]
    if calendar_id == 6:
        return _hijri_date(culture, year, month, day, era)
    if calendar_id == 8:
        return _hebrew_date(year, month, day, era)
    if calendar_id in _GREGORIAN_CALENDARS or calendar_id in _YEAR_OFFSETS:
        if era not in (0, 1) or year < 1:
            raise ValueError("Calendar year or era is invalid.")
        return datetime.date(year - _YEAR_OFFSETS.get(calendar_id, 0), month, day)
    if min(year, month, day) < 1 or era < 0 or max(year, month, day, era) > 0xFFFFFFFF:
        raise ValueError("Calendar date fields must be positive.")
    kernel = _kernel()
    if not hasattr(kernel, "ConvertCalDateTimeToSystemTime"):
        raise NotImplementedError(
            "This Windows version lacks native calendar conversion."
        )
    convert = kernel.ConvertCalDateTimeToSystemTime
    convert.argtypes = [ctypes.POINTER(_CalendarTime), ctypes.POINTER(_SystemTime)]
    if era == 0:
        era = max(value["number"] for value in culture["eras"])
    source = _CalendarTime(calendar_id, era, year, month, day)
    target = _SystemTime()
    update_weekday = kernel.UpdateCalendarDayOfWeek
    update_weekday.argtypes = [ctypes.POINTER(_CalendarTime)]
    if not update_weekday(ctypes.byref(source)):
        raise ValueError(
            "Windows rejected the calendar date (error {0}).".format(
                ctypes.get_last_error()
            )
        )
    if not convert(ctypes.byref(source), ctypes.byref(target)):
        raise ValueError(
            "Windows rejected the calendar date (error {0}).".format(
                ctypes.get_last_error()
            )
        )
    return datetime.date(target.year, target.month, target.day)


def calendar_fields(culture, gregorian_date):
    """Read calendar date fields for omitted components of a parsed date.

    :param culture: Metadata returned by get_culture.
    :type culture: dict
    :param gregorian_date: Gregorian date, usually the target's local today.
    :type gregorian_date: datetime.date
    :returns: A tuple of calendar year, month, day, and era.
    :rtype: tuple
    :raises ValueError: If the date is outside the selected calendar's range.
    :raises NotImplementedError: If the host lacks native calendar conversion.
    """
    calendar_id = culture["calendar_id"]
    if calendar_id == 6:
        return _hijri_fields(culture, gregorian_date)
    if calendar_id == 8:
        return _hebrew_fields(gregorian_date)
    if calendar_id in _GREGORIAN_CALENDARS or calendar_id in _YEAR_OFFSETS:
        year = gregorian_date.year + _YEAR_OFFSETS.get(calendar_id, 0)
        if year < 1:
            raise ValueError("The date precedes the selected calendar's first year.")
        return year, gregorian_date.month, gregorian_date.day, 1
    kernel = _kernel()
    if not hasattr(kernel, "ConvertSystemTimeToCalDateTime"):
        raise NotImplementedError(
            "This Windows version lacks native calendar conversion."
        )
    convert = kernel.ConvertSystemTimeToCalDateTime
    convert.argtypes = [
        ctypes.POINTER(_SystemTime),
        ctypes.c_uint32,
        ctypes.POINTER(_CalendarTime),
    ]
    source = _SystemTime(
        gregorian_date.year,
        gregorian_date.month,
        (gregorian_date.weekday() + 1) % 7,
        gregorian_date.day,
    )
    target = _CalendarTime()
    if not convert(ctypes.byref(source), calendar_id, ctypes.byref(target)):
        raise ValueError(
            "Windows rejected the calendar date (error {0}).".format(
                ctypes.get_last_error()
            )
        )
    return target.year, target.month, target.day, target.era


def format_alternative_date(calendar_id, gregorian_date):
    """Render a Japanese or Hebrew expiration date using native calendar data.

    :param calendar_id: Japanese calendar 3 or Hebrew calendar 8.
    :type calendar_id: int
    :param gregorian_date: Gregorian date to render in the selected calendar.
    :type gregorian_date: datetime.date
    :returns: The fixed yyyy-MM-dd date portion used in account expiration diffs.
    :rtype: str
    :raises ValueError: If the calendar ID is unsupported or its date is invalid.
    :raises OSError: If Windows cannot format the alternative calendar date.
    """
    if calendar_id == 8:
        _hebrew_range(gregorian_date)
        locale_id = 0x40D
    elif calendar_id == 3:
        if gregorian_date < datetime.date(1868, 9, 8):
            raise ValueError(
                "The date is outside the Japanese calendar's supported range."
            )
        locale_id = 0x411
    else:
        raise ValueError("Native expiration formatting requires Japanese or Hebrew.")
    kernel = _kernel()
    formatter = kernel.GetDateFormatW
    formatter.argtypes = [
        ctypes.c_uint32,
        ctypes.c_uint32,
        ctypes.POINTER(_SystemTime),
        ctypes.c_wchar_p,
        ctypes.c_wchar_p,
        ctypes.c_int,
    ]
    formatter.restype = ctypes.c_int
    date = _SystemTime(gregorian_date.year, gregorian_date.month, 0, gregorian_date.day)
    # Alternative formatting supplies native Hebrew numerals or Japanese era
    # years, including on XP where calendar-field conversion is unavailable.
    arguments = (locale_id, 4, ctypes.byref(date), "yyyy-MM-dd")
    size = formatter(*(arguments + (None, 0)))
    if not size:
        raise ctypes.WinError(ctypes.get_last_error())
    buffer = ctypes.create_unicode_buffer(size)
    if not formatter(*(arguments + (buffer, size))):
        raise ctypes.WinError(ctypes.get_last_error())
    return buffer.value
