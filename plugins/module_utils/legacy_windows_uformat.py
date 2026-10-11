# -*- coding: utf-8 -*-
# Copyright 2026 sustainablelobster
# SPDX-License-Identifier: GPL-3.0-or-later

"""Format listener process dates using the Windows PowerShell 5.1 UFormat rules."""

import ctypes
import datetime
import decimal
import re

# Sibling helpers are staged beside the Python 3.4 target payload.
# pylint: disable=import-error
import legacy_windows_calendar as calendar
import legacy_windows_time as native_time

# pylint: enable=import-error

_SECOND = 10000000
_DAY = 86400 * _SECOND
_FILETIME_EPOCH = 504911232000000000
_UNIX_EPOCH = datetime.datetime(1970, 1, 1)
_FORMAT_ERROR = "Input string was not in a correct format."
_UFORMAT_PATTERNS = {
    "A": "dddd",
    "a": "ddd",
    "B": "MMMM",
    "b": "MMM",
    "h": "MMM",
    "D": "MM/dd/yy",
    "d": "dd",
    "H": "HH",
    "I": "hh",
    "k": "HH",
    "l": "hh",
    "M": "mm",
    "m": "MM",
    "p": "tt",
    "R": "HH:mm",
    "r": "hh:mm:ss tt",
    "S": "ss",
    "T": "HH:mm:ss",
    "X": "HH:mm:ss",
    "G": "yyyy",
    "g": "yy",
    "x": "MM/dd/yy",
    "y": "yy",
    "Y": "yyyy",
    "Z": "zz",
}


def _number_symbols():
    kernel = ctypes.WinDLL("kernel32", use_last_error=True)
    read = kernel.GetLocaleInfoW
    read.argtypes = [
        ctypes.c_uint32,
        ctypes.c_uint32,
        ctypes.c_wchar_p,
        ctypes.c_int,
    ]
    read.restype = ctypes.c_int
    result = []
    for field in (0xE, 0x50, 0x51):
        size = read(0x400, field, None, 0)
        if not size:
            raise ctypes.WinError(ctypes.get_last_error())
        buffer = ctypes.create_unicode_buffer(size)
        if not read(0x400, field, buffer, size):
            raise ctypes.WinError(ctypes.get_last_error())
        result.append(buffer.value)
    return result[0], result[1] or "+", result[2]


def _seconds(value):
    delta = value - _UNIX_EPOCH
    ticks = (delta.days * 86400 + delta.seconds) * _SECOND
    ticks += delta.microseconds * 10
    # Framework TimeSpan.TotalSeconds multiplies ticks before Double's G15
    # formatting. JSON argument conversion has different Decimal semantics.
    with decimal.localcontext() as context:
        context.prec = 15
        context.rounding = decimal.ROUND_HALF_UP
        number = +decimal.Decimal.from_float(ticks * 0.0000001)
    if -4 <= number.adjusted() < 15:
        text = format(number, "f")
        if "." in text:
            text = text.rstrip("0").rstrip(".")
    else:
        mantissa, exponent = format(number, "E").split("E")
        if "." in mantissa:
            mantissa = mantissa.rstrip("0").rstrip(".")
        text = mantissa + "E" + format(int(exponent), "+03d")
    separator, positive, negative = _number_symbols()
    return text.translate(str.maketrans({".": separator, "+": positive, "-": negative}))


def _local_ticks(value):
    ticks = (value.toordinal() - 1) * _DAY
    ticks += (value.hour * 3600 + value.minute * 60 + value.second) * _SECOND
    return ticks + value.microsecond * 10


def _offset(value):
    ticks = _local_ticks(value)
    universal = native_time.local_ticks_to_file_time(ticks) + _FILETIME_EPOCH
    return (ticks - universal) // (_SECOND * 60)


def _datetime_from_ticks(ticks):
    days, remainder = divmod(ticks, _DAY)
    return datetime.datetime.fromordinal(days + 1) + datetime.timedelta(
        microseconds=remainder // 10
    )


def _timezone(value, width, time_only):
    if time_only and value.toordinal() == 1:
        value = _datetime_from_ticks(native_time.current_local_ticks())
    offset = _offset(value)
    hours, minutes = divmod(abs(offset), 60)
    result = ("-" if offset < 0 else "+") + str(hours).zfill(min(width, 2))
    return result + ":{0:02d}".format(minutes) if width >= 3 else result


def _invariant_culture():
    months = (
        "January February March April May June July August September October "
        "November December"
    ).split() + [""]
    days = "Sunday Monday Tuesday Wednesday Thursday Friday Saturday".split()
    return {
        "calendar_id": 1,
        "month_names": months,
        "month_abbreviations": [name[:3] for name in months],
        "day_names": days,
        "day_abbreviations": [name[:3] for name in days],
        "date_separator": "/",
        "time_separator": ":",
        "am": "AM",
        "pm": "PM",
    }


def _culture_field(culture, name):
    value = culture[name]
    if value is None:
        raise NotImplementedError(
            "This Windows version does not provide the {0} locale field "
            "required by date_uformat.".format(name)
        )
    return value


def _expand_pattern(value, pattern, culture):
    universal = False
    if not pattern:
        pattern = "G"
        if value.toordinal() == 1 and culture["calendar_id"] in (3, 4, 6, 8, 22, 23):
            pattern = "s"
    if len(pattern) != 1:
        return value, pattern, culture, universal
    fixed = {
        "o": "yyyy'-'MM'-'dd'T'HH':'mm':'ss.fffffffK",
        "O": "yyyy'-'MM'-'dd'T'HH':'mm':'ss.fffffffK",
        "r": "ddd, dd MMM yyyy HH':'mm':'ss 'GMT'",
        "R": "ddd, dd MMM yyyy HH':'mm':'ss 'GMT'",
        "s": "yyyy'-'MM'-'dd'T'HH':'mm':'ss",
        "u": "yyyy'-'MM'-'dd HH':'mm':'ss'Z'",
    }
    if pattern in fixed:
        return value, fixed[pattern], _invariant_culture(), universal
    if pattern == "U":
        ticks = (
            native_time.local_ticks_to_file_time(_local_ticks(value)) + _FILETIME_EPOCH
        )
        value = _datetime_from_ticks(ticks)
        culture = calendar.get_culture(culture["name"], calendar_id=1)
        pattern, universal = "F", True
    components = {
        "d": ("short_date",),
        "D": ("long_date",),
        "f": ("long_date", "short_time"),
        "F": ("full_datetime",),
        "g": ("short_date", "short_time"),
        "G": ("short_date", "long_time"),
        "m": ("month_day",),
        "M": ("month_day",),
        "t": ("short_time",),
        "T": ("long_time",),
        "y": ("year_month",),
        "Y": ("year_month",),
    }
    if pattern not in components:
        raise ValueError("Input string was not in a correct format.")
    return (
        value,
        " ".join(_culture_field(culture, key) for key in components[pattern]),
        culture,
        universal,
    )


def _date_part(value, token, count, culture, pattern):
    if token == "d" and count >= 3:
        names = "day_abbreviations" if count == 3 else "day_names"
        return culture[names][(value.weekday() + 1) % 7]
    year, month, day, era = calendar.calendar_fields(culture, value.date())
    if token == "g":
        return next(
            entry["name"] for entry in culture["eras"] if entry["number"] == era
        )
    if token == "M" and count >= 3:
        field = "month_abbreviations" if count == 3 else "month_names"
        if count >= 4 and re.search(r"(?<!d)dd?(?!d)", pattern):
            field = "month_genitive"
        if culture["calendar_id"] == 8 and month >= 7 and (year * 7 + 1) % 19 >= 7:
            month += 1
        return _culture_field(culture, field)[month - 1]
    if culture["calendar_id"] == 8:
        parts = calendar.format_alternative_date(8, value.date()).split("-")
        return parts[{"y": 0, "M": 1, "d": 2}[token]]
    if token == "y":
        if culture["calendar_id"] in (3, 4):
            count = min(count, 2)
        elif count <= 2:
            year %= 100
        return str(year).zfill(count)
    return str(month if token == "M" else day).zfill(min(count, 2))


def _quoted_literal(pattern, index):
    quote = pattern[index]
    index += 1
    literal = []
    while index < len(pattern) and pattern[index] != quote:
        if pattern[index] == "\\":
            index += 1
        if index == len(pattern):
            raise ValueError(_FORMAT_ERROR)
        literal.append(pattern[index])
        index += 1
    if index == len(pattern):
        raise ValueError(_FORMAT_ERROR)
    return "".join(literal), index + 1


def _date_tokens(pattern):
    # Width zero identifies a quoted or escaped literal, never a date field.
    index = 0
    while index < len(pattern):
        token = pattern[index]
        index += 1
        count = 1
        if token == "%":
            if index == len(pattern) or pattern[index] == "%":
                raise ValueError(_FORMAT_ERROR)
            token, index = pattern[index], index + 1
        elif token in "gHhmsfFtdMyz":
            while index < len(pattern) and pattern[index] == token:
                count, index = count + 1, index + 1
        if token in ("'", '"'):
            literal, index = _quoted_literal(pattern, index - 1)
            yield literal, 0
        elif token == "\\":
            if index == len(pattern):
                raise ValueError(_FORMAT_ERROR)
            yield pattern[index], 0
            index += 1
        else:
            yield token, count


def _time_part(value, token, count, culture, universal):
    if token in "hHms":
        number = {
            "h": value.hour % 12 or 12,
            "H": value.hour,
            "m": value.minute,
            "s": value.second,
        }[token]
        return str(number).zfill(min(count, 2))
    if token in "fF":
        if count > 7:
            raise ValueError(_FORMAT_ERROR)
        text = "{0:07d}".format(value.microsecond * 10)[:count]
        return text.rstrip("0") if token == "F" else text
    if token == "t":
        text = culture["am" if value.hour < 12 else "pm"]
        return text[:1] if count == 1 else text
    if token == "K":
        return "Z" if universal else _timezone(value, 3, False)
    if token in "/:":
        return culture["date_separator" if token == "/" else "time_separator"]
    return token


def _custom_date(value, pattern, culture, universal=False):
    result = []
    time_only = True
    for token, count in _date_tokens(pattern):
        if not count:
            text = token
        elif token in "dMyg":
            text = _date_part(value, token, count, culture, pattern)
            if token != "g":
                time_only = False
        elif token == "z":
            text = _timezone(value, count, time_only)
        else:
            text = _time_part(value, token, count, culture, universal)
        if token == "F" and not text and result and result[-1].endswith("."):
            result[-1] = result[-1][:-1]
        result.append(text)
    return "".join(result)


def _item_pattern(pattern, index):
    custom = []
    if pattern[index] == ":":
        index += 1
        while index < len(pattern):
            token = pattern[index]
            if token in "{}":
                if pattern[index : index + 2] == token * 2:
                    custom.append(token)
                    index += 2
                    continue
                if token == "{":
                    raise ValueError(_FORMAT_ERROR)
                break
            custom.append(token)
            index += 1
    if index >= len(pattern) or pattern[index] != "}":
        raise ValueError(_FORMAT_ERROR)
    return "".join(custom), index + 1


def _composite_item(value, pattern, index, culture):
    header = re.match(r"([0-9]+) *(?:, *(-?[0-9]+) *)?(?=[:}])", pattern[index:])
    if header is None:
        raise ValueError(_FORMAT_ERROR)
    if int(header.group(1)) != 0:
        raise ValueError(
            "Index (zero based) must be greater than or equal to zero and "
            "less than the size of the argument list."
        )
    custom, index = _item_pattern(pattern, index + header.end())
    date, expanded, selected, universal = _expand_pattern(value, custom, culture)
    text = _custom_date(date, expanded, selected, universal)
    alignment = int(header.group(2) or "0")
    if alignment:
        # Composite alignment counts UTF-16 units, as String.Length does.
        width = len(text.encode("utf-16-le", "surrogatepass")) // 2
        padding = " " * max(0, abs(alignment) - width)
        text = text + padding if alignment < 0 else padding + text
    return text, index


def _composite(value, pattern, culture):
    result = []
    index = 0
    while index < len(pattern):
        token = pattern[index]
        index += 1
        if token not in "{}":
            result.append(token)
        elif pattern[index : index + 1] == token:
            result.append(token)
            index += 1
        elif token == "}":
            raise ValueError(_FORMAT_ERROR)
        else:
            text, index = _composite_item(value, pattern, index, culture)
            result.append(text)
    return "".join(result)


def _uformat_pattern(value, format_string):
    day_of_year = value.toordinal() - datetime.date(value.year, 1, 1).toordinal() + 1
    fields = {
        "C": str(value.year // 100),
        "e": "{0:2d}".format(value.day),
        "j": str(day_of_year),
        "u": str((value.weekday() + 1) % 7),
        "U": str(day_of_year // 7),
        "V": str(day_of_year // 7 + 1),
        "n": "\n",
        "t": "\t",
    }
    for alias, original in (("W", "U"), ("w", "u")):
        fields[alias] = fields[original]
    result = []
    index = 1 if format_string.startswith("+") else 0
    while index < len(format_string):
        code = format_string[index]
        index += 1
        if code == "%":
            if index == len(format_string):
                raise ValueError("Index was outside the bounds of the array.")
            code = format_string[index]
            if code in _UFORMAT_PATTERNS:
                code = "{0:" + _UFORMAT_PATTERNS[code] + "}"
            elif code == "c":
                code = (
                    "{0:ddd} {0:MMM} "
                    + "{0:2d}".format(value.day)
                    + " {0:HH}:{0:mm}:{0:ss} {0:yyyy}"
                )
            elif code == "s":
                code = _seconds(value)
            else:
                code = fields.get(code, code)
            index += 1
        result.append(code)
    return "".join(result)


def format_date(value, format_string):
    """Render a local process creation date with the upstream UFormat syntax.

    :param value: Naive local process creation datetime, or None if unavailable.
    :type value: datetime.datetime or None
    :param format_string: Windows PowerShell 5.1 UFormat pattern, or None for
        the upstream JSON serialization of the unchanged local DateTime.
    :type format_string: str or None
    :returns: Formatted process creation time, retaining an unavailable date.
    :rtype: str or None
    :raises ValueError: If the date or format is invalid.
    :raises OSError: If Windows cannot read culture or timezone information.
    :raises NotImplementedError: If Windows lacks the selected calendar API or
        locale metadata required by the format. Missing patterns and names are
        identified explicitly, not substituted from another culture.
    """
    if value is None:
        return None
    if not isinstance(value, datetime.datetime) or value.tzinfo is not None:
        raise ValueError("Process creation date must be a naive local datetime.")
    if format_string is None:
        universal = native_time.local_ticks_to_file_time(_local_ticks(value))
        epoch_ticks = universal - 116444736000000000
        milliseconds = abs(epoch_ticks) // 10000
        if epoch_ticks < 0:
            milliseconds = -milliseconds
        return "/Date({0})/".format(milliseconds)
    if not isinstance(format_string, str) or not format_string:
        raise ValueError("Index was outside the bounds of the array.")
    pattern = _uformat_pattern(value, format_string)
    return _composite(value, pattern, calendar.get_culture())
