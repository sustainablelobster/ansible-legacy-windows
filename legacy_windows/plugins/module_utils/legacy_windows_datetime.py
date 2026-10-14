# -*- coding: utf-8 -*-
# Copyright 2026 sustainablelobster
# SPDX-License-Identifier: GPL-3.0-or-later

"""Parse exact file timestamps and render local user account expiration dates."""

import datetime

# Target helpers are staged together, outside the controller's import path.
import legacy_windows_calendar as calendar  # pylint: disable=import-error
import legacy_windows_time as native_time  # pylint: disable=import-error

_SECOND = 10000000
_DAY = 86400 * _SECOND
_MAX_TICKS = 3155378975999999999
_ACCOUNT_EXPIRATION_FORMAT = "yyyy-MM-dd'T'HH:mm:ss.FFFFFFFK"


def _metadata(culture, key):
    value = culture[key]
    if value is None:
        raise NotImplementedError(
            "Windows does not expose {0} for culture {1!r} on this target.".format(
                key, culture["name"]
            )
        )
    return value


def _invariant_culture():
    # The parser's month-name data does not require the rendering helper.
    # pylint: disable=duplicate-code
    months = (
        "January February March April May June July August September October "
        "November December"
    ).split() + [""]
    # pylint: enable=duplicate-code
    days = "Sunday Monday Tuesday Wednesday Thursday Friday Saturday".split()
    return {
        "name": "",
        "lcid": 127,
        "calendar_id": 1,
        "calendar": "System.Globalization.GregorianCalendar",
        "two_digit_year_max": 2029,
        "date_separator": "/",
        "time_separator": ":",
        "am": "AM",
        "pm": "PM",
        "month_names": months,
        "month_abbreviations": [name[:3] for name in months],
        "month_genitive": months,
        "abbreviated_genitive": [name[:3] for name in months],
        "day_names": days,
        "day_abbreviations": [name[:3] for name in days],
        "eras": [{"number": 1, "name": "A.D.", "abbreviation": "AD"}],
    }


def _expand_format(pattern, culture):
    if len(pattern) != 1:
        return pattern, culture, None
    invariant = {
        "o": "yyyy-MM-dd'T'HH:mm:ss.fffffffK",
        "O": "yyyy-MM-dd'T'HH:mm:ss.fffffffK",
        "r": "ddd, dd MMM yyyy HH:mm:ss 'GMT'",
        "R": "ddd, dd MMM yyyy HH:mm:ss 'GMT'",
        "s": "yyyy-MM-dd'T'HH:mm:ss",
        "u": "yyyy-MM-dd HH:mm:ss'Z'",
    }
    if pattern in invariant:
        return invariant[pattern], _invariant_culture(), None
    if pattern == "U":
        culture = calendar.get_culture(culture["name"], calendar_id=1)
        return culture["full_datetime"], culture, 0
    # Keep the timestamp option mapping separate from date rendering.
    # pylint: disable=duplicate-code
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
    # pylint: enable=duplicate-code
    if pattern not in components:
        raise ValueError("Unknown standard timestamp format: " + pattern)
    return (
        " ".join(_metadata(culture, key) for key in components[pattern]),
        culture,
        None,
    )


# A single parse operation owns the cursor and fields; no other public operations
# are useful while a timestamp is only partially consumed.
class _TimestampParser:  # pylint: disable=too-few-public-methods
    def __init__(self, value, pattern, culture, offset):
        self.value = value
        self.pattern = pattern
        self.culture = culture
        self.position = 0
        self.fields = {} if offset is None else {"offset": offset}
        self.twelve_hour = False
        self.two_digit_year = False

    def _set(self, name, value):
        if name in self.fields and self.fields[name] != value:
            raise ValueError("Conflicting timestamp field: " + name)
        self.fields[name] = value

    def _literal(self, value):
        if not self.value.startswith(value, self.position):
            raise ValueError("Timestamp does not match its format.")
        self.position += len(value)

    def _number(self, minimum, maximum):
        start = self.position
        while (
            self.position - start < maximum
            and self.position < len(self.value)
            and "0" <= self.value[self.position] <= "9"
        ):
            self.position += 1
        digits = self.value[start : self.position]
        if len(digits) < minimum:
            raise ValueError("Timestamp has an invalid numeric field.")
        return int(digits) if digits else 0, len(digits)

    def _name(self, choices, initial=False):
        for text, number in sorted(
            choices, key=lambda pair: len(pair[0]), reverse=True
        ):
            candidate = self.value[self.position : self.position + len(text)]
            equal = (
                candidate == text
                if initial
                else calendar.names_equal(self.culture, candidate, text)
            )
            if equal:
                self.position += len(text)
                return number
        raise ValueError("Timestamp contains an unrecognized localized name.")

    def _offset(self, count):
        sign = self.value[self.position : self.position + 1]
        if sign not in ("+", "-"):
            raise ValueError("Timestamp offset requires a sign.")
        self.position += 1
        hours, _ = self._number(2 if count == 2 else 1, 2)
        minutes = 0
        if count >= 3:
            if self.value[self.position : self.position + 1] == ":":
                self.position += 1
            minutes, _ = self._number(2, 2)
            if minutes >= 60:
                raise ValueError("Timestamp offset minutes must be below 60.")
        self._set("offset", (hours * 60 + minutes) * (-1 if sign == "-" else 1))

    def _date(self, token, count):
        if token == "y":
            self.two_digit_year = self.two_digit_year or count <= 2
            minimum = 1 if count == 1 else count
            maximum = 2 if count <= 2 else count
            value, _ = self._number(minimum, maximum)
            self._set("year", value)
        elif token == "g":
            if any(
                era[key] is None
                for era in self.culture["eras"]
                for key in ("name", "abbreviation")
            ):
                raise NotImplementedError(
                    "Windows does not expose complete era names on this target."
                )
            choices = [
                (era[key], era["number"])
                for era in self.culture["eras"]
                for key in ("name", "abbreviation")
                if era[key]
            ]
            self.fields["era"] = self._name(choices)
        elif count <= 2:
            value, _ = self._number(count, 2)
            self._set("month" if token == "M" else "day", value)
        elif token == "M":
            keys = (
                ("month_abbreviations", "abbreviated_genitive")
                if count == 3
                else ("month_names", "month_genitive")
            )
            choices = [
                (name, index + 1)
                for key in keys
                for index, name in enumerate(_metadata(self.culture, key))
                if name
            ]
            self._set("month", self._name(choices))
        else:
            key = "day_abbreviations" if count == 3 else "day_names"
            self._set(
                "weekday",
                self._name(
                    [(name, index) for index, name in enumerate(self.culture[key])]
                ),
            )

    def _clock(self, token, count):
        if token in "hHms":
            value, _ = self._number(min(count, 2), 2)
            self._set(
                {"h": "hour", "H": "hour", "m": "minute", "s": "second"}[token], value
            )
            self.twelve_hour = self.twelve_hour or token == "h"
        elif token in "fF":
            if count > 7:
                raise ValueError("Timestamp precision cannot exceed seven digits.")
            number, digits = self._number(count if token == "f" else 0, count)
            self._set("fraction", number * 10 ** (7 - digits))
        else:
            choices = [(self.culture["am"], 0), (self.culture["pm"], 1)]
            if count == 1:
                choices = [(name[:1], mark) for name, mark in choices]
            elif not self.culture["am"] and not self.culture["pm"]:
                choices = [("", 1)]
            self._set("period", self._name(choices, initial=count == 1))

    def _quoted(self, index):
        quote = self.pattern[index]
        index += 1
        while index < len(self.pattern):
            token = self.pattern[index]
            if token == quote:
                return index + 1
            if token == "\\":
                index += 1
                if index == len(self.pattern):
                    break
                token = self.pattern[index]
            self._literal(token)
            index += 1
        raise ValueError("Timestamp format contains an unterminated literal.")

    def _zone(self, token, count):
        if token == "z":
            self._offset(count)
        elif token == "K":
            current = self.value[self.position : self.position + 1]
            if current == "Z":
                self.position += 1
                self._set("offset", 0)
            elif current in ("+", "-"):
                self._offset(3)
        else:
            self._set("offset", 0)
            if self.value[self.position : self.position + 3].lower() == "gmt":
                self.position += 3
            elif self.value[self.position : self.position + 1].lower() == "z":
                self.position += 1
            else:
                raise ValueError("Timestamp requires a UTC timezone marker.")

    def _token(self, index):
        token = self.pattern[index]
        count = 1
        if token in "yMdghHmsfFtz":
            while (
                index + count < len(self.pattern)
                and self.pattern[index + count] == token
            ):
                count += 1
        if token in "yMdg":
            self._date(token, count)
        elif token in "hHmsfFt":
            self._clock(token, count)
        elif token in "zKZ":
            self._zone(token, count)
        elif token in "/:":
            separator = self.culture[
                "date_separator" if token == "/" else "time_separator"
            ]
            use_literal = self.value.startswith(token, self.position) and not (
                len(separator) > 1 and separator.startswith(token)
            )
            self._literal(token if use_literal else separator)
        elif (
            token == "."
            and self.pattern.startswith("FF", index + 1)
            and not self.value.startswith(".", self.position)
        ):
            while (
                index + count < len(self.pattern) and self.pattern[index + count] == "F"
            ):
                count += 1
        elif token == "G" and self.pattern.startswith("GMT", index):
            self._zone("Z", 1)
            count = 3
        else:
            self._literal(token)
        return count

    def _scan(self):
        index = 0
        while index < len(self.pattern):
            token = self.pattern[index]
            if token in "'\"":
                index = self._quoted(index)
                continue
            if token == "%":
                index += 1
                if index == len(self.pattern) or self.pattern[index] == "%":
                    raise ValueError(
                        "Timestamp format contains an invalid percent escape."
                    )
                continue
            if token == "\\":
                index += 1
                if index == len(self.pattern):
                    raise ValueError("Timestamp format ends with an escape.")
                self._literal(self.pattern[index])
                index += 1
                continue
            index += self._token(index)
        if self.position != len(self.value):
            raise ValueError("Timestamp has unconsumed characters.")

    def _finish(self, today):
        fields = self.fields
        if any(name in fields for name in ("year", "month", "day")):
            year = fields.get("year")
            if year is None:
                year = calendar.calendar_fields(self.culture, today)[0]
            elif self.two_digit_year:
                year = calendar.expand_year(self.culture, year)
            date = calendar.calendar_date(
                self.culture,
                year,
                fields.get("month", 1),
                fields.get("day", 1),
                fields.get("era", 0),
            )
        else:
            date = today
        if "weekday" in fields and fields["weekday"] != (date.weekday() + 1) % 7:
            raise ValueError("Timestamp weekday does not match its date.")
        hour = fields.get("hour", 0)
        period = fields.get("period")
        if self.twelve_hour:
            if hour > 12:
                raise ValueError("Twelve-hour timestamp hour must not exceed 12.")
            hour = hour % 12 + (12 if period == 1 else 0)
        elif (period == 0 and hour >= 12) or (period == 1 and hour < 12):
            raise ValueError("Timestamp hour conflicts with AM or PM.")
        microseconds, remainder = divmod(fields.get("fraction", 0), 10)
        value = datetime.datetime(
            date.year,
            date.month,
            date.day,
            hour,
            fields.get("minute", 0),
            fields.get("second", 0),
            microseconds,
        )
        return value, remainder, fields.get("offset")

    def parse(self, today):
        """Scan one expanded format and return its validated timestamp fields.

        :param today: Gregorian date used for omitted date fields.
        :type today: datetime.date
        :returns: Naive datetime, remaining 100ns digit, and optional UTC offset.
        :rtype: tuple
        :raises ValueError: If the value does not satisfy the format or calendar.
        """
        self._scan()
        return self._finish(today)


def parse_timestamp(value, pattern, culture, today):
    """Parse an exact timestamp without applying the machine's timezone.

    :param value: Timestamp string supplied by the caller.
    :type value: str
    :param pattern: Standard or custom Windows timestamp format string.
    :type pattern: str
    :param culture: Native calendar metadata returned by ``get_culture``.
    :type culture: dict
    :param today: Current Gregorian local date for omitted date components.
    :type today: datetime.date
    :returns: Tuple of naive Gregorian datetime, final 100ns digit (0..9),
        and explicit UTC offset in minutes, or None when no offset is present.
    :rtype: tuple
    :raises ValueError: If the value, format, or resulting date is invalid.
    :raises OSError: If Windows cannot compare localized names or read a calendar.
    :raises NotImplementedError: If Windows lacks required calendar metadata.
    """
    if not isinstance(value, str) or not value:
        raise ValueError("Timestamp must be a nonempty string.")
    if not isinstance(pattern, str) or not pattern:
        raise ValueError("Timestamp format must be a nonempty string.")
    expanded, culture, offset = _expand_format(pattern, culture)
    return _TimestampParser(value, expanded, culture, offset).parse(today)


def _datetime_ticks(value, remainder):
    return (
        (value.toordinal() - 1) * _DAY
        + (value.hour * 3600 + value.minute * 60 + value.second) * _SECOND
        + value.microsecond * 10
        + remainder
    )


def parse_account_expiration(value):
    """Parse an invariant account expiration date into local time and its offset.

    :param value: A complete Gregorian date, optionally followed by a time,
        up to seven fractional digits, and a UTC marker or numeric offset.
        An omitted offset means UTC. The caller handles empty values and never.
    :type value: str
    :returns: Local 100ns ticks since 0001-01-01 and the local UTC offset in
        minutes. Retaining that offset distinguishes daylight-saving overlaps.
    :rtype: tuple[int, int]
    :raises ValueError: If the input or converted local date is invalid.
    :raises OSError: If Windows cannot retrieve timezone rules or convert time.
    """
    for pattern in ("yyyy-MM-dd", _ACCOUNT_EXPIRATION_FORMAT):
        try:
            parsed, remainder, offset = parse_timestamp(
                value, pattern, _invariant_culture(), datetime.date.min
            )
            break
        except ValueError:
            continue
    else:
        raise ValueError("Invalid account expiration date.")
    ticks = _datetime_ticks(parsed, remainder)
    utc_ticks = ticks - (0 if offset is None else offset) * 60 * _SECOND
    local_ticks = native_time.utc_ticks_to_local_ticks(utc_ticks)
    local_offset = (local_ticks - utc_ticks) // (60 * _SECOND)
    # The reference parser wraps a negative result once only when the source
    # date is 0001-01-01; the offset still describes the original conversion.
    if ticks < _DAY and local_ticks < 0:
        local_ticks += _DAY
    if not 0 <= local_ticks <= _MAX_TICKS:
        raise ValueError("Account expiration is outside local years 1 to 9999.")
    return local_ticks, local_offset


def _account_expiration_date(culture, date):
    calendar_id = culture["calendar_id"]
    if calendar_id in (3, 8):
        return calendar.format_alternative_date(calendar_id, date)
    year, month, day, _ = calendar.calendar_fields(culture, date)
    # Taiwan era years retain the reference's two-digit floor even though
    # the fixed account-expiration pattern contains four y's.
    return "{0:0{3}d}-{1:02d}-{2:02d}".format(
        year, month, day, 2 if calendar_id == 4 else 4
    )


def format_account_expiration(local_ticks, offset_minutes=None, culture=None):
    """Render an account expiration using the current account's calendar.

    :param local_ticks: Integer 100ns units since 0001-01-01 in local wall time.
    :type local_ticks: int
    :param offset_minutes: Signed local UTC offset, or None for a stored ADSI
        date without timezone information. Zero renders as +00:00, not Z.
    :type offset_minutes: int or None
    :param culture: Optional native calendar metadata; defaults to the account.
    :type culture: dict or None
    :returns: Calendar date and time with trailing fractional zeros removed,
        followed by the supplied offset when present.
    :rtype: str
    :raises ValueError: If ticks, offset type, or calendar date are invalid.
    :raises OSError: If Windows cannot read culture data or convert the calendar.
    :raises NotImplementedError: If Windows lacks required calendar metadata.
    """
    if not isinstance(local_ticks, int) or not 0 <= local_ticks <= _MAX_TICKS:
        raise ValueError("Account expiration must be between years 1 and 9999.")
    if offset_minutes is not None and not isinstance(offset_minutes, int):
        raise ValueError("Account expiration offset must be integer minutes.")
    if culture is None:
        culture = calendar.get_culture()
    days, within_day = divmod(local_ticks, _DAY)
    date = datetime.date.fromordinal(days + 1)
    date_text = _account_expiration_date(culture, date)
    seconds, fraction = divmod(within_day, _SECOND)
    hour, seconds = divmod(seconds, 3600)
    minute, second = divmod(seconds, 60)
    result = "{0}T{1:02d}{4}{2:02d}{4}{3:02d}".format(
        date_text, hour, minute, second, _metadata(culture, "time_separator")
    )
    if fraction:
        result += "." + "{0:07d}".format(fraction).rstrip("0")
    if offset_minutes is not None:
        result += "{0}{1:02d}:{2:02d}".format(
            "-" if offset_minutes < 0 else "+",
            abs(offset_minutes) // 60,
            abs(offset_minutes) % 60,
        )
    return result


def parse_local_ticks(value, pattern, culture=None):
    """Parse a file timestamp and normalize it to local wall-clock ticks.

    :param value: Timestamp string supplied by the caller.
    :type value: str
    :param pattern: Standard or custom Windows timestamp format string.
    :type pattern: str
    :param culture: Optional native culture metadata; defaults to the target user.
    :type culture: dict or None
    :returns: Integer 100ns units since 0001-01-01 local time.
    :rtype: int
    :raises ValueError: If parsing or offset conversion produces an invalid date.
    :raises OSError: If native culture or timezone operations fail.
    :raises NotImplementedError: If Windows lacks required calendar metadata.
    """
    if culture is None:
        culture = calendar.get_culture()
    today = datetime.date.fromordinal(native_time.current_local_ticks() // _DAY + 1)
    parsed, remainder, offset = parse_timestamp(value, pattern, culture, today)
    ticks = _datetime_ticks(parsed, remainder)
    if offset is not None:
        ticks = native_time.utc_ticks_to_local_ticks(ticks - offset * 60 * _SECOND)
        if ticks < 0:
            ticks += _DAY
        if not 0 <= ticks <= _MAX_TICKS:
            raise ValueError(
                "Timestamp offset places the local date outside years 1 to 9999."
            )
    return ticks
