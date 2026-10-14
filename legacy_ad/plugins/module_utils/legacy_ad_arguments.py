# Copyright 2026 sustainablelobster
# SPDX-License-Identifier: GPL-3.0-or-later

"""Normalize public integer arguments using the released Int32 contract."""

import re


def as_int32(value: object, name: str) -> int:
    """Convert a JSON integer or signed decimal string to a signed Int32.

    :param value: Public argument value, before normalization.
    :type value: object
    :param str name: Argument name used in validation errors.
    :returns: Integer within the signed 32-bit range.
    :rtype: int
    :raises ValueError: The value is not a decimal Int32.
    """
    if isinstance(value, bool):
        raise ValueError(name + " must be an integer.")
    if isinstance(value, int):
        number = value
    elif isinstance(value, str):
        # Int32.Parse accepts ASCII whitespace and a terminal NUL suffix,
        # not Python's broader Unicode whitespace or numeric extensions.
        text = value.lstrip(" \t\n\r\v\f").rstrip("\0").rstrip(" \t\n\r\v\f")
        if not re.match(r"^[+-]?[0-9]+$", text):
            raise ValueError(name + " must be an integer.")
        number = int(text, 10)
    else:
        # Upstream serializes even whole JSON floats with a decimal point;
        # Int32.Parse rejects them rather than truncating or coercing them.
        raise ValueError(name + " must be an integer.")
    if not -2147483648 <= number <= 2147483647:
        raise ValueError(name + " must fit a signed 32-bit integer.")
    return number
