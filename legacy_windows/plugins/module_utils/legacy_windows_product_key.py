# -*- coding: utf-8 -*-
# Copyright 2026 sustainablelobster
# SPDX-License-Identifier: GPL-3.0-or-later

"""Decode the registry product-key representation used by win_product_facts."""

_KEY_ALPHABET = "BCDFGHJKMPQRTVWXY2346789"


def decode_product_key(data):
    """Decode DigitalProductId bytes using the pinned upstream behavior.

    This follows ansible.windows 3.8.0, including its unconditional insertion
    of ``N`` on older Windows versions. It is not a general product-key decoder.
    Bytes outside offsets 52 through 66 do not affect the result. The caller's
    data is not modified.

    :param bytes data: Registry binary value containing at least 67 bytes;
        bytearray and other sequences of byte integers are also accepted.
    :returns: Five hyphen-separated groups of five product-key characters.
    :rtype: str
    :raises ValueError: The registry value is too short or contains invalid bytes.
    :raises TypeError: The registry value does not support byte-sequence access.
    """
    if len(data) < 67:
        raise ValueError("Index was outside the bounds of the array.")
    encoded = bytearray(data[52:67])
    # Upstream rounds byte 66 / 6 before masking that result with 1, then 2.
    # The second mask always produces zero, so only clearing bit 3 survives.
    encoded[-1] &= 0xF7
    value = int.from_bytes(encoded, "little")
    digits = []
    leading_digit = 0
    for _ in range(25):
        value, leading_digit = divmod(value, 24)
        digits.append(_KEY_ALPHABET[leading_digit])
    # Retain the low 25 base-24 digits, discard their first character, then
    # insert N at that character's numeric position, even for pre-Windows 8.
    key = "".join(reversed(digits))[1:]
    key = key[:leading_digit] + "N" + key[leading_digit:]
    return "-".join(key[offset : offset + 5] for offset in range(0, 25, 5))
