# -*- coding: utf-8 -*-
# Copyright 2026 sustainablelobster
# SPDX-License-Identifier: GPL-3.0-or-later

"""Decode Windows text streams with measured BOM and replacement behavior."""

import codecs
import re
from encodings.cp1252 import decoding_table

_WINDOWS_1252_TABLE = "".join(
    chr(value) if character == "\ufffe" else character
    for value, character in enumerate(decoding_table)
)


def decode_bytes(data, encoding):
    """Decode bytes using an initial BOM or the caller's selected encoding.

    Replacement behavior preserves the measured Windows handling of malformed
    UTF-8, bytes outside ASCII, and undefined Windows-1252 control bytes.

    :param data: Complete encoded text, including any initial byte-order mark.
    :type data: bytes
    :param encoding: Canonical Python text-codec name used without a BOM.
    :type encoding: str
    :returns: Decoded text without an initial byte-order mark.
    :rtype: str
    :raises LookupError: If the selected encoding is unknown.
    """
    for marker, detected in (
        (codecs.BOM_UTF32_LE, "utf-32-le"),
        (codecs.BOM_UTF32_BE, "utf-32-be"),
        (codecs.BOM_UTF8, "utf-8"),
        (codecs.BOM_UTF16_LE, "utf-16-le"),
        (codecs.BOM_UTF16_BE, "utf-16-be"),
    ):
        if data.startswith(marker):
            data = data[len(marker) :]
            encoding = detected
            break
    if encoding == "utf-8":
        # .NET groups these invalid leading pairs into one replacement character.
        data = re.sub(
            b"\xe0[\x80-\x9f]|\xed[\xa0-\xbf]|\xf0[\x80-\x8f]|\xf4[\x90-\xbf]",
            b"\xef\xbf\xbd",
            data,
        )
    if encoding == "cp1252":
        return codecs.charmap_decode(data, "replace", _WINDOWS_1252_TABLE)[0]
    decoded = data.decode(encoding, "replace")
    if encoding == "ascii":
        decoded = decoded.replace("\ufffd", "?")
    return decoded
