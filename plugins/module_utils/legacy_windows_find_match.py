# -*- coding: utf-8 -*-
# Copyright 2026 Joe Lustri
# SPDX-License-Identifier: GPL-3.0-or-later AND MIT

"""Preliminary filename matching without a managed or third-party runtime.

Wildcards use UTF-16 characters and Windows current-culture casing. Bracket
ranges retain .NET Framework's fixed historical lowercase expansion table;
single characters use the target's native lowercase mapping.
Native Unicode tables vary with Windows. Systems rejecting linguistic flags
use the older supported lowercase or case-insensitive comparison flags.

Regular expressions use Python 3.4's ``re`` engine, not .NET's engine. A small
syntax translation handles named groups, named backreferences, and ``\\z``.
All expressions operate on UTF-16 code units. General categories, shorthand
classes and word boundaries use fixed Unicode8 ranges; surrounding literal
and range casing retains Python, not upstream culture semantics.
Recognized unsupported .NET constructs fail explicitly.
This helper does not establish complete upstream regular-expression parity.
"""

import ctypes
import os

# The module action stages this Python 3.4-compatible sibling helper.
import legacy_windows_regex as regex  # pylint: disable=import-error

# Adapted from RegexCharClass.cs in microsoft/referencesource, commit
# ec9fa9ae770d522a5b5f0607898044b7478574a3. Copyright (c) Microsoft Corporation.
# The table and range expansion are MIT-licensed; see
# LICENSES/microsoft-referencesource-MIT.txt and NOTICE.
# Rows contain inclusive endpoints, an endpoint operation, and its operand.
_RANGE_LOWERCASE = (
    (0x0041, 0x005A, "add", 32),
    (0x00C0, 0x00DE, "add", 32),
    (0x0100, 0x012E, "or_one", 0),
    (0x0130, 0x0130, "set", 0x0069),
    (0x0132, 0x0136, "or_one", 0),
    (0x0139, 0x0147, "add_odd", 0),
    (0x014A, 0x0176, "or_one", 0),
    (0x0178, 0x0178, "set", 0x00FF),
    (0x0179, 0x017D, "add_odd", 0),
    (0x0181, 0x0181, "set", 0x0253),
    (0x0182, 0x0184, "or_one", 0),
    (0x0186, 0x0186, "set", 0x0254),
    (0x0187, 0x0187, "set", 0x0188),
    (0x0189, 0x018A, "add", 205),
    (0x018B, 0x018B, "set", 0x018C),
    (0x018E, 0x018E, "set", 0x01DD),
    (0x018F, 0x018F, "set", 0x0259),
    (0x0190, 0x0190, "set", 0x025B),
    (0x0191, 0x0191, "set", 0x0192),
    (0x0193, 0x0193, "set", 0x0260),
    (0x0194, 0x0194, "set", 0x0263),
    (0x0196, 0x0196, "set", 0x0269),
    (0x0197, 0x0197, "set", 0x0268),
    (0x0198, 0x0198, "set", 0x0199),
    (0x019C, 0x019C, "set", 0x026F),
    (0x019D, 0x019D, "set", 0x0272),
    (0x019F, 0x019F, "set", 0x0275),
    (0x01A0, 0x01A4, "or_one", 0),
    (0x01A7, 0x01A7, "set", 0x01A8),
    (0x01A9, 0x01A9, "set", 0x0283),
    (0x01AC, 0x01AC, "set", 0x01AD),
    (0x01AE, 0x01AE, "set", 0x0288),
    (0x01AF, 0x01AF, "set", 0x01B0),
    (0x01B1, 0x01B2, "add", 217),
    (0x01B3, 0x01B5, "add_odd", 0),
    (0x01B7, 0x01B7, "set", 0x0292),
    (0x01B8, 0x01B8, "set", 0x01B9),
    (0x01BC, 0x01BC, "set", 0x01BD),
    (0x01C4, 0x01C5, "set", 0x01C6),
    (0x01C7, 0x01C8, "set", 0x01C9),
    (0x01CA, 0x01CB, "set", 0x01CC),
    (0x01CD, 0x01DB, "add_odd", 0),
    (0x01DE, 0x01EE, "or_one", 0),
    (0x01F1, 0x01F2, "set", 0x01F3),
    (0x01F4, 0x01F4, "set", 0x01F5),
    (0x01FA, 0x0216, "or_one", 0),
    (0x0386, 0x0386, "set", 0x03AC),
    (0x0388, 0x038A, "add", 37),
    (0x038C, 0x038C, "set", 0x03CC),
    (0x038E, 0x038F, "add", 63),
    (0x0391, 0x03AB, "add", 32),
    (0x03E2, 0x03EE, "or_one", 0),
    (0x0401, 0x040F, "add", 80),
    (0x0410, 0x042F, "add", 32),
    (0x0460, 0x0480, "or_one", 0),
    (0x0490, 0x04BE, "or_one", 0),
    (0x04C1, 0x04C3, "add_odd", 0),
    (0x04C7, 0x04C7, "set", 0x04C8),
    (0x04CB, 0x04CB, "set", 0x04CC),
    (0x04D0, 0x04EA, "or_one", 0),
    (0x04EE, 0x04F4, "or_one", 0),
    (0x04F8, 0x04F8, "set", 0x04F9),
    (0x0531, 0x0556, "add", 48),
    (0x10A0, 0x10C5, "add", 48),
    (0x1E00, 0x1EF8, "or_one", 0),
    (0x1F08, 0x1F0F, "add", -8),
    (0x1F18, 0x1F1F, "add", -8),
    (0x1F28, 0x1F2F, "add", -8),
    (0x1F38, 0x1F3F, "add", -8),
    (0x1F48, 0x1F4D, "add", -8),
    (0x1F59, 0x1F59, "set", 0x1F51),
    (0x1F5B, 0x1F5B, "set", 0x1F53),
    (0x1F5D, 0x1F5D, "set", 0x1F55),
    (0x1F5F, 0x1F5F, "set", 0x1F57),
    (0x1F68, 0x1F6F, "add", -8),
    (0x1F88, 0x1F8F, "add", -8),
    (0x1F98, 0x1F9F, "add", -8),
    (0x1FA8, 0x1FAF, "add", -8),
    (0x1FB8, 0x1FB9, "add", -8),
    (0x1FBA, 0x1FBB, "add", -74),
    (0x1FBC, 0x1FBC, "set", 0x1FB3),
    (0x1FC8, 0x1FCB, "add", -86),
    (0x1FCC, 0x1FCC, "set", 0x1FC3),
    (0x1FD8, 0x1FD9, "add", -8),
    (0x1FDA, 0x1FDB, "add", -100),
    (0x1FE8, 0x1FE9, "add", -8),
    (0x1FEA, 0x1FEB, "add", -112),
    (0x1FEC, 0x1FEC, "set", 0x1FE5),
    (0x1FF8, 0x1FF9, "add", -128),
    (0x1FFA, 0x1FFB, "add", -126),
    (0x1FFC, 0x1FFC, "set", 0x1FF3),
    (0x2160, 0x216F, "add", 16),
    (0x24B6, 0x24D0, "add", 26),
    (0xFF21, 0xFF3A, "add", 32),
)


def _kernel():
    if os.name != "nt":
        raise ValueError("Filename culture operations require a Windows target.")
    kernel = ctypes.WinDLL("kernel32", use_last_error=True)
    kernel.GetUserDefaultLCID.argtypes = []
    kernel.GetUserDefaultLCID.restype = ctypes.c_uint32
    kernel.LCMapStringW.argtypes = [
        ctypes.c_uint32,
        ctypes.c_uint32,
        ctypes.c_wchar_p,
        ctypes.c_int,
        ctypes.c_wchar_p,
        ctypes.c_int,
    ]
    kernel.LCMapStringW.restype = ctypes.c_int
    kernel.CompareStringW.argtypes = [
        ctypes.c_uint32,
        ctypes.c_uint32,
        ctypes.c_wchar_p,
        ctypes.c_int,
        ctypes.c_wchar_p,
        ctypes.c_int,
    ]
    kernel.CompareStringW.restype = ctypes.c_int
    return kernel


def _utf16_units(value):
    encoded = value.encode("utf-16-le", "surrogatepass")
    return "".join(
        chr(encoded[index] | (encoded[index + 1] << 8))
        for index in range(0, len(encoded), 2)
    )


def _map_lower(kernel, value, locale, flags):
    if not value:
        return value
    length = len(_utf16_units(value))
    required = kernel.LCMapStringW(locale, flags, value, length, None, 0)
    if not required and flags == 0x01000100 and ctypes.get_last_error() == 1004:
        flags = 0x100
        required = kernel.LCMapStringW(locale, flags, value, length, None, 0)
    if not required:
        raise ctypes.WinError(ctypes.get_last_error())
    buffer = ctypes.create_unicode_buffer(required)
    written = kernel.LCMapStringW(locale, flags, value, length, buffer, required)
    if not written:
        raise ctypes.WinError(ctypes.get_last_error())
    return buffer[:written]


def _current_lower():
    kernel = _kernel()
    locale = kernel.GetUserDefaultLCID()
    cache = {}

    def _lower(character):
        if character not in cache:
            # .NET's char overload leaves individual surrogate halves unchanged.
            if 0xD800 <= ord(character) <= 0xDFFF:
                cache[character] = character
            else:
                cache[character] = _map_lower(kernel, character, locale, 0x01000100)
        return cache[character]

    return _lower


def path_key(path):
    """Return the Windows invariant-lowercase key used for path deduplication.

    This does not resolve links, normalize separators, or make a path absolute.

    :param path: The already resolved path.
    :type path: str
    :returns: The invariant-lowercase path.
    :rtype: str
    :raises ValueError: If called outside Windows.
    :raises OSError: If native casing fails.
    """
    return _map_lower(_kernel(), path, 0x7F, 0x100)


def compare_paths(left, right):
    """Compare paths using the Windows account's case-insensitive culture.

    Equal collation keys return zero. Python's stable sorting of equal keys
    does not reproduce PowerShell's unspecified ordering of those ties.
    XP and Server 2003 reject linguistic casing and use their older native
    case-insensitive comparison instead; their culture tables can differ.

    :param left: First full path.
    :type left: str
    :param right: Second full path.
    :type right: str
    :returns: Negative, zero, or positive according to the culture comparison.
    :rtype: int
    :raises ValueError: If called outside Windows.
    :raises OSError: If native comparison fails.
    """
    if not left or not right:
        return (left > right) - (left < right)
    kernel = _kernel()
    locale = kernel.GetUserDefaultLCID()
    strings = (
        left,
        len(_utf16_units(left)),
        right,
        len(_utf16_units(right)),
    )
    result = kernel.CompareStringW(locale, 0x08000001, *strings)
    # ERROR_INVALID_FLAGS is observed on XP/2003 for NORM_LINGUISTIC_CASING.
    if not result and ctypes.get_last_error() == 1004:
        result = kernel.CompareStringW(locale, 1, *strings)
    if not result:
        raise ctypes.WinError(ctypes.get_last_error())
    return result - 2


def _wildcard_error(pattern):
    return ValueError(
        "The specified wildcard character pattern is not valid: " + pattern
    )


def _bracket_members(pattern, index):
    members = []
    first = True
    while index < len(pattern):
        character = pattern[index]
        if character == "]" and not first:
            break
        escaped = character == "`"
        if escaped:
            index += 1
            if index == len(pattern):
                raise _wildcard_error(pattern)
            character = pattern[index]
        members.append((character, escaped))
        first = False
        index += 1
    if index == len(pattern):
        raise _wildcard_error(pattern)
    return members, index + 1


def _range_characters(first, last):
    accepted = {chr(code) for code in range(first, last + 1)}
    for start, end, operation, operand in _RANGE_LOWERCASE:
        if start > last:
            break
        if end < first:
            continue
        start, end = max(start, first), min(end, last)
        if operation == "set":
            start = end = operand
        elif operation == "add":
            start, end = start + operand, end + operand
        elif operation == "or_one":
            start, end = start | 1, end | 1
        else:  # add_odd: round odd endpoints up to the following even value.
            start, end = start + (start & 1), end + (end & 1)
        accepted.update(chr(code) for code in range(start, end + 1))
    return accepted


def _bracket(pattern, index, lower):
    members, following = _bracket_members(pattern, index)
    accepted = set()
    offset = 0
    while offset < len(members):
        start = members[offset][0]
        if offset + 2 < len(members) and members[offset + 1] == ("-", False):
            end = members[offset + 2][0]
            if start > end:
                raise _wildcard_error(pattern)
            if end == "[":
                # PowerShell's bracket regex treats '-[' as an unfinished
                # subtraction, even though the wildcard parser accepts it.
                raise ValueError(
                    'parsing "'
                    + pattern[index - 1 : following]
                    + '" - Unterminated [] set.'
                )
            if start == end:
                accepted.add(lower(start))
            else:
                accepted.update(_range_characters(ord(start), ord(end)))
            offset += 3
        else:
            accepted.add(lower(start))
            offset += 1
    return accepted, following


def _wildcard_tokens(pattern, lower):
    pattern = _utf16_units(pattern)
    tokens = []
    index = 0
    while index < len(pattern):
        character = pattern[index]
        if character == "[":
            bracket, index = _bracket(pattern, index + 1, lower)
            tokens.append(("characters", bracket))
            continue
        if character == "*":
            tokens.append(("star", None))
        elif character == "?":
            tokens.append(("any", None))
        else:
            if character == "`":
                if pattern == "`":
                    break
                if index + 1 < len(pattern):
                    index += 1
                    character = pattern[index]
            tokens.append(("characters", {lower(character)}))
        index += 1
    return tokens


def _wildcard_matches(name, tokens):
    position = 0
    index = 0
    last_star = -1
    star_end = 0
    while position < len(name):
        if index < len(tokens) and tokens[index][0] == "star":
            last_star = index
            star_end = position
            index += 1
        elif index < len(tokens) and (
            tokens[index][0] == "any" or name[position] in tokens[index][1]
        ):
            position += 1
            index += 1
        elif last_star != -1:
            # Only the most recent star needs expansion. Earlier successful
            # segments need not be retried as in a backtracking regex engine.
            star_end += 1
            position = star_end
            index = last_star + 1
        else:
            return False
    return all(kind == "star" for kind, _members in tokens[index:])


def matches(name, patterns, use_regex=False, case_sensitive=False):
    """Match a filename against lazily evaluated alternative patterns.

    ``None`` disables filtering; an empty sequence matches nothing. Wildcards
    always ignore case, even when ``case_sensitive`` is true. Regex matching
    uses Python 3.4 semantics with the limited translations described above;
    it is not full .NET regex compatibility. Unreached patterns are not parsed.

    :param name: Filename without its parent path.
    :type name: str
    :param patterns: Alternative patterns, or None to disable filtering.
    :type patterns: iterable or None
    :param use_regex: Use regular expressions instead of wildcard patterns.
    :type use_regex: bool
    :param case_sensitive: Disable regex case-insensitive matching.
    :type case_sensitive: bool
    :returns: Whether any evaluated pattern matches.
    :rtype: bool
    :raises ValueError: If an evaluated pattern is invalid or unsupported, or
        wildcard culture operations are requested outside Windows.
    :raises OSError: If native wildcard casing fails.
    """
    if patterns is None:
        return True
    lower = None
    normalized = None
    for pattern in patterns:
        if not use_regex:
            if pattern == "*":
                return True
            if lower is None:
                lower = _current_lower()
                normalized = "".join(
                    lower(character) for character in _utf16_units(name)
                )
            if _wildcard_matches(normalized, _wildcard_tokens(pattern, lower)):
                return True
            continue
        if regex.search(name, pattern, case_sensitive):
            return True
    return False
