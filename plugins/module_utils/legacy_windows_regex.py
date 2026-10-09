# -*- coding: utf-8 -*-
# Copyright 2026 Joe Lustri
# SPDX-License-Identifier: GPL-3.0-or-later

r"""Search text with Python 3.4 re and limited upstream syntax translations.

Named groups, named backreferences, and the \Z/\z end anchors are translated.
All expressions operate on UTF-16 code units, as measured on upstream.
General-category escapes use fixed Unicode8 facts. Inline options must appear
at the pattern prefix. Unicode word/digit/space classes and word boundaries use
those same facts; boundaries also include the two zero-width joiners.
Other expressions retain Python re semantics; this does not implement the full
.NET dialect or culture rules.
Recognized unsupported constructs fail explicitly instead of being reinterpreted.
"""

import re
from functools import lru_cache


def _unsupported_regex(feature):
    return ValueError(
        "Unsupported regular-expression {0}; "
        "use Python 3.4 re syntax.".format(feature)
    )


def _group_name(pattern, start, delimiter):
    end = pattern.find(delimiter, start)
    if end == -1:
        raise ValueError("Unterminated regular-expression group name.")
    name = pattern[start:end]
    if "-" in name:
        raise _unsupported_regex("balancing group")
    if re.match(r"\A[A-Za-z_][A-Za-z_0-9]*\Z", name) is None:
        raise _unsupported_regex("group name " + repr(name))
    return name, end + 1


def _regex_escape(pattern, index, in_class):
    escaped = pattern[index + 1]
    if escaped in "wWdDsS":
        return {"shorthand": escaped}, index + 2
    if escaped in "bB" and not in_class:
        return {"boundary": escaped}, index + 2
    if escaped in "pP":
        if pattern[index + 2 : index + 3] != "{":
            raise ValueError("A Unicode category escape requires braces.")
        end = pattern.find("}", index + 3)
        if end == -1:
            raise ValueError("Unterminated Unicode category escape.")
        return {
            "category": pattern[index + 3 : end],
            "negative": escaped == "P",
        }, end + 1
    if escaped == "k" and not in_class:
        if index + 2 == len(pattern) or pattern[index + 2] not in "<'":
            raise ValueError("Invalid regular-expression named backreference.")
        delimiter = ">" if pattern[index + 2] == "<" else "'"
        name, following = _group_name(pattern, index + 3, delimiter)
        return "(?P=" + name + ")", following
    if escaped.isalpha() and escaped not in "AbBdDsSwWZanrtfvxuUz":
        raise _unsupported_regex("escape \\" + escaped)
    if escaped == "Z" and not in_class:
        # Upstream permits the position before one terminal LF; Python's \Z
        # is strict end. A lookahead keeps the anchor zero-width in either case.
        return r"(?=\n?\Z)", index + 2
    return (r"\Z" if escaped == "z" else pattern[index : index + 2]), index + 2


@lru_cache(maxsize=128)
def _category_class(name, insensitive):
    # Wildcard consumers need not stage the Unicode dataset.
    try:
        # pylint: disable-next=import-outside-toplevel
        from ansible.module_utils.legacy_windows_regex_categories import CATEGORY_RANGES
    except ImportError:
        # The same helper also runs directly in isolated target/unit fixtures.
        # pylint: disable-next=import-outside-toplevel
        from legacy_windows_regex_categories import CATEGORY_RANGES

    if name in "LMNPSZC" and len(name) == 1:
        names = [key for key in CATEGORY_RANGES if key.startswith(name)]
    elif name in CATEGORY_RANGES:
        names = [name]
    else:
        raise _unsupported_regex("Unicode general category " + repr(name))
    if insensitive and name in ("Lu", "Ll", "Lt"):
        names = ["Lu", "Ll", "Lt"]
    ranges = sorted(pair for key in names for pair in CATEGORY_RANGES[key])
    merged = []
    for first, last in ranges:
        if merged and first <= merged[-1][1] + 1:
            merged[-1] = (merged[-1][0], max(last, merged[-1][1]))
        else:
            merged.append((first, last))
    body = "".join(r"\u{0:04x}-\u{1:04x}".format(first, last) for first, last in merged)
    guard = ""
    if insensitive:
        # Python3.4's only cross-category BMP case cluster contains one mark and
        # three iota letters. Word/nonword assertions distinguish them without
        # changing case handling in the surrounding user expression.
        if name in ("L", "Lu", "Ll", "Lt"):
            guard = r"(?!(?=\W)[\u0345])"
        elif name in ("M", "Mn"):
            guard = r"(?!(?=\w)[\u0345])"
    return "(?:" + guard + "[" + body + "])"


def _category_atom(part, insensitive):
    positive = _category_class(part["category"], insensitive)
    return "(?:(?!" + positive + r")[\s\S])" if part["negative"] else positive


@lru_cache(maxsize=3)
def _shorthand_class(kind):
    # Microsoft's documented classes use these Unicode categories, not
    # Python3.4's older alphanumeric and whitespace predicates.
    # These identifiers are official Unicode category abbreviations.
    categories = {
        "w": ("L", "Mn", "Nd", "Pc"),  # codespell:ignore nd
        "d": ("Nd",),  # codespell:ignore nd
        "s": ("Z",),
    }
    names = categories[kind]
    members = [_category_class(name, False) for name in names]
    if kind == "s":
        members.append(r"[\u0009-\u000d\u0085]")
    return "(?:" + "|".join(members) + ")"


def _shorthand_atom(escaped):
    positive = _shorthand_class(escaped.lower())
    return "(?:(?!" + positive + r")[\s\S])" if escaped.isupper() else positive


def _word_boundary(escaped):
    # .NET word boundaries additionally treat U+200C/U+200D as word units;
    # they are not members of its ordinary \w class. Every branch consumes
    # exactly one UTF16 unit, so standard re supports these lookbehinds.
    word = "(?:" + _shorthand_class("w") + r"|[\u200c\u200d])"
    left_word, right_word = "(?<=" + word + ")", "(?=" + word + ")"
    left_other, right_other = "(?<!" + word + ")", "(?!" + word + ")"
    if escaped == "b":
        return "(?:" + left_other + right_word + "|" + left_word + right_other + ")"
    return "(?:" + left_word + right_word + "|" + left_other + right_other + ")"


def _regex_class(pattern, index):
    following = index + 1
    negative = pattern[following : following + 1] == "^"
    if negative:
        following += 1
    literal = []
    categories = []
    first = True
    after_category = False
    while following < len(pattern):
        character = pattern[following]
        if character == "]" and not first:
            if not categories:
                return (
                    "[" + ("^" if negative else "") + "".join(literal) + "]",
                    following + 1,
                )
            return {
                "class": "".join(literal),
                "categories": categories,
                "negative": negative,
            }, following + 1
        if character == "\\" and following + 1 < len(pattern):
            expression, following = _regex_escape(pattern, following, True)
            if isinstance(expression, dict):
                if len(literal) > 1 and literal[-1] == "-":
                    raise ValueError("A character-class escape cannot end a range.")
                categories.append(expression)
                after_category = True
            else:
                literal.append(expression)
                after_category = False
        else:
            if character == "-" and pattern[following + 1 : following + 2] == "[":
                raise _unsupported_regex("character-class subtraction")
            # Removing properties must not move a literal caret into the
            # leading negation position of the remaining ordinary class.
            if character == "^" or (character == "-" and after_category):
                character = "\\" + character
            literal.append(character)
            after_category = False
            following += 1
        first = False
    if not categories:
        return pattern[index:], len(pattern)
    raise ValueError("Unterminated regular expression character class.")


def _expression_part(part, insensitive):
    if isinstance(part, str):
        return part
    if "shorthand" in part:
        return _shorthand_atom(part["shorthand"])
    if "boundary" in part:
        return _word_boundary(part["boundary"])
    if "category" in part:
        return _category_atom(part, insensitive)
    members = [_expression_part(member, insensitive) for member in part["categories"]]
    if part["class"]:
        members.append("[" + part["class"] + "]")
    union = "(?:" + "|".join(members) + ")"
    return "(?:(?!" + union + r")[\s\S])" if part["negative"] else union


def _utf16_units(value):
    encoded = value.encode("utf-16-le", "surrogatepass")
    return "".join(
        chr(encoded[index] | (encoded[index + 1] << 8))
        for index in range(0, len(encoded), 2)
    )


def _regex_group(pattern, index):
    if pattern.startswith("(?#", index):
        end = index + 3
        while end < len(pattern) and pattern[end] != ")":
            end += 2 if pattern[end] == "\\" else 1
        if end >= len(pattern):
            raise ValueError("Unterminated regular-expression comment.")
        return pattern[index : end + 1], end + 1, "comment"
    if pattern.startswith("(?>", index):
        raise _unsupported_regex("atomic group")
    if pattern.startswith("(?'", index) or (
        pattern.startswith("(?<", index)
        and pattern[index + 3 : index + 4] not in ("=", "!")
    ):
        delimiter = "'" if pattern[index + 2] == "'" else ">"
        name, following = _group_name(pattern, index + 3, delimiter)
        return "(?P<" + name + ">", following, "named"
    options = re.match(r"\(\?([A-Za-z-]+)([:)])", pattern[index:])
    if options:
        flags, ending = options.groups()
        if (
            ending == ":"
            or "-" in flags
            or any(flag not in "aiLmsux" for flag in flags)
        ):
            raise _unsupported_regex("inline options")
        return options.group(), index + options.end(), "options"
    kind = "numeric" if re.match(r"\(\?\([0-9]", pattern[index:]) else "other"
    return "(", index + 1, kind


def _regex_expression(pattern, insensitive):
    output = []
    index = 0
    verbose = False
    named = False
    numbered_reference = False
    prefix_end = re.match(r"(?:\(\?[aiLmsux]+\))*", pattern).end()
    nonprefix_options = False
    while index < len(pattern):
        character = pattern[index]
        if character == "\\" and index + 1 < len(pattern):
            numbered_reference = numbered_reference or (
                pattern[index + 1] in "123456789"
            )
            expression, index = _regex_escape(pattern, index, False)
            output.append(expression)
            continue
        if character == "[":
            expression, index = _regex_class(pattern, index)
            output.append(expression)
            continue
        if verbose and character == "#":
            end = pattern.find("\n", index)
            if end == -1:
                output.append(pattern[index:])
                break
            output.append(pattern[index : end + 1])
            index = end + 1
            continue
        if pattern.startswith("(?", index):
            group_start = index
            expression, index, kind = _regex_group(pattern, index)
            nonprefix_options = nonprefix_options or (
                kind == "options" and group_start >= prefix_end
            )
            output.append(expression)
            named = named or kind == "named"
            verbose = verbose or (kind == "options" and "x" in expression)
            insensitive = insensitive or (kind == "options" and "i" in expression)
            numbered_reference = numbered_reference or kind == "numeric"
            continue
        if pattern[index + 1 : index + 2] == "+" and (
            character in "*+?"
            or (
                character == "}"
                and re.search(r"(?<!\\)\{[0-9]+(?:,[0-9]*)?\}\Z", pattern[: index + 1])
            )
        ):
            raise _unsupported_regex("possessive quantifier")
        output.append(character)
        index += 1
    if named and numbered_reference:
        raise _unsupported_regex("numeric reference combined with .NET named groups")
    categories = any(
        isinstance(part, dict)
        and (
            "category" in part
            or any("category" in member for member in part.get("categories", []))
        )
        for part in output
    )
    if nonprefix_options:
        # Python3.4 applies inline flags globally, unlike upstream's positional
        # options. Reject later flags rather than silently change earlier matches.
        raise _unsupported_regex(
            "non-prefix inline options (put flags at the pattern prefix)"
        )
    if any(not isinstance(part, str) for part in output) and any(
        isinstance(part, str) and re.match(r"\(\?[aiLmsux]*[aL]", part)
        for part in output
    ):
        raise _unsupported_regex("ASCII/locale options with Unicode classes")
    expression = "".join(_expression_part(part, insensitive) for part in output)
    return _utf16_units(expression), categories


def search(text, pattern, case_sensitive=False):
    """Search text using the standard-library regular-expression engine.

    Patterns are validated when this function is called, not before a caller
    reaches a file or name to test. Text and literal patterns use UTF-16 code
    units, so an ordinary dot consumes one surrogate, not a whole emoji.
    Word/digit/space shorthand uses fixed Unicode8 categories; word boundaries
    also consider zero-width joiners. Character-class ``\\b`` remains backspace.
    Matching is case-insensitive by default;
    multiline and singleline matching require explicit inline options at the
    pattern prefix: Python3.4 cannot preserve upstream's scope for later options.
    ``\\Z`` also matches before one terminal LF; ``\\z`` is strict end.

    :param text: Text to search, preserving line endings.
    :type text: str
    :param pattern: Regular expression with the limited translations above.
    :type pattern: str
    :param case_sensitive: Disable case-insensitive matching.
    :type case_sensitive: bool
    :returns: Whether the expression matches any part of the text.
    :rtype: bool
    :raises ValueError: If the expression is invalid or unsupported.
    """
    expression, _categories = _regex_expression(pattern, not case_sensitive)
    text = _utf16_units(text)
    flags = 0 if case_sensitive else re.IGNORECASE
    try:
        return re.search(expression, text, flags) is not None
    except re.error as error:
        raise ValueError(
            "Invalid regular expression {0!r}: {1}".format(pattern, error)
        ) from error
