# Copyright 2026 sustainablelobster
# SPDX-License-Identifier: GPL-3.0-or-later

"""Translate the AD expression-filter language without executing expressions."""

import re
import uuid

from legacy_ad_ldap import escape_filter  # pylint: disable=import-error

ALIASES = {
    "distinguishedname": ("DistinguishedName", "distinguishedName"),
    "name": ("Name", "name"),
    "objectclass": ("ObjectClass", "objectClass"),
    "objectguid": ("ObjectGUID", "objectGUID"),
    "created": ("Created", "whenCreated"),
    "modified": ("Modified", "whenChanged"),
    "deleted": ("Deleted", "isDeleted"),
    "description": ("Description", "description"),
    "displayname": ("DisplayName", "displayName"),
    "objectcategory": ("ObjectCategory", "objectCategory"),
    "canonicalname": ("CanonicalName", "canonicalName"),
    "lastknownparent": ("LastKnownParent", "lastKnownParent"),
}
_OPERATORS = (
    "eq",
    "ne",
    "le",
    "lt",
    "ge",
    "gt",
    "approx",
    "band",
    "bor",
    "recursivematch",
    "like",
    "notlike",
    "and",
    "or",
    "not",
)


def _quoted(text, offset):
    quote = text[offset]
    offset += 1
    value = []
    while offset < len(text):
        character = text[offset]
        offset += 1
        if character == quote:
            if quote == "'" and offset < len(text) and text[offset] == quote:
                value.append(quote)
                offset += 1
                continue
            break
        if quote == '"' and character == "`":
            if offset >= len(text):
                raise ValueError("Unterminated escape in AD filter string.")
            character = text[offset]
            offset += 1
            character = {"0": "\0", "n": "\n", "r": "\r", "t": "\t"}.get(
                character, character
            )
        value.append(character)
    else:
        raise ValueError("Unterminated quoted string in AD filter.")
    # AD expression strings accept LDAP escapes for NUL/backslash.
    value = re.sub(
        r"\\(00|5[cC])", lambda match: chr(int(match.group(1), 16)), "".join(value)
    )
    return value, offset


def _tokens(text):
    offset = 0
    while offset < len(text):
        if text[offset].isspace():
            offset += 1
            continue
        character = text[offset]
        if character in "()":
            yield character, character
            offset += 1
        elif character in "\"'":
            value, offset = _quoted(text, offset)
            yield "value", value
        else:
            match = re.match(r"[^\s()'\"]+", text[offset:])
            if not match:
                raise ValueError("Invalid character in AD filter.")
            value = match.group(0)
            offset += len(value)
            lower = value.lower()
            if lower.startswith("-") and lower[1:] in _OPERATORS:
                yield "operator", lower[1:]
            elif lower in ("$true", "$false"):
                yield "value", "TRUE" if lower == "$true" else "FALSE"
            elif value.startswith("$"):
                raise ValueError("Variables are not available in AD filters: " + value)
            elif re.match(r"^-?(0[xX][0-9a-fA-F]+|[0-9]+)$", value):
                yield "value", str(int(value, 16 if "x" in lower else 10))
            else:
                yield "attribute", value
    yield "end", ""


# The parser's only entry point is expression_to_ldap; methods are private grammar rules.
class _Parser:  # pylint: disable=too-few-public-methods
    def __init__(self, text):
        self.tokens = iter(_tokens(text))
        self.current = next(self.tokens)

    def _take(self, kind, value=None):
        if self.current[0] != kind or (value is not None and self.current[1] != value):
            raise ValueError("Invalid AD filter: expected " + (value or kind) + ".")
        result = self.current[1]
        self.current = next(self.tokens)
        return result

    def parse(self):
        """Read an expression up to its closing parenthesis or end.

        :returns: The equivalent LDAP filter.
        :rtype: str
        """
        result = self._conjunction()
        while self.current == ("operator", "or"):
            self._take("operator", "or")
            result = "(|" + result + self._conjunction() + ")"
        return result

    def _conjunction(self):
        result = self._component()
        while self.current == ("operator", "and"):
            self._take("operator", "and")
            result = "(&" + result + self._component() + ")"
        return result

    def _component(self):
        if self.current == ("operator", "not"):
            self._take("operator", "not")
            return "(!" + self._component() + ")"
        if self.current[0] == "(":
            self._take("(")
            result = self.parse()
            self._take(")")
            return result
        attribute = self._take("attribute")
        if not re.match(r"^[A-Za-z][A-Za-z0-9-]*$", attribute):
            raise ValueError("Invalid attribute in AD filter: " + attribute)
        attribute = ALIASES.get(attribute.lower(), (None, attribute))[1]
        operator = self._take("operator")
        if operator in ("and", "or", "not"):
            raise ValueError("An AD comparison operator is required.")
        value = self._take("value")
        if attribute.lower() == "objectguid":
            try:
                value = uuid.UUID(value).bytes_le
            except ValueError as error:
                raise ValueError("objectGUID comparisons require a GUID.") from error
        if operator in ("like", "notlike") and isinstance(value, str):
            value = "*".join(escape_filter(part) for part in value.split("*"))
        else:
            value = escape_filter(value)
        if operator in ("eq", "ne", "like", "notlike"):
            result = "(" + attribute + "=" + value + ")"
            return "(!" + result + ")" if operator in ("ne", "notlike") else result
        if operator in ("le", "ge", "approx"):
            comparison = {"le": "<=", "ge": ">=", "approx": "~="}[operator]
            return "(" + attribute + comparison + value + ")"
        if operator in ("lt", "gt"):
            comparison = ">=" if operator == "lt" else "<="
            return "(&({0}=*)(!({0}{1}{2})))".format(attribute, comparison, value)
        oid = {"band": "803", "bor": "804", "recursivematch": "1941"}[operator]
        return "({0}:1.2.840.113556.1.4.{1}:={2})".format(attribute, oid, value)


def expression_to_ldap(text):
    """Convert an AD expression string to an equivalent LDAP filter.

    :param text: AD expression using comparisons, Boolean joins and parentheses.
    :type text: str
    :returns: An LDAP filter; quoted text is escaped rather than evaluated.
    :rtype: str
    :raises ValueError: If syntax is invalid or an expression uses variables.
    """
    if not isinstance(text, str) or "\0" in text:
        raise ValueError("filter must be text without NUL characters.")
    if text.strip() == "*":
        return "(objectClass=*)"
    parser = _Parser(text)
    result = parser.parse()
    if parser.current[0] != "end":
        raise ValueError("Unexpected trailing text in AD filter.")
    return result
