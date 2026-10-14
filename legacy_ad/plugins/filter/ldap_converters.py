"""Convert controller-side LDAP values and parse RFC 4514 distinguished names."""

# Copyright: (c) 2023, Ansible Project
# Copyright 2026 sustainablelobster
# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import annotations

import base64
import datetime
import re
import struct
import typing as t
import uuid

# Ansible does not distribute typing metadata for its controller interfaces.
from ansible.errors import AnsibleFilterError  # type: ignore[import-untyped]
from ansible.module_utils.common.collections import (  # type: ignore[import-untyped]
    is_sequence,
)

_RDN_TYPE_PATTERN = re.compile(
    r"""
[\ ]*  # Ignore leading spaces
(
    (
        # Lead char is a letter, subsequent chars can be numbers or -
        [a-zA-Z][a-zA-Z0-9-]*
    )
    |
    (
        # First number must a decimal without a leading 0 unless 0.
        # Must also contain at least another entry separated by '.'.
        ([0-9]|[1-9][0-9]+)
        (
            \.([0-9]|[1-9][0-9]+)
        )+
    )
)
[\ ]*=  # Ignore trailing spaces before the =
""".encode(
        "utf-8"
    ),
    re.VERBOSE,
)

_RDN_VALUE_HEXSTRING_PATTERN = re.compile(
    r"""
[\ ]*  # Ignore leading spaces
\#  # Starts with '#'
(
    ([0-9a-fA-F]{2})+
)
[\ ]*  # Ignore trailing spaces
(?:[+,]|$)  # Terminated by '+', ',', or the end of the string
""".encode(
        "utf-8"
    ),
    re.VERBOSE,
)

_RDN_VALUE_ESCAPE_PATTERN = re.compile(
    r"""
(
    (?P<literal>
        [+,;<>#=\\\"\ ]
    )
    |
    (?P<hex>
        ([0-9a-fA-F]{2})
    )
)
""".encode(
        "utf-8"
    ),
    re.VERBOSE,
)


def _parse_rdn_type(value: memoryview) -> t.Optional[t.Tuple[bytes, int]]:
    if match := _RDN_TYPE_PATTERN.match(value):
        return match.group(1), len(match.group(0))

    return None


# Keeping the delimiter and escape rules in one scan preserves upstream parsing.
def _parse_rdn_value(  # pylint: disable=too-many-branches
    value: memoryview,
) -> t.Optional[t.Tuple[bytes, int, bool]]:
    if hex_match := _RDN_VALUE_HEXSTRING_PATTERN.match(value):
        full_value = hex_match.group(0)
        more_rdns = full_value.endswith(b"+")

        b_value = base64.b16decode(hex_match.group(1).upper())
        return b_value, len(full_value), more_rdns

    # Parsing the string value variant as regex is too complicated due to the
    # myriad of rules and escaping so it is done manually.
    read = 0
    new_value = bytearray()
    found_spaces = 0

    total_len = len(value)
    while read < total_len:
        current_value = value[read]
        current_char = chr(current_value)
        read += 1

        # We only count the spaces in the middle of the string so we need to
        # keep track of how many have been found until the next character.
        if current_char == " ":
            if new_value:
                found_spaces += 1

            continue

        if current_char in [",", "+"]:
            break

        # We can add any spaces we are still tentatively collecting as there's
        # a real value after it.
        if found_spaces:
            new_value += b" " * found_spaces
            found_spaces = 0

        if current_char == "#" and not new_value:
            remaining = (
                value[read - 1 :].tobytes().decode("utf-8", errors="surrogateescape")
            )
            raise AnsibleFilterError(
                "Found leading # for attribute value but does not match "
                f"hexstring format at '{remaining}'"
            )

        if current_char in ["\00", '"', ";", "<", ">"]:
            remaining = (
                value[read - 1 :].tobytes().decode("utf-8", errors="surrogateescape")
            )
            raise AnsibleFilterError(
                f"Found unescaped character '{current_char}' "
                f"in attribute value at '{remaining}'"
            )

        if current_char == "\\":
            if escape_match := _RDN_VALUE_ESCAPE_PATTERN.match(value, pos=read):
                if literal_value := escape_match.group("literal"):
                    new_value += literal_value
                    read += 1

                else:
                    new_value += base64.b16decode(escape_match.group("hex").upper())
                    read += 2

            else:
                remaining = (
                    value[read - 1 :]
                    .tobytes()
                    .decode("utf-8", errors="surrogateescape")
                )
                raise AnsibleFilterError(
                    f"Found invalid escape sequence in attribute value at '{remaining}"
                )

        else:
            new_value.append(current_value)

    if new_value:
        return bytes(new_value), read, current_char == "+"

    return None


def _per_sequence(func: t.Callable[..., t.Any]) -> t.Callable[..., t.Any]:
    def wrapper(value: t.Any, *args: t.Any, **kwargs: t.Any) -> t.Any:
        """Apply the filter to one value or each item in an Ansible sequence.

        :param value: Scalar input or an Ansible sequence.
        :param args: Positional filter options.
        :param kwargs: Named filter options.
        :returns: The scalar result, or one result per sequence item.
        """
        if is_sequence(value):
            return [func(v, *args, **kwargs) for v in value]
        return func(value, *args, **kwargs)

    return wrapper


@_per_sequence
def as_datetime(
    value: t.Any,
    # The format keyword is part of the released filter interface.
    # pylint: disable-next=redefined-builtin
    format: str = "%Y-%m-%dT%H:%M:%S.%f%z",
) -> str:
    """Format an LDAP FILETIME as a UTC date and time.

    :param value: Integer, decimal string, bytes, or a sequence of those values.
    :param format: The strftime format, defaulting to a UTC ISO-like timestamp.
    :returns: Formatted string, or one string per input sequence item.
    """
    if isinstance(value, bytes):
        value = value.decode("utf-8")

    if isinstance(value, str):
        value = int(value)

    # FILETIME is 100s of nanoseconds since 1601-01-01. As Python does not
    # support nanoseconds the delta is number of microseconds.
    ft_epoch = datetime.datetime(
        year=1601,
        month=1,
        day=1,
        tzinfo=datetime.timezone.utc,
    )
    delta = datetime.timedelta(microseconds=value // 10)
    dt = ft_epoch + delta

    return dt.strftime(format)


@_per_sequence
def as_guid(value: t.Any) -> str:
    """Convert LDAP little-endian GUID bytes to their canonical string.

    :param value: Raw GUID bytes, base64 text, or a sequence of those values.
    :returns: Canonical GUID string, or one string per input sequence item.
    """
    if isinstance(value, bytes):
        guid = uuid.UUID(bytes_le=value)

    else:
        b_value = base64.b64decode(str(value))
        guid = uuid.UUID(bytes_le=b_value)

    return str(guid)


@_per_sequence
def as_sid(value: t.Any) -> str:
    """Convert raw LDAP SID bytes to the Windows SID string format.

    :param value: Raw SID bytes, base64 text, or a sequence of those values.
    :returns: SID string, or one string per input sequence item.
    :raises AnsibleTemplatePluginError: The bytes cannot contain the declared SID parts.
    """
    if isinstance(value, bytes):
        view = memoryview(value)
    else:
        b_value = base64.b64decode(value)
        view = memoryview(b_value)

    if len(view) < 8:
        raise AnsibleFilterError("Raw SID bytes must be at least 8 bytes long")

    revision = view[0]
    sub_authority_count = view[1]
    authority = struct.unpack(">Q", view[:8])[0] & ~0xFFFF000000000000

    view = view[8:]
    if len(view) < sub_authority_count * 4:
        raise AnsibleFilterError("Not enough data to unpack SID")

    sub_authorities: t.List[str] = []
    for dummy in range(sub_authority_count):
        auth = struct.unpack("<I", view[:4])[0]
        sub_authorities.append(str(auth))
        view = view[4:]

    return f"S-{revision}-{authority}-{'-'.join(sub_authorities)}"


@_per_sequence
def dn_escape(value: str) -> str:
    """Escape a value for insertion into a distinguished-name component.

    :param value: RDN attribute value, without its attribute name and equals sign.
    :returns: Escaped RDN value, or one value per input sequence item.
    """
    escaped_value = []

    end_idx = len(value) - 1
    for idx, c in enumerate(value):
        if (
            # Starting char cannot be ' ' or #
            (idx == 0 and c in [" ", "#"])
            # Ending char cannot be ' '
            or (idx == end_idx and c == " ")
            # Any of these chars need to be escaped
            # These are documented in RFC 4514
            or (c in ['"', "+", ",", ";", "<", ">", "\\"])
        ):
            escaped_value.append(rf"\{c}")

        elif c in ["\00", "\n", "\r", "=", "/"]:
            # These are extra chars MS says to escape, it must be done using
            # the hex syntax
            # https://learn.microsoft.com/en-us/previous-versions/windows/desktop/ldap/distinguished-names
            escaped_int = ord(c)
            escaped_value.append(rf"\{escaped_int:02X}")

        else:
            escaped_value.append(c)

    return "".join(escaped_value)


@_per_sequence
def parse_dn(value: str) -> t.List[t.List[str]]:
    """Parse a distinguished name into lists of attribute/value pairs per RDN.

    :param value: RFC 4514 distinguished name, or a sequence of names.
    :returns: Lists of RDN components, or one parsed result per sequence item.
    :raises AnsibleTemplatePluginError: An RDN name, value, or escape is invalid.
    """

    # This behaviour is defined in RFC 4514 and while not defined in that RFC
    # this will also remove any extra spaces before and after , = and +.
    dn: t.List[t.List[str]] = []

    # This operates on bytes for 2 reasons:
    #   1. We can use a memoryview for more efficient slicing
    #   2. Attribute value hex escaping is done per byte, we cannot decode
    #      back to a string until we have the final value.
    # surrogateescape is used for all conversions to ensure non-unicode bytes
    # are preserved using the escape behaviour in UTF-8.
    b_value = value.encode("utf-8", errors="surrogateescape")
    b_view = memoryview(b_value)

    while b_view:
        rdns: t.List[str] = []

        while True:
            attr_type = _parse_rdn_type(b_view)
            if not attr_type:
                remaining = b_view.tobytes().decode("utf-8", errors="surrogateescape")
                raise AnsibleFilterError(
                    f"Expecting attribute type in RDN entry from '{remaining}'"
                )

            rdns.append(attr_type[0].decode("utf-8", errors="surrogateescape"))
            b_view = b_view[attr_type[1] :]

            attr_value = _parse_rdn_value(b_view)
            if not attr_value:
                remaining = b_view.tobytes().decode("utf-8", errors="surrogateescape")
                raise AnsibleFilterError(
                    f"Expecting attribute value in RDN entry from '{remaining}'"
                )

            rdns.append(attr_value[0].decode("utf-8", errors="surrogateescape"))
            b_view = b_view[attr_value[1] :]

            # If ended with + we want to continue parsing the AVA values
            if attr_value[2]:
                continue
            break

        dn.append(rdns)

    return dn


@_per_sequence
def split_dn(
    value: str,
    section: t.Literal["leaf", "parent"] = "leaf",
    /,
) -> str:
    """Return the canonical leaf or parent of a distinguished name.

    :param value: RFC 4514 distinguished name, or a sequence of names.
    :param section: Select the leaf RDN or the remaining parent components.
    :returns: Canonical DN section, or one section per input sequence item.
    """

    parsed_dn = parse_dn(value)

    if not parsed_dn:
        return ""

    def _join_rdn(rdn: list[str]) -> str:
        pairs = zip(rdn[0::2], rdn[1::2])
        return "+".join([f"{atv[0]}={dn_escape(atv[1])}" for atv in pairs])

    if section == "leaf":
        return _join_rdn(parsed_dn[0])
    return ",".join(_join_rdn(rdn) for rdn in parsed_dn[1:])


# Ansible discovers filter plugins through this single registry method.
class FilterModule:  # pylint: disable=too-few-public-methods
    """Expose the six upstream LDAP filters under this collection's namespace."""

    def filters(self) -> t.Dict[str, t.Callable[..., t.Any]]:
        """Return Ansible's filter-name mapping.

        :returns: Filter callables keyed by their public short names.
        """
        return {
            "as_datetime": as_datetime,
            "as_guid": as_guid,
            "as_sid": as_sid,
            "dn_escape": dn_escape,
            "parse_dn": parse_dn,
            "split_dn": split_dn,
        }
