# -*- coding: utf-8 -*-
# Copyright 2026 Joe Lustri
# SPDX-License-Identifier: GPL-3.0-or-later

"""Edit Windows hosts lines with the pinned upstream matching behavior."""

import codecs
import ctypes
import ipaddress
import os
import re
import socket

# These existing helpers keep target text and Windows comparison rules aligned.
import legacy_windows_environment as environment  # pylint: disable=import-error
from legacy_windows_module import DOTNET_WHITESPACE  # pylint: disable=import-error
from legacy_windows_text import decode_bytes  # pylint: disable=import-error

_SPACE = "[" + re.escape(DOTNET_WHITESPACE) + "]"


def parse_address(text):
    """Parse an IP literal without looking up a host or requiring IPv6 support.

    :param text: Original address spelling.
    :type text: str
    :returns: Address family (4 or 6) and canonical text, or None if invalid.
    :rtype: tuple or None
    :raises ValueError: If the pinned parser's signed scope conversion overflows.
    """
    if (
        not text
        or any(character in DOTNET_WHITESPACE for character in text)
        or "\0" in text
    ):
        return None
    if ":" not in text:
        try:
            packed = socket.inet_aton(text)
        except OSError:
            return None
        return 4, socket.inet_ntoa(packed)
    return _parse_ipv6(text)


def _parse_ipv6(candidate):
    if candidate.startswith("["):
        bracket = candidate.find("]")
        if bracket == -1:
            return None
        suffix = candidate[bracket + 1 :]
        if suffix and (
            re.match(r"\A:[0-9]+\Z", suffix) is None or int(suffix[1:]) > 65535
        ):
            return None
        candidate = candidate[1:bracket]
    address_text, delimiter, scope_text = candidate.partition("%")
    if delimiter and re.match(r"\A[0-9]+\Z", scope_text) is None:
        return None
    scope = int(scope_text) if delimiter else 0
    if scope > 0xFFFFFFFF:
        return None
    try:
        address = ipaddress.IPv6Address(address_text)
    except ValueError:
        return None
    if scope >= 0x80000000:
        # The observed framework parser sign-extends the native scope DWORD.
        raise ValueError(
            "Unhandled exception while executing module: Exception calling "
            '"TryParse" with "2" argument(s): "Specified argument was out of '
            'the range of valid values.\r\nParameter name: scopeid"'
        )
    if address.ipv4_mapped is not None:
        normalized = "::ffff:" + str(address.ipv4_mapped)
    elif int(address) >> 32 == 0 and int(address) > 0xFFFF:
        normalized = "::" + str(ipaddress.IPv4Address(int(address)))
    else:
        normalized = str(address)
    if scope:
        normalized += "%" + str(scope)
    return 6, normalized


def _hosts_path():
    if os.name != "nt":
        raise ValueError("Hosts file management requires a Windows target.")
    return os.path.join(os.environ["SystemRoot"], "System32", "drivers", "etc", "hosts")


def _read_encoding():
    kernel = ctypes.WinDLL("kernel32", use_last_error=True)
    kernel.GetACP.argtypes = []
    kernel.GetACP.restype = ctypes.c_uint32
    return "cp" + str(kernel.GetACP())


def read_hosts():
    """Read the existing system hosts file using BOM or default ANSI decoding.

    :returns: Lines without their CR, LF, or CRLF terminators.
    :rtype: list
    :raises OSError: If the file or Windows code page cannot be read.
    :raises ValueError: If called outside Windows.
    :raises LookupError: If the Windows ANSI code page is unavailable.
    """
    with open(_hosts_path(), "rb") as stream:
        content = decode_bytes(stream.read(), _read_encoding())
    if not content:
        return []
    lines = re.split(r"\r\n|\r|\n", content)
    if lines[-1] == "":
        lines.pop()
    return lines


def write_hosts(lines):
    """Replace hosts content using Windows ANSI encoding and CRLF terminators.

    Writes preserve the existing file object and its security descriptor.

    :param lines: Edited logical lines.
    :type lines: list
    :raises OSError: If opening or writing the file fails.
    :raises ValueError: If called outside Windows.
    :raises UnicodeError: If Windows cannot encode the content.
    """
    content = "".join(line + "\r\n" for line in lines)
    # The native MBCS codec supplies Windows's default-codepage best-fit mapping.
    encoded = codecs.encode(content, "mbcs", "replace")
    with open(_hosts_path(), "wb") as stream:
        stream.write(encoded)


def _entry(line):
    pure = line.split("#", 1)[0].strip(DOTNET_WHITESPACE)
    parts = re.split(_SPACE + "+", pure)
    if len(parts) < 2:
        return None
    address = parse_address(parts[0])
    if address is None:
        # The pinned parser accesses the null result even after TryParse fails.
        raise ValueError(
            "Unhandled exception while executing module: The property "
            "'IPAddressToString' cannot be found on this object. "
            "Verify that the property exists."
        )
    return {
        "ip": address[1],
        "family": address[0],
        "name": parts[1],
        "aliases": parts[2:],
    }


def _contains(names, name):
    return any(environment.values_equal(existing, name) for existing in names)


def _find_name(line, name):
    comment = line.find("#")
    end = comment if comment >= 0 else len(line)
    # Upstream escapes dots only; other metacharacters retain regex meaning.
    pattern = _SPACE + "+" + name.replace(".", r"\.") + "(" + _SPACE + "|$)"
    try:
        return re.compile(pattern, re.IGNORECASE).search(line, 0, end)
    except re.error as error:
        raise ValueError("Invalid host-name expression: " + str(error)) from error


def _remove_names(lines, index, names):
    original = line = lines[index]
    for name in names:
        match = _find_name(line, name)
        if match is None:
            continue
        line = line[: match.start() + 1] + line[match.end() :]
        if re.search(_SPACE, line.split("#", 1)[0].strip(DOTNET_WHITESPACE)) is None:
            del lines[index]
            # Upstream omits the changed flag when the last name removes a line.
            return True, False
    lines[index] = line
    return False, line != original


def _add_names(lines, index, names):
    original = line = lines[index]
    for name in names:
        if _find_name(line, name) is not None:
            continue
        comment = line.find("#")
        at = comment if comment >= 0 else len(line)
        line = line[:at] + " " + name + " " + line[at:]
    lines[index] = line
    return line != original


def _finish_present(lines, selected, parameters, kept):
    aliases = parameters["aliases"] or []
    requested = kept if parameters["action"] == "remove" else aliases + kept
    if selected >= 0:
        entry = _entry(lines[selected])
        additions = [
            alias for alias in requested if not _contains(entry["aliases"], alias)
        ]
        return _add_names(lines, selected, additions) if additions else False
    lines.append(
        "{0} {1} {2}".format(
            parameters["ip_address"] or "",
            parameters["canonical_name"] or "",
            " ".join(requested),
        )
    )
    return True


# The ordered scan carries aliases between rows and preserves upstream's index
# and changed-flag behavior; splitting that state would obscure the decisions.
# pylint: disable=too-many-locals,too-many-branches,too-many-nested-blocks
def _present(lines, parameters):
    address = parameters["ip_address"]
    name = parameters["canonical_name"]
    aliases = parameters["aliases"] or []
    action = parameters["action"]
    parsed = parse_address(address) if address else None
    family = parsed[0] if parsed else 4
    kept = []
    selected = -1
    changed = False
    index = 0
    while index < len(lines):
        entry = _entry(lines[index])
        if entry is None:
            index += 1
            continue
        remove = []
        if environment.values_equal(entry["ip"], address):
            if environment.values_equal(entry["name"], name):
                selected = index
                if action == "set":
                    remove = [
                        alias
                        for alias in entry["aliases"]
                        if not _contains(aliases, alias)
                    ]
                elif action == "remove":
                    remove = aliases
            else:
                remove = aliases + ([name] if name is not None else [])
        elif entry["family"] == family:
            same_name = environment.values_equal(entry["name"], name)
            alias_is_name = action != "remove" and _contains(aliases, entry["name"])
            if same_name or alias_is_name:
                del lines[index]
                changed = True
                if (same_name and action != "set") or (
                    alias_is_name and action == "add"
                ):
                    for alias in entry["aliases"]:
                        if not _contains(aliases + kept + [name], alias):
                            kept.append(alias)
                continue
            if action == "remove":
                remove = [name] if name is not None else []
            else:
                remove = aliases + ([name] if name is not None else [])
        if remove:
            removed, edited = _remove_names(lines, index, remove)
            changed = changed or edited
            if removed:
                continue
        index += 1
    return _finish_present(lines, selected, parameters, kept) or changed


# pylint: enable=too-many-locals,too-many-branches,too-many-nested-blocks


def edit_lines(lines, parameters):
    """Apply the pinned upstream entry and alias rules without changing input.

    :param lines: Existing logical hosts lines.
    :type lines: list
    :param parameters: Bound state, canonical_name, ip_address, aliases, action.
    :type parameters: dict
    :returns: Edited logical lines and the upstream changed flag.
    :rtype: tuple
    :raises ValueError: If a name's regular expression is invalid.
    :raises OSError: If Windows string comparison fails.
    """
    updated = list(lines)
    state = parameters["state"]
    if state == "absent":
        name, address = parameters["canonical_name"], parameters["ip_address"]
        kept = []
        for line in updated:
            entry = _entry(line)
            remove = (
                entry is not None
                and (not address or environment.values_equal(entry["ip"], address))
                and (not name or environment.values_equal(entry["name"], name))
            )
            if not remove:
                kept.append(line)
        return kept, len(kept) != len(updated)
    if state == "present":
        return updated, _present(updated, parameters)
    return updated, False
