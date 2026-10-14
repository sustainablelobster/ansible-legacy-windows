# Copyright 2026 sustainablelobster
# SPDX-License-Identifier: GPL-3.0-or-later

"""Convert directory values using the directory's own attribute schema."""

import base64
import ctypes
import datetime
import re
import uuid

import legacy_windows_account as accounts  # pylint: disable=import-error
from legacy_ad_filter import ALIASES  # pylint: disable=import-error
from legacy_ad_ldap import SCOPE_SUBTREE  # pylint: disable=import-error


def _time(value):
    text = value.decode("ascii")
    match = re.match(r"^(\d{14})(?:[.,](\d+))?(Z|[+-]\d{4})$", text)
    if not match:
        # UTCTime has a two-digit year, unlike GeneralizedTime.
        match = re.match(r"^(\d{12})(?:[.,](\d+))?(Z|[+-]\d{4})$", text)
        if not match:
            raise ValueError("Invalid directory time: " + text)
        prefix = "19" if int(match.group(1)[:2]) >= 50 else "20"
        date = prefix + match.group(1)
    else:
        date = match.group(1)
    instant = datetime.datetime.strptime(date, "%Y%m%d%H%M%S")
    zone = match.group(3)
    if zone != "Z":
        delta = datetime.timedelta(hours=int(zone[1:3]), minutes=int(zone[3:5]))
        instant -= delta if zone[0] == "+" else -delta
    fraction = ((match.group(2) or "") + "0000000")[:7]
    return "{0:04d}-{1:02d}-{2:02d}T{3:02d}:{4:02d}:{5:02d}.{6}Z".format(
        instant.year,
        instant.month,
        instant.day,
        instant.hour,
        instant.minute,
        instant.second,
        fraction,
    )


def sid_text(value):
    """Decode a binary SID without depending on the workstation interpreter.

    :param value: Binary SID returned by LDAP.
    :type value: bytes
    :returns: Canonical decimal SID text.
    :rtype: str
    :raises ValueError: If the SID has an invalid header or length.
    """
    if len(value) < 8 or value[0] != 1 or len(value) != 8 + 4 * value[1]:
        raise ValueError("The directory returned an invalid binary SID.")
    authority = int.from_bytes(value[2:8], "big")
    subs = [
        int.from_bytes(value[offset : offset + 4], "little")
        for offset in range(8, len(value), 4)
    ]
    return "S-1-" + str(authority) + "".join("-" + str(number) for number in subs)


def _sid(value):
    sid = sid_text(value)
    name = accounts.sid_to_name(sid)
    return {"Sid": sid, "Name": None if name == sid else name}


def security_descriptor_text(value):
    """Format a binary Windows security descriptor as SDDL.

    :param value: Self-relative binary security descriptor returned by LDAP.
    :type value: bytes
    :returns: The descriptor's owner, group, DACL and available SACL as SDDL.
    :rtype: str
    :raises OSError: If Windows rejects the descriptor.
    """
    library = ctypes.WinDLL("advapi32", use_last_error=True)
    # This Windows ABI also appears in the independent ACL execution fixture.
    # pylint: disable=duplicate-code
    library.ConvertSecurityDescriptorToStringSecurityDescriptorW.argtypes = [
        ctypes.c_void_p,
        ctypes.c_uint32,
        ctypes.c_uint32,
        ctypes.POINTER(ctypes.c_wchar_p),
        ctypes.POINTER(ctypes.c_uint32),
    ]
    library.ConvertSecurityDescriptorToStringSecurityDescriptorW.restype = ctypes.c_int
    # pylint: enable=duplicate-code
    kernel = ctypes.WinDLL("kernel32", use_last_error=True)
    kernel.LocalFree.argtypes = [ctypes.c_void_p]
    kernel.LocalFree.restype = ctypes.c_void_p
    buffer = ctypes.create_string_buffer(value)
    output = ctypes.c_wchar_p()
    try:
        if not library.ConvertSecurityDescriptorToStringSecurityDescriptorW(
            buffer, 1, 15, ctypes.byref(output), None
        ):
            raise ctypes.WinError(ctypes.get_last_error())
        return output.value
    finally:
        if output:
            kernel.LocalFree(output)


def security_descriptor_bytes(value):
    """Copy an SDDL descriptor into self-relative bytes owned by Python.

    :param value: Security descriptor in SDDL format.
    :type value: str
    :returns: Self-relative descriptor bytes suitable for LDAP modification.
    :rtype: bytes
    :raises OSError: If Windows rejects the descriptor.
    """
    library = ctypes.WinDLL("advapi32", use_last_error=True)
    library.ConvertStringSecurityDescriptorToSecurityDescriptorW.argtypes = [
        ctypes.c_wchar_p,
        ctypes.c_uint32,
        ctypes.POINTER(ctypes.c_void_p),
        ctypes.POINTER(ctypes.c_uint32),
    ]
    library.ConvertStringSecurityDescriptorToSecurityDescriptorW.restype = ctypes.c_int
    kernel = ctypes.WinDLL("kernel32", use_last_error=True)
    kernel.LocalFree.argtypes = [ctypes.c_void_p]
    kernel.LocalFree.restype = ctypes.c_void_p
    output = ctypes.c_void_p()
    length = ctypes.c_uint32()
    try:
        if not library.ConvertStringSecurityDescriptorToSecurityDescriptorW(
            value, 1, ctypes.byref(output), ctypes.byref(length)
        ):
            raise ctypes.WinError(ctypes.get_last_error())
        return ctypes.string_at(output, length.value)
    finally:
        if output:
            kernel.LocalFree(output)


def is_explicit_everyone_deny(fields):
    """Recognize an explicit Everyone deny ACE's six SDDL fields.

    :param fields: Semicolon-separated fields from one SDDL ACE.
    :type fields: list[str]
    :returns: Whether this ACE is an explicit Everyone deny rule.
    :rtype: bool
    """
    return (
        len(fields) == 6
        and fields[0] == "D"
        and "ID" not in fields[1]
        and fields[5] in ("WD", "S-1-1-0")
    )


def protected_from_deletion(value):
    """Read the explicit Everyone deny-delete ACE used by AD protection.

    :param value: The object's security descriptor in SDDL.
    :type value: str
    :returns: Whether an explicit deny ACE covers delete and delete-tree.
    :rtype: bool
    """
    for ace in re.findall(r"\(([^()]*)\)", value):
        fields = ace.split(";")
        if not is_explicit_everyone_deny(fields):
            continue
        rights = fields[2]
        if rights.startswith("0x"):
            mask = int(rights, 16)
            if mask & 0x10040 == 0x10040:
                return True
        elif "SD" in rights and "DT" in rights:
            return True
    return False


def _cast_value(name, syntax, value):
    if name.lower() == "objectguid":
        result = str(uuid.UUID(bytes_le=value))
    elif syntax == "2.5.5.17":
        result = _sid(value)
    elif syntax == "2.5.5.15":
        result = security_descriptor_text(value)
    elif syntax == "2.5.5.10":
        result = base64.b64encode(value).decode("ascii")
    elif syntax in ("2.5.5.9", "2.5.5.16"):
        result = int(value)
    elif syntax == "2.5.5.8":
        if value not in (b"TRUE", b"FALSE"):
            raise ValueError("Invalid directory Boolean for " + name)
        result = value == b"TRUE"
    elif syntax == "2.5.5.11":
        result = _time(value)
    else:
        result = value.decode("utf-8")
    return result


class DirectorySchema:
    """Load and apply the target directory's LDAP attribute definitions.

    :param connection: Authenticated native LDAP connection.
    """

    def __init__(self, connection):
        rows = connection.search(
            connection.naming_context("schemaNamingContext"),
            SCOPE_SUBTREE,
            "(objectClass=attributeSchema)",
            ["lDAPDisplayName", "attributeSyntax", "isSingleValued"],
        )
        self.attributes = {}
        for row in rows:
            values = {key.lower(): data for key, data in row["attributes"].items()}
            name = values["ldapdisplayname"][0].decode("utf-8")
            self.attributes[name.lower()] = {
                "name": name,
                "syntax": values["attributesyntax"][0].decode("ascii"),
                "single": values.get("issinglevalued", [b"FALSE"])[0] == b"TRUE",
            }

    def attribute_name(self, name):
        """Resolve a familiar AD property alias to its LDAP display name.

        :param name: AD property or LDAP display name.
        :type name: str
        :returns: LDAP attribute name or None when the property is unknown.
        :rtype: str or None
        """
        alias = ALIASES.get(name.lower(), (None, name))[1]
        info = self.attributes.get(alias.lower())
        return info["name"] if info else None

    def cast(self, name, values):
        """Convert one attribute's byte values and preserve cardinality.

        :param name: LDAP display name of the attribute.
        :type name: str
        :param values: Sequence of copied LDAP byte values.
        :type values: list[bytes]
        :returns: A scalar/null for single-valued schema attributes, else a list.
        :rtype: object
        :raises ValueError: If the schema or returned values are malformed.
        """
        info = self.attributes.get(name.lower())
        if info is None:
            raise ValueError(
                "The directory returned an attribute missing from its schema: " + name
            )
        converted = [_cast_value(name, info["syntax"], value) for value in values]
        if info["single"]:
            if len(converted) > 1:
                raise ValueError(
                    "The directory returned multiple values for single-valued " + name
                )
            return converted[0] if converted else None
        return converted
