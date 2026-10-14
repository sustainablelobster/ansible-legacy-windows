# Copyright 2026 sustainablelobster
# SPDX-License-Identifier: GPL-3.0-or-later

"""Manage existing GPO links as the native directory's ordered gPLink value."""

import ctypes
import os
import re
import uuid

from legacy_ad_arguments import as_int32  # pylint: disable=import-error
from legacy_ad_ldap import (  # pylint: disable=import-error
    SCOPE_BASE,
    SCOPE_ONE_LEVEL,
    LDAPConnection,
    escape_filter,
)
from legacy_windows_module import as_bool, as_string  # pylint: disable=import-error

PARAMETERS = (
    "name",
    "guid",
    "target",
    "state",
    "enabled",
    "enforced",
    "order",
    "domain_server",
)


class _DomainController(ctypes.Structure):  # pylint: disable=too-few-public-methods
    _fields_ = [
        ("controller", ctypes.c_wchar_p),
        ("address", ctypes.c_wchar_p),
        ("address_type", ctypes.c_uint32),
        ("domain_guid", ctypes.c_ubyte * 16),
        ("domain", ctypes.c_wchar_p),
        ("forest", ctypes.c_wchar_p),
        ("flags", ctypes.c_uint32),
        ("controller_site", ctypes.c_wchar_p),
        ("client_site", ctypes.c_wchar_p),
    ]


def _pdc():
    if os.name != "nt":
        raise OSError("Native Group Policy management requires a Windows target.")
    library = ctypes.WinDLL("netapi32", use_last_error=True)
    text, pointer = ctypes.c_wchar_p, ctypes.c_void_p
    library.DsGetDcNameW.argtypes = [
        text,
        text,
        pointer,
        text,
        ctypes.c_uint32,
        ctypes.POINTER(pointer),
    ]
    library.DsGetDcNameW.restype = ctypes.c_uint32
    library.NetApiBufferFree.argtypes = [pointer]
    library.NetApiBufferFree.restype = ctypes.c_uint32
    buffer = pointer()
    try:
        # GroupPolicy's default server is the PDC emulator, not an arbitrary DC.
        code = library.DsGetDcNameW(
            None, None, None, None, 0x40000011, ctypes.byref(buffer)
        )
        if code:
            raise OSError(
                code,
                "Failed to discover the domain PDC: "
                + ctypes.FormatError(code).strip(),
            )
        if not buffer:
            raise OSError("Windows returned no PDC discovery information.")
        server = ctypes.cast(
            buffer, ctypes.POINTER(_DomainController)
        ).contents.controller
        if not server:
            raise OSError("Windows returned no PDC name.")
        return server.lstrip("\\")
    finally:
        if buffer:
            library.NetApiBufferFree(buffer)


def parameters(raw):
    """Normalize the released GPO-link module's complete public arguments.

    :param dict raw: Input module arguments and Ansible controller flags.
    :returns: Validated options preserving omitted link settings.
    :rtype: dict
    :raises ValueError: Required values, choices, strings or numbers are invalid.
    """
    values = {
        name: as_string(raw.get(name), name)
        for name in PARAMETERS
        if name not in ("enabled", "enforced", "order")
    }
    for name, value in values.items():
        if value is not None and "\0" in value:
            raise ValueError(name + " must not contain NUL characters.")
    if (values["name"] is None) == (values["guid"] is None):
        raise ValueError("Exactly one of name or guid must be provided.")
    if not values["target"]:
        raise ValueError("target is required and must not be empty.")
    values["state"] = "present" if values["state"] is None else values["state"].lower()
    if values["state"] not in ("present", "absent"):
        raise ValueError("state must be present or absent.")
    for name in ("enabled", "enforced"):
        values[name] = None if raw.get(name) is None else as_bool(raw[name], name)
    order = raw.get("order")
    values["order"] = None if order is None else as_int32(order, "order")
    values["check_mode"] = as_bool(
        raw.get("_ansible_check_mode", False), "_ansible_check_mode"
    )
    values["diff_mode"] = as_bool(raw.get("_ansible_diff", False), "_ansible_diff")
    return values


def _gpo(connection, arguments):
    base = "CN=Policies,CN=System," + connection.naming_context()
    if arguments["guid"]:
        try:
            guid = uuid.UUID(arguments["guid"])
        except ValueError:
            raise ValueError(
                "Failed to find GPO: guid must be a valid GPO GUID."
            ) from None
        rows = connection.search(
            "CN={" + str(guid) + "}," + base,
            SCOPE_BASE,
            "(objectClass=groupPolicyContainer)",
            ["cn"],
        )
    else:
        if not arguments["name"]:
            raise ValueError("Failed to find GPO: name must not be empty.")
        rows = connection.search(
            base,
            SCOPE_ONE_LEVEL,
            "(&(objectClass=groupPolicyContainer)(displayName="
            + escape_filter(arguments["name"])
            + "))",
            ["cn"],
        )
    if len(rows) != 1:
        raise ValueError(
            "Failed to find GPO: the identifier must resolve to exactly one existing GPO."
        )
    cn = {name.lower(): values for name, values in rows[0]["attributes"].items()}.get(
        "cn", []
    )
    if len(cn) != 1:
        raise ValueError(
            "Failed to find GPO: the directory returned no unique policy identifier."
        )
    return rows[0]["dn"], uuid.UUID(cn[0].decode("utf-8"))


def _links(text):
    if not text.strip():
        return []
    matches = list(
        re.finditer(r"\[(LDAP://[^\]]+);([0-9]+)\]", text, flags=re.IGNORECASE)
    )
    if "".join(match.group(0) for match in matches) != text:
        raise ValueError(
            "The target contains a malformed gPLink value; no links were changed."
        )
    # LDAP persists links from lowest to highest precedence. GroupPolicy's
    # public Order counts in the opposite direction, with Order 1 highest.
    return [
        {"path": match.group(1), "flags": int(match.group(2))}
        for match in reversed(matches)
    ]


def _matches(link, guid):
    match = re.match(r"^LDAP://CN=({?[0-9a-f-]+}?),", link["path"], flags=re.IGNORECASE)
    if match is None:
        return False
    try:
        return uuid.UUID(match.group(1)) == guid
    except ValueError:
        return False


def _snapshot(link, position):
    return {
        "enabled": not bool(link["flags"] & 1),
        "enforced": bool(link["flags"] & 2),
        "order": position + 1,
    }


def _flags(flags, arguments):
    if arguments["enabled"] is not None:
        flags = flags & ~1 if arguments["enabled"] else flags | 1
    if arguments["enforced"] is not None:
        flags = flags | 2 if arguments["enforced"] else flags & ~2
    return flags


def _desired_links(arguments, links, dn, guid, result):
    index = next(
        (position for position, link in enumerate(links) if _matches(link, guid)), None
    )
    before = _snapshot(links[index], index) if index is not None else {}
    after = {}
    updated = [dict(link) for link in links]
    if arguments["state"] == "absent":
        if index is not None:
            updated.pop(index)
    else:
        created = index is None
        link = {"path": "LDAP://" + dn, "flags": 0} if created else updated.pop(index)
        link["flags"] = _flags(link["flags"], arguments)
        position = arguments["order"]
        position = (
            len(updated) + 1
            if position is None and created
            else index + 1 if position is None else position
        )
        if not 1 <= position <= len(updated) + 1:
            raise ValueError(
                "order must be between 1 and "
                + str(len(updated) + 1)
                + " for this target."
            )
        updated.insert(position - 1, link)
        after = _snapshot(link, position - 1)
        # The released module reports null rather than computed order on a new
        # link whose caller omitted order, even though Windows appends the link.
        if created and arguments["order"] is None:
            after["order"] = None
    if arguments["diff_mode"]:
        result["diff"] = {"before": before, "after": after}
    return updated


def manage_gpo(arguments, result):
    """Apply one GPO-link request without editing policy contents or inheritance.

    :param dict arguments: Validated GPO-link options and check/diff flags.
    :param dict result: Result retaining the requested diff and completed writes.
    :raises ValueError: GPO, target, order or existing link data is invalid.
    :raises OSError: Domain discovery or native LDAP operations fail.
    """
    server = arguments["domain_server"] or _pdc()
    with LDAPConnection(server) as connection:
        dn, guid = _gpo(connection, arguments)
        rows = connection.search(
            arguments["target"],
            SCOPE_BASE,
            "(objectClass=*)",
            ["gPLink", "objectClass"],
        )
        if len(rows) != 1:
            raise ValueError(
                "Failed to read GP links on target '"
                + arguments["target"]
                + "': container not found."
            )
        raw = {name.lower(): values for name, values in rows[0]["attributes"].items()}
        classes = [
            value.decode("utf-8").lower() for value in raw.get("objectclass", [])
        ]
        if not set(classes) & {"organizationalunit", "domaindns", "site"}:
            raise ValueError("The GPO link target must be an OU, domain, or site.")
        values = raw.get("gplink", [])
        if len(values) > 1:
            raise ValueError(
                "The target returned multiple values for the single-valued gPLink attribute."
            )
        existing = _links(values[0].decode("utf-8") if values else "")
        desired = _desired_links(arguments, existing, dn, guid, result)
        if desired == existing:
            return
        # Upstream reports a changed request before its link writer is called,
        # including failures. Read directory state separately after a failure.
        result["changed"] = True
        if not arguments["check_mode"]:
            text = "".join(
                "[{0};{1}]".format(link["path"], link["flags"])
                for link in reversed(desired)
            )
            connection.modify(
                rows[0]["dn"],
                [(2 if text else 1, "gPLink", [text.encode("utf-8")] if text else [])],
            )
