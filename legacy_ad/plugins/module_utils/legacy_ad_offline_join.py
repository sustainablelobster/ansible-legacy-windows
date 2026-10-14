# -*- coding: utf-8 -*-
# Copyright 2026 sustainablelobster
# SPDX-License-Identifier: GPL-3.0-or-later

"""Resolve existing AD computer accounts and produce native offline join blobs."""

import ctypes
import os
import uuid

import legacy_ad_ldap as ldap  # pylint: disable=import-error
import legacy_windows_account as accounts  # pylint: disable=import-error

_COMPUTERS_CONTAINER_GUID = "AA312825768811D1ADED00C04FD8D5CD"
_REUSE_ACCOUNT = 0x00000002
_ROOT_CA_CERTS = 0x00000010


class _ProvisioningParameters(
    ctypes.Structure
):  # pylint: disable=too-few-public-methods
    _fields_ = [
        ("version", ctypes.c_uint32),
        ("domain", ctypes.c_wchar_p),
        ("machine_name", ctypes.c_wchar_p),
        ("machine_ou", ctypes.c_wchar_p),
        ("domain_controller", ctypes.c_wchar_p),
        ("options", ctypes.c_uint32),
        ("certificate_templates", ctypes.c_void_p),
        ("certificate_count", ctypes.c_uint32),
        ("policy_names", ctypes.c_void_p),
        ("policy_name_count", ctypes.c_uint32),
        ("policy_paths", ctypes.c_void_p),
        ("policy_path_count", ctypes.c_uint32),
        ("netbios_name", ctypes.c_wchar_p),
        ("site_name", ctypes.c_wchar_p),
        ("primary_dns_domain", ctypes.c_wchar_p),
    ]


def _attributes(entry):
    return {key.lower(): values for key, values in entry["attributes"].items()}


def _rdn(value):
    result = []
    for index, character in enumerate(value):
        escape = character in ',+"\\<>;='
        escape = escape or (index == 0 and character in " #")
        escape = escape or (index == len(value) - 1 and character == " ")
        result.append(("\\" if escape else "") + character)
    return "".join(result)


def _computer_container(connection, domain_dn):
    entries = connection.search(
        domain_dn, ldap.SCOPE_BASE, "(objectClass=*)", ["wellKnownObjects"]
    )
    if len(entries) != 1:
        raise ValueError(
            "The directory did not return its default naming-context object."
        )
    prefix = "B:32:" + _COMPUTERS_CONTAINER_GUID + ":"
    for value in _attributes(entries[0]).get("wellknownobjects", []):
        text = value.decode("utf-8")
        if text[: len(prefix)].upper() == prefix:
            return text[len(prefix) :]
    raise ValueError(
        "The domain does not advertise its default computer-account container."
    )


def _find_computer(connection, domain_dn, identity, name, path):
    if identity is None:
        base = (
            "CN="
            + _rdn(name)
            + ","
            + (path or _computer_container(connection, domain_dn))
        )
        return base, connection.search(
            base, ldap.SCOPE_BASE, "(objectClass=computer)", ["sAMAccountName"]
        )
    try:
        guid = uuid.UUID(identity)
    except ValueError:
        guid = None
    if guid is not None:
        assertion = "(objectGUID=" + ldap.escape_filter(guid.bytes_le) + ")"
    elif identity.upper().startswith("S-1-"):
        assertion = (
            "(objectSid=" + ldap.escape_filter(accounts.sid_bytes(identity)) + ")"
        )
    elif "=" in identity:
        return identity, connection.search(
            identity, ldap.SCOPE_BASE, "(objectClass=computer)", ["sAMAccountName"]
        )
    else:
        sam = identity if identity.endswith("$") else identity + "$"
        assertion = "(sAMAccountName=" + ldap.escape_filter(sam) + ")"
    query = "(&(objectClass=computer)" + assertion + ")"
    return identity, connection.search(
        domain_dn, ldap.SCOPE_SUBTREE, query, ["sAMAccountName"]
    )


def computer_account(identity=None, name=None, path=None, server=None):
    """Resolve an existing computer and its DNS domain using caller credentials.

    :param str identity: Computer DN, GUID, SID or sAMAccountName.
    :param str name: Computer CN, used instead of identity.
    :param str path: Container distinguished name for name lookup.
    :param str server: Optional LDAP/domain-controller endpoint.
    :returns: DNS domain and machine sAMAccountName without its trailing dollar.
    :rtype: tuple
    :raises ValueError: No matching account, domain metadata, or usable SAM name exists.
    :raises OSError: Native LDAP authentication or search fails.
    """
    with ldap.LDAPConnection(server) as connection:
        domain_dn = connection.naming_context()
        selected, entries = _find_computer(connection, domain_dn, identity, name, path)
        if len(entries) != 1:
            raise ValueError(
                "Failed to find domain computer account '" + selected + "'."
            )
        values = _attributes(entries[0]).get("samaccountname", [])
        if len(values) != 1 or not values[0].endswith(b"$") or len(values[0]) < 2:
            raise ValueError(
                "The computer account has no valid sAMAccountName ending with '$'."
            )
        machine_name = values[0][:-1].decode("utf-8")
        references = connection.search(
            connection.naming_context("configurationNamingContext"),
            ldap.SCOPE_SUBTREE,
            "(&(objectClass=crossRef)(nCName=" + ldap.escape_filter(domain_dn) + "))",
            ["dnsRoot"],
        )
        if len(references) != 1:
            raise ValueError(
                "The directory did not identify the computer account's DNS domain."
            )
        roots = _attributes(references[0]).get("dnsroot", [])
        if len(roots) != 1 or not roots[0]:
            raise ValueError(
                "The computer account's directory partition has no DNS domain name."
            )
        return roots[0].decode("utf-8"), machine_name


def provisioning_api(root_ca_certs=False):
    """Resolve supported provisioning APIs before resetting an account password.

    :param bool root_ca_certs: Whether to include local root CA certificates.
    :returns: Native library and selected provisioning function name.
    :rtype: tuple
    :raises OSError: The native API or required certificate feature is unavailable.
    """
    if os.name != "nt":
        raise OSError("Offline domain provisioning requires a Windows target.")
    library = ctypes.WinDLL("netapi32", use_last_error=True)
    number = ctypes.c_uint32
    pointer = ctypes.c_void_p
    text = ctypes.c_wchar_p
    output = ctypes.POINTER(pointer)
    size = ctypes.POINTER(number)
    library.NetApiBufferFree.argtypes = [pointer]
    library.NetApiBufferFree.restype = number
    if getattr(library, "NetCreateProvisioningPackage", None) is not None:
        name = "NetCreateProvisioningPackage"
        arguments = [ctypes.POINTER(_ProvisioningParameters), output, size, output]
    elif root_ca_certs:
        raise OSError(
            "provision_root_ca_certs requires NetCreateProvisioningPackage "
            "(Windows 8 / Server 2012 or later); no account password was changed."
        )
    elif getattr(library, "NetProvisionComputerAccount", None) is not None:
        name = "NetProvisionComputerAccount"
        arguments = [text, text, text, text, number, output, size, output]
    else:
        raise OSError(
            "Offline provisioning requires NetProvisionComputerAccount "
            "(Windows 7 / Server 2008 R2 or later); no account password was changed."
        )
    function = getattr(library, name)
    function.argtypes = arguments
    function.restype = number
    return library, name


def provision(domain, machine_name, server=None, root_ca_certs=False):
    """Reuse a computer account, reset its password, and return its binary blob.

    :param str domain: DNS domain containing the account.
    :param str machine_name: Existing sAMAccountName without its trailing dollar.
    :param str server: Optional domain controller for provisioning.
    :param bool root_ca_certs: Include local root CA certificates when supported.
    :returns: Opaque binary data accepted by NetRequestOfflineDomainJoin.
    :rtype: bytes
    :raises OSError: Windows rejects provisioning or returns no blob.
    """
    library, name = provisioning_api(root_ca_certs)
    buffer = ctypes.c_void_p()
    size = ctypes.c_uint32()
    flags = _REUSE_ACCOUNT | (_ROOT_CA_CERTS if root_ca_certs else 0)
    try:
        if name == "NetCreateProvisioningPackage":
            parameters = _ProvisioningParameters(
                version=1,
                domain=domain,
                machine_name=machine_name,
                domain_controller=server,
                options=flags,
            )
            code = library.NetCreateProvisioningPackage(
                ctypes.byref(parameters), ctypes.byref(buffer), ctypes.byref(size), None
            )
        else:
            # The account was resolved first. Reuse its existing location rather
            # than ask provisioning to create or move it in an explicit OU.
            code = library.NetProvisionComputerAccount(
                domain,
                machine_name,
                None,
                server,
                flags,
                ctypes.byref(buffer),
                ctypes.byref(size),
                None,
            )
        if code:
            message = ctypes.FormatError(code).rstrip(".\r\n ")
            raise OSError(
                code,
                "Offline provisioning failed (0x{0:08X}): {1}".format(code, message),
            )
        if not buffer or not size.value:
            raise OSError(
                "Windows returned no offline provisioning blob after resetting "
                "the computer-account password."
            )
        return ctypes.string_at(buffer, size.value)
    finally:
        if buffer:
            library.NetApiBufferFree(buffer)
