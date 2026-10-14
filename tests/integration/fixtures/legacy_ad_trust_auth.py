"""Observe a fresh LDAP bind's native security package and routed principals."""

# Copyright 2026 sustainablelobster
# SPDX-License-Identifier: GPL-3.0-or-later

import ctypes
import json
import sys

# The fixture stages this exact installed target helper beside the observer.
from legacy_ad_ldap import SCOPE_BASE, LDAPConnection  # pylint: disable=import-error


# Fixed SSPI records describe the Windows boundary, not a new auth provider.
# pylint: disable=too-few-public-methods
class _PackageInformation(ctypes.Structure):
    _fields_ = [
        ("capabilities", ctypes.c_uint32),
        ("version", ctypes.c_uint16),
        ("rpc_id", ctypes.c_uint16),
        ("maximum_token", ctypes.c_uint32),
        ("name", ctypes.c_wchar_p),
        ("comment", ctypes.c_wchar_p),
    ]


class _NegotiationInformation(ctypes.Structure):
    _fields_ = [
        ("package", ctypes.POINTER(_PackageInformation)),
        ("state", ctypes.c_uint32),
    ]


class _NativeNames(ctypes.Structure):
    _fields_ = [("client", ctypes.c_wchar_p), ("server", ctypes.c_wchar_p)]


class _ContextHandle(ctypes.Structure):
    _fields_ = [("lower", ctypes.c_size_t), ("upper", ctypes.c_size_t)]


# pylint: enable=too-few-public-methods


def _security_library():
    library = ctypes.WinDLL("secur32", use_last_error=True)
    library.QueryContextAttributesW.argtypes = [
        ctypes.c_void_p,
        ctypes.c_uint32,
        ctypes.c_void_p,
    ]
    library.QueryContextAttributesW.restype = ctypes.c_int32
    library.FreeContextBuffer.argtypes = [ctypes.c_void_p]
    library.FreeContextBuffer.restype = ctypes.c_int32
    return library


def _check(status, operation):
    if status:
        raise OSError(
            status, operation + " failed (0x{0:08x})".format(status & 0xFFFFFFFF)
        )


def _native_names(security, context):
    names = _NativeNames()
    status = security.QueryContextAttributesW(
        ctypes.byref(context), 13, ctypes.byref(names)
    )
    result = {"native_names_status": status}
    if status == 0:
        try:
            result["client_principal"] = names.client
            result["service_principal"] = names.server
        finally:
            for offset in (_NativeNames.client.offset, _NativeNames.server.offset):
                pointer = ctypes.c_void_p.from_address(
                    ctypes.addressof(names) + offset
                ).value
                if pointer:
                    _check(
                        security.FreeContextBuffer(pointer),
                        "Free native principal name",
                    )
    return result


def observe(server, username, password, identity):
    """Bind afresh and inspect actual SSPI routing without changing trust state.

    :param str server: Exact resource-forest LDAP controller hostname.
    :param str username: Explicit fixture user principal from the other forest.
    :param str password: Fixture user secret, received only through standard input.
    :param str identity: Protected directory object to read on that controller.
    :returns: Observed package, principals, signing, sealing and directory identity.
    :rtype: dict
    :raises OSError: LDAP authentication, protected reading or SSPI querying fails.
    """
    security = _security_library()
    result = {"server": server, "python": list(sys.version_info[:3])}
    with LDAPConnection(server, username, password) as connection:
        result["naming_context"] = connection.naming_context()
        rows = connection.search(
            identity, SCOPE_BASE, "(objectClass=*)", ["objectGUID", "objectClass"]
        )
        result["protected_objects"] = [row["dn"] for row in rows]
        get_option = connection.library.ldap_get_optionW
        get_option.argtypes = [ctypes.c_void_p, ctypes.c_int, ctypes.c_void_p]
        get_option.restype = ctypes.c_uint32
        for field, option in (("signing", 0x95), ("encryption", 0x96)):
            enabled = ctypes.c_uint32()
            _check(
                get_option(connection.handle, option, ctypes.byref(enabled)),
                "Read LDAP " + field,
            )
            result[field] = enabled.value
        # The vendor LDAP wrapper passes a two-pointer handle by reference.
        # This option writes caller-owned storage, not an allocated pointer.
        context = _ContextHandle()
        _check(
            get_option(connection.handle, 0x99, ctypes.byref(context)),
            "Read LDAP security context",
        )
        negotiation = _NegotiationInformation()
        _check(
            security.QueryContextAttributesW(
                ctypes.byref(context), 12, ctypes.byref(negotiation)
            ),
            "Read negotiated authentication package",
        )
        if not negotiation.package:
            raise OSError("Windows returned no negotiated authentication package.")
        try:
            result["package"] = negotiation.package.contents.name
            result["negotiation_state"] = negotiation.state
        finally:
            _check(
                security.FreeContextBuffer(negotiation.package),
                "Free authentication package information",
            )
        result.update(_native_names(security, context))
    return result


def main():
    """Read secret fixture input and emit only the native observation.

    :raises AssertionError: The fixture is not executing actual Python 3.4.4.
    """
    assert sys.version_info[:3] == (3, 4, 4)
    settings = json.load(sys.stdin)
    print(
        json.dumps(
            observe(
                settings["server"],
                settings["username"],
                settings["password"],
                settings["identity"],
            )
        )
    )


if __name__ == "__main__":
    main()
