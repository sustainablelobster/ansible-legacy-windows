# -*- coding: utf-8 -*-
# Copyright 2026 sustainablelobster
# SPDX-License-Identifier: GPL-3.0-or-later

"""Read active membership and request changes through native Windows APIs."""

import ctypes
import os
import socket
import sys

from legacy_windows_wmi import WmiConnection  # pylint: disable=import-error

_JOIN_DOMAIN = 0x00000001
_ACCOUNT_CREATE = 0x00000002
_ACCOUNT_DISABLE = 0x00000004
_DEFER_SPN_SET = 0x00000100
_JOIN_WITH_NEW_NAME = 0x00000400
_PROVISION_ONLINE_CALLER = 0x40000000


class _DomainInformation(ctypes.Structure):  # pylint: disable=too-few-public-methods
    _fields_ = [
        ("role", ctypes.c_int),
        ("flags", ctypes.c_uint32),
        ("netbios_name", ctypes.c_wchar_p),
        ("dns_name", ctypes.c_wchar_p),
        ("forest_name", ctypes.c_wchar_p),
        ("domain_guid", ctypes.c_ubyte * 16),
    ]


def _library():
    if os.name != "nt":
        raise OSError("Computer membership operations require a Windows target.")
    library = ctypes.WinDLL("netapi32", use_last_error=True)
    text = ctypes.c_wchar_p
    number = ctypes.c_uint32
    signatures = (
        ("NetJoinDomain", [text, text, text, text, text, number]),
        ("NetUnjoinDomain", [text, text, text, number]),
        ("NetRenameMachineInDomain", [text, text, text, text, number]),
    )
    for name, arguments in signatures:
        function = getattr(library, name)
        function.argtypes = arguments
        function.restype = number
    return library


def _check(code, operation):
    if code:
        message = ctypes.FormatError(code).rstrip(".\r\n ")
        raise OSError(
            code, "{0} failed (0x{1:08X}): {2}".format(operation, code, message)
        )


def _dns_domain():
    library = _library()
    library.DsRoleGetPrimaryDomainInformation.argtypes = [
        ctypes.c_wchar_p,
        ctypes.c_int,
        ctypes.POINTER(ctypes.c_void_p),
    ]
    library.DsRoleGetPrimaryDomainInformation.restype = ctypes.c_uint32
    library.DsRoleFreeMemory.argtypes = [ctypes.c_void_p]
    library.DsRoleFreeMemory.restype = None
    buffer = ctypes.c_void_p()
    try:
        _check(
            library.DsRoleGetPrimaryDomainInformation(None, 1, ctypes.byref(buffer)),
            "Read computer DNS domain",
        )
        if not buffer:
            raise OSError("Windows returned no primary-domain information.")
        return ctypes.cast(buffer, ctypes.POINTER(_DomainInformation)).contents.dns_name
    finally:
        if buffer:
            library.DsRoleFreeMemory(buffer)


def current_state():
    """Read the hostname and membership visible to the running operating system.

    :returns: Active hostname, domain/workgroup names, and domain-membership flag.
    :rtype: dict
    :raises OSError: The computer-system provider returns no usable state.
    """
    with WmiConnection() as connection:
        rows = connection.query(
            "SELECT Domain,PartOfDomain FROM Win32_ComputerSystem",
            ["Domain", "PartOfDomain"],
        )
    if len(rows) != 1 or rows[0]["PartOfDomain"] is None:
        raise OSError("WMI returned no usable Win32_ComputerSystem membership state.")
    part_of_domain = bool(rows[0]["PartOfDomain"])
    return {
        "hostname": socket.gethostname(),
        "state": "domain" if part_of_domain else "workgroup",
        "dns_domain_name": (
            (_dns_domain() or rows[0]["Domain"]) if part_of_domain else None
        ),
        "workgroup_name": None if part_of_domain else rows[0]["Domain"],
    }


def _rename_local(name):
    kernel = ctypes.WinDLL("kernel32", use_last_error=True)
    kernel.SetComputerNameExW.argtypes = [ctypes.c_int, ctypes.c_wchar_p]
    kernel.SetComputerNameExW.restype = ctypes.c_int
    # ComputerNamePhysicalDnsHostname updates the pending DNS and NetBIOS names.
    if not kernel.SetComputerNameExW(5, name):
        _check(ctypes.get_last_error(), "Set computer name")


def rename(name, username=None, password=None, domain_member=False):
    """Request a local or domain computer rename without restarting Windows.

    :param str name: Requested DNS hostname.
    :param str username: Domain user, used only for a domain-member rename.
    :param str password: Password paired with username.
    :param bool domain_member: Whether the current membership is a domain.
    :raises OSError: Windows rejects the rename or directory account update.
    """
    if domain_member:
        code = _library().NetRenameMachineInDomain(
            None, name, username, password, _ACCOUNT_CREATE
        )
        _check(code, "Rename domain computer")
    else:
        _rename_local(name)


# The six arguments map directly to one native join operation and its optional
# rename; replacing them with an opaque options dictionary obscures the API.
# pylint: disable=too-many-arguments,too-many-positional-arguments
def join_domain(domain, username, password, ou=None, server=None, hostname=None):
    """Join a domain, optionally using a new hostname in the same reboot cycle.

    :param str domain: DNS domain name.
    :param str username: Domain credential in DOMAIN\\user or UPN form.
    :param str password: Domain password.
    :param str ou: Optional distinguished name of the computer-account OU.
    :param str server: Optional preferred domain controller.
    :param str hostname: Optional replacement hostname.
    :raises OSError: Joining or renaming fails. If a later step fails, the error's
        ``rename_applied`` and ``join_applied`` attributes identify completed
        native rename and join requests that still require a reboot.
    """
    library = _library()
    options = _JOIN_DOMAIN | _ACCOUNT_CREATE
    renamed = False
    joined = False
    # XP cannot join using a pending name. Its documented join-then-rename
    # sequence defers directory SPN updates until the account has its final name.
    old_windows = sys.getwindowsversion().major < 6  # pylint: disable=no-member
    if hostname:
        if old_windows:
            options |= _DEFER_SPN_SET
        else:
            _rename_local(hostname)
            renamed = True
            options |= _JOIN_WITH_NEW_NAME
    target = domain + "\\" + server.lstrip("\\") if server else domain
    try:
        code = library.NetJoinDomain(None, target, ou, username, password, options)
        _check(code, "Join domain")
        joined = True
        if hostname and old_windows:
            code = library.NetRenameMachineInDomain(
                None, hostname, username, password, _ACCOUNT_CREATE
            )
            _check(code, "Rename joined computer")
    except OSError as error:
        # A successful join cannot be rolled back safely after a rename failure.
        error.rename_applied = renamed
        error.join_applied = joined
        raise


# pylint: enable=too-many-arguments,too-many-positional-arguments


def join_workgroup(name, username=None, password=None, domain_member=False):
    """Leave a domain when needed, then request the desired workgroup.

    :param str name: Requested workgroup name.
    :param str username: Domain credential used to disable the old domain account.
    :param str password: Password paired with username.
    :param bool domain_member: Whether the current computer belongs to a domain.
    :raises OSError: Windows rejects a change. ``unjoin_applied`` on the exception
        identifies a completed unjoin followed by a failed workgroup change.
    """
    library = _library()
    unjoined = False
    try:
        if domain_member:
            _check(
                library.NetUnjoinDomain(None, username, password, _ACCOUNT_DISABLE),
                "Leave domain",
            )
            unjoined = True
        _check(library.NetJoinDomain(None, name, None, None, None, 0), "Set workgroup")
    except OSError as error:
        error.unjoin_applied = unjoined
        raise


def require_offline_join():
    """Resolve offline joining before mutation, rejecting missing native support.

    :returns: Configured native offline-domain-join entry point.
    :rtype: ctypes function
    :raises OSError: The operating system does not expose offline domain joining.
    """
    library = _library()
    function = getattr(library, "NetRequestOfflineDomainJoin", None)
    if function is None:
        raise OSError(
            "Offline domain joining requires NetRequestOfflineDomainJoin "
            "(Windows 7 / Server 2008 R2 or later)."
        )
    function.argtypes = [
        ctypes.c_void_p,
        ctypes.c_uint32,
        ctypes.c_uint32,
        ctypes.c_wchar_p,
    ]
    function.restype = ctypes.c_uint32
    return function


def join_offline(blob):
    """Stage an opaque binary join blob into the currently running Windows image.

    :param bytes blob: Provisioning bytes returned by offline_join.
    :raises OSError: The native API is absent or rejects the provisioning data.
    """
    function = require_offline_join()
    buffer = ctypes.create_string_buffer(blob, len(blob))
    code = function(
        buffer, len(blob), _PROVISION_ONLINE_CALLER, os.environ["SystemRoot"]
    )
    _check(code, "Perform offline domain join")
