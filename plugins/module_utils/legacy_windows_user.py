# -*- coding: utf-8 -*-
# Copyright 2026 Joe Lustri
# SPDX-License-Identifier: GPL-3.0-or-later

"""Read and change local users through Windows APIs on Python 3.4.4."""

import ctypes
import os

from legacy_windows_account import sid_to_string  # pylint: disable=import-error

_USER_NOT_FOUND = 2221
_MAX_PREFERRED_LENGTH = 0xFFFFFFFF


# Native records have no Python behavior; their fields follow the Windows ABI.
class _UserInfo1(ctypes.Structure):  # pylint: disable=too-few-public-methods
    _fields_ = [
        ("name", ctypes.c_wchar_p),
        ("password", ctypes.c_wchar_p),
        ("password_age", ctypes.c_uint32),
        ("priv", ctypes.c_uint32),
        ("home_dir", ctypes.c_wchar_p),
        ("comment", ctypes.c_wchar_p),
        ("flags", ctypes.c_uint32),
        ("script_path", ctypes.c_wchar_p),
    ]


class _UserInfo4(ctypes.Structure):  # pylint: disable=too-few-public-methods
    _fields_ = [
        ("name", ctypes.c_wchar_p),
        ("password", ctypes.c_wchar_p),
        ("password_age", ctypes.c_uint32),
        ("priv", ctypes.c_uint32),
        ("home_dir", ctypes.c_wchar_p),
        ("comment", ctypes.c_wchar_p),
        ("flags", ctypes.c_uint32),
        ("script_path", ctypes.c_wchar_p),
        ("auth_flags", ctypes.c_uint32),
        ("full_name", ctypes.c_wchar_p),
        ("usr_comment", ctypes.c_wchar_p),
        ("parameters", ctypes.c_wchar_p),
        ("workstations", ctypes.c_wchar_p),
        ("last_logon", ctypes.c_uint32),
        ("last_logoff", ctypes.c_uint32),
        ("acct_expires", ctypes.c_uint32),
        ("max_storage", ctypes.c_uint32),
        ("units_per_week", ctypes.c_uint32),
        ("logon_hours", ctypes.c_void_p),
        ("bad_pw_count", ctypes.c_uint32),
        ("num_logons", ctypes.c_uint32),
        ("logon_server", ctypes.c_wchar_p),
        ("country_code", ctypes.c_uint32),
        ("code_page", ctypes.c_uint32),
        ("user_sid", ctypes.c_void_p),
        ("primary_group_id", ctypes.c_uint32),
        ("profile", ctypes.c_wchar_p),
        ("home_dir_drive", ctypes.c_wchar_p),
        ("password_expired", ctypes.c_uint32),
    ]


class _UserInfo1003(ctypes.Structure):  # pylint: disable=too-few-public-methods
    _fields_ = [("password", ctypes.c_wchar_p)]


class _LocalGroupUsersInfo0(ctypes.Structure):  # pylint: disable=too-few-public-methods
    _fields_ = [("name", ctypes.c_wchar_p)]


class _WorkstationInfo100(ctypes.Structure):  # pylint: disable=too-few-public-methods
    _fields_ = [
        ("platform_id", ctypes.c_uint32),
        ("computer", ctypes.c_wchar_p),
        ("langroup", ctypes.c_wchar_p),
        ("version_major", ctypes.c_uint32),
        ("version_minor", ctypes.c_uint32),
    ]


def _netapi():
    if os.name != "nt":
        raise ValueError("Local user operations require a Windows target.")
    library = ctypes.WinDLL("netapi32")
    library.NetUserGetInfo.argtypes = [
        ctypes.c_wchar_p,
        ctypes.c_wchar_p,
        ctypes.c_uint32,
        ctypes.POINTER(ctypes.c_void_p),
    ]
    library.NetUserGetInfo.restype = ctypes.c_uint32
    # Keep fixed NetAPI signatures beside their user-specific record layouts.
    # Sharing them with group operations would obscure buffer ownership.
    # pylint: disable=duplicate-code
    library.NetUserAdd.argtypes = [
        ctypes.c_wchar_p,
        ctypes.c_uint32,
        ctypes.c_void_p,
        ctypes.POINTER(ctypes.c_uint32),
    ]
    library.NetUserAdd.restype = ctypes.c_uint32
    library.NetUserSetInfo.argtypes = [
        ctypes.c_wchar_p,
        ctypes.c_wchar_p,
        ctypes.c_uint32,
        ctypes.c_void_p,
        ctypes.POINTER(ctypes.c_uint32),
    ]
    library.NetUserSetInfo.restype = ctypes.c_uint32
    library.NetUserDel.argtypes = [ctypes.c_wchar_p, ctypes.c_wchar_p]
    library.NetUserDel.restype = ctypes.c_uint32
    library.NetUserGetLocalGroups.argtypes = [
        ctypes.c_wchar_p,
        ctypes.c_wchar_p,
        ctypes.c_uint32,
        ctypes.c_uint32,
        ctypes.POINTER(ctypes.c_void_p),
        ctypes.c_uint32,
        ctypes.POINTER(ctypes.c_uint32),
        ctypes.POINTER(ctypes.c_uint32),
    ]
    library.NetUserGetLocalGroups.restype = ctypes.c_uint32
    # pylint: enable=duplicate-code
    library.NetWkstaGetInfo.argtypes = [
        ctypes.c_wchar_p,
        ctypes.c_uint32,
        ctypes.POINTER(ctypes.c_void_p),
    ]
    library.NetWkstaGetInfo.restype = ctypes.c_uint32
    library.NetApiBufferFree.argtypes = [ctypes.c_void_p]
    library.NetApiBufferFree.restype = ctypes.c_uint32
    return library


def _validate_name(name):
    if not isinstance(name, str):
        raise ValueError("Local user name must be a string.")


def _check(status, operation, parameter=None):
    if status:
        message = "{0} failed (native status {1}".format(operation, status)
        if parameter is not None:
            message += ", parameter {0}".format(parameter.value)
        message += "): " + ctypes.FormatError(status)
        raise ctypes.WinError(status, message)


def read_user(name):
    """Read one local user's copied properties without returning password data.

    :param name: Local account name; Windows performs its native lookup.
    :type name: str
    :returns: Native field names and a copied SID string, or None if absent.
        String fields preserve native null values. Flags, account expiration
        seconds and password-expired state retain their native integer values.
    :rtype: dict or None
    :raises ValueError: If the name is invalid or the target is not Windows.
    :raises OSError: If reading the account or copying its SID fails.
    """
    _validate_name(name)
    library = _netapi()
    buffer = ctypes.c_void_p()
    try:
        status = library.NetUserGetInfo(None, name, 4, ctypes.byref(buffer))
        if status == _USER_NOT_FOUND:
            return None
        _check(status, "NetUserGetInfo(4)")
        information = ctypes.cast(buffer, ctypes.POINTER(_UserInfo4)).contents
        result = {
            field: getattr(information, field)
            for field in (
                "name",
                "full_name",
                "comment",
                "home_dir",
                "script_path",
                "profile",
                "flags",
                "password_expired",
                "acct_expires",
            )
        }
        result["sid"] = sid_to_string(information.user_sid)
        return result
    finally:
        if buffer:
            library.NetApiBufferFree(buffer)


def create_user(name, password, flags):
    """Create a local account with explicit flags and native level-one defaults.

    :param name: Local account name to create.
    :type name: str
    :param password: Initial password, or None to omit it.
    :type password: str or None
    :param flags: Native user-account flags to assign.
    :type flags: int
    :raises ValueError: If the name is invalid or the target is not Windows.
    :raises OSError: If Windows rejects account creation.
    """
    _validate_name(name)
    information = _UserInfo1(name, password, 0, 1, None, None, flags, None)
    parameter = ctypes.c_uint32()
    status = _netapi().NetUserAdd(
        None, 1, ctypes.byref(information), ctypes.byref(parameter)
    )
    _check(status, "NetUserAdd(1)", parameter)


def update_user(name, changes):
    """Apply scalar changes in one native call while preserving other fields.

    The fresh native record and its borrowed pointers stay alive through the
    update. Its null password pointer preserves the account's password.

    :param name: Existing local account name.
    :type name: str
    :param changes: Requested native fields: home_dir, comment, flags,
        script_path, full_name, acct_expires, profile or password_expired.
    :type changes: dict
    :raises ValueError: If the name or a field is invalid, or the target is
        not Windows.
    :raises OSError: If reading or updating the account fails.
    """
    _validate_name(name)
    allowed = (
        "home_dir",
        "comment",
        "flags",
        "script_path",
        "full_name",
        "acct_expires",
        "profile",
        "password_expired",
    )
    if any(field not in allowed for field in changes):
        raise ValueError("Unsupported local user property in changes.")
    library = _netapi()
    buffer = ctypes.c_void_p()
    try:
        status = library.NetUserGetInfo(None, name, 4, ctypes.byref(buffer))
        _check(status, "NetUserGetInfo(4) before update")
        information = ctypes.cast(buffer, ctypes.POINTER(_UserInfo4)).contents
        for field, value in changes.items():
            setattr(information, field, value)
        parameter = ctypes.c_uint32()
        status = library.NetUserSetInfo(
            None, name, 4, ctypes.byref(information), ctypes.byref(parameter)
        )
        _check(status, "NetUserSetInfo(4)", parameter)
    finally:
        if buffer:
            library.NetApiBufferFree(buffer)


def set_password(name, password):
    """Reset a password independently of the account's scalar-property batch.

    :param name: Existing local account name.
    :type name: str
    :param password: New password, including an empty string if requested.
    :type password: str
    :raises ValueError: If the name is invalid or the target is not Windows.
    :raises OSError: If Windows rejects the password reset.
    """
    _validate_name(name)
    information = _UserInfo1003(password)
    parameter = ctypes.c_uint32()
    status = _netapi().NetUserSetInfo(
        None, name, 1003, ctypes.byref(information), ctypes.byref(parameter)
    )
    _check(status, "NetUserSetInfo(1003)", parameter)


def delete_user(name):
    """Delete exactly the supplied local account without searching other names.

    :param name: Existing local account name.
    :type name: str
    :raises ValueError: If the name is invalid or the target is not Windows.
    :raises OSError: If Windows rejects deletion, including a missing account.
    """
    _validate_name(name)
    _check(_netapi().NetUserDel(None, name), "NetUserDel")


def local_group_names(name):
    """Read direct local-group memberships in native enumeration order.

    :param name: Existing local account name.
    :type name: str
    :returns: Copied names of groups containing the account directly.
    :rtype: list[str]
    :raises ValueError: If the name is invalid or the target is not Windows.
    :raises OSError: If Windows cannot return the complete enumeration.
    """
    _validate_name(name)
    library = _netapi()
    buffer = ctypes.c_void_p()
    count = ctypes.c_uint32()
    total = ctypes.c_uint32()
    try:
        # Keep this API's argument order and borrowed buffer in one place;
        # a generic enumeration wrapper would obscure their ownership.
        # pylint: disable=duplicate-code
        status = library.NetUserGetLocalGroups(
            None,
            name,
            0,
            0,
            ctypes.byref(buffer),
            _MAX_PREFERRED_LENGTH,
            ctypes.byref(count),
            ctypes.byref(total),
        )
        # pylint: enable=duplicate-code
        _check(status, "NetUserGetLocalGroups(0)")
        entries = ctypes.cast(buffer, ctypes.POINTER(_LocalGroupUsersInfo0))
        return [entries[index].name for index in range(count.value)]
    finally:
        if buffer:
            library.NetApiBufferFree(buffer)


def account_path(name):
    """Build a local account's WinNT path from native workstation identity.

    :param name: Canonical local user or group name.
    :type name: str
    :returns: WinNT path containing the workgroup or domain, computer and name.
    :rtype: str
    :raises ValueError: If the name is invalid or the target is not Windows.
    :raises OSError: If reading the workstation identity fails.
    """
    _validate_name(name)
    library = _netapi()
    buffer = ctypes.c_void_p()
    try:
        status = library.NetWkstaGetInfo(None, 100, ctypes.byref(buffer))
        _check(status, "NetWkstaGetInfo(100)")
        information = ctypes.cast(buffer, ctypes.POINTER(_WorkstationInfo100)).contents
        return "WinNT://{0}/{1}/{2}".format(
            information.langroup, information.computer, name
        )
    finally:
        if buffer:
            library.NetApiBufferFree(buffer)


def password_matches(name, password):
    """Check a local password using upstream's network-logon error semantics.

    Account, logon-hours, workstation and logon-type restrictions count as a
    matching password. Other unexpected native failures are propagated.

    :param name: Existing local account name.
    :type name: str
    :param password: Password to test without including it in failures.
    :type password: str
    :returns: Whether Windows accepts the credentials or reports a restriction.
    :rtype: bool
    :raises ValueError: If the name is invalid or the target is not Windows.
    :raises OSError: If logon fails unexpectedly or the token cannot be closed.
    """
    _validate_name(name)
    if os.name != "nt":
        raise ValueError("Local user operations require a Windows target.")
    security = ctypes.WinDLL("advapi32", use_last_error=True)
    security.LogonUserW.argtypes = [
        ctypes.c_wchar_p,
        ctypes.c_wchar_p,
        ctypes.c_wchar_p,
        ctypes.c_uint32,
        ctypes.c_uint32,
        ctypes.POINTER(ctypes.c_void_p),
    ]
    security.LogonUserW.restype = ctypes.c_int
    kernel = ctypes.WinDLL("kernel32", use_last_error=True)
    kernel.CloseHandle.argtypes = [ctypes.c_void_p]
    kernel.CloseHandle.restype = ctypes.c_int
    token = ctypes.c_void_p()
    if security.LogonUserW(name, ".", password, 3, 0, ctypes.byref(token)):
        if not kernel.CloseHandle(token):
            _check(ctypes.get_last_error(), "CloseHandle after LogonUserW")
        return True
    error = ctypes.get_last_error()
    if error == 1326:
        return False
    if error in (1327, 1328, 1329, 1385):
        return True
    _check(error, "LogonUserW")
    return False
