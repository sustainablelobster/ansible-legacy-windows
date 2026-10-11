# -*- coding: utf-8 -*-
# Copyright 2026 sustainablelobster
# SPDX-License-Identifier: GPL-3.0-or-later

"""Read the current process token without changing its security state."""

import ctypes
import os
import sys

# The action plugin stages target helpers beside the payload.
import legacy_windows_account as account  # pylint: disable=import-error

_GROUP_ATTRIBUTES = (
    (0x00000001, "Mandatory"),
    (0x00000002, "Enabled by default"),
    (0x00000004, "Enabled"),
    (0x00000008, "Owner"),
    (0x00000010, "Use for deny only"),
    (0x00000020, "Integrity"),
    (0x00000040, "Integrity enabled"),
    (0x20000000, "Resource"),
    (0xC0000000, "Logon id"),
)
_TOKEN_TYPES = {1: "TokenPrimary", 2: "TokenImpersonation"}
_IMPERSONATION_LEVELS = {
    0: "SecurityAnonymous",
    1: "SecurityIdentification",
    2: "SecurityImpersonation",
    3: "SecurityDelegation",
}


# LUID retains its signed high DWORD while conversion masks to an unsigned ID.
class _Luid(ctypes.Structure):  # pylint: disable=too-few-public-methods
    _fields_ = [("low", ctypes.c_uint32), ("high", ctypes.c_int32)]


# Windows pads each pointer-bearing group record to pointer alignment.
class _SidAndAttributes(ctypes.Structure):  # pylint: disable=too-few-public-methods
    _fields_ = [("sid", ctypes.c_void_p), ("attributes", ctypes.c_uint32)]


# The first record's offset includes native padding after the DWORD count.
class _TokenGroups(ctypes.Structure):  # pylint: disable=too-few-public-methods
    _fields_ = [("count", ctypes.c_uint32), ("groups", _SidAndAttributes * 1)]


# A privilege record uses only DWORD-aligned fields on both Windows ABIs.
class _LuidAndAttributes(ctypes.Structure):  # pylint: disable=too-few-public-methods
    _fields_ = [("luid", _Luid), ("attributes", ctypes.c_uint32)]


# No pointer alignment is required between this count and its first privilege.
class _TokenPrivileges(ctypes.Structure):  # pylint: disable=too-few-public-methods
    _fields_ = [("count", ctypes.c_uint32), ("privileges", _LuidAndAttributes * 1)]


# All fields are present to preserve native TOKEN_STATISTICS offsets and size.
class _TokenStatistics(ctypes.Structure):  # pylint: disable=too-few-public-methods
    _fields_ = [
        ("token_id", _Luid),
        ("authentication_id", _Luid),
        ("expiration_time", ctypes.c_int64),
        ("token_type", ctypes.c_int32),
        ("impersonation_level", ctypes.c_int32),
        ("dynamic_charged", ctypes.c_uint32),
        ("dynamic_available", ctypes.c_uint32),
        ("group_count", ctypes.c_uint32),
        ("privilege_count", ctypes.c_uint32),
        ("modified_id", _Luid),
    ]


def _libraries():
    if os.name != "nt":
        raise ValueError("Token information requires a Windows target.")
    security = ctypes.WinDLL("advapi32", use_last_error=True)
    kernel = ctypes.WinDLL("kernel32", use_last_error=True)
    # Keep this independently staged wrapper's native ABI declarations local.
    # pylint: disable=duplicate-code
    security.OpenProcessToken.argtypes = [
        ctypes.c_void_p,
        ctypes.c_uint32,
        ctypes.POINTER(ctypes.c_void_p),
    ]
    security.OpenProcessToken.restype = ctypes.c_int
    security.GetTokenInformation.argtypes = [
        ctypes.c_void_p,
        ctypes.c_int,
        ctypes.c_void_p,
        ctypes.c_uint32,
        ctypes.POINTER(ctypes.c_uint32),
    ]
    security.GetTokenInformation.restype = ctypes.c_int
    security.LookupPrivilegeNameW.argtypes = [
        ctypes.c_wchar_p,
        ctypes.POINTER(_Luid),
        ctypes.c_wchar_p,
        ctypes.POINTER(ctypes.c_uint32),
    ]
    security.LookupPrivilegeNameW.restype = ctypes.c_int
    security.CheckTokenMembership.argtypes = [
        ctypes.c_void_p,
        ctypes.c_void_p,
        ctypes.POINTER(ctypes.c_int),
    ]
    security.CheckTokenMembership.restype = ctypes.c_int
    kernel.GetCurrentProcess.argtypes = []
    kernel.GetCurrentProcess.restype = ctypes.c_void_p
    kernel.CloseHandle.argtypes = [ctypes.c_void_p]
    kernel.CloseHandle.restype = ctypes.c_int
    # pylint: enable=duplicate-code
    return security, kernel


def _query_information(security, token, information_class):
    # The token query owns its sizing retries and returned native buffer.
    # pylint: disable=duplicate-code
    needed = ctypes.c_uint32()
    buffer, size = None, 0
    while True:
        if security.GetTokenInformation(
            token, information_class, buffer, size, ctypes.byref(needed)
        ):
            return buffer
        error = ctypes.get_last_error()
        if error != 122:
            raise ctypes.WinError(error)
        size = max(needed.value, size * 2, 1)
        buffer = ctypes.create_string_buffer(size)
    # pylint: enable=duplicate-code


def _privilege_name(security, luid):
    length = ctypes.c_uint32()
    name = None
    while True:
        if security.LookupPrivilegeNameW(
            None, ctypes.byref(luid), name, ctypes.byref(length)
        ):
            return name.value
        error = ctypes.get_last_error()
        if error != 122:
            raise ctypes.WinError(error)
        length.value += 1
        name = ctypes.create_unicode_buffer(length.value)


def _privileges(security, token):
    buffer = _query_information(security, token, 3)
    count = ctypes.c_uint32.from_buffer(buffer).value
    records = (_LuidAndAttributes * count).from_buffer(
        buffer, _TokenPrivileges.privileges.offset
    )
    privileges = {}
    for record in records:
        state = "disabled"
        if record.attributes & 1:
            state = "enabled-by-default"
        elif record.attributes & 2:
            state = "enabled"
        privileges[_privilege_name(security, record.luid)] = state
    return privileges


def _groups(security, token):
    buffer = _query_information(security, token, 2)
    count = ctypes.c_uint32.from_buffer(buffer).value
    if not count:
        return [], []
    records = (_SidAndAttributes * count).from_buffer(
        buffer, _TokenGroups.groups.offset
    )
    groups, enabled = [], []
    for record in records:
        # Logon groups still contribute rights even though public groups omit them.
        if record.attributes & 4:
            enabled.append(account.sid_to_string(record.sid))
        if record.attributes & 0xC0000000 == 0xC0000000:
            continue
        description = account.describe_sid(record.sid)
        description["attributes"] = [
            name for flag, name in _GROUP_ATTRIBUTES if record.attributes & flag == flag
        ]
        groups.append(description)
    return groups, enabled


def _integrity_label(security, token, warnings):
    try:
        buffer = _query_information(security, token, 25)
    except OSError as error:
        # Library setup requires Windows, which supplies this platform-only API.
        # pylint: disable-next=no-member
        if getattr(error, "winerror", None) != 87 or sys.getwindowsversion().major >= 6:
            raise
        warnings.append(
            "label is unavailable: Windows does not support TokenIntegrityLevel "
            "(Win32 error 87)."
        )
        return None
    label = _SidAndAttributes.from_buffer(buffer)
    return account.describe_sid(label.sid)


def _is_administrator(security):
    sid = ctypes.create_string_buffer(account.sid_bytes("S-1-5-32-544"))
    member = ctypes.c_int()
    # A null token asks Windows about effective membership, including deny-only
    # restrictions and any thread impersonation, rather than group presence.
    if not security.CheckTokenMembership(None, sid, ctypes.byref(member)):
        raise ctypes.WinError(ctypes.get_last_error())
    return bool(member.value)


def token_information(warnings):
    """Copy current token details and the inputs needed for logon-session reads.

    :param warnings: Receives a named warning when integrity labels are unavailable.
    :type warnings: list[str]
    :returns: Public token fields, unsigned authentication ID, enabled group SID
        strings in native order, and effective administrator membership. Native
        handles and borrowed pointers are released before returning.
    :rtype: tuple[dict, int, list[str], bool]
    :raises ValueError: If called outside Windows.
    :raises OSError: If a required native token or account lookup fails.
    """
    security, kernel = _libraries()
    token = ctypes.c_void_p()
    if not security.OpenProcessToken(
        kernel.GetCurrentProcess(), 8, ctypes.byref(token)
    ):
        raise ctypes.WinError(ctypes.get_last_error())
    try:
        privileges = _privileges(security, token)
        groups, enabled = _groups(security, token)
        label = _integrity_label(security, token, warnings)
        buffer = _query_information(security, token, 10)
        statistics = _TokenStatistics.from_buffer(buffer)
        authentication_id = (
            (statistics.authentication_id.high & 0xFFFFFFFF) << 32
        ) | statistics.authentication_id.low
        fields = {
            "groups": groups,
            "privileges": privileges,
            "label": label,
            "token_type": _TOKEN_TYPES.get(
                statistics.token_type, str(statistics.token_type)
            ),
            "impersonation_level": _IMPERSONATION_LEVELS.get(
                statistics.impersonation_level, str(statistics.impersonation_level)
            ),
        }
        return fields, authentication_id, enabled, _is_administrator(security)
    finally:
        kernel.CloseHandle(token)
