# -*- coding: utf-8 -*-
# Copyright 2026 sustainablelobster
# SPDX-License-Identifier: GPL-3.0-or-later

"""Read Windows logon-session metadata and assigned logon rights through LSA."""

import ctypes
import datetime
import os

# Sibling helpers are staged beside the Python 3.4 target payload.
# pylint: disable=import-error
import legacy_windows_account as account
import legacy_windows_time as native_time

# pylint: enable=import-error

_STATUS_ACCESS_DENIED = 0xC0000022
_STATUS_OBJECT_NAME_NOT_FOUND = 0xC0000034
_POLICY_LOOKUP_NAMES = 0x800
_SECOND = 10000000
_FILETIME_EPOCH = 504911232000000000
_MAX_TICKS = 3155378975999999999
_LOGON_TYPES = {
    0: "System",
    2: "Interactive",
    3: "Network",
    4: "Batch",
    5: "Service",
    6: "Proxy",
    7: "Unlock",
    8: "NetworkCleartext",
    9: "NewCredentials",
    10: "RemoteInteractive",
    11: "CachedInteractive",
    12: "CachedRemoteInteractive",
    13: "CachedUnlock",
}
_USER_FLAGS = (
    (0x4000, "Optimized"),
    (0x8000, "Winlogon"),
    (0x10000, "Pkinit"),
    # Keep the spelling produced by the pinned upstream enum LOGON_NOT_OPTMIZED.
    (0x20000, "Not optmized"),  # codespell:ignore optmized
)


# These structures describe native memory and have no independent behavior.
class _Luid(ctypes.Structure):  # pylint: disable=too-few-public-methods
    _fields_ = [("low", ctypes.c_uint32), ("high", ctypes.c_int32)]


class _UnicodeString(ctypes.Structure):  # pylint: disable=too-few-public-methods
    # Repeat the fixed Windows record layout without adding a staging dependency.
    # pylint: disable=duplicate-code
    _fields_ = [
        ("length", ctypes.c_uint16),
        ("maximum_length", ctypes.c_uint16),
        ("buffer", ctypes.c_void_p),
    ]
    # pylint: enable=duplicate-code


class _SessionData(ctypes.Structure):  # pylint: disable=too-few-public-methods
    # Only the consumed prefix is declared; Size governs whether its fields exist.
    _fields_ = [
        ("size", ctypes.c_uint32),
        ("logon_id", _Luid),
        ("username", _UnicodeString),
        ("login_domain", _UnicodeString),
        ("authentication_package", _UnicodeString),
        # Upstream marshals this ULONG through a signed Int32-backed enum.
        ("logon_type", ctypes.c_int32),
        ("session", ctypes.c_uint32),
        ("sid", ctypes.c_void_p),
        ("login_time", ctypes.c_uint64),
        ("logon_server", _UnicodeString),
        ("dns_domain_name", _UnicodeString),
        ("upn", _UnicodeString),
        ("user_flags", ctypes.c_uint32),
    ]


class _ObjectAttributes(ctypes.Structure):  # pylint: disable=too-few-public-methods
    # Repeat the fixed Windows record layout without adding a staging dependency.
    # pylint: disable=duplicate-code
    _fields_ = [
        ("length", ctypes.c_uint32),
        ("root_directory", ctypes.c_void_p),
        ("object_name", ctypes.c_void_p),
        ("attributes", ctypes.c_uint32),
        ("security_descriptor", ctypes.c_void_p),
        ("security_quality_of_service", ctypes.c_void_p),
    ]
    # pylint: enable=duplicate-code


def _security():
    if os.name != "nt":
        raise ValueError("Logon queries require a Windows target.")
    library = ctypes.WinDLL("advapi32")
    library.LsaNtStatusToWinError.argtypes = [ctypes.c_uint32]
    library.LsaNtStatusToWinError.restype = ctypes.c_uint32
    library.LsaOpenPolicy.argtypes = [
        ctypes.POINTER(_UnicodeString),
        ctypes.POINTER(_ObjectAttributes),
        ctypes.c_uint32,
        ctypes.POINTER(ctypes.c_void_p),
    ]
    library.LsaOpenPolicy.restype = ctypes.c_uint32
    library.LsaEnumerateAccountRights.argtypes = [
        ctypes.c_void_p,
        ctypes.c_void_p,
        ctypes.POINTER(ctypes.c_void_p),
        ctypes.POINTER(ctypes.c_uint32),
    ]
    library.LsaEnumerateAccountRights.restype = ctypes.c_uint32
    library.LsaFreeMemory.argtypes = [ctypes.c_void_p]
    library.LsaFreeMemory.restype = ctypes.c_uint32
    library.LsaClose.argtypes = [ctypes.c_void_p]
    library.LsaClose.restype = ctypes.c_uint32
    return library


def _sessions():
    if os.name != "nt":
        raise ValueError("Logon queries require a Windows target.")
    library = ctypes.WinDLL("secur32")
    library.LsaEnumerateLogonSessions.argtypes = [
        ctypes.POINTER(ctypes.c_uint32),
        ctypes.POINTER(ctypes.c_void_p),
    ]
    library.LsaEnumerateLogonSessions.restype = ctypes.c_uint32
    library.LsaGetLogonSessionData.argtypes = [
        ctypes.POINTER(_Luid),
        ctypes.POINTER(ctypes.c_void_p),
    ]
    library.LsaGetLogonSessionData.restype = ctypes.c_uint32
    library.LsaFreeReturnBuffer.argtypes = [ctypes.c_void_p]
    library.LsaFreeReturnBuffer.restype = ctypes.c_uint32
    return library


def _check_status(library, status, operation):
    if status:
        raise ctypes.WinError(
            library.LsaNtStatusToWinError(status), operation + " failed"
        )


def _unicode(value):
    # Upstream uses PtrToStringUni without Length, retaining null versus empty.
    return ctypes.wstring_at(value.buffer) if value.buffer else None


def _login_time(file_time):
    if not file_time or file_time > native_time.local_ticks_to_file_time(_MAX_TICKS):
        return None
    local_ticks = native_time.file_time_to_local_ticks(file_time)
    offset = (local_ticks - file_time - _FILETIME_EPOCH) // (60 * _SECOND)
    days, within_day = divmod(local_ticks, 86400 * _SECOND)
    date = datetime.date.fromordinal(days + 1)
    seconds, fraction = divmod(within_day, _SECOND)
    hour, seconds = divmod(seconds, 3600)
    minute, second = divmod(seconds, 60)
    return "{0}T{1:02d}:{2:02d}:{3:02d}.{4:07d}{5}{6:02d}:{7:02d}".format(
        date.isoformat(),
        hour,
        minute,
        second,
        fraction,
        "-" if offset < 0 else "+",
        abs(offset) // 60,
        abs(offset) % 60,
    )


def _session_data(pointer):
    if not pointer:
        raise ValueError("LsaGetLogonSessionData returned no session data.")
    size = ctypes.cast(pointer, ctypes.POINTER(ctypes.c_uint32)).contents.value
    if size < _SessionData.logon_id.offset + ctypes.sizeof(_Luid):
        raise ValueError("SECURITY_LOGON_SESSION_DATA is missing its LogonId.")
    value = _SessionData()
    # XP and Server 2003 stop before UserFlags. Never read beyond their Size.
    ctypes.memmove(ctypes.byref(value), pointer, min(size, ctypes.sizeof(value)))
    return value


def _session_result(value, warnings):
    if value.size < _SessionData.upn.offset + ctypes.sizeof(_UnicodeString):
        raise ValueError("SECURITY_LOGON_SESSION_DATA is missing base session fields.")
    flags = None
    if value.size >= _SessionData.user_flags.offset + ctypes.sizeof(ctypes.c_uint32):
        flags = [name for flag, name in _USER_FLAGS if value.user_flags & flag]
    else:
        warnings.append(
            "user_flags is unavailable because Windows returned logon-session "
            "data without the UserFlags field."
        )
    return {
        "logon_id": ((value.logon_id.high & 0xFFFFFFFF) << 32) | value.logon_id.low,
        "account": account.describe_sid(value.sid),
        "login_domain": _unicode(value.login_domain),
        "authentication_package": _unicode(value.authentication_package),
        "logon_type": _LOGON_TYPES.get(value.logon_type, str(value.logon_type)),
        "login_time": _login_time(value.login_time),
        "logon_server": _unicode(value.logon_server),
        "dns_domain_name": _unicode(value.dns_domain_name),
        "upn": _unicode(value.upn),
        "user_flags": flags,
    }


def logon_session(authentication_id, warnings):
    """Find the current token's session in LSA's native enumeration order.

    :param authentication_id: Unsigned 64-bit authentication LUID from the token.
    :type authentication_id: int
    :param warnings: Receives a named warning if UserFlags is unavailable.
    :type warnings: list[str]
    :returns: Public account, session, authentication, time, and flag fields.
    :rtype: dict
    :raises ValueError: If called outside Windows, no matching session exists,
        or native data lacks the required base fields.
    :raises OSError: If enumeration or native conversion fails. Access-denied
        sessions are skipped, as in the pinned upstream module.
    """
    security, sessions = _security(), _sessions()
    count = ctypes.c_uint32()
    identifiers = ctypes.c_void_p()
    try:
        status = sessions.LsaEnumerateLogonSessions(
            ctypes.byref(count), ctypes.byref(identifiers)
        )
        _check_status(security, status, "LsaEnumerateLogonSessions")
        entries = ctypes.cast(identifiers, ctypes.POINTER(_Luid))
        for index in range(count.value):
            pointer = ctypes.c_void_p()
            try:
                status = sessions.LsaGetLogonSessionData(
                    ctypes.byref(entries[index]), ctypes.byref(pointer)
                )
                if status == _STATUS_ACCESS_DENIED:
                    continue
                _check_status(security, status, "LsaGetLogonSessionData")
                value = _session_data(pointer)
                logon_id = (
                    (value.logon_id.high & 0xFFFFFFFF) << 32
                ) | value.logon_id.low
                if logon_id == authentication_id:
                    return _session_result(value, warnings)
            finally:
                if pointer:
                    sessions.LsaFreeReturnBuffer(pointer)
    finally:
        if identifiers:
            sessions.LsaFreeReturnBuffer(identifiers)
    raise ValueError(
        "Could not find the data for logon session {0}".format(authentication_id)
    )


def _account_rights(library, policy, sid):
    binary_sid = ctypes.create_string_buffer(account.sid_bytes(sid))
    pointer = ctypes.c_void_p()
    count = ctypes.c_uint32()
    try:
        status = library.LsaEnumerateAccountRights(
            policy, binary_sid, ctypes.byref(pointer), ctypes.byref(count)
        )
        if status == _STATUS_OBJECT_NAME_NOT_FOUND:
            return []
        _check_status(library, status, "LsaEnumerateAccountRights")
        entries = ctypes.cast(pointer, ctypes.POINTER(_UnicodeString))
        return [_unicode(entries[index]) for index in range(count.value)]
    finally:
        if pointer:
            library.LsaFreeMemory(pointer)


def logon_rights(enabled_group_sid_strings):
    """Read distinct logon rights of enabled groups under an administrator token.

    :param enabled_group_sid_strings: Enabled token group SIDs in native order,
        including enabled logon SIDs. The caller checks administrator membership.
    :type enabled_group_sid_strings: list[str]
    :returns: Rights containing case-sensitive ``Logon`` in first occurrence order.
    :rtype: list[str]
    :raises ValueError: If called outside Windows.
    :raises OSError: If policy access, SID conversion, or rights enumeration fails.
        An account with no policy rights contributes an empty list.
    """
    library = _security()
    attributes = _ObjectAttributes(ctypes.sizeof(_ObjectAttributes))
    policy = ctypes.c_void_p()
    rights = []
    try:
        status = library.LsaOpenPolicy(
            None, ctypes.byref(attributes), _POLICY_LOOKUP_NAMES, ctypes.byref(policy)
        )
        _check_status(library, status, "LsaOpenPolicy")
        for sid in enabled_group_sid_strings:
            for right in _account_rights(library, policy, sid):
                if "Logon" in right and right not in rights:
                    rights.append(right)
        return rights
    finally:
        if policy:
            library.LsaClose(policy)
