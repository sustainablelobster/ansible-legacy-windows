# -*- coding: utf-8 -*-
# Copyright 2026 sustainablelobster
# SPDX-License-Identifier: GPL-3.0-or-later

"""Request native passwordless logons and inspect their LSA session types."""

import ctypes
import os

import legacy_windows_account as account  # pylint: disable=import-error

_HANDLE = ctypes.c_void_p
_DWORD = ctypes.c_uint32


# These fixed Windows records describe memory rather than Python objects.
class _Luid(ctypes.Structure):  # pylint: disable=too-few-public-methods
    _fields_ = [("low", _DWORD), ("high", ctypes.c_int32)]


class _String(ctypes.Structure):  # pylint: disable=too-few-public-methods
    _fields_ = [
        ("length", ctypes.c_uint16),
        ("maximum_length", ctypes.c_uint16),
        ("buffer", _HANDLE),
    ]


class _S4ULogon(ctypes.Structure):  # pylint: disable=too-few-public-methods
    _fields_ = [
        ("message_type", _DWORD),
        ("flags", _DWORD),
        ("username", _String),
        ("domain", _String),
    ]


class _TokenSource(ctypes.Structure):  # pylint: disable=too-few-public-methods
    _fields_ = [("name", ctypes.c_char * 8), ("identifier", _Luid)]


class _QuotaLimits(ctypes.Structure):  # pylint: disable=too-few-public-methods
    _fields_ = [
        ("paged_pool", ctypes.c_size_t),
        ("non_paged_pool", ctypes.c_size_t),
        ("minimum_working_set", ctypes.c_size_t),
        ("maximum_working_set", ctypes.c_size_t),
        ("pagefile", ctypes.c_size_t),
        ("time_limit", ctypes.c_int64),
    ]


class _SessionData(ctypes.Structure):  # pylint: disable=too-few-public-methods
    _fields_ = [
        ("size", _DWORD),
        ("identifier", _Luid),
        ("username", _String),
        ("domain", _String),
        ("package", _String),
        ("logon_type", _DWORD),
    ]


def _libraries():
    library = ctypes.WinDLL("secur32", use_last_error=True)
    security = ctypes.WinDLL("advapi32", use_last_error=True)
    kernel = ctypes.WinDLL("kernel32", use_last_error=True)
    library.LsaRegisterLogonProcess.argtypes = [
        ctypes.POINTER(_String),
        ctypes.POINTER(_HANDLE),
        ctypes.POINTER(_DWORD),
    ]
    library.LsaRegisterLogonProcess.restype = _DWORD
    library.LsaLookupAuthenticationPackage.argtypes = [
        _HANDLE,
        ctypes.POINTER(_String),
        ctypes.POINTER(_DWORD),
    ]
    library.LsaLookupAuthenticationPackage.restype = _DWORD
    library.LsaLogonUser.argtypes = [
        _HANDLE,
        ctypes.POINTER(_String),
        _DWORD,
        _DWORD,
        _HANDLE,
        _DWORD,
        _HANDLE,
        ctypes.POINTER(_TokenSource),
        ctypes.POINTER(_HANDLE),
        ctypes.POINTER(_DWORD),
        ctypes.POINTER(_Luid),
        ctypes.POINTER(_HANDLE),
        ctypes.POINTER(_QuotaLimits),
        ctypes.POINTER(_DWORD),
    ]
    library.LsaLogonUser.restype = _DWORD
    library.LsaGetLogonSessionData.argtypes = [_HANDLE, ctypes.POINTER(_HANDLE)]
    library.LsaGetLogonSessionData.restype = _DWORD
    library.LsaFreeReturnBuffer.argtypes = [_HANDLE]
    library.LsaFreeReturnBuffer.restype = _DWORD
    library.LsaDeregisterLogonProcess.argtypes = [_HANDLE]
    library.LsaDeregisterLogonProcess.restype = _DWORD
    security.LsaNtStatusToWinError.argtypes = [_DWORD]
    security.LsaNtStatusToWinError.restype = _DWORD
    security.AllocateLocallyUniqueId.argtypes = [ctypes.POINTER(_Luid)]
    security.AllocateLocallyUniqueId.restype = ctypes.c_int
    kernel.CloseHandle.argtypes = [_HANDLE]
    kernel.CloseHandle.restype = ctypes.c_int
    return library, security, kernel


def _check_status(security, status, operation, substatus=0):
    if status:
        detail = "{0} failed (NTSTATUS 0x{1:08x}".format(operation, status)
        if substatus:
            detail += "; substatus 0x{0:08x}".format(substatus)
        raise ctypes.WinError(security.LsaNtStatusToWinError(status), detail + ")")


def _ansi(value):
    buffer = ctypes.create_string_buffer(value.encode("ascii"))
    return buffer, _String(len(buffer.value), len(buffer), ctypes.addressof(buffer))


def _authentication_buffer(username, domain):
    user_bytes, domain_bytes = username.encode("utf-16-le"), domain.encode("utf-16-le")
    if max(len(user_bytes), len(domain_bytes)) > 65535:
        raise ValueError("S4U account names must fit in a Windows counted string.")
    offset = ctypes.sizeof(_S4ULogon)
    buffer = ctypes.create_string_buffer(offset + len(user_bytes) + len(domain_bytes))
    value = _S4ULogon.from_buffer(buffer)
    # KerbS4ULogon and MsV1_0S4ULogon both use message type 12.
    value.message_type = 12
    value.username = _String(
        len(user_bytes), len(user_bytes), ctypes.addressof(buffer) + offset
    )
    value.domain = _String(
        len(domain_bytes), len(domain_bytes), value.username.buffer + len(user_bytes)
    )
    ctypes.memmove(value.username.buffer, user_bytes, len(user_bytes))
    ctypes.memmove(value.domain.buffer, domain_bytes, len(domain_bytes))
    return buffer


def session_logon_type(authentication_id):
    """Read a token's logon type, returning None for inaccessible sessions.

    :param authentication_id: Copied eight-byte AuthenticationId LUID.
    :type authentication_id: bytes
    :returns: Native SECURITY_LOGON_TYPE, or None if it cannot be established.
    :rtype: int or None
    """
    library, _, _ = _libraries()
    identifier = _Luid.from_buffer_copy(authentication_id)
    data = _HANDLE()
    try:
        if library.LsaGetLogonSessionData(ctypes.byref(identifier), ctypes.byref(data)):
            return None
        if not data:
            return None
        size = _DWORD.from_address(data.value).value
        if size < _SessionData.logon_type.offset + ctypes.sizeof(_DWORD):
            return None
        return ctypes.cast(data, ctypes.POINTER(_SessionData)).contents.logon_type
    finally:
        if data:
            library.LsaFreeReturnBuffer(data)


# Keep the native output buffers beside their single cleanup boundary; dividing
# this call's ownership across classes would conceal rather than simplify it.
# pylint: disable-next=too-many-locals
def logon_token(sid, logon_type):
    """Acquire a passwordless native S4U token for the resolved account.

    The caller must already impersonate a token with enabled SeTcbPrivilege.
    The returned handle belongs to the caller. No password-derived outbound
    network credentials are supplied by this local logon.

    :param sid: Requested canonical account SID.
    :type sid: str
    :param logon_type: Requested runas type; Network uses network logon, others Batch.
    :type logon_type: str
    :returns: Open native logon token; Network can produce an impersonation token.
    :rtype: ctypes.c_void_p
    :raises OSError: If account resolution, LSA registration or logon fails.
    :raises ValueError: If the account cannot be translated to a qualified name.
    """
    name = account.sid_to_name(sid)
    if "\\" not in name:
        raise ValueError("Cannot resolve S4U account SID to a qualified account name.")
    domain, username = name.split("\\", 1)
    domain_account = domain.lower() != os.environ.get("COMPUTERNAME", "").lower()
    package = "Kerberos" if domain_account else "MICROSOFT_AUTHENTICATION_PACKAGE_V1_0"
    library, security, kernel = _libraries()
    origin_buffer, origin = _ansi("legacy_windows")
    package_buffer, package_name = _ansi(package)
    # Keep the counted strings and contiguous Unicode authentication buffer alive
    # until the native call returns, regardless of Python object collection.
    authentication = _authentication_buffer(username, domain)
    connection, profile, token = _HANDLE(), _HANDLE(), _HANDLE()
    mode, package_id, profile_length, substatus = _DWORD(), _DWORD(), _DWORD(), _DWORD()
    source = _TokenSource(name=b"legacy\0\0")
    identifier, quotas = _Luid(), _QuotaLimits()
    try:
        _check_status(
            security,
            library.LsaRegisterLogonProcess(
                ctypes.byref(origin), ctypes.byref(connection), ctypes.byref(mode)
            ),
            "LsaRegisterLogonProcess",
        )
        _check_status(
            security,
            library.LsaLookupAuthenticationPackage(
                connection, ctypes.byref(package_name), ctypes.byref(package_id)
            ),
            "LsaLookupAuthenticationPackage(" + package + ")",
        )
        if not security.AllocateLocallyUniqueId(ctypes.byref(source.identifier)):
            raise ctypes.WinError(ctypes.get_last_error())
        status = library.LsaLogonUser(
            connection,
            ctypes.byref(origin),
            3 if logon_type == "Network" else 4,
            package_id,
            authentication,
            ctypes.sizeof(authentication),
            None,
            ctypes.byref(source),
            ctypes.byref(profile),
            ctypes.byref(profile_length),
            ctypes.byref(identifier),
            ctypes.byref(token),
            ctypes.byref(quotas),
            ctypes.byref(substatus),
        )
        _check_status(security, status, "LsaLogonUser S4U", substatus.value)
        if not token:
            raise ValueError("LsaLogonUser S4U returned no token.")
        result, token = token, _HANDLE()
        return result
    finally:
        if profile:
            library.LsaFreeReturnBuffer(profile)
        if token:
            kernel.CloseHandle(token)
        if connection:
            library.LsaDeregisterLogonProcess(connection)
        # Explicit references document native pointer lifetimes.
        del origin_buffer, package_buffer
