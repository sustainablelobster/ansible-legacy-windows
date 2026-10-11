# -*- coding: utf-8 -*-
# Copyright 2026 sustainablelobster
# SPDX-License-Identifier: GPL-3.0-or-later

"""Acquire native Windows logon tokens for the runas execution wrapper."""

import ctypes
import os
import sys
from contextlib import ExitStack, contextmanager

import legacy_windows_account as account  # pylint: disable=import-error
import legacy_windows_s4u as s4u  # pylint: disable=import-error

_HANDLE = ctypes.c_void_p
_DWORD = ctypes.c_uint32
_BOOL = ctypes.c_int
_LOGON_TYPES = {
    "Interactive": 2,
    "Network": 3,
    "Batch": 4,
    "Service": 5,
    "Unlock": 7,
    "NetworkCleartext": 8,
    "NewCredentials": 9,
}
_SERVICE_ACCOUNTS = {
    "S-1-5-19": "LocalService",
    "S-1-5-20": "NetworkService",
}


# The native records have no methods or independent Python state.
class _Luid(ctypes.Structure):  # pylint: disable=too-few-public-methods
    _fields_ = [("low", _DWORD), ("high", ctypes.c_int32)]


class _Privilege(ctypes.Structure):  # pylint: disable=too-few-public-methods
    _fields_ = [("luid", _Luid), ("attributes", _DWORD)]


class _PrivilegeChange(ctypes.Structure):  # pylint: disable=too-few-public-methods
    _fields_ = [("count", _DWORD), ("privilege", _Privilege)]


def _libraries():
    if os.name != "nt":
        raise ValueError("Privilege escalation requires a Windows target.")
    security = ctypes.WinDLL("advapi32", use_last_error=True)
    kernel = ctypes.WinDLL("kernel32", use_last_error=True)
    processes = ctypes.WinDLL("psapi", use_last_error=True)
    security.OpenProcessToken.argtypes = [_HANDLE, _DWORD, ctypes.POINTER(_HANDLE)]
    security.OpenProcessToken.restype = _BOOL
    security.GetTokenInformation.argtypes = [
        _HANDLE,
        ctypes.c_int,
        _HANDLE,
        _DWORD,
        ctypes.POINTER(_DWORD),
    ]
    security.GetTokenInformation.restype = _BOOL
    security.LookupPrivilegeValueW.argtypes = [
        ctypes.c_wchar_p,
        ctypes.c_wchar_p,
        ctypes.POINTER(_Luid),
    ]
    security.LookupPrivilegeValueW.restype = _BOOL
    security.AdjustTokenPrivileges.argtypes = [
        _HANDLE,
        _BOOL,
        _HANDLE,
        _DWORD,
        _HANDLE,
        ctypes.POINTER(_DWORD),
    ]
    security.AdjustTokenPrivileges.restype = _BOOL
    security.DuplicateTokenEx.argtypes = [
        _HANDLE,
        _DWORD,
        _HANDLE,
        ctypes.c_int,
        ctypes.c_int,
        ctypes.POINTER(_HANDLE),
    ]
    security.DuplicateTokenEx.restype = _BOOL
    security.ImpersonateLoggedOnUser.argtypes = [_HANDLE]
    security.ImpersonateLoggedOnUser.restype = _BOOL
    security.RevertToSelf.argtypes = []
    security.RevertToSelf.restype = _BOOL
    security.LogonUserW.argtypes = [
        ctypes.c_wchar_p,
        ctypes.c_wchar_p,
        ctypes.c_wchar_p,
        _DWORD,
        _DWORD,
        ctypes.POINTER(_HANDLE),
    ]
    security.LogonUserW.restype = _BOOL
    kernel.OpenProcess.argtypes = [_DWORD, _BOOL, _DWORD]
    kernel.OpenProcess.restype = _HANDLE
    kernel.GetCurrentProcess.argtypes = []
    kernel.GetCurrentProcess.restype = _HANDLE
    kernel.CloseHandle.argtypes = [_HANDLE]
    kernel.CloseHandle.restype = _BOOL
    processes.EnumProcesses.argtypes = [_HANDLE, _DWORD, ctypes.POINTER(_DWORD)]
    processes.EnumProcesses.restype = _BOOL
    return security, kernel, processes


def _information(security, token, kind):
    length = _DWORD()
    buffer, size = None, 0
    while True:
        if security.GetTokenInformation(
            token, kind, buffer, size, ctypes.byref(length)
        ):
            return buffer
        error = ctypes.get_last_error()
        if error != 122:
            raise ctypes.WinError(error)
        size = max(length.value, size * 2, 1)
        buffer = ctypes.create_string_buffer(size)


@contextmanager
def _privilege(security, token, name):
    requested = _PrivilegeChange(1)
    if not security.LookupPrivilegeValueW(
        None, name, ctypes.byref(requested.privilege.luid)
    ):
        raise ctypes.WinError(ctypes.get_last_error())
    requested.privilege.attributes = 2
    previous = _PrivilegeChange()
    needed = _DWORD()
    try:
        if not security.AdjustTokenPrivileges(
            token,
            False,
            ctypes.byref(requested),
            ctypes.sizeof(previous),
            ctypes.byref(previous),
            ctypes.byref(needed),
        ):
            raise ctypes.WinError(ctypes.get_last_error())
        # An absent privilege is not added. Password logon can still work.
        error = ctypes.get_last_error()
        if error not in (0, 1300):
            raise ctypes.WinError(error)
        yield
    finally:
        if previous.count and not security.AdjustTokenPrivileges(
            token, False, ctypes.byref(previous), 0, None, None
        ):
            raise ctypes.WinError(ctypes.get_last_error())


def _process_ids(processes):
    capacity = 256
    while True:
        values = (_DWORD * capacity)()
        length = _DWORD()
        if not processes.EnumProcesses(
            values, ctypes.sizeof(values), ctypes.byref(length)
        ):
            raise ctypes.WinError(ctypes.get_last_error())
        if length.value < ctypes.sizeof(values):
            return values[: length.value // ctypes.sizeof(_DWORD)]
        capacity *= 2


def _has_privilege(security, privileges, name):
    expected = _Luid()
    if not security.LookupPrivilegeValueW(None, name, ctypes.byref(expected)):
        raise ctypes.WinError(ctypes.get_last_error())
    count = _DWORD.from_buffer(privileges).value
    entries = (_Privilege * count).from_buffer(
        privileges, _PrivilegeChange.privilege.offset
    )
    return any(
        entry.luid.low == expected.low and entry.luid.high == expected.high
        for entry in entries
    )


def _candidate_privileges(security, token, sid, system):
    user_information = _information(security, token, 1)
    user = _HANDLE.from_buffer(user_information).value
    if account.sid_to_string(user) != sid:
        return None
    statistics = _information(security, token, 10)
    if s4u.session_logon_type(statistics.raw[8:16]) in (None, 3):
        # Network-only or unreadable sessions are not reliable launch identities.
        # A fresh S4U Batch token is preferable.
        return None
    privileges = _information(security, token, 3)
    if system and not _has_privilege(security, privileges, "SeTcbPrivilege"):
        return None
    return _DWORD.from_buffer(privileges).value


def _user_token(security, kernel, processes, sid, system=False):
    best, privilege_count = None, -1
    try:
        for pid in _process_ids(processes):
            process = kernel.OpenProcess(0x400, False, pid)
            if not process:
                continue
            token = _HANDLE()
            try:
                if not security.OpenProcessToken(process, 0xF, ctypes.byref(token)):
                    continue
                count = _candidate_privileges(security, token, sid, system)
                if count is None or (system and count <= privilege_count):
                    continue
                duplicate = _HANDLE()
                if not security.DuplicateTokenEx(
                    token, 0x02000000, None, 2, 1, ctypes.byref(duplicate)
                ):
                    continue
                if best:
                    kernel.CloseHandle(best)
                best, privilege_count = duplicate, count
                if not system:
                    return best
            except OSError:
                # A protected or exiting process is not a usable token source.
                continue
            finally:
                if token:
                    kernel.CloseHandle(token)
                kernel.CloseHandle(process)
        return best
    except Exception:
        if best:
            kernel.CloseHandle(best)
        raise


def _system_token(security, kernel, processes):
    return _user_token(security, kernel, processes, "S-1-5-18", system=True)


def _linked_token(security, kernel, token):
    # TokenElevationType and linked tokens were introduced with Vista UAC.
    if sys.getwindowsversion().major < 6:  # pylint: disable=no-member
        return None
    if _DWORD.from_buffer(_information(security, token, 18)).value != 3:
        return None
    # TokenLinkedToken requires a handle-sized buffer; a zero-length sizing
    # probe returns ERROR_BAD_LENGTH on Windows 7 instead of a required size.
    linked, length = _HANDLE(), _DWORD()
    if not security.GetTokenInformation(
        token, 19, ctypes.byref(linked), ctypes.sizeof(linked), ctypes.byref(length)
    ):
        raise ctypes.WinError(ctypes.get_last_error())
    # TOKEN_STATISTICS starts with two LUIDs and an eight-byte expiration time.
    if ctypes.c_int.from_buffer(_information(security, linked, 10), 24).value != 1:
        kernel.CloseHandle(linked)
        return None
    return linked


@contextmanager
def _impersonation(security, system):
    if not system:
        yield False
        return
    with _privilege(security, system, "SeTcbPrivilege"):
        active = bool(security.ImpersonateLoggedOnUser(system))
        try:
            yield active
        finally:
            if active and not security.RevertToSelf():
                raise ctypes.WinError(ctypes.get_last_error())


# These six native acquisition inputs share the enclosing handle lifetime.
# pylint: disable-next=too-many-arguments,too-many-positional-arguments
def _requested_tokens(security, kernel, processes, lifetime, request, system):
    username, password = request["username"], request["password"]
    logon_type, sid = request["logon_type"], request["sid"]
    if sid == "S-1-5-18":
        if not system:
            raise ValueError("Cannot acquire the SYSTEM token required for runas.")
        return [system]
    if sid in _SERVICE_ACCOUNTS and not system:
        raise ValueError(
            "Cannot acquire the SYSTEM token required for service-account runas."
        )
    if (
        password is None
        and sid not in _SERVICE_ACCOUNTS
        and logon_type != "NewCredentials"
    ):
        if not system:
            raise ValueError(
                "Passwordless runas requires an accessible SYSTEM token and "
                "permission to impersonate it; connect with an administrative "
                "account with SeDebugPrivilege and SeImpersonatePrivilege."
            )
        token = _user_token(security, kernel, processes, sid)
        if not token:
            token = s4u.logon_token(sid, logon_type)
    else:
        user, domain, kind = _credentials(username, sid, logon_type)
        token = _HANDLE()
        if not security.LogonUserW(
            user, domain, password, kind, 0, ctypes.byref(token)
        ):
            raise ctypes.WinError(ctypes.get_last_error())
    lifetime.callback(kernel.CloseHandle, token)
    linked = _linked_token(security, kernel, token)
    if linked:
        lifetime.callback(kernel.CloseHandle, linked)
        return [linked, token]
    return [token]


def _credentials(username, sid, logon_type):
    if sid in _SERVICE_ACCOUNTS:
        return _SERVICE_ACCOUNTS[sid], "NT AUTHORITY", 5
    if "\\" in username:
        domain, username = username.split("\\", 1)
    else:
        domain = None if "@" in username else "."
    return username, domain, _LOGON_TYPES[logon_type]


def token_sid(token):
    """Copy a token's user SID before releasing the native query buffer.

    :param token: Open native token handle with TOKEN_QUERY access.
    :type token: ctypes.c_void_p
    :returns: Canonical SID string for the token user.
    :rtype: str
    :raises OSError: If token information or SID conversion fails.
    """
    security, _, _ = _libraries()
    information = _information(security, token, 1)
    return account.sid_to_string(_HANDLE.from_buffer(information).value)


def _temporary_system_token(security, process_token):
    import legacy_windows_system_token as system_token  # pylint: disable=import-outside-toplevel,import-error

    with _privilege(security, process_token, "SeImpersonatePrivilege"):
        return system_token.acquire_token()


@contextmanager
def _launch_privileges(security, process_token, system, request):
    with ExitStack() as lifetime:
        if sys.getwindowsversion().major < 6:  # pylint: disable=no-member
            token = process_token
            if system and not (
                request["password"] is not None
                and request["logon_type"] == "Interactive"
            ):
                # XP's token-only CreateProcessAsUserW requires privileges held
                # by SYSTEM, not ordinarily assigned to an administrator. Keep
                # the authenticated identity active through launch and restore
                # it when the enclosing task finishes; add no new user rights.
                if not lifetime.enter_context(_impersonation(security, system)):
                    raise ValueError(
                        "Cannot impersonate SYSTEM for legacy token launch."
                    )
                token = system
            for name in (
                "SeAssignPrimaryTokenPrivilege",
                "SeIncreaseQuotaPrivilege",
                "SeBackupPrivilege",
                "SeRestorePrivilege",
            ):
                lifetime.enter_context(_privilege(security, token, name))
        yield


@contextmanager
def logon_tokens(username, password, logon_type):
    """Keep the acquired primary and linked tokens alive through child execution.

    :param username: Requested local, domain, UPN or well-known service account.
    :type username: str
    :param password: Password, or None for a passwordless token request.
    :type password: str or None
    :param logon_type: Canonical Ansible runas logon type.
    :type logon_type: str
    :returns: Context manager yielding native token handles, preferred first.
    :rtype: context manager
    :raises OSError: If Windows cannot obtain or restore the requested tokens.
    :raises ValueError: If passwordless impersonation is unavailable or the type
        is invalid. Passwordless named accounts reuse an eligible existing token
        or request S4U; an empty password still performs a password logon.
    """
    if logon_type not in _LOGON_TYPES:
        raise ValueError("Invalid runas logon type: " + str(logon_type))
    security, kernel, processes = _libraries()
    sid = None
    if logon_type != "NewCredentials":
        sid = account.account_name_to_sid(username)
    process_token, system = _HANDLE(), None
    with ExitStack() as lifetime:
        if not security.OpenProcessToken(
            kernel.GetCurrentProcess(), 0x28, ctypes.byref(process_token)
        ):
            raise ctypes.WinError(ctypes.get_last_error())
        lifetime.callback(kernel.CloseHandle, process_token)
        with _privilege(security, process_token, "SeDebugPrivilege"):
            if logon_type != "NewCredentials":
                system = _system_token(security, kernel, processes)
                if not system and (
                    sid == "S-1-5-18" or sid in _SERVICE_ACCOUNTS or password is None
                ):
                    # Legacy SYSTEM token DACLs can deny an administrator even
                    # with debug privilege. The one-shot native service obtains
                    # its own token without changing those existing permissions.
                    system = _temporary_system_token(security, process_token)
        if system:
            lifetime.callback(kernel.CloseHandle, system)
        with _impersonation(security, system) as impersonated:
            request = {
                "username": username,
                "password": password,
                "logon_type": logon_type,
                "sid": sid,
            }
            tokens = _requested_tokens(
                security,
                kernel,
                processes,
                lifetime,
                request,
                system if impersonated else None,
            )
        with _launch_privileges(security, process_token, system, request):
            yield tokens
