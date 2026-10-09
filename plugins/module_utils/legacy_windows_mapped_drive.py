# -*- coding: utf-8 -*-
# Copyright 2026 Joe Lustri
# SPDX-License-Identifier: GPL-3.0-or-later

"""Manage persistent network mappings through native Windows APIs."""

import ctypes
import os
import sys
from contextlib import contextmanager

import legacy_windows_account as account  # pylint: disable=import-error


# NETRESOURCEW uses fixed-width DWORDs followed by native-width string pointers.
class _Resource(ctypes.Structure):  # pylint: disable=too-few-public-methods
    _fields_ = [
        ("scope", ctypes.c_uint32),
        ("kind", ctypes.c_uint32),
        ("display", ctypes.c_uint32),
        ("usage", ctypes.c_uint32),
        ("local", ctypes.c_wchar_p),
        ("remote", ctypes.c_wchar_p),
        ("comment", ctypes.c_wchar_p),
        ("provider", ctypes.c_wchar_p),
    ]


class _Luid(ctypes.Structure):  # pylint: disable=too-few-public-methods
    _fields_ = [("low", ctypes.c_uint32), ("high", ctypes.c_int32)]


class _Privilege(ctypes.Structure):  # pylint: disable=too-few-public-methods
    _fields_ = [("luid", _Luid), ("attributes", ctypes.c_uint32)]


def _libraries():
    if os.name != "nt":
        raise ValueError("Mapped drives require a Windows target.")
    network = ctypes.WinDLL("mpr", use_last_error=True)
    kernel = ctypes.WinDLL("kernel32", use_last_error=True)
    security = ctypes.WinDLL("advapi32", use_last_error=True)
    # Keep this independently staged wrapper's native ABI declarations local.
    # pylint: disable=duplicate-code
    network.WNetOpenEnumW.argtypes = [
        ctypes.c_uint32,
        ctypes.c_uint32,
        ctypes.c_uint32,
        ctypes.c_void_p,
        ctypes.POINTER(ctypes.c_void_p),
    ]
    network.WNetOpenEnumW.restype = ctypes.c_uint32
    network.WNetEnumResourceW.argtypes = [
        ctypes.c_void_p,
        ctypes.POINTER(ctypes.c_uint32),
        ctypes.c_void_p,
        ctypes.POINTER(ctypes.c_uint32),
    ]
    network.WNetEnumResourceW.restype = ctypes.c_uint32
    network.WNetCloseEnum.argtypes = [ctypes.c_void_p]
    network.WNetCloseEnum.restype = ctypes.c_uint32
    network.WNetAddConnection2W.argtypes = [
        ctypes.POINTER(_Resource),
        ctypes.c_wchar_p,
        ctypes.c_wchar_p,
        ctypes.c_uint32,
    ]
    network.WNetAddConnection2W.restype = ctypes.c_uint32
    network.WNetCancelConnection2W.argtypes = [
        ctypes.c_wchar_p,
        ctypes.c_uint32,
        ctypes.c_int,
    ]
    network.WNetCancelConnection2W.restype = ctypes.c_uint32
    kernel.GetCurrentProcess.argtypes = []
    kernel.GetCurrentProcess.restype = ctypes.c_void_p
    kernel.OpenProcess.argtypes = [ctypes.c_uint32, ctypes.c_int, ctypes.c_uint32]
    kernel.OpenProcess.restype = ctypes.c_void_p
    kernel.CloseHandle.argtypes = [ctypes.c_void_p]
    kernel.CloseHandle.restype = ctypes.c_int
    kernel.GetLogicalDrives.argtypes = []
    kernel.GetLogicalDrives.restype = ctypes.c_uint32
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
    security.LookupPrivilegeValueW.argtypes = [
        ctypes.c_wchar_p,
        ctypes.c_wchar_p,
        ctypes.POINTER(_Luid),
    ]
    security.LookupPrivilegeValueW.restype = ctypes.c_int
    security.ImpersonateLoggedOnUser.argtypes = [ctypes.c_void_p]
    security.ImpersonateLoggedOnUser.restype = ctypes.c_int
    security.RevertToSelf.argtypes = []
    security.RevertToSelf.restype = ctypes.c_int
    # pylint: enable=duplicate-code
    return network, kernel, security


def _check(code, context):
    if code:
        # The original Win32Exception strips terminal periods from Windows'
        # message; errors 55 and 2250 were measured against the pinned helper.
        message = ctypes.FormatError(ctypes.c_int32(code).value).strip().rstrip(".")
        raise OSError(
            code, "{0} ({1}, Win32ErrorCode {2})".format(context, message, code)
        )


def _token_information(security, token, kind):
    size = ctypes.c_uint32()
    buffer = None
    while not security.GetTokenInformation(
        token, kind, buffer, 0 if buffer is None else len(buffer), ctypes.byref(size)
    ):
        code = ctypes.get_last_error()
        if code != 122:
            _check(code, "Failed to get token information")
        buffer = ctypes.create_string_buffer(size.value)
    return buffer


@contextmanager
def _impersonate(security, token):
    if token and not security.ImpersonateLoggedOnUser(token):
        _check(ctypes.get_last_error(), "Failed to impersonate token")
    try:
        yield
    finally:
        if token and not security.RevertToSelf():
            _check(ctypes.get_last_error(), "Failed to revert impersonation")


def _process_ids():
    processes = ctypes.WinDLL("psapi", use_last_error=True)
    processes.EnumProcesses.argtypes = [
        ctypes.c_void_p,
        ctypes.c_uint32,
        ctypes.POINTER(ctypes.c_uint32),
    ]
    processes.EnumProcesses.restype = ctypes.c_int
    count = 1024
    while True:
        buffer = (ctypes.c_uint32 * count)()
        used = ctypes.c_uint32()
        if not processes.EnumProcesses(
            buffer, ctypes.sizeof(buffer), ctypes.byref(used)
        ):
            _check(ctypes.get_last_error(), "Failed to enumerate processes")
        if used.value < ctypes.sizeof(buffer):
            return list(buffer[: used.value // ctypes.sizeof(ctypes.c_uint32)])
        count *= 2


def _linked_token(security, kernel, current):
    tcb = _Luid()
    if not security.LookupPrivilegeValueW(None, "SeTcbPrivilege", ctypes.byref(tcb)):
        _check(ctypes.get_last_error(), "Failed to find SeTcbPrivilege")
    for pid in _process_ids():
        process = kernel.OpenProcess(0x0400, False, pid)
        if not process:
            continue
        system = ctypes.c_void_p()
        try:
            if not security.OpenProcessToken(process, 0xA, ctypes.byref(system)):
                continue
            try:
                user = _token_information(security, system, 1)
                sid = ctypes.c_void_p.from_buffer(user).value
                if account.sid_to_string(sid) != "S-1-5-18":
                    continue
                buffer = _token_information(security, system, 3)
                count = ctypes.c_uint32.from_buffer(buffer).value
                privileges = (_Privilege * count).from_buffer(buffer, 4)
                if not any(
                    privilege.luid.low == tcb.low and privilege.luid.high == tcb.high
                    for privilege in privileges
                ):
                    continue
                with _impersonate(security, system):
                    linked = _token_information(security, current, 19)
                    return ctypes.c_void_p(ctypes.c_void_p.from_buffer(linked).value)
            finally:
                kernel.CloseHandle(system)
        finally:
            kernel.CloseHandle(process)
    return None


def _limited_token(security, kernel):
    # XP and Server 2003 have no split tokens or TokenElevationType information.
    if sys.getwindowsversion().major < 6:  # pylint: disable=no-member
        return None
    token = ctypes.c_void_p()
    if not security.OpenProcessToken(
        kernel.GetCurrentProcess(), 0xA, ctypes.byref(token)
    ):
        _check(ctypes.get_last_error(), "Failed to open process token")
    try:
        elevation = _token_information(security, token, 18)
        if ctypes.c_uint32.from_buffer(elevation).value == 2:
            return _linked_token(security, kernel, token)
        return None
    finally:
        kernel.CloseHandle(token)


class Mappings:
    """Perform mapping operations in one selected user logon session."""

    def __init__(self, network, security, token):
        self.network = network
        self.security = security
        self.token = token

    def remembered(self):
        """Return persistent drive/path pairs in native enumeration order.

        :returns: Records containing the drive name and UNC path.
        :rtype: list[dict]
        """
        with _impersonate(self.security, self.token):
            handle = ctypes.c_void_p()
            _check(
                self.network.WNetOpenEnumW(3, 1, 0, None, ctypes.byref(handle)),
                "WNetOpenEnumW()",
            )
            try:
                result = []
                while True:
                    size = ctypes.c_uint32(16384)
                    count = ctypes.c_uint32(0xFFFFFFFF)
                    buffer = ctypes.create_string_buffer(size.value)
                    code = self.network.WNetEnumResourceW(
                        handle, ctypes.byref(count), buffer, ctypes.byref(size)
                    )
                    if code == 259:
                        return result
                    _check(code, "WNetEnumResourceW()")
                    for entry in (_Resource * count.value).from_buffer(buffer):
                        result.append({"drive": entry.local, "path": entry.remote})
            finally:
                self.network.WNetCloseEnum(handle)

    def add(self, drive, path, username=None, password=None):
        """Persist a mapping; supplied credentials authenticate only this connection.

        :param drive: Local name including its colon.
        :type drive: str
        :param path: UNC target.
        :type path: str
        :param username: Optional connection account; None selects cached credentials.
        :type username: str or None
        :param password: Optional password, not stored by this helper.
        :type password: str or None
        :raises OSError: If Windows rejects the connection.
        """
        resource = _Resource(kind=1, local=drive, remote=path)
        with _impersonate(self.security, self.token):
            _check(
                self.network.WNetAddConnection2W(
                    ctypes.byref(resource), password, username, 1
                ),
                "Failed to map {0} to '{1}' with WNetAddConnection2W()".format(
                    drive, path
                ),
            )

    def remove(self, drive):
        """Force-disconnect a mapping and remove its saved profile entry.

        :param drive: Local name including its colon.
        :type drive: str
        :raises OSError: If Windows rejects cancellation.
        """
        with _impersonate(self.security, self.token):
            _check(
                self.network.WNetCancelConnection2W(drive, 1, True),
                "Failed to remove mapped drive {0} with WNetCancelConnection2W()".format(
                    drive
                ),
            )


@contextmanager
def open_mappings():
    """Select the persistent-mapping session and close an owned linked token.

    Elevated split-token processes use their linked limited session, matching
    the mappings visible to an interactive user. Non-split and legacy tokens
    use their current session without impersonation.

    :returns: Context manager yielding a Mappings instance.
    :rtype: context manager
    :raises OSError: If native token discovery or impersonation fails.
    """
    network, kernel, security = _libraries()
    token = _limited_token(security, kernel)
    try:
        yield Mappings(network, security, token)
    finally:
        if token:
            kernel.CloseHandle(token)


def logical_drives():
    """Return occupied DOS drive letters, including local disks and substitutions.

    :returns: Uppercase drive letters without colons.
    :rtype: list[str]
    """
    _, kernel, _ = _libraries()
    mask = kernel.GetLogicalDrives()
    if not mask:
        _check(ctypes.get_last_error(), "GetLogicalDrives()")
    return [chr(65 + index) for index in range(26) if mask & (1 << index)]


def clear_username(letter):
    """Clear the saved connection username without persisting its password.

    :param letter: Drive letter of a successfully created mapping.
    :type letter: str
    :raises OSError: If the existing per-user mapping registry key is inaccessible.
    """
    import winreg  # pylint: disable=import-outside-toplevel,import-error

    with winreg.OpenKey(
        winreg.HKEY_CURRENT_USER, "Network\\" + letter, 0, winreg.KEY_SET_VALUE
    ) as key:
        winreg.SetValueEx(key, "UserName", 0, winreg.REG_SZ, "")
