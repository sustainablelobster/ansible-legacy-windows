# -*- coding: utf-8 -*-
# Copyright 2026 sustainablelobster
# SPDX-License-Identifier: GPL-3.0-or-later

"""Inspect one Windows filesystem link and prepare backup access."""

import ctypes
import ntpath
import os
import struct

_DIRECTORY = 0x10
_REPARSE_POINT = 0x400
_INVALID_HANDLE = int(ctypes.c_void_p(-1).value)
_MAX_PATH = 260
_MAX_REPARSE_DATA = 16 * 1024


# These records describe native token memory layouts and need no methods.
class _Luid(ctypes.Structure):  # pylint: disable=too-few-public-methods
    _fields_ = [("low", ctypes.c_uint32), ("high", ctypes.c_int32)]


class _TokenPrivilege(ctypes.Structure):  # pylint: disable=too-few-public-methods
    _fields_ = [
        ("count", ctypes.c_uint32),
        ("luid", _Luid),
        ("attributes", ctypes.c_uint32),
    ]


def _kernel():
    if os.name != "nt":
        raise ValueError("Link inspection requires a Windows target.")
    kernel = ctypes.WinDLL("kernel32", use_last_error=True)
    kernel.GetFileAttributesW.argtypes = [ctypes.c_wchar_p]
    kernel.GetFileAttributesW.restype = ctypes.c_uint32
    # Keep each helper's native declarations local; sharing this fixed ABI
    # would couple otherwise independent link and metadata helpers.
    # pylint: disable=duplicate-code
    kernel.CreateFileW.argtypes = [
        ctypes.c_wchar_p,
        ctypes.c_uint32,
        ctypes.c_uint32,
        ctypes.c_void_p,
        ctypes.c_uint32,
        ctypes.c_uint32,
        ctypes.c_void_p,
    ]
    kernel.CreateFileW.restype = ctypes.c_void_p
    # pylint: enable=duplicate-code
    kernel.DeviceIoControl.argtypes = [
        ctypes.c_void_p,
        ctypes.c_uint32,
        ctypes.c_void_p,
        ctypes.c_uint32,
        ctypes.c_void_p,
        ctypes.c_uint32,
        ctypes.POINTER(ctypes.c_uint32),
        ctypes.c_void_p,
    ]
    kernel.DeviceIoControl.restype = ctypes.c_int
    kernel.CloseHandle.argtypes = [ctypes.c_void_p]
    kernel.CloseHandle.restype = ctypes.c_int
    kernel.GetCurrentProcess.argtypes = []
    kernel.GetCurrentProcess.restype = ctypes.c_void_p
    return kernel


def _security():
    security = ctypes.WinDLL("advapi32", use_last_error=True)
    security.LookupPrivilegeValueW.argtypes = [
        ctypes.c_wchar_p,
        ctypes.c_wchar_p,
        ctypes.POINTER(_Luid),
    ]
    security.LookupPrivilegeValueW.restype = ctypes.c_int
    security.OpenProcessToken.argtypes = [
        ctypes.c_void_p,
        ctypes.c_uint32,
        ctypes.POINTER(ctypes.c_void_p),
    ]
    security.OpenProcessToken.restype = ctypes.c_int
    security.GetTokenInformation.argtypes = [
        ctypes.c_void_p,
        ctypes.c_uint32,
        ctypes.c_void_p,
        ctypes.c_uint32,
        ctypes.POINTER(ctypes.c_uint32),
    ]
    security.GetTokenInformation.restype = ctypes.c_int
    security.AdjustTokenPrivileges.argtypes = [
        ctypes.c_void_p,
        ctypes.c_int,
        ctypes.POINTER(_TokenPrivilege),
        ctypes.c_uint32,
        ctypes.c_void_p,
        ctypes.c_void_p,
    ]
    security.AdjustTokenPrivileges.restype = ctypes.c_int
    return security


def _open_token(kernel, security, access):
    token = ctypes.c_void_p()
    if not security.OpenProcessToken(
        kernel.GetCurrentProcess(), access, ctypes.byref(token)
    ):
        raise ctypes.WinError(ctypes.get_last_error())
    return token


def _privilege_attributes(kernel, security, luid):
    token = _open_token(kernel, security, 0x8)  # TOKEN_QUERY.
    try:
        required = ctypes.c_uint32()
        security.GetTokenInformation(token, 3, None, 0, ctypes.byref(required))
        error = ctypes.get_last_error()
        if error != 122:
            raise ctypes.WinError(error)
        buffer = ctypes.create_string_buffer(required.value)
        if not security.GetTokenInformation(
            token, 3, buffer, len(buffer), ctypes.byref(required)
        ):
            raise ctypes.WinError(ctypes.get_last_error())
        count = struct.unpack_from("<I", buffer)[0]
        for index in range(count):
            low, high, attributes = struct.unpack_from("<IiI", buffer, 4 + index * 12)
            if (low, high) == (luid.low, luid.high):
                return attributes
        return None
    finally:
        kernel.CloseHandle(token)


def enable_backup_privilege():
    """Enable SeBackupPrivilege only when present and currently disabled.

    The current process keeps the enabled privilege for subsequent file reads;
    all token handles are closed. An absent privilege is left absent.

    :raises OSError: If Windows cannot query or enable the privilege.
    """
    kernel = _kernel()
    security = _security()
    luid = _Luid()
    if not security.LookupPrivilegeValueW(
        None, "SeBackupPrivilege", ctypes.byref(luid)
    ):
        raise ctypes.WinError(ctypes.get_last_error())
    attributes = _privilege_attributes(kernel, security, luid)
    if attributes is None or attributes & 2:
        return
    token = _open_token(
        kernel, security, 0x28
    )  # TOKEN_QUERY | TOKEN_ADJUST_PRIVILEGES.
    try:
        state = _TokenPrivilege(1, luid, 2)
        success = security.AdjustTokenPrivileges(
            token, False, ctypes.byref(state), 0, None, None
        )
        error = ctypes.get_last_error()
        if not success or error:
            raise ctypes.WinError(error)
    finally:
        kernel.CloseHandle(token)


def _reparse_info(kernel, path):
    # LinkUtil requests numeric FileAccess.Read, exclusive sharing, and both
    # backup semantics and OPEN_REPARSE_POINT to inspect the entry itself.
    handle = kernel.CreateFileW(path, 1, 0, None, 3, 0x02200000, None)
    if handle == _INVALID_HANDLE:
        raise ctypes.WinError(ctypes.get_last_error())
    try:
        buffer = ctypes.create_string_buffer(_MAX_REPARSE_DATA)
        received = ctypes.c_uint32()
        if not kernel.DeviceIoControl(
            handle,
            0x900A8,
            None,
            0,
            buffer,
            len(buffer),
            ctypes.byref(received),
            None,
        ):
            raise ctypes.WinError(ctypes.get_last_error())
        data = buffer.raw[: received.value]
    finally:
        kernel.CloseHandle(handle)
    return _parse_reparse(data)


def _parse_reparse(data):
    if len(data) < 8:
        raise ValueError("Invalid reparse point data: missing header.")
    tag = struct.unpack_from("<I", data)[0]
    if tag == 0xA000000C:
        kind, start = "symbolic", 20
    elif tag == 0xA0000003:
        kind, start = "junction", 16
    else:
        raise ValueError("Invalid Reparse Tag: {0}".format(tag))
    if len(data) < start:
        raise ValueError("Invalid reparse point data: missing name offsets.")
    offset, length = struct.unpack_from("<HH", data, 8)
    if offset % 2 or length % 2 or start + offset + length > len(data):
        raise ValueError("Invalid reparse point data: invalid substitute name.")
    target = data[start + offset : start + offset + length].decode(
        "utf-16-le", "surrogatepass"
    )
    if target.startswith("\\??\\"):
        target = target[4:]
    relative = kind == "symbolic" and struct.unpack_from("<I", data, 16)[0] == 1
    return {"type": kind, "target": target, "relative": relative}


def _hardlink_info(kernel, path):
    try:
        first = kernel.FindFirstFileNameW
        following = kernel.FindNextFileNameW
    except AttributeError as error:
        raise NotImplementedError(
            "Hard-link name enumeration requires Windows Vista or Windows Server "
            "2008 or later; this Windows version lacks FindFirstFileNameW/"
            "FindNextFileNameW."
        ) from error
    first.argtypes = [
        ctypes.c_wchar_p,
        ctypes.c_uint32,
        ctypes.POINTER(ctypes.c_uint32),
        ctypes.c_wchar_p,
    ]
    first.restype = ctypes.c_void_p
    following.argtypes = [
        ctypes.c_void_p,
        ctypes.POINTER(ctypes.c_uint32),
        ctypes.c_wchar_p,
    ]
    following.restype = ctypes.c_int
    kernel.GetVolumePathNameW.argtypes = [
        ctypes.c_wchar_p,
        ctypes.c_wchar_p,
        ctypes.c_uint32,
    ]
    kernel.GetVolumePathNameW.restype = ctypes.c_int
    kernel.FindClose.argtypes = [ctypes.c_void_p]
    kernel.FindClose.restype = ctypes.c_int
    buffer = ctypes.create_unicode_buffer(_MAX_PATH)
    if not kernel.GetVolumePathNameW(path, buffer, _MAX_PATH):
        raise ctypes.WinError(ctypes.get_last_error())
    volume = buffer.value
    length = ctypes.c_uint32(_MAX_PATH)
    handle = first(path, 0, ctypes.byref(length), buffer)
    if handle == _INVALID_HANDLE:
        return None
    targets = []
    try:
        while True:
            name = buffer.value
            if name.startswith("\\"):
                name = name[1:]
            targets.append(ntpath.join(volume, name))
            length.value = _MAX_PATH
            if not following(handle, ctypes.byref(length), buffer):
                break
    finally:
        kernel.FindClose(handle)
    if len(targets) > 1:
        return {"type": "hard", "target": targets}
    return None


def get_link_info(path):
    """Read one entry's link type and targets without following its final link.

    :param path: Literal Windows filesystem path.
    :type path: str
    :returns: None for ordinary entries; otherwise a dictionary with type and
        target. Hard-link targets are absolute names in native order, including
        the queried name. Symbolic and junction targets are substitute names
        with only the leading NT object-directory prefix removed; relative
        records whether a symbolic target needs resolution by the caller.
    :rtype: dict or None
    :raises OSError: If Windows cannot inspect attributes, volume, or reparse data.
    :raises ValueError: If a reparse tag or its name data is unsupported.
    :raises NotImplementedError: If hard-link enumeration APIs are unavailable.
    """
    kernel = _kernel()
    attributes = kernel.GetFileAttributesW(path)
    if attributes == 0xFFFFFFFF:
        raise ctypes.WinError(ctypes.get_last_error())
    if attributes & _REPARSE_POINT:
        return _reparse_info(kernel, path)
    if not attributes & _DIRECTORY:
        return _hardlink_info(kernel, path)
    return None
