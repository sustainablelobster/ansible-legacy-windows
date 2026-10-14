# -*- coding: utf-8 -*-
# Copyright 2026 sustainablelobster
# SPDX-License-Identifier: GPL-3.0-or-later

"""Read exact Windows metadata and remove entries without following links."""

import ctypes
import os

_DIRECTORY = 0x10
_REPARSE_POINT = 0x400
_HIDDEN = 0x2
_FORCE_ATTRIBUTES = 0x7  # ReadOnly, Hidden, and System.


# Keeping fixed ABI records here avoids coupling file writes to the stat helper.
# These ctypes records describe native memory layouts and need no methods.
# pylint: disable=duplicate-code
class _FileTime(ctypes.Structure):  # pylint: disable=too-few-public-methods
    _fields_ = [("low", ctypes.c_uint32), ("high", ctypes.c_uint32)]


class _AttributeData(ctypes.Structure):  # pylint: disable=too-few-public-methods
    _fields_ = [
        ("attributes", ctypes.c_uint32),
        ("creation_time", _FileTime),
        ("access_time", _FileTime),
        ("modification_time", _FileTime),
        ("size_high", ctypes.c_uint32),
        ("size_low", ctypes.c_uint32),
    ]


# pylint: enable=duplicate-code


def _kernel():
    if os.name != "nt":
        raise ValueError("Filesystem operations require a Windows target.")
    kernel = ctypes.WinDLL("kernel32", use_last_error=True)
    # Each separately staged helper declares the Windows ABI it calls; sharing
    # these signatures would make file writes depend on the stat implementation.
    # pylint: disable=duplicate-code
    kernel.GetFileAttributesExW.argtypes = [
        ctypes.c_wchar_p,
        ctypes.c_int,
        ctypes.POINTER(_AttributeData),
    ]
    kernel.GetFileAttributesExW.restype = ctypes.c_int
    kernel.GetSystemTimeAsFileTime.argtypes = [ctypes.POINTER(_FileTime)]
    kernel.GetSystemTimeAsFileTime.restype = None
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
    kernel.GetFileType.argtypes = [ctypes.c_void_p]
    kernel.GetFileType.restype = ctypes.c_uint32
    kernel.SetFileTime.argtypes = [
        ctypes.c_void_p,
        ctypes.POINTER(_FileTime),
        ctypes.POINTER(_FileTime),
        ctypes.POINTER(_FileTime),
    ]
    kernel.SetFileTime.restype = ctypes.c_int
    kernel.ReadFile.argtypes = [
        ctypes.c_void_p,
        ctypes.c_void_p,
        ctypes.c_uint32,
        ctypes.POINTER(ctypes.c_uint32),
        ctypes.c_void_p,
    ]
    kernel.ReadFile.restype = ctypes.c_int
    kernel.CloseHandle.argtypes = [ctypes.c_void_p]
    kernel.CloseHandle.restype = ctypes.c_int
    # pylint: enable=duplicate-code
    kernel.DeleteFileW.argtypes = [ctypes.c_wchar_p]
    kernel.DeleteFileW.restype = ctypes.c_int
    kernel.RemoveDirectoryW.argtypes = [ctypes.c_wchar_p]
    kernel.RemoveDirectoryW.restype = ctypes.c_int
    kernel.SetFileAttributesW.argtypes = [ctypes.c_wchar_p, ctypes.c_uint32]
    kernel.SetFileAttributesW.restype = ctypes.c_int
    return kernel


def _ticks(value):
    return (value.high << 32) | value.low


def file_info(path):
    """Read attributes and exact UTC timestamps of the named entry.

    :param path: Literal Windows file or directory path.
    :type path: str
    :returns: Attributes and access_time/modification_time FILETIME integers,
        or None for a missing file or parent. A final link is not followed.
    :rtype: dict or None
    :raises OSError: If Windows cannot read the entry's metadata.
    """
    kernel = _kernel()
    data = _AttributeData()
    if not kernel.GetFileAttributesExW(path, 0, ctypes.byref(data)):
        error = ctypes.get_last_error()
        if error in (2, 3):
            return None
        raise ctypes.WinError(error)
    return {
        "attributes": data.attributes,
        "access_time": _ticks(data.access_time),
        "modification_time": _ticks(data.modification_time),
    }


def current_file_time():
    """Read the current UTC time in native 100-nanosecond units.

    :returns: FILETIME ticks since 1601-01-01 UTC.
    :rtype: int
    """
    value = _FileTime()
    _kernel().GetSystemTimeAsFileTime(ctypes.byref(value))
    return _ticks(value)


# Separate native access, sharing, flags, and disposition make each caller's
# handle contract visible; grouping them would obscure the CreateFileW call.
def _open_disk(  # pylint: disable=too-many-arguments
    kernel, path, access, share, flags, *, disposition=3
):
    handle = kernel.CreateFileW(path, access, share, None, disposition, flags, None)
    if handle == ctypes.c_void_p(-1).value:
        raise ctypes.WinError(ctypes.get_last_error())
    try:
        if kernel.GetFileType(handle) != 1:
            raise ValueError("Only disk files and directories are supported.")
    except Exception:
        kernel.CloseHandle(handle)
        raise
    return handle


def create_empty_file(path):
    """Create an empty disk file with upstream sharing and anonymous SQOS.

    Callers check for an existing entry before creation. Like the upstream
    create-mode stream, a file appearing after that check is truncated.

    :param path: Literal Windows file path; the parent must already exist.
    :type path: str
    :raises ValueError: If the opened handle does not refer to a disk file.
    :raises OSError: If Windows cannot create or open the file.
    """
    kernel = _kernel()
    handle = _open_disk(kernel, path, 0x40000000, 1, 0x00100000, disposition=2)
    kernel.CloseHandle(handle)


def set_file_time(path, is_directory, field, value):
    """Set one timestamp using .NET Framework's access and sharing rules.

    :param path: Literal Windows path; the final link is followed.
    :type path: str
    :param is_directory: Whether to use the directory timestamp setter's flags.
    :type is_directory: bool
    :param field: Either access_time or modification_time.
    :type field: str
    :param value: UTC FILETIME ticks, from 1601 through year 9999 inclusive.
    :type value: int
    :raises ValueError: If the field or time is invalid, or the handle is not disk.
    :raises OSError: If Windows cannot open the entry or set its timestamp.
    """
    if field not in ("access_time", "modification_time"):
        raise ValueError("Timestamp field must be access_time or modification_time.")
    kernel = _kernel()
    # FileStream uses read/write sharing and anonymous SQOS; Directory uses
    # write/delete sharing and backup semantics. Both request GENERIC_WRITE.
    share = 6 if is_directory else 3
    flags = 0x02000000 if is_directory else 0x00100000
    handle = _open_disk(kernel, path, 0x40000000, share, flags)
    try:
        # .NET opens first, then converts DateTime to FILETIME. Preserve that
        # failure order, including for dates earlier than the FILETIME epoch.
        if not isinstance(value, int) or not 0 <= value <= 2650467743999999999:
            raise ValueError("File timestamp must be between 1601 and 9999.")
        timestamp = _FileTime(value & 0xFFFFFFFF, value >> 32)
        access_time = ctypes.byref(timestamp) if field == "access_time" else None
        modification_time = (
            ctypes.byref(timestamp) if field == "modification_time" else None
        )
        if not kernel.SetFileTime(handle, None, access_time, modification_time):
            raise ctypes.WinError(ctypes.get_last_error())
    finally:
        kernel.CloseHandle(handle)


def read_prefix(path, count):
    """Read at most count bytes with .NET OpenRead's sharing rules.

    :param path: Literal Windows file path; the final link is followed.
    :type path: str
    :param count: Maximum number of bytes, between zero and a Windows DWORD.
    :type count: int
    :returns: The bytes returned by one bounded native read, without padding.
    :rtype: bytes
    :raises ValueError: If count is invalid or the opened handle is not disk.
    :raises OSError: If Windows cannot open or read the file.
    """
    if not isinstance(count, int) or not 0 <= count <= 0xFFFFFFFF:
        raise ValueError("Read count must be an integer from 0 through 4294967295.")
    kernel = _kernel()
    handle = _open_disk(kernel, path, 0x80000000, 1, 0x00100000)
    try:
        if not count:
            return b""
        buffer = ctypes.create_string_buffer(count)
        received = ctypes.c_uint32()
        if not kernel.ReadFile(handle, buffer, count, ctypes.byref(received), None):
            raise ctypes.WinError(ctypes.get_last_error())
        return buffer.raw[: received.value]
    finally:
        kernel.CloseHandle(handle)


def remove_file(path):
    """Delete one file entry, leaving a symbolic link's target intact.

    :param path: Literal Windows file path.
    :type path: str
    :raises OSError: If Windows cannot delete the entry.
    """
    if not _kernel().DeleteFileW(path):
        raise ctypes.WinError(ctypes.get_last_error())


def remove_directory(path):
    """Remove an empty directory or a directory link without traversal.

    :param path: Literal Windows directory or junction path.
    :type path: str
    :raises OSError: If Windows cannot remove the entry.
    """
    if not _kernel().RemoveDirectoryW(path):
        raise ctypes.WinError(ctypes.get_last_error())


def set_attributes(path, attributes):
    """Set the Windows attribute bits for one filesystem entry.

    :param path: Literal Windows file or directory path.
    :type path: str
    :param attributes: Windows file attribute flags.
    :type attributes: int
    :raises OSError: If Windows cannot change the entry's attributes.
    """
    if not _kernel().SetFileAttributesW(path, attributes):
        raise ctypes.WinError(ctypes.get_last_error())


def _children(path, include_hidden):
    directories = []
    files = []
    for name in os.listdir(path):
        child = os.path.join(path, name)
        try:
            info = file_info(child)
            if info is None:
                raise ctypes.WinError(2)
        except OSError as error:
            error.filename = child
            raise
        attributes = info["attributes"]
        if not include_hidden and attributes & _HIDDEN:
            continue
        entries = directories if attributes & _DIRECTORY else files
        entries.append((child, attributes))
    # The measured Windows PowerShell 5.1 provider groups directories before
    # files, retaining native enumeration order within each group. Do not sort.
    return directories + files


def _delete_entry(path, attributes):
    if attributes & _DIRECTORY:
        remove_directory(path)
    else:
        remove_file(path)


def _force_delete_entry(path, attributes):
    set_attributes(path, attributes & ~_FORCE_ATTRIBUTES)
    try:
        _delete_entry(path, attributes)
    except OSError as deletion_error:
        try:
            if file_info(path) is not None:
                set_attributes(path, attributes)
        except OSError as restoration_error:
            # Keep the deletion's native code and also report failed recovery;
            # otherwise the caller could mistake changed attributes for intact.
            deletion_error.strerror = (
                "{0}; could not restore original attributes: {1}".format(
                    deletion_error.strerror, restoration_error
                )
            )
            raise deletion_error from restoration_error
        raise


def _remove_entry(path, attributes, check_mode, forced):
    try:
        if attributes & _REPARSE_POINT:
            if not check_mode:
                if forced and not attributes & _DIRECTORY:
                    _force_delete_entry(path, attributes)
                else:
                    _delete_entry(path, attributes)
            return
        if attributes & _DIRECTORY:
            for child, child_attributes in _children(path, forced):
                _remove_entry(child, child_attributes, check_mode, forced)
            if not forced and not check_mode:
                for child, child_attributes in _children(path, True):
                    _remove_entry(child, child_attributes, False, True)
        if not check_mode:
            _force_delete_entry(path, attributes)
    except OSError as error:
        if error.filename is None:
            error.filename = path
        raise


def remove_path(path, check_mode=False):
    """Remove a literal tree using the measured Windows PowerShell 5.1 order.

    Visible entries are visited first, grouping directories before files in
    native enumeration order. A final forced pass includes hidden entries in
    the same grouping. Reparse points are removed without visiting targets.
    This is a bounded removal contract, not complete win_file parity.

    :param path: Literal Windows file, directory, or link path.
    :type path: str
    :param check_mode: Inspect the visible tree without changing it. The final
        forced pass is not visited, as with the upstream WhatIf operation.
    :type check_mode: bool
    :returns: False when the root is missing; True on success or check mode.
    :rtype: bool
    :raises OSError: At the first failure, retaining its native error code and
        failing filename. Earlier removals are not rolled back. Attributes are
        restored after a failed forced deletion; recovery failures are included.
    """
    try:
        info = file_info(path)
        if info is None:
            return False
        _remove_entry(path, info["attributes"], check_mode, False)
        return True
    except OSError as error:
        if error.filename is None:
            error.filename = path
        raise
