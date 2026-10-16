# -*- coding: utf-8 -*-
# Copyright 2026 sustainablelobster
# SPDX-License-Identifier: GPL-3.0-or-later

"""Own native virtual-disk handles and locate their actual drive-letter mounts."""

import ctypes
import os
import re
import uuid

from legacy_windows_owner import ownership_privileges  # pylint: disable=import-error
from legacy_windows_wmi import _Guid  # pylint: disable=import-error

_POINTER = ctypes.c_void_p
_DWORD = ctypes.c_uint32
_MICROSOFT_PROVIDER = "ec984aec-a0f9-47e9-901f-71415a66345b"


# These records are the published virtdisk.h version-1 ABI, not state models.
# pylint: disable=too-few-public-methods
class _StorageType(ctypes.Structure):
    _fields_ = [("device", _DWORD), ("vendor", _Guid)]


class _VersionOne(ctypes.Structure):
    _fields_ = [("version", _DWORD), ("value", _DWORD)]


class _DeviceNumber(ctypes.Structure):
    _fields_ = [("kind", _DWORD), ("number", _DWORD), ("partition", _DWORD)]


# pylint: enable=too-few-public-methods


def _check(status, operation):
    if status:
        error = ctypes.WinError(status)
        raise OSError(error.errno, operation + ": " + error.strerror, None, status)


def _libraries():
    try:
        disk = ctypes.WinDLL("virtdisk", use_last_error=True)
    except OSError as error:
        raise OSError(
            "The installed Windows virtual-disk API is unavailable."
        ) from error
    kernel = ctypes.WinDLL("kernel32", use_last_error=True)
    disk.OpenVirtualDisk.argtypes = [
        ctypes.POINTER(_StorageType),
        ctypes.c_wchar_p,
        _DWORD,
        _DWORD,
        ctypes.POINTER(_VersionOne),
        ctypes.POINTER(_POINTER),
    ]
    disk.OpenVirtualDisk.restype = _DWORD
    disk.GetVirtualDiskPhysicalPath.argtypes = [
        _POINTER,
        ctypes.POINTER(_DWORD),
        ctypes.c_wchar_p,
    ]
    disk.GetVirtualDiskPhysicalPath.restype = _DWORD
    disk.AttachVirtualDisk.argtypes = [
        _POINTER,
        _POINTER,
        _DWORD,
        _DWORD,
        ctypes.POINTER(_VersionOne),
        _POINTER,
    ]
    disk.AttachVirtualDisk.restype = _DWORD
    disk.DetachVirtualDisk.argtypes = [_POINTER, _DWORD, _DWORD]
    disk.DetachVirtualDisk.restype = _DWORD
    # These fixed kernel32 declarations belong to this virtual-disk handle
    # owner; another feature's bindings are not a runtime dependency.
    # pylint: disable=duplicate-code
    kernel.CloseHandle.argtypes = [_POINTER]
    kernel.CloseHandle.restype = ctypes.c_int32
    kernel.GetLogicalDrives.argtypes = []
    kernel.GetLogicalDrives.restype = _DWORD
    kernel.CreateFileW.argtypes = [
        ctypes.c_wchar_p,
        _DWORD,
        _DWORD,
        _POINTER,
        _DWORD,
        _DWORD,
        _POINTER,
    ]
    kernel.CreateFileW.restype = _POINTER
    kernel.DeviceIoControl.argtypes = [
        _POINTER,
        _DWORD,
        _POINTER,
        _DWORD,
        _POINTER,
        _DWORD,
        ctypes.POINTER(_DWORD),
        _POINTER,
    ]
    kernel.DeviceIoControl.restype = ctypes.c_int32
    # pylint: enable=duplicate-code
    return disk, kernel


def _drive_paths(kernel, physical_path):
    match = re.match(r"\A\\\\\.\\(PhysicalDrive|CdRom)(\d+)\Z", physical_path, re.I)
    if match is None:
        raise ValueError("Unrecognized attached device path: " + physical_path)
    expected_kind = 7 if match.group(1).lower() == "physicaldrive" else 2
    expected_number = int(match.group(2))
    drives = kernel.GetLogicalDrives()
    if not drives:
        raise ctypes.WinError(ctypes.get_last_error())
    paths = []
    for index in range(26):
        if not drives & (1 << index):
            continue
        letter = chr(ord("A") + index) + ":"
        handle = kernel.CreateFileW("\\\\.\\" + letter, 0, 7, None, 3, 0, None)
        if handle == _POINTER(-1).value:
            # An unrelated removable or access-controlled volume must not hide
            # a readable drive on the selected image. No match still fails above.
            if ctypes.get_last_error() in (2, 5, 21):
                continue
            raise ctypes.WinError(ctypes.get_last_error())
        try:
            number, used = _DeviceNumber(), _DWORD()
            if not kernel.DeviceIoControl(
                handle,
                0x2D1080,
                None,
                0,
                ctypes.byref(number),
                ctypes.sizeof(number),
                ctypes.byref(used),
                None,
            ):
                if ctypes.get_last_error() in (1, 5, 21, 50):
                    continue
                raise ctypes.WinError(ctypes.get_last_error())
            if number.kind == expected_kind and number.number == expected_number:
                paths.append(letter + "\\")
        finally:
            kernel.CloseHandle(handle)
    return paths


class DiskImage:
    """Keep one image's native handle alive for a complete management operation.

    :param str path: Local ISO, VHD or VHDX file path.
    :raises OSError: The installed provider or file cannot be opened.
    """

    def __init__(self, path):
        self.path = path
        self.disk = None
        self.kernel = None
        self.handle = None
        self.storage = _StorageType(
            {".iso": 1, ".vhd": 2, ".vhdx": 3}.get(
                os.path.splitext(path)[1].lower(), 0
            ),
            _Guid.from_buffer_copy(uuid.UUID(_MICROSOFT_PROVIDER).bytes_le),
        )

    def _open(self, access):
        handle = _POINTER()
        _check(
            self.disk.OpenVirtualDisk(
                ctypes.byref(self.storage),
                self.path,
                access,
                0,
                ctypes.byref(_VersionOne(1, 1)),
                ctypes.byref(handle),
            ),
            "OpenVirtualDisk",
        )
        self.handle = handle

    def __enter__(self):
        self.disk, self.kernel = _libraries()
        # DETACH is also required to reopen a permanently attached image for
        # inspection; this read handle never requests writable file access.
        self._open(0xD0000)
        return self

    def __exit__(self, exc_type, exc_value, traceback):
        if self.handle:
            self.kernel.CloseHandle(self.handle)
            self.handle = None

    def physical_path(self):
        """Read the physical device, returning None for an unattached image.

        :returns: Native device path or None.
        :rtype: str or None
        :raises OSError: The provider cannot read attachment information.
        """
        buffer = ctypes.create_unicode_buffer(512)
        size = _DWORD(ctypes.sizeof(buffer))
        status = self.disk.GetVirtualDiskPhysicalPath(
            self.handle, ctypes.byref(size), buffer
        )
        if status in (55, 1168):
            return None
        _check(status, "GetVirtualDiskPhysicalPath")
        return buffer.value

    def mount_paths(self):
        """Read drive-letter roots belonging to this image's physical device.

        :returns: Actual assigned drive-letter roots, or an empty list.
        :rtype: list
        :raises OSError: A required native volume query fails.
        :raises ValueError: The provider returns an unrecognized device path.
        """
        physical = self.physical_path()
        return _drive_paths(self.kernel, physical) if physical else []

    def attach(self):
        """Attach persistently using the installed provider and available privilege.

        :raises OSError: The provider or caller's access rights prevent attaching.
        """
        self.kernel.CloseHandle(self.handle)
        self.handle = None
        readonly = self.storage.device == 1
        self._open(0xD0000 if readonly else 0xE0000)
        with ownership_privileges(("SeManageVolumePrivilege",)):
            _check(
                self.disk.AttachVirtualDisk(
                    self.handle,
                    None,
                    4 | int(readonly),
                    0,
                    ctypes.byref(_VersionOne(1, 0)),
                    None,
                ),
                "AttachVirtualDisk",
            )

    def detach(self):
        """Detach only this image while restoring the caller's privilege state.

        :raises OSError: The provider or caller's access rights prevent detaching.
        """
        with ownership_privileges(("SeManageVolumePrivilege",)):
            _check(self.disk.DetachVirtualDisk(self.handle, 0, 0), "DetachVirtualDisk")
