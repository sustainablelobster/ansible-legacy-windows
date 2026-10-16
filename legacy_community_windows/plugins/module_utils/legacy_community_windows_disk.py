# -*- coding: utf-8 -*-
# Copyright 2026 sustainablelobster
# SPDX-License-Identifier: GPL-3.0-or-later

"""Read and initialize the selected physical disk using published Windows IOCTLs."""

import ctypes
import os
import struct
import uuid

from legacy_windows_owner import ownership_privileges  # pylint: disable=import-error
from legacy_windows_wmi import WmiConnection  # pylint: disable=import-error

_DWORD = ctypes.c_uint32
_POINTER = ctypes.c_void_p


def select_disk(selectors):
    """Resolve an upstream disk selector to one local physical-device path.

    :param dict selectors: Exactly one disk_number, uniqueid or path selector.
    :returns: Device path opened by the native disk API.
    :rtype: str
    :raises ValueError: The selector matches no disk or more than one disk.
    :raises OSError: A native provider query fails.
    """
    key, expected = next(iter(selectors.items()))
    try:
        with WmiConnection("ROOT\\Microsoft\\Windows\\Storage") as connection:
            fields = ("Number", "UniqueId", "Path")
            rows = connection.query(
                "SELECT " + ",".join(fields) + " FROM MSFT_Disk", fields
            )
            field = {"disk_number": "Number", "uniqueid": "UniqueId", "path": "Path"}[
                key
            ]
            matches = [
                row
                for row in rows
                if str(row[field]).casefold() == str(expected).casefold()
            ]
            paths = [r"\\.\PhysicalDrive" + str(row["Number"]) for row in matches]
    except OSError as error:
        if getattr(error, "hresult", None) not in (0x8004100E, 0x80041010):
            raise
        paths = _select_legacy(key, expected)
    if len(paths) != 1:
        raise ValueError(
            "Disk selector matched {0} local disks; exactly one is required".format(
                len(paths)
            )
        )
    return paths[0]


def _select_legacy(key, expected):
    with WmiConnection() as connection:
        fields = ("Index", "DeviceID", "PNPDeviceID")
        rows = connection.query(
            "SELECT " + ",".join(fields) + " FROM Win32_DiskDrive", fields
        )
    paths = []
    for row in rows:
        if key == "uniqueid":
            with Disk(row["DeviceID"]) as disk:
                actual = disk.read_layout()["uniqueid"]
        else:
            actual = row["Index"] if key == "disk_number" else row["DeviceID"]
        if str(actual).casefold() == str(expected).casefold():
            paths.append(row["DeviceID"])
    return paths


# These structures mirror the corresponding public winioctl.h records.
# pylint: disable=too-few-public-methods
class _SetAttributes(ctypes.Structure):
    _fields_ = [
        ("version", _DWORD),
        ("persist", ctypes.c_ubyte),
        ("reserved", ctypes.c_ubyte * 3),
        ("attributes", ctypes.c_uint64),
        ("mask", ctypes.c_uint64),
        ("reserved2", _DWORD * 4),
    ]


class _CreateDisk(ctypes.Structure):
    _fields_ = [("style", _DWORD), ("parameters", ctypes.c_ubyte * 20)]


# pylint: enable=too-few-public-methods


def _kernel():
    kernel = ctypes.WinDLL("kernel32", use_last_error=True)
    # These kernel32 signatures are fixed by winioctl.h. Keep the small binding
    # beside its disk handle owner rather than importing an unrelated feature.
    # pylint: disable=duplicate-code
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
    kernel.CloseHandle.argtypes = [_POINTER]
    kernel.CloseHandle.restype = ctypes.c_int32
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
    return kernel


class Disk:
    """Own a handle to one selected physical disk for native layout operations.

    :param str path: Explicit local physical-device path.
    :param bool writable: Request native write access only for actual mutation.
    :raises OSError: Windows cannot open the selected disk.
    """

    def __init__(self, path, writable=False):
        self.path = path
        self.writable = writable
        self.kernel = None
        self.handle = None

    def __enter__(self):
        self.kernel = _kernel()
        self.handle = self.kernel.CreateFileW(
            self.path, 0xC0000000 if self.writable else 0, 3, None, 3, 0, None
        )
        if self.handle == _POINTER(-1).value:
            raise ctypes.WinError(ctypes.get_last_error())
        return self

    def __exit__(self, exc_type, exc_value, traceback):
        if self.handle is not None:
            self.kernel.CloseHandle(self.handle)
            self.handle = None

    def _control(self, code, source=None, output_size=0):
        destination = ctypes.create_string_buffer(output_size) if output_size else None
        returned = _DWORD()
        if not self.kernel.DeviceIoControl(
            self.handle,
            code,
            ctypes.byref(source) if source is not None else None,
            ctypes.sizeof(source) if source is not None else 0,
            destination,
            output_size,
            ctypes.byref(returned),
            None,
        ):
            raise ctypes.WinError(ctypes.get_last_error())
        return destination.raw[: returned.value] if destination is not None else None

    def read_layout(self):
        """Read partition style, signature and native persistent disk attributes.

        :returns: Layout identity, style, partition count and optional attributes.
        :rtype: dict
        :raises OSError: A required layout or attribute query fails.
        """
        layout = self._control(0x70050, output_size=65536)
        style, count = struct.unpack_from("<II", layout)
        identity = None
        if style == 0:
            signature = struct.unpack_from("<I", layout, 8)[0]
            # Some legacy drivers report a raw disk as an empty MBR record
            # with neither partition entries nor a disk signature.
            if count == 0 and signature == 0:
                style = 2
            else:
                identity = "{0:08X}".format(signature)
        elif style == 1:
            identity = str(uuid.UUID(bytes_le=layout[8:24]))
        attributes = None
        try:
            raw = self._control(0x700F0, output_size=16)
            attributes = struct.unpack_from("<Q", raw, 8)[0]
        except OSError as error:
            # Older disk drivers do not expose persistent offline/read-only
            # attributes. Do not turn access-denied or device errors into nulls.
            if getattr(error, "winerror", None) not in (1, 50):
                raise
        return {
            "style": {0: "mbr", 1: "gpt", 2: "raw"}.get(style, "unknown"),
            "partition_count": count,
            "uniqueid": identity,
            "attributes": attributes,
        }

    def bring_online(self):
        """Clear only the persistent offline and read-only disk attributes.

        :raises OSError: The provider cannot update the selected attributes.
        """
        values = _SetAttributes(
            version=ctypes.sizeof(_SetAttributes), persist=1, mask=3
        )
        with ownership_privileges(("SeManageVolumePrivilege",)):
            self._control(0x7C0F4, values)
            self._control(0x70140)

    def clear(self):
        """Remove partition-table signatures from only this selected disk.

        :raises OSError: Windows cannot clear the selected disk layout.
        """
        with ownership_privileges(("SeManageVolumePrivilege",)):
            self._control(0x7C100)
            self._control(0x70140)

    def initialize(self, style):
        """Create a new MBR or GPT layout on an already raw disk.

        :param str style: Requested mbr or gpt partition style.
        :raises ValueError: The requested style is unknown or the disk is not raw.
        :raises OSError: Windows cannot initialize the selected disk.
        """
        if style not in ("mbr", "gpt"):
            raise ValueError("Partition style must be mbr or gpt")
        if self.read_layout()["style"] != "raw":
            raise ValueError(
                "Refusing to initialize a non-raw disk without clearing it"
            )
        parameters = _CreateDisk(0 if style == "mbr" else 1)
        raw = (
            struct.pack("<I", int.from_bytes(os.urandom(4), "little") or 1)
            if style == "mbr"
            else uuid.uuid4().bytes_le + struct.pack("<I", 128)
        )
        ctypes.memmove(parameters.parameters, raw, len(raw))
        with ownership_privileges(("SeManageVolumePrivilege",)):
            self._control(0x7C058, parameters)
            self._control(0x70140)
