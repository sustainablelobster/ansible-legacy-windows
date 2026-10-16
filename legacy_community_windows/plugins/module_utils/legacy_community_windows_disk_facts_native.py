# -*- coding: utf-8 -*-
# Copyright 2026 sustainablelobster
# SPDX-License-Identifier: GPL-3.0-or-later

"""Read optional storage fields and native disk and volume metadata."""

import ctypes
import struct
import uuid

from legacy_community_windows_disk import Disk  # pylint: disable=import-error
from legacy_windows_account import sid_bytes  # pylint: disable=import-error
from legacy_windows_wmi import (  # pylint: disable=import-error
    WmiConnection,
    _read_property,
)


# Only the row reader changes; query and COM lifetime remain inherited.
class FactsConnection(WmiConnection):  # pylint: disable=too-few-public-methods
    """Read optional facts without hiding access, provider or conversion errors.

    :param str namespace: Local WMI namespace containing the selected classes.
    """

    def __init__(self, namespace="ROOT\\CIMV2"):
        super().__init__(namespace)
        self.missing_properties = set()

    def _properties(self, instance, properties):
        values = {}
        for name in properties:
            try:
                values[name] = _read_property(instance, self._automation, name)
            except OSError as error:
                if getattr(error, "hresult", None) != 0x80041002:
                    raise
                class_name = _read_property(instance, self._automation, "__CLASS")
                self.missing_properties.add(class_name + "." + name)
                values[name] = None
        return values


def require_administrator():
    """Require the effective administrator token used by released disk facts.

    :raises OSError: Native membership lookup fails.
    :raises PermissionError: The current token is not an administrator.
    """
    security = ctypes.WinDLL("advapi32", use_last_error=True)
    security.CheckTokenMembership.argtypes = [
        ctypes.c_void_p,
        ctypes.c_void_p,
        ctypes.POINTER(ctypes.c_int32),
    ]
    security.CheckTokenMembership.restype = ctypes.c_int32
    sid = ctypes.create_string_buffer(sid_bytes("S-1-5-32-544"))
    member = ctypes.c_int32()
    if not security.CheckTokenMembership(None, sid, ctypes.byref(member)):
        raise ctypes.WinError(ctypes.get_last_error())
    if not member.value:
        raise PermissionError("Module was not started with elevated rights")


def _partition_entries(raw):
    count = struct.unpack_from("<I", raw, 4)[0]
    if count == 0:
        return []
    if len(raw) < 48 + count * 144:
        raise ValueError("The disk driver returned a truncated partition layout")
    result = []
    for index in range(count):
        start = 48 + index * 144
        style, offset, size, number = struct.unpack_from("<I4xqqI", raw, start)
        if not size:
            continue
        entry = {"number": number, "offset": offset, "size": size}
        if style == 0:
            entry.update(mbr_type=raw[start + 32], active=bool(raw[start + 33]))
        elif style == 1:
            attributes = struct.unpack_from("<Q", raw, start + 64)[0]
            entry.update(
                gpt_type="{"
                + str(uuid.UUID(bytes_le=raw[start + 32 : start + 48]))
                + "}",
                guid="{" + str(uuid.UUID(bytes_le=raw[start + 48 : start + 64])) + "}",
                hidden=bool(attributes & (1 << 62)),
                shadow_copy=bool(attributes & (1 << 61)),
                no_default_driveletter=bool(attributes & (1 << 63)),
            )
        result.append(entry)
    return result


def _device_descriptor(raw, path, warnings):
    if len(raw) < 36:
        raise ValueError("The disk driver returned a truncated storage descriptor")
    size = struct.unpack_from("<I", raw, 4)[0]
    if size < 36:
        raise ValueError("The disk driver returned an invalid storage descriptor size")
    # Some drivers advertise a final padding byte they do not return. Decode
    # only the actual bytes inside Size; missing optional strings are not disks
    # or layout failures and must not discard the rest of the inventory.
    extent = min(size, len(raw))
    result = {"bus_type": struct.unpack_from("<I", raw, 28)[0]}
    for name, position in (
        ("manufacturer", 12),
        ("model", 16),
        ("firmware_version", 20),
        ("serial_number", 24),
    ):
        offset = struct.unpack_from("<I", raw, position)[0]
        result[name] = None
        if not offset:
            continue
        if offset < 36 or offset >= extent:
            reason = "invalid string offset {0}".format(offset)
        else:
            end = raw.find(b"\0", offset, extent)
            if end != -1:
                result[name] = raw[offset:end].decode("ascii", "replace").strip()
                continue
            reason = "unterminated string"
        warnings.append(
            "Storage descriptor for {0} has an {1} for {2}; "
            "that native field is unavailable.".format(path, reason, name)
        )
    return result


def describe_disk(path):
    """Read physical layout and device metadata without requesting write access.

    :param str path: Explicit physical-device path resolved by Windows.
    :returns: Layout, partitions, device fields, geometry and optional-field warnings.
    :rtype: dict
    :raises OSError: Required native disk access or metadata lookup fails.
    :raises ValueError: A driver returns truncated or invalid native data.
    """
    with Disk(path) as disk:
        result = {
            "layout": disk.read_layout(),
            "device": {},
            "sector_size": None,
            "size": None,
            "warnings": [],
        }
        # The common handle owns these published IOCTL buffers. Only storage
        # fact decoding is specialized here; no second device client is opened.
        # pylint: disable=protected-access
        result["partitions"] = _partition_entries(
            disk._control(0x70050, output_size=65536)
        )
        try:
            geometry = disk._control(0x700A0, output_size=1024)
            result["size"] = struct.unpack_from("<q", geometry, 24)[0]
        except OSError as error:
            if getattr(error, "winerror", None) not in (1, 50):
                raise
        query = ctypes.create_string_buffer(12)
        try:
            result["device"] = _device_descriptor(
                disk._control(0x2D1400, query, 65536), path, result["warnings"]
            )
        except OSError as error:
            if getattr(error, "winerror", None) not in (1, 50):
                raise
        query[0] = b"\x06"  # StorageAccessAlignmentProperty.
        try:
            alignment = disk._control(0x2D1400, query, 28)
            result["sector_size"] = struct.unpack_from("<I", alignment, 20)[0]
        except OSError as error:
            # Older storage stacks reject this optional property with
            # ERROR_INVALID_PARAMETER, even when their device query succeeds.
            if getattr(error, "winerror", None) not in (1, 50, 87):
                raise
            result["warnings"].append(
                "Storage alignment is unavailable for {0}; the physical sector "
                "size is unknown.".format(path)
            )
        # pylint: enable=protected-access
    return result


def volume_details(root):
    """Read a mounted volume's actual GUID path and allocation-unit size.

    :param str root: Existing drive-letter mount root.
    :returns: Native volume path and allocation unit size in bytes.
    :rtype: dict
    :raises OSError: Windows cannot query the selected mounted volume.
    """
    kernel = ctypes.WinDLL("kernel32", use_last_error=True)
    dword = ctypes.c_uint32
    kernel.GetDiskFreeSpaceW.argtypes = [ctypes.c_wchar_p] + [ctypes.POINTER(dword)] * 4
    kernel.GetDiskFreeSpaceW.restype = ctypes.c_int32
    kernel.GetVolumeNameForVolumeMountPointW.argtypes = [
        ctypes.c_wchar_p,
        ctypes.c_wchar_p,
        dword,
    ]
    kernel.GetVolumeNameForVolumeMountPointW.restype = ctypes.c_int32
    sectors, sector_size, free, total = dword(), dword(), dword(), dword()
    if not kernel.GetDiskFreeSpaceW(
        root,
        ctypes.byref(sectors),
        ctypes.byref(sector_size),
        ctypes.byref(free),
        ctypes.byref(total),
    ):
        raise ctypes.WinError(ctypes.get_last_error())
    volume = ctypes.create_unicode_buffer(261)
    if not kernel.GetVolumeNameForVolumeMountPointW(root, volume, len(volume)):
        raise ctypes.WinError(ctypes.get_last_error())
    return {
        "path": volume.value,
        "allocation_unit_size": sectors.value * sector_size.value,
    }
