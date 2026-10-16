"""Read optional device strings directly, without collection helper imports."""

# Copyright 2026 sustainablelobster
# SPDX-License-Identifier: GPL-3.0-or-later

import ctypes
import json
import struct
import sys


def _read_descriptor(path):
    kernel = ctypes.WinDLL("kernel32", use_last_error=True)
    pointer = ctypes.c_void_p
    dword = ctypes.c_uint32
    kernel.CreateFileW.argtypes = [
        ctypes.c_wchar_p,
        dword,
        dword,
        pointer,
        dword,
        dword,
        pointer,
    ]
    kernel.CreateFileW.restype = pointer
    # This oracle declares the published ABI independently instead of importing
    # the collection's disk wrapper, so the native read is a separate control.
    # pylint: disable=duplicate-code
    kernel.DeviceIoControl.argtypes = [
        pointer,
        dword,
        pointer,
        dword,
        pointer,
        dword,
        ctypes.POINTER(dword),
        pointer,
    ]
    kernel.DeviceIoControl.restype = ctypes.c_int32
    # pylint: enable=duplicate-code
    kernel.CloseHandle.argtypes = [pointer]
    kernel.CloseHandle.restype = ctypes.c_int32
    device = kernel.CreateFileW(path, 0x80000000, 3, None, 3, 0, None)
    if device == pointer(-1).value:
        raise ctypes.WinError(ctypes.get_last_error())
    try:
        query = ctypes.create_string_buffer(12)
        output = ctypes.create_string_buffer(65536)
        returned = dword()
        if not kernel.DeviceIoControl(
            device,
            0x2D1400,
            query,
            12,
            output,
            len(output),
            ctypes.byref(returned),
            None,
        ):
            raise ctypes.WinError(ctypes.get_last_error())
        return output.raw[: returned.value]
    finally:
        kernel.CloseHandle(device)


def main():
    """Print independently queried storage descriptor fields and Python version.

    :raises OSError: Windows cannot open or query the selected read-only device.
    :raises ValueError: The native response does not contain its fixed header.
    """
    raw = _read_descriptor(sys.argv[1])
    if len(raw) < 36:
        raise ValueError("The independent native descriptor header is truncated")
    version, size = struct.unpack_from("<II", raw)
    if size < 36:
        raise ValueError("The independent native descriptor size is invalid")
    extent = min(len(raw), size)
    fields, unavailable = {}, []
    for index, name in enumerate(
        ("manufacturer", "model", "firmware_version", "serial_number")
    ):
        offset = struct.unpack_from("<I", raw, 12 + index * 4)[0]
        end = raw.find(b"\0", offset, extent) if 36 <= offset < extent else -1
        fields[name] = (
            None if end == -1 else raw[offset:end].decode("ascii", "replace").strip()
        )
        if offset and end == -1:
            unavailable.append(name)
    print(
        json.dumps(
            {
                "python_version": list(sys.version_info[:3]),
                "returned_bytes": len(raw),
                "descriptor_version": version,
                "descriptor_size": size,
                "fields": fields,
                "malformed_fields": unavailable,
            }
        )
    )


if __name__ == "__main__":
    main()
