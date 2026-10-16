"""Read a classic Windows event record independently of the collection."""

# Copyright 2026 sustainablelobster
# SPDX-License-Identifier: GPL-3.0-or-later

import binascii
import ctypes
import json
import struct
import sys


def read_event(name):
    """Count the test log's records and decode its latest native record.

    :param str name: The uniquely owned classic event log name.
    :returns: Event count and latest identifier, type, source, message and bytes.
    :rtype: dict
    :raises OSError: The native log cannot be opened or read.
    """
    library = ctypes.WinDLL("advapi32", use_last_error=True)
    library.OpenEventLogW.argtypes = [ctypes.c_wchar_p, ctypes.c_wchar_p]
    library.OpenEventLogW.restype = ctypes.c_void_p
    library.CloseEventLog.argtypes = [ctypes.c_void_p]
    library.CloseEventLog.restype = ctypes.c_int
    library.GetNumberOfEventLogRecords.argtypes = [
        ctypes.c_void_p,
        ctypes.POINTER(ctypes.c_uint32),
    ]
    library.GetNumberOfEventLogRecords.restype = ctypes.c_int
    # ReadEventLogW's fixed ABI is declared independently so this fixture does
    # not verify the collection using the collection's own event-log bindings.
    # pylint: disable=duplicate-code
    library.ReadEventLogW.argtypes = [
        ctypes.c_void_p,
        ctypes.c_uint32,
        ctypes.c_uint32,
        ctypes.c_void_p,
        ctypes.c_uint32,
        ctypes.POINTER(ctypes.c_uint32),
        ctypes.POINTER(ctypes.c_uint32),
    ]
    library.ReadEventLogW.restype = ctypes.c_int
    # pylint: enable=duplicate-code
    handle = library.OpenEventLogW(None, name)
    if not handle:
        raise ctypes.WinError(ctypes.get_last_error())
    try:
        count = ctypes.c_uint32()
        if not library.GetNumberOfEventLogRecords(handle, ctypes.byref(count)):
            raise ctypes.WinError(ctypes.get_last_error())
        result = {"count": count.value}
        if count.value:
            buffer = ctypes.create_string_buffer(65536)
            used, needed = ctypes.c_uint32(), ctypes.c_uint32()
            if not library.ReadEventLogW(
                handle,
                9,
                0,
                buffer,
                len(buffer),
                ctypes.byref(used),
                ctypes.byref(needed),
            ):
                raise ctypes.WinError(ctypes.get_last_error())
            row = struct.unpack_from("<6I4H6I", buffer.raw)
            result.update(
                event_id=row[5] & 65535,
                entry_type=row[6],
                category=row[8],
                source=ctypes.wstring_at(ctypes.addressof(buffer) + 56),
                message=ctypes.wstring_at(ctypes.addressof(buffer) + row[11]),
                raw_data=binascii.hexlify(
                    buffer.raw[row[15] : row[15] + row[14]]
                ).decode("ascii"),
            )
        return result
    finally:
        library.CloseEventLog(handle)


if __name__ == "__main__":
    print(json.dumps(read_event(sys.argv[1])))
