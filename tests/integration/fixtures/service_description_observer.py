# -*- coding: utf-8 -*-
# SPDX-License-Identifier: GPL-3.0-or-later

"""Observe service-description query errors without changing configuration."""

import ctypes
import json
import sys


def observe_description(name):
    """Query the native description boundary using actual Python 3.4.4.

    :param str name: Existing service key; no configuration or state is changed.
    :returns: Actual runtime and native probe/allocated-query outcomes.
    :rtype: dict
    :raises AssertionError: The interpreter is not Python 3.4.4.
    :raises OSError: The read-only service handle cannot be opened.
    """
    assert sys.version_info[:3] == (3, 4, 4)
    library = ctypes.WinDLL("advapi32", use_last_error=True)
    pointer, dword = ctypes.c_void_p, ctypes.c_uint32
    library.OpenSCManagerW.argtypes = [ctypes.c_wchar_p, ctypes.c_wchar_p, dword]
    library.OpenSCManagerW.restype = pointer
    library.OpenServiceW.argtypes = [pointer, ctypes.c_wchar_p, dword]
    library.OpenServiceW.restype = pointer
    library.CloseServiceHandle.argtypes = [pointer]
    library.CloseServiceHandle.restype = ctypes.c_int
    library.QueryServiceConfig2W.argtypes = [
        pointer,
        dword,
        pointer,
        dword,
        ctypes.POINTER(dword),
    ]
    library.QueryServiceConfig2W.restype = ctypes.c_int
    manager = library.OpenSCManagerW(None, None, 1)
    if not manager:
        raise ctypes.WinError(ctypes.get_last_error())
    service = None
    try:
        service = library.OpenServiceW(manager, name, 1)
        if not service:
            raise ctypes.WinError(ctypes.get_last_error())
        needed = dword()
        probe = library.QueryServiceConfig2W(service, 1, None, 0, ctypes.byref(needed))
        probe_error = 0 if probe else ctypes.get_last_error()
        memory = ctypes.create_string_buffer(max(needed.value, 4096))
        query = library.QueryServiceConfig2W(
            service, 1, memory, len(memory), ctypes.byref(needed)
        )
        return {
            "python": list(sys.version_info[:3]),
            "probe_error": probe_error,
            "query_error": 0 if query else ctypes.get_last_error(),
            "needed": needed.value,
        }
    finally:
        if service:
            library.CloseServiceHandle(service)
        library.CloseServiceHandle(manager)


if __name__ == "__main__":
    print(json.dumps(observe_description(sys.argv[1])))
