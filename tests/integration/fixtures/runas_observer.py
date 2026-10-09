"""Observe the actual worker SID, binary input and process environment."""

# SPDX-License-Identifier: GPL-3.0-or-later

import base64
import ctypes
import json
import os
import sys


def main():
    """Query the current process token without creating or changing a token."""
    assert sys.version_info[:3] == (3, 4, 4)
    kernel = ctypes.WinDLL("kernel32", use_last_error=True)
    security = ctypes.WinDLL("advapi32", use_last_error=True)
    kernel.GetCurrentProcess.restype = ctypes.c_void_p
    kernel.CloseHandle.argtypes = [ctypes.c_void_p]
    kernel.CloseHandle.restype = ctypes.c_int
    kernel.LocalFree.argtypes = [ctypes.c_void_p]
    kernel.LocalFree.restype = ctypes.c_void_p
    # Verify worker identity independently of the production token helper.
    # pylint: disable=duplicate-code
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
    security.ConvertSidToStringSidW.argtypes = [
        ctypes.c_void_p,
        ctypes.POINTER(ctypes.c_void_p),
    ]
    security.ConvertSidToStringSidW.restype = ctypes.c_int
    # pylint: enable=duplicate-code
    token, sid_text = ctypes.c_void_p(), ctypes.c_void_p()
    try:
        assert security.OpenProcessToken(
            kernel.GetCurrentProcess(), 8, ctypes.byref(token)
        )
        needed = ctypes.c_uint32()
        assert not security.GetTokenInformation(token, 1, None, 0, ctypes.byref(needed))
        assert ctypes.get_last_error() == 122 and needed.value
        information = ctypes.create_string_buffer(needed.value)
        assert security.GetTokenInformation(
            token, 1, information, needed.value, ctypes.byref(needed)
        )
        sid = ctypes.c_void_p.from_buffer(information)
        assert security.ConvertSidToStringSidW(sid, ctypes.byref(sid_text))
        body = base64.b64decode(sys.argv[1])
        print(
            json.dumps(
                {
                    "sid": ctypes.wstring_at(sid_text),
                    "body_base64": base64.b64encode(body).decode("ascii"),
                    "python": list(sys.version_info[:3]),
                    "environment": os.environ.get("LEGACY_WINDOWS_RUNAS_TEST"),
                },
                sort_keys=True,
            )
        )
    finally:
        if sid_text:
            kernel.LocalFree(sid_text)
        if token:
            assert kernel.CloseHandle(token)


if __name__ == "__main__":
    main()
