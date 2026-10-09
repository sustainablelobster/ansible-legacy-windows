"""Quiesce only WUA runtime immediately after the owned snapshot rollback."""

# SPDX-License-Identifier: GPL-3.0-or-later

import ctypes
import json
import sys
import time

assert sys.version_info[:3] == (3, 4, 4)
api = ctypes.WinDLL("advapi32", use_last_error=True)
api.OpenSCManagerW.argtypes = [ctypes.c_wchar_p, ctypes.c_wchar_p, ctypes.c_uint32]
api.OpenSCManagerW.restype = ctypes.c_void_p
api.OpenServiceW.argtypes = [ctypes.c_void_p, ctypes.c_wchar_p, ctypes.c_uint32]
api.OpenServiceW.restype = ctypes.c_void_p
# The snapshot recovery script must bind SCM without importing tested code.
# pylint: disable=duplicate-code
api.QueryServiceStatusEx.argtypes = [
    ctypes.c_void_p,
    ctypes.c_int,
    ctypes.c_void_p,
    ctypes.c_uint32,
    ctypes.POINTER(ctypes.c_uint32),
]
api.QueryServiceStatusEx.restype = ctypes.c_int
# pylint: enable=duplicate-code
api.ControlService.argtypes = [ctypes.c_void_p, ctypes.c_uint32, ctypes.c_void_p]
api.ControlService.restype = ctypes.c_int
api.CloseServiceHandle.argtypes = [ctypes.c_void_p]
api.CloseServiceHandle.restype = ctypes.c_int
manager = api.OpenSCManagerW(None, None, 1)
if not manager:
    raise ctypes.WinError(ctypes.get_last_error())
service = None
try:
    service = api.OpenServiceW(manager, "wuauserv", 0x24)
    if not service:
        raise ctypes.WinError(ctypes.get_last_error())

    def _service_status():
        status = (ctypes.c_uint32 * 9)()
        needed = ctypes.c_uint32()
        if not api.QueryServiceStatusEx(
            service, 0, status, ctypes.sizeof(status), ctypes.byref(needed)
        ):
            raise ctypes.WinError(ctypes.get_last_error())
        return {
            name: status[index]
            for index, name in enumerate(
                (
                    "type",
                    "state",
                    "controls",
                    "win32_exit",
                    "service_exit",
                    "checkpoint",
                    "wait_hint",
                    "process_id",
                    "flags",
                )
            )
        }

    before = _service_status()
    print(
        json.dumps(
            {
                "phase": "before_stop",
                "name": "wuauserv",
                "python": list(sys.version_info[:3]),
                "status": before,
            }
        ),
        flush=True,
    )
    if before["state"] != 1:
        control_status = (ctypes.c_uint32 * 7)()
        if before["state"] != 3 and not api.ControlService(service, 1, control_status):
            raise ctypes.WinError(ctypes.get_last_error())
        deadline = time.monotonic() + 20
        while _service_status()["state"] != 1:
            if time.monotonic() >= deadline:
                raise OSError("wuauserv did not reach stopped within twenty seconds.")
            time.sleep(0.1)
    print(
        json.dumps(
            {"phase": "after_stop", "name": "wuauserv", "status": _service_status()}
        ),
        flush=True,
    )
finally:
    if service:
        api.CloseServiceHandle(service)
    api.CloseServiceHandle(manager)
