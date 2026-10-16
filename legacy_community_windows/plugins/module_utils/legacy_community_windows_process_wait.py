# -*- coding: utf-8 -*-
# Copyright 2026 sustainablelobster
# SPDX-License-Identifier: GPL-3.0-or-later

"""Select processes using WMI and wait on native handles without PID resampling."""

import ctypes
import ntpath
import time
from contextlib import ExitStack

# The action explicitly stages this complete native helper closure.
import legacy_windows_account as account  # pylint: disable=import-error
import legacy_windows_regex as matching  # pylint: disable=import-error
from legacy_windows_wmi import WmiConnection  # pylint: disable=import-error


def processes(parameters):
    """Read and filter one process snapshot.

    :param dict parameters: Validated names, pattern, PID and owner selectors.
    :returns: Public name, PID and available owner fields in enumeration order.
    :rtype: list
    :raises OSError: WMI enumeration or requested account resolution fails.
    :raises ValueError: A regular expression or account selector is invalid.
    """
    owner = account.name_to_sid(parameters["owner"]) if parameters["owner"] else None
    names = parameters["process_name_exact"]
    names = {name.casefold() for name in names} if names else None
    owners = {}
    result = []
    with WmiConnection() as connection:
        rows = connection.query(
            "SELECT ProcessId, Name FROM Win32_Process", ["ProcessId", "Name", "__PATH"]
        )
        for row in rows:
            pid = row["ProcessId"]
            name = "Idle" if pid == 0 else ntpath.splitext(row["Name"])[0]
            if parameters["pid"] and parameters["pid"] != pid:
                continue
            if names is not None and name.casefold() not in names:
                continue
            pattern = parameters["process_name_pattern"]
            if pattern and not matching.search(name, pattern):
                continue
            username = None
            try:
                identity = connection.call_method(
                    row["__PATH"], "GetOwner", ["Domain", "User", "ReturnValue"]
                )
                if identity["ReturnValue"] == 0 and identity["User"] is not None:
                    username = (
                        identity["Domain"] + "\\" if identity["Domain"] else ""
                    ) + identity["User"]
            except OSError:
                # Exited or protected processes may not expose an owner, just
                # as Get-Process -IncludeUserName leaves that value unavailable.
                pass
            if owner:
                if not username:
                    continue
                if username not in owners:
                    owners[username] = account.account_name_to_sid(username)
                if owners[username] != owner:
                    continue
            result.append({"name": name, "pid": pid, "owner": username})
    return result


def wait_for_exit(pids, timeout):
    """Wait for only the initial PIDs, retaining handles until completion.

    :param list pids: Process identifiers from the initial matching snapshot.
    :param int timeout: Maximum seconds after opening that snapshot's handles.
    :returns: Whether all initially observed processes have exited.
    :rtype: bool
    :raises OSError: A live process cannot be opened or waited on.
    :raises ValueError: The timeout is negative.
    """
    if not pids:
        return True
    if timeout < 0:
        raise ValueError("timeout must not be negative when waiting for exit")
    # These fixed kernel32 signatures stay beside the lifetime of this wait's
    # process handles, independent of other modules that also open processes.
    # pylint: disable=duplicate-code
    kernel = ctypes.WinDLL("kernel32", use_last_error=True)
    kernel.OpenProcess.argtypes = [ctypes.c_uint32, ctypes.c_int, ctypes.c_uint32]
    kernel.OpenProcess.restype = ctypes.c_void_p
    kernel.CloseHandle.argtypes = [ctypes.c_void_p]
    kernel.CloseHandle.restype = ctypes.c_int
    # pylint: enable=duplicate-code
    kernel.WaitForSingleObject.argtypes = [ctypes.c_void_p, ctypes.c_uint32]
    kernel.WaitForSingleObject.restype = ctypes.c_uint32
    with ExitStack() as cleanup:
        handles = []
        for pid in pids:
            handle = kernel.OpenProcess(0x00100000, False, pid)
            if not handle:
                error = ctypes.get_last_error()
                if error in (87, 1168):
                    continue  # The snapshotted process exited before OpenProcess.
                raise ctypes.WinError(error)
            cleanup.callback(kernel.CloseHandle, handle)
            handles.append(handle)
        deadline = time.monotonic() + timeout
        for handle in handles:
            while True:
                remaining = max(0.0, deadline - time.monotonic())
                milliseconds = min(0xFFFFFFFE, int(remaining * 1000))
                status = kernel.WaitForSingleObject(handle, milliseconds)
                if status == 0:
                    break
                if status == 258:
                    if milliseconds == 0xFFFFFFFE and time.monotonic() < deadline:
                        continue
                    return False
                raise ctypes.WinError(ctypes.get_last_error())
    return True
