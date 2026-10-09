# -*- coding: utf-8 -*-
# Copyright 2021 Ansible Project
# Copyright 2026 Joe Lustri
# SPDX-License-Identifier: GPL-3.0-or-later
# Derived from ansible.windows 3.8.0; modified by Joe Lustri on 2026-10-09.

"""Run native reboot commands and boot/readiness observations on Python 3.4.4."""

import base64
import ctypes
import datetime
import os
import subprocess
import sys

try:
    import winreg
except ImportError:
    winreg = None

import legacy_windows_boot as boot  # pylint: disable=import-error
from legacy_windows_process import run_command  # pylint: disable=import-error

_LOGON_KEY = r"SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon\AutoLogonChecked"
_AUTO_START_EVENT = r"Global\SC_AutoStartComplete"
DEFAULT_BOOT_COMMAND = (
    "(Get-CimInstance -ClassName Win32_OperatingSystem -Property LastBootUpTime)"
    ".LastBootUpTime.ToFileTime()"
)


def _command(arguments):
    result = run_command(
        arguments[0],
        subprocess.list2cmdline(arguments),
        {"chdir": None, "stdin": None, "output_encoding_override": None},
    )
    return {
        "rc": result["rc"],
        "stdout": result.get("stdout", "").strip(),
        "stderr": result.get("stderr", result.get("msg", "")).strip(),
    }


def _powershell(command):
    # Only explicitly supplied command interfaces invoke PowerShell. Native
    # default boot, shutdown and logon-readiness operations never require it.
    script = command + (
        "; If (-not $?) { If (Get-Variable LASTEXITCODE -ErrorAction SilentlyContinue)"
        " { exit $LASTEXITCODE } Else { exit 1 } }"
    )
    encoded = base64.b64encode(script.encode("utf-16-le")).decode("ascii")
    # These are fixed engine flags for an explicitly requested PowerShell command.
    # pylint: disable=duplicate-code
    return _command(
        [
            "powershell.exe",
            "-NoProfile",
            "-NonInteractive",
            "-ExecutionPolicy",
            "Unrestricted",
            "-EncodedCommand",
            encoded,
        ]
    )
    # pylint: enable=duplicate-code


def _uses_legacy_readiness():
    # Linux's developer interpreter does not expose this Windows-only API.
    version = sys.getwindowsversion()  # pylint: disable=no-member
    return version.major == 5 and version.minor in (1, 2)


def _auto_start_complete():
    kernel = ctypes.WinDLL("kernel32", use_last_error=True)
    kernel.OpenEventW.argtypes = [ctypes.c_uint32, ctypes.c_int, ctypes.c_wchar_p]
    kernel.OpenEventW.restype = ctypes.c_void_p
    kernel.WaitForSingleObject.argtypes = [ctypes.c_void_p, ctypes.c_uint32]
    kernel.WaitForSingleObject.restype = ctypes.c_uint32
    kernel.CloseHandle.argtypes = [ctypes.c_void_p]
    kernel.CloseHandle.restype = ctypes.c_int
    # This SCM-owned, boot-scoped event is observed with SYNCHRONIZE only.
    # Never create/reset it: doing so could falsify Windows' startup signal.
    handle = kernel.OpenEventW(0x00100000, False, _AUTO_START_EVENT)
    if not handle:
        raise OSError(
            "Cannot open SCM startup-completion event {0}: {1}".format(
                _AUTO_START_EVENT, ctypes.WinError(ctypes.get_last_error())
            )
        )
    try:
        state = kernel.WaitForSingleObject(handle, 0)
        if state == 0:
            return True
        if state == 258:
            return False
        if state == 0xFFFFFFFF:
            raise OSError(
                "Cannot read SCM startup-completion event {0}: {1}".format(
                    _AUTO_START_EVENT, ctypes.WinError(ctypes.get_last_error())
                )
            )
        raise OSError("Unexpected SCM startup event wait result: {0}".format(state))
    finally:
        if not kernel.CloseHandle(handle):
            raise OSError(
                "Cannot close SCM startup-completion event handle: {0}".format(
                    ctypes.WinError(ctypes.get_last_error())
                )
            )


def observe_boot(command=None):
    """Return the original boot-command string without a default PowerShell call.

    :param str command: Optional explicitly supplied PowerShell boot command.
    :returns: Exit code and complete trimmed command streams.
    :rtype: dict
    :raises OSError: Native WMI cannot read the operating-system boot time.
    :raises ValueError: WMI returns an invalid boot timestamp.
    """
    if command and command != DEFAULT_BOOT_COMMAND:
        return _powershell(command)
    delta = boot.last_boot_time() - datetime.datetime(1601, 1, 1)
    ticks = (delta.days * 86400 + delta.seconds) * 10000000 + delta.microseconds * 10
    return {"rc": 0, "stdout": str(ticks), "stderr": ""}


def request_reboot(delay, message, default_readiness):
    """Schedule a native reboot, removing the modern logon marker if requested.

    :param float delay: Seconds until reboot; the controller enforces two or more.
    :param str message: Shutdown message passed as one native argument.
    :param bool default_readiness: Whether the built-in readiness check is used.
    :returns: Native shutdown exit code and complete trimmed streams.
    :rtype: dict
    :raises OSError: Communication with the native shutdown process fails.
    :raises ValueError: The delay cannot be converted to an integer.
    :raises TypeError: The delay is not numeric.
    :raises OverflowError: The delay is infinite.
    """
    # The original formats its timeout before sending any marker-removal or
    # shutdown command; conversion failures must likewise happen before writes.
    timeout = int(delay)
    if default_readiness and not _uses_legacy_readiness():
        try:
            winreg.DeleteKey(winreg.HKEY_LOCAL_MACHINE, _LOGON_KEY)
        except OSError:
            # The original marker removal uses ErrorAction SilentlyContinue.
            pass
    shutdown = os.path.join(os.environ["SystemRoot"], "System32", "shutdown.exe")
    return _command([shutdown, "/r", "/t", str(timeout), "/c", message])


def abort_reboot():
    """Abort a previously scheduled native shutdown.

    :returns: Native shutdown exit code and complete trimmed streams.
    :rtype: dict
    :raises OSError: Communication with the native shutdown process fails.
    """
    shutdown = os.path.join(os.environ["SystemRoot"], "System32", "shutdown.exe")
    return _command([shutdown, "/a"])


def observe_readiness(command=None, expected=None):
    """Check a custom command or the operating system's native startup signal.

    XP/Server 2003 use SCM automatic-service/driver startup completion. This
    does not establish that GINA has displayed its logon prompt or completed
    pre-login configuration. Newer Windows retain the original LogonUI key.

    :param str command: Optional explicitly supplied PowerShell test command.
    :param str expected: Controller-generated success marker for the native check.
    :returns: Exit code and complete trimmed command streams.
    :rtype: dict
    Missing, unsignaled or unreadable signals return failure for controller retry.

    :raises OSError: Communication with an explicit custom command fails.
    """
    if command:
        return _powershell(command)
    try:
        if _uses_legacy_readiness():
            if not _auto_start_complete():
                return {
                    "rc": 1,
                    "stdout": "",
                    "stderr": "SCM has not completed automatic service/driver startup "
                    "({0}).".format(_AUTO_START_EVENT),
                }
            return {"rc": 0, "stdout": expected, "stderr": ""}
        with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, _LOGON_KEY):
            return {"rc": 0, "stdout": expected, "stderr": ""}
    except OSError as error:
        return {"rc": 1, "stdout": "", "stderr": str(error)}
