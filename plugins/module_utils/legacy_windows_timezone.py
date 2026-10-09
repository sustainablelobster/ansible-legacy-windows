# -*- coding: utf-8 -*-
# Copyright 2026 Joe Lustri
# SPDX-License-Identifier: GPL-3.0-or-later

"""Manage installed Windows timezone IDs."""

import ctypes
import os
import re
import struct
import subprocess
import sys

try:
    import winreg
except ImportError:
    winreg = None

from legacy_windows_environment import values_equal  # pylint: disable=import-error
from legacy_windows_owner import ownership_privileges  # pylint: disable=import-error

# The timestamp helper owns the fixed-width Windows time-record layouts.
from legacy_windows_time import (  # pylint: disable=import-error
    _SystemTime,
    _TimeZoneInformation,
)

_CATALOGUE = r"SOFTWARE\Microsoft\Windows NT\CurrentVersion\Time Zones"


class TimeZoneCommandError(RuntimeError):
    """Report the native utility's failed operation and captured output.

    :param str action: Human-readable operation used by the module failure.
    :param str stdout: Utility output, joined with LF and no final line break.
    :param str stderr: Utility errors, joined with LF and no final line break.
    :param int rc: Nonzero utility exit code.
    """

    def __init__(self, action, stdout, stderr, rc):
        super().__init__("An error occurred when {0}.".format(action))
        self.action = action
        self.stdout = stdout
        self.stderr = stderr
        self.rc = rc


def _tzutil():
    if os.name != "nt":
        raise ValueError("Timezone operations require a Windows target.")
    path = os.path.join(os.environ["SystemRoot"], "System32", "tzutil.exe")
    if os.path.isfile(path):
        return path
    # This standard-library function exists only in the Windows build of Python.
    if sys.getwindowsversion().major >= 6:  # pylint: disable=no-member
        # The legacy setter disables dynamic rules on Vista and newer systems.
        raise OSError(
            "tzutil.exe is required on Windows Vista and later; install the "
            "Windows timezone utility before using win_timezone."
        )
    return None


def _command(tool, action, arguments):
    with subprocess.Popen(
        [tool] + arguments, stdout=subprocess.PIPE, stderr=subprocess.PIPE
    ) as process:
        stdout, stderr = process.communicate()
        rc = process.returncode
    kernel = ctypes.WinDLL("kernel32")
    kernel.GetOEMCP.argtypes = []
    kernel.GetOEMCP.restype = ctypes.c_uint32
    encoding = "cp{0}".format(kernel.GetOEMCP())
    output = "\n".join(stdout.decode(encoding, "replace").splitlines())
    errors = "\n".join(stderr.decode(encoding, "replace").splitlines())
    if rc:
        raise TimeZoneCommandError(action, output, errors, rc)
    return output


def _kernel():
    kernel = ctypes.WinDLL("kernel32", use_last_error=True)
    kernel.GetTimeZoneInformation.argtypes = [ctypes.POINTER(_TimeZoneInformation)]
    kernel.GetTimeZoneInformation.restype = ctypes.c_uint32
    kernel.SetTimeZoneInformation.argtypes = [ctypes.POINTER(_TimeZoneInformation)]
    kernel.SetTimeZoneInformation.restype = ctypes.c_int
    return kernel


def _catalogue():
    entries = {}
    with winreg.OpenKey(
        winreg.HKEY_LOCAL_MACHINE,
        _CATALOGUE,
        0,
        winreg.KEY_READ | winreg.KEY_WOW64_64KEY,
    ) as parent:
        for index in range(winreg.QueryInfoKey(parent)[0]):
            name = winreg.EnumKey(parent, index)
            with winreg.OpenKey(parent, name) as key:
                entries[name] = {
                    field: winreg.QueryValueEx(key, field)[0]
                    for field in ("Std", "Dlt", "TZI")
                }
    return entries


def _native_zone():
    zone = _TimeZoneInformation()
    if _kernel().GetTimeZoneInformation(ctypes.byref(zone)) == 0xFFFFFFFF:
        raise ctypes.WinError(ctypes.get_last_error())
    return zone


def _wide_name(value):
    encoded = value.encode("utf-16-le", "surrogatepass")
    if len(encoded) > 62:
        raise ValueError("Installed timezone names must fit in 31 UTF-16 units.")
    return (ctypes.c_uint16 * 32).from_buffer_copy(encoded.ljust(64, b"\0"))


def _definition(entry, disabled):
    data = entry["TZI"]
    if not isinstance(data, bytes) or len(data) != 44:
        raise ValueError("Installed timezone TZI must contain 44 binary bytes.")
    bias, standard_bias, daylight_bias, standard, daylight = struct.unpack(
        "<lll16s16s", data
    )
    return _TimeZoneInformation(
        bias,
        _wide_name(entry["Std"]),
        _SystemTime() if disabled else _SystemTime.from_buffer_copy(standard),
        standard_bias,
        _wide_name(entry["Dlt"]),
        _SystemTime() if disabled else _SystemTime.from_buffer_copy(daylight),
        daylight_bias,
    )


def get_timezone():
    """Read the current timezone ID, including disabled DST where applicable.

    XP and Server 2003 identify the installed ID by its native standard name
    and bias. They expose recurring rules rather than modern yearly histories.

    :returns: Current canonical timezone ID, possibly suffixed with _dstoff.
    :rtype: str
    :raises TimeZoneCommandError: The native utility cannot read the timezone.
    :raises OSError: Windows cannot read settings or has no matching installed ID.
    :raises ValueError: The target is not Windows or installed data is invalid.
    """
    tool = _tzutil()
    if tool:
        return _command(tool, "getting the current machine's timezone setting", ["/g"])
    zone = _native_zone()
    standard = bytes(zone.standard_name).decode("utf-16-le").split("\0", 1)[0]
    for name, entry in _catalogue().items():
        definition = _definition(entry, False)
        if values_equal(standard, entry["Std"]) and zone.bias == definition.bias:
            disabled = (
                not zone.standard_date.month
                and not zone.daylight_date.month
                and definition.daylight_date.month
            )
            return name + ("_dstoff" if disabled else "")
    raise OSError("The current native timezone has no matching installed ID.")


def available_timezones():
    """Read timezone validation entries supplied by Windows.

    The modern utility lists both display labels and IDs. Returning every
    output line preserves the original module's check-mode validation.
    Legacy systems without the utility return their installed registry IDs.

    :returns: Validation strings in the native catalogue or utility order.
    :rtype: list[str]
    :raises TimeZoneCommandError: The native utility cannot list timezones.
    :raises OSError: Windows cannot read the catalogue or its utility is missing.
    :raises ValueError: The target is not Windows.
    """
    tool = _tzutil()
    if tool:
        return _command(tool, "listing the available timezones", ["/l"]).split("\n")
    return list(_catalogue())


def set_timezone(requested):
    """Set a Windows timezone by ID, with an optional _dstoff suffix.

    Modern Windows uses its installed native utility, retaining dynamic rules.
    XP and Server 2003 use their installed recurring rules and temporarily
    enable the existing system-time privilege, restoring it after the write.

    :param str requested: Installed timezone ID and optional DST-disable suffix.
    :raises TimeZoneCommandError: The native utility cannot apply the request.
    :raises OSError: Windows cannot read settings, enable privileges, or write.
    :raises ValueError: The request is not an installed ID or data is invalid.
    """
    tool = _tzutil()
    if tool:
        # Windows PowerShell's native invocation omits an empty string argument.
        arguments = ["/s", requested] if requested else ["/s"]
        _command(tool, "setting the specified timezone", arguments)
        return
    disabled = requested.lower().endswith("_dstoff")
    name = re.sub("_dstoff$", "", requested, flags=re.IGNORECASE)
    entries = _catalogue()
    matches = [key for key in entries if values_equal(key, name)]
    if not matches:
        raise ValueError("The requested timezone is not an installed timezone ID.")
    zone = _definition(entries[matches[0]], disabled)
    with ownership_privileges(("SeSystemtimePrivilege",)):
        if not _kernel().SetTimeZoneInformation(ctypes.byref(zone)):
            raise ctypes.WinError(ctypes.get_last_error())
