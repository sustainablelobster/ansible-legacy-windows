# -*- coding: utf-8 -*-
# Copyright 2026 sustainablelobster
# SPDX-License-Identifier: GPL-3.0-or-later

"""Read and rename the local Windows computer through native interfaces."""

import ctypes
import os
import socket
import sys

from legacy_windows_wmi import WmiConnection  # pylint: disable=import-error


def read_hostname():
    """Read the active DNS hostname with the original provider's spelling.

    XP's computer-system provider has no DNSHostName property. On that system,
    the native Winsock hostname supplies the corresponding DNS label instead.

    :returns: Active DNS hostname, retaining its native capitalization.
    :rtype: str
    :raises OSError: The target is not Windows or its native provider fails.
    """
    if os.name != "nt":
        raise OSError("Computer hostname operations require a Windows target.")
    # This standard-library function exists only in Windows builds of Python.
    version = sys.getwindowsversion()  # pylint: disable=no-member
    if version.major == 5 and version.minor == 1:
        return socket.gethostname()
    with WmiConnection() as connection:
        rows = connection.query(
            "SELECT DNSHostName FROM Win32_ComputerSystem", ["DNSHostName"]
        )
    if not rows or not isinstance(rows[0]["DNSHostName"], str):
        raise OSError("WMI returned no Win32_ComputerSystem DNS hostname.")
    return rows[0]["DNSHostName"]


def rename_hostname(name, check_mode=False):
    """Request a new computer name without rebooting the target.

    Check mode mirrors Windows PowerShell 5.1: null and empty names fail
    parameter binding, but nonempty names are not validated by the provider.
    Real operations leave name validation to the local WMI Rename method.

    :param name: Requested name, or None for an explicit null module argument.
    :type name: str or None
    :param bool check_mode: Validate parameter binding without changing names.
    :raises ValueError: The requested name is null or empty.
    :raises OSError: WMI cannot invoke Rename or rejects the requested name.
    """
    if not name:
        raise ValueError(
            "Cannot validate argument on parameter 'NewName'. The argument "
            "is null or empty. Provide an argument that is not null or empty, "
            "and then try the command again."
        )
    if check_mode:
        return
    active = socket.gethostname()
    with WmiConnection() as connection:
        rows = connection.query("SELECT Name FROM Win32_ComputerSystem", ["__PATH"])
        if not rows or not rows[0]["__PATH"]:
            raise OSError("WMI returned no locatable Win32_ComputerSystem instance.")
        result = connection.call_method(
            rows[0]["__PATH"],
            "Rename",
            ["ReturnValue"],
            {"Name": name, "UserName": None, "Password": None},
        )
    code = result["ReturnValue"]
    if code:
        message = ctypes.FormatError(code).rstrip(".\r\n ")
        raise OSError(
            "Fail to rename computer '{0}' to '{1}' due to the following "
            "exception: {2}.".format(active, name, message)
        )
