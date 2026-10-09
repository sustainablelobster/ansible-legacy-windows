# -*- coding: utf-8 -*-
# Copyright 2026 Joe Lustri
# SPDX-License-Identifier: GPL-3.0-or-later

"""Read and update Windows computer description and registration strings."""

try:
    import winreg
except ImportError:
    winreg = None

from legacy_windows_wmi import WmiConnection  # pylint: disable=import-error

_REGISTRATION = r"SOFTWARE\Microsoft\Windows NT\CurrentVersion"


def read_description():
    """Read the operating system's computer description.

    :returns: Description text, or None when the provider reports a null value.
    :rtype: str or None
    :raises OSError: The WMI provider fails or returns no operating system.
    """
    with WmiConnection() as connection:
        rows = connection.query(
            "SELECT Description FROM Win32_OperatingSystem", ["Description"]
        )
    if not rows:
        raise OSError("WMI returned no Win32_OperatingSystem instance.")
    return rows[0]["Description"]


def write_description(value):
    """Update the operating system's computer description.

    :param value: New description, or None to restore a null property.
    :type value: str or None
    :raises OSError: WMI cannot locate or update the operating system instance.
    :raises ValueError: The description is neither a string nor None.
    """
    with WmiConnection() as connection:
        rows = connection.query(
            "SELECT Description FROM Win32_OperatingSystem", ["__PATH"]
        )
        if not rows or not rows[0]["__PATH"]:
            raise OSError("WMI returned no locatable Win32_OperatingSystem instance.")
        connection.set_string_property(rows[0]["__PATH"], "Description", value)


def read_registration(name):
    """Read a registration value from the native 64-bit registry view.

    :param str name: RegisteredOwner or RegisteredOrganization.
    :returns: Stored registration value.
    :rtype: object
    :raises OSError: The registry key or value is inaccessible.
    :raises ValueError: The requested registration value is missing.
    """
    if winreg is None:
        raise OSError("Computer registration requires a Windows target.")
    with winreg.OpenKey(
        winreg.HKEY_LOCAL_MACHINE,
        _REGISTRATION,
        0,
        winreg.KEY_QUERY_VALUE | winreg.KEY_WOW64_64KEY,
    ) as key:
        try:
            return winreg.QueryValueEx(key, name)[0]
        except OSError as error:
            if getattr(error, "winerror", error.errno) != 2:
                raise
            raise ValueError(
                "Unhandled exception while executing module: Property {0} "
                "does not exist at path HKEY_LOCAL_MACHINE\\{1}\\.".format(
                    name, _REGISTRATION
                )
            ) from error


def write_registration(name, value):
    """Write a registration string to the native 64-bit registry view.

    :param str name: RegisteredOwner or RegisteredOrganization.
    :param str value: New registration string.
    :raises OSError: The registry key cannot be opened or written.
    """
    if winreg is None:
        raise OSError("Computer registration requires a Windows target.")
    with winreg.OpenKey(
        winreg.HKEY_LOCAL_MACHINE,
        _REGISTRATION,
        0,
        winreg.KEY_SET_VALUE | winreg.KEY_WOW64_64KEY,
    ) as key:
        winreg.SetValueEx(key, name, 0, winreg.REG_SZ, value)
