# -*- coding: utf-8 -*-
# Copyright 2026 sustainablelobster
# SPDX-License-Identifier: GPL-3.0-or-later

"""Use the native WMI file provider for NTFS compression operations."""

import os

# The action stages this native helper beside the target payload.
from legacy_windows_wmi import WmiConnection  # pylint: disable=import-error


def _quoted(value):
    return "'" + value.replace("\\", "\\\\").replace("'", "\\'") + "'"


def volume_info(path):
    """Read the containing logical drive's filesystem and compression capability.

    :param str path: Literal Windows file or directory path.
    :returns: Filesystem name and ``supports_compression`` boolean.
    :rtype: dict
    :raises OSError: WMI cannot identify the drive or read its properties.
    :raises ValueError: WMI returns an unsupported scalar property type.
    :raises MemoryError: Allocation of a WMI query string fails.
    """
    drive = os.path.splitdrive(os.path.abspath(path))[0]
    properties = ["FileSystem", "SupportsFileBasedCompression"]
    with WmiConnection() as connection:
        rows = connection.query(
            "SELECT {0} FROM Win32_LogicalDisk WHERE DeviceID={1}".format(
                ", ".join(properties), _quoted(drive)
            ),
            properties,
        )
    if not rows:
        raise OSError("WMI returned no logical disk for path {0!r}.".format(path))
    filesystem = rows[0]["FileSystem"]
    supported = rows[0]["SupportsFileBasedCompression"]
    if not isinstance(filesystem, str) or not isinstance(supported, bool):
        raise OSError(
            "WMI did not report the filesystem and compression capability "
            "for path {0!r}.".format(path)
        )
    return {"filesystem": filesystem, "supports_compression": supported}


def set_compression(path, is_directory, compressed, recurse):
    """Invoke the provider's CompressEx or UnCompressEx method on one path.

    :param str path: Literal Windows file or directory path.
    :param bool is_directory: Whether the path names a directory.
    :param bool compressed: Requested compression attribute.
    :param bool recurse: Whether the provider should also process descendants.
    :returns: Unmodified native provider ReturnValue, including nonzero failures.
    :rtype: int
    :raises OSError: WMI cannot locate the item, invoke the method, or read a code.
    :raises ValueError: A WMI property type or method input is not supported.
    :raises MemoryError: Allocation of a WMI string fails.
    """
    full_name = os.path.abspath(path)
    class_name = "Win32_Directory" if is_directory else "CIM_LogicalFile"
    method = "CompressEx" if compressed else "UnCompressEx"
    with WmiConnection() as connection:
        rows = connection.query(
            "SELECT Name FROM {0} WHERE Name={1}".format(
                class_name, _quoted(full_name)
            ),
            ["__PATH"],
        )
        if not rows or not rows[0]["__PATH"]:
            raise OSError(
                "WMI returned no {0} instance for path {1!r}.".format(
                    class_name, full_name
                )
            )
        result = connection.call_method(
            rows[0]["__PATH"], method, ["ReturnValue"], {"Recursive": recurse}
        )["ReturnValue"]
    if not isinstance(result, int) or isinstance(result, bool):
        raise OSError("WMI {0} returned no integer ReturnValue.".format(method))
    return result
