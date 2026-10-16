#!/usr/bin/python
# -*- coding: utf-8 -*-
# Copyright: (c) 2019, Varun Chopra (@chopraaa) <v@chopraaa.com>
# Copyright 2026 sustainablelobster
# SPDX-License-Identifier: GPL-3.0-or-later

"""Format one explicitly selected local volume through its native WMI provider."""

# WANT_JSON

import re

from legacy_windows_module import (  # pylint: disable=import-error
    as_bool,
    as_string,
    read_arguments,
    run_module,
)
from legacy_windows_wmi import WmiConnection  # pylint: disable=import-error

DOCUMENTATION = r"""
module: win_format
short_description: Formats an existing volume or a new volume on an existing partition on Windows
description:
  - The M(sustainablelobster.legacy_community_windows.win_format) module formats an existing volume or a new volume on an existing partition on Windows
options:
  drive_letter:
    description:
      - Used to specify the drive letter of the volume to be formatted.
    type: str
  path:
    description:
      - Used to specify the path to the volume to be formatted.
    type: str
  label:
    description:
      - Used to specify the label of the volume to be formatted.
    type: str
  new_label:
    description:
      - Used to specify the new file system label of the formatted volume.
    type: str
  file_system:
    description:
      - Used to specify the file system to be used when formatting the target volume.
    type: str
    choices: [ ntfs, refs, exfat, fat32, fat ]
  allocation_unit_size:
    description:
      - Specifies the cluster size to use when formatting the volume.
      - If no cluster size is specified when you format a partition, defaults are selected based on
        the size of the partition.
      - This value must be a multiple of the physical sector size of the disk.
    type: int
  large_frs:
    description:
      - Specifies that large File Record System (FRS) should be used.
    type: bool
  compress:
    description:
      - Enable compression on the resulting NTFS volume.
      - NTFS compression is not supported where I(allocation_unit_size) is more than 4096.
    type: bool
  integrity_streams:
    description:
      - Enable integrity streams on the resulting ReFS volume.
    type: bool
  full:
    description:
      - A full format writes to every sector of the disk, takes much longer to perform than the
        default (quick) format, and is not recommended on storage that is thinly provisioned.
      - Specify C(true) for full format.
    type: bool
    default: no
  force:
    description:
      - Specify if formatting should be forced for volumes that are not created from new partitions
        or if the source and target file system are different.
    type: bool
    default: no
notes:
  - Requires an installed native volume-formatting provider and permission to format the selected volume.
  - Large file records and integrity-stream settings require the modern storage provider.
  - Changing I(new_label) reformats the volume rather than renaming it, matching the released module.
  - One of three parameters (I(drive_letter), I(path) and I(label)) are mandatory to identify the target
    volume but more than one cannot be specified at the same time.
  - This module is idempotent if I(force) is not specified and file system labels remain preserved.
  - For more information, see U(https://learn.microsoft.com/en-us/windows-hardware/drivers/storage/format-msft-volume)
seealso:
  - module: sustainablelobster.legacy_community_windows.win_disk_facts
  - module: sustainablelobster.legacy_community_windows.win_partition
author:
  - Varun Chopra (@chopraaa) <v@chopraaa.com>
"""

EXAMPLES = r"""
- name: Create a partition with drive letter D and size 5 GiB
  sustainablelobster.legacy_community_windows.win_partition:
    drive_letter: D
    partition_size: 5 GiB
    disk_number: 1

- name: Full format the newly created partition as NTFS and label it
  sustainablelobster.legacy_community_windows.win_format:
    drive_letter: D
    file_system: NTFS
    new_label: Formatted
    full: true
"""

RETURN = r"""
#
"""


_VOLUME_PROPERTIES = (
    "__PATH",
    "DeviceID",
    "DriveLetter",
    "Label",
    "FileSystem",
    "Capacity",
    "BlockSize",
)
_STORAGE_NAMESPACE = "ROOT\\Microsoft\\Windows\\Storage"


def _arguments(arguments):
    selectors = {
        name: as_string(arguments.get(name), name)
        for name in ("drive_letter", "path", "label")
        if arguments.get(name) is not None
    }
    if len(selectors) != 1:
        raise ValueError("Exactly one of drive_letter, path and label is required")
    if "drive_letter" in selectors and not re.match(
        r"^[A-Za-z]$", selectors["drive_letter"]
    ):
        raise ValueError("drive_letter must be a single character A-Z")
    options = {
        name: as_bool(arguments.get(name, False), name)
        for name in ("full", "force", "_ansible_check_mode")
    }
    for name in ("large_frs", "compress", "integrity_streams"):
        options[name] = (
            as_bool(arguments[name], name) if arguments.get(name) is not None else None
        )
    options["new_label"] = as_string(arguments.get("new_label"), "new_label")
    system = as_string(arguments.get("file_system"), "file_system")
    if system is not None:
        system = system.lower()
        if system not in ("ntfs", "refs", "exfat", "fat32", "fat"):
            raise ValueError("file_system must be ntfs, refs, exfat, fat32 or fat")
    options["file_system"] = system
    size = arguments.get("allocation_unit_size")
    if size is not None:
        try:
            size = int(size)
        except (ValueError, TypeError, OverflowError) as error:
            raise ValueError(
                "allocation_unit_size must be a positive integer"
            ) from error
        if not 0 < size <= 0xFFFFFFFF:
            raise ValueError("allocation_unit_size must be a positive 32-bit integer")
    options["allocation_unit_size"] = size
    if options["integrity_streams"] and system != "refs":
        raise ValueError("Integrity streams can be enabled only on ReFS volumes")
    if options["compress"]:
        if system != "ntfs":
            raise ValueError("Compression can be enabled only on NTFS volumes")
        if size is not None and size > 4096:
            raise ValueError(
                "NTFS compression is not supported above 4096 bytes per allocation unit"
            )
    return selectors, options


def _select_volume(connection, selectors):
    name, expected = next(iter(selectors.items()))
    rows = connection.query(
        "SELECT " + ",".join(_VOLUME_PROPERTIES[1:]) + " FROM Win32_Volume",
        _VOLUME_PROPERTIES,
    )
    field = {"drive_letter": "DriveLetter", "path": "DeviceID", "label": "Label"}[name]
    if name == "drive_letter":
        expected += ":"
    matches = [
        row
        for row in rows
        if str(row.get(field) or "").casefold() == expected.casefold()
    ]
    if not matches:
        raise ValueError("No local volume matched " + name + "=" + expected)
    if len(matches) != 1:
        raise ValueError("More than one local volume matched " + name + "=" + expected)
    return matches[0]


def _needs_format(volume, options):
    if options["force"]:
        return True
    current_size = int(volume["BlockSize"] or 0)
    requested_size = options["allocation_unit_size"]
    if requested_size is not None and current_size and requested_size != current_size:
        raise ValueError(
            "force must be true to change the current allocation unit size"
        )
    system = volume["FileSystem"]
    if (
        options["file_system"]
        and system
        and options["file_system"].casefold() != system.casefold()
    ):
        raise ValueError("force must be true to change the current file system")
    return not int(volume["Capacity"] or 0) or (
        options["new_label"] is not None
        and options["new_label"].casefold() != (volume["Label"] or "").casefold()
    )


def _format_modern(volume, options):
    try:
        with WmiConnection(_STORAGE_NAMESPACE) as connection:
            rows = connection.query("SELECT Path FROM MSFT_Volume", ("__PATH", "Path"))
            matches = [
                row
                for row in rows
                if row["Path"].casefold() == volume["DeviceID"].casefold()
            ]
            if len(matches) != 1:
                raise ValueError(
                    "Modern storage provider did not uniquely identify the selected volume"
                )
            inputs = {"Full": options["full"]}
            for source, target in (
                ("new_label", "FileSystemLabel"),
                ("file_system", "FileSystem"),
                ("large_frs", "UseLargeFRS"),
                ("compress", "Compress"),
                ("integrity_streams", "SetIntegrityStreams"),
            ):
                if options[source] is not None:
                    inputs[target] = options[source]
            if options["allocation_unit_size"] is not None:
                inputs["AllocationUnitSize"] = str(options["allocation_unit_size"])
            response = connection.call_method(
                matches[0]["__PATH"],
                "Format",
                ("ReturnValue", "ExtendedStatus"),
                inputs,
            )
            if response["ReturnValue"]:
                raise OSError(
                    "MSFT_Volume.Format failed with status {0}: {1}".format(
                        response["ReturnValue"], response["ExtendedStatus"]
                    )
                )
        return True
    except OSError as error:
        if getattr(error, "hresult", None) in (0x8004100E, 0x80041010):
            return False
        raise


def _format_legacy(connection, volume, options):
    if options["large_frs"] or options["integrity_streams"]:
        raise ValueError(
            "The installed legacy volume provider cannot set large_frs or integrity_streams"
        )
    inputs = {"QuickFormat": not options["full"]}
    for source, target in (
        ("new_label", "Label"),
        ("file_system", "FileSystem"),
        ("compress", "EnableCompression"),
    ):
        if options[source] is not None:
            inputs[target] = options[source]
    if options["allocation_unit_size"] is not None:
        inputs["ClusterSize"] = str(options["allocation_unit_size"])
    response = connection.call_method(
        volume["__PATH"], "Format", ("ReturnValue",), inputs
    )
    if response["ReturnValue"]:
        raise OSError(
            "Win32_Volume.Format failed with status " + str(response["ReturnValue"])
        )


def _manage(arguments):
    selectors, options = _arguments(arguments)
    with WmiConnection() as connection:
        volume = _select_volume(connection, selectors)
        if not _needs_format(volume, options):
            return {"changed": False}
        if options["new_label"] is None and not options["force"]:
            options["new_label"] = volume["Label"] or ""
        if not options["_ansible_check_mode"]:
            if not _format_modern(volume, options):
                _format_legacy(connection, volume, options)
    return {"changed": True}


def main():
    """Validate the public formatting interface and report native changes."""
    run_module(
        lambda: _manage(
            read_arguments(
                (
                    "drive_letter",
                    "path",
                    "label",
                    "new_label",
                    "file_system",
                    "allocation_unit_size",
                    "large_frs",
                    "full",
                    "compress",
                    "integrity_streams",
                    "force",
                ),
                "sustainablelobster.legacy_community_windows.win_format",
                allow_unknown=True,
            )
        )
    )


if __name__ == "__main__":
    main()
