# -*- coding: utf-8 -*-
# Copyright 2018 Varun Chopra (@chopraaa) <v@chopraaa.com>
# Copyright 2026 sustainablelobster
# SPDX-License-Identifier: GPL-3.0-or-later

"""Validate released partition requests and call the installed native provider."""

import re
from contextlib import ExitStack

from legacy_community_windows_partition_legacy import (  # pylint: disable=import-error
    LegacyPartitions,
)
from legacy_windows_module import as_bool, as_string  # pylint: disable=import-error
from legacy_windows_wmi import WmiConnection  # pylint: disable=import-error

_NAMESPACE = r"ROOT\Microsoft\Windows\Storage"
_TOLERANCE = 1049000
_MBR = {"fat12": 1, "fat16": 4, "extended": 5, "huge": 6, "ifs": 7, "fat32": 12}
_GPT = {
    "system_partition": "c12a7328-f81f-11d2-ba4b-00a0c93ec93b",
    "microsoft_reserved": "e3c9e316-0b5c-4db8-817d-f92df00215ae",
    "basic_data": "ebd0a0a2-b9e5-4433-87c0-68b6b72699c7",
    "microsoft_recovery": "de94bba4-06d1-4d40-a16a-bfd50179d6ac",
}
_ATTRIBUTES = {"read_only": "IsReadOnly", "active": "IsActive", "hidden": "IsHidden"}
_FIELDS = {
    "disk_number": "DiskNumber",
    "number": "PartitionNumber",
    "size": "Size",
    "offset": "Offset",
    "drive_letter": "DriveLetter",
    "offline": "IsOffline",
    "mbr_type": "MbrType",
    "gpt_type": "GptType",
    "read_only": "IsReadOnly",
    "active": "IsActive",
    "hidden": "IsHidden",
    "path": "__PATH",
}


def _size(value):
    if value is None:
        return None
    if str(value) == "-1":
        return -1
    match = re.match(r"\A([0-9]+) *(B|Ki?B|Mi?B|Gi?B|Ti?B)\Z", str(value), re.I)
    if match is None:
        raise ValueError(
            "Invalid partition size. Use B, KB, KiB, MB, MiB, GB, GiB, TB or TiB."
        )
    unit = match.group(2).upper()
    exponent = "BKMGT".index(unit[0])
    size = int(match.group(1)) * (1024 if "I" in unit else 1000) ** exponent
    if not 0 < size < 2**64:
        raise ValueError(
            "partition_size must be a positive unsigned 64-bit byte count."
        )
    return size


def _number(value, name):
    if value is None:
        return None
    if isinstance(value, bool) or not isinstance(value, (int, str)):
        raise ValueError(name + " must be a nonnegative integer.")
    if isinstance(value, str) and not re.match(r"\A[+-]?[0-9]+\Z", value.strip()):
        raise ValueError(name + " must be a nonnegative integer.")
    number = int(value)
    if not 0 <= number <= 2147483647:
        raise ValueError(name + " must be a nonnegative integer.")
    return number


def _options(arguments):
    result = {
        name: _number(arguments.get(name), name)
        for name in ("disk_number", "partition_number")
    }
    if result["partition_number"] == 0:
        raise ValueError("partition_number must be positive.")
    result["drive_letter"] = as_string(arguments.get("drive_letter"), "drive_letter")
    letter = result["drive_letter"]
    if letter is not None:
        if letter.casefold() == "auto":
            result["drive_letter"] = "auto"
        elif re.match(r"\A[A-Za-z]\Z", letter):
            result["drive_letter"] = letter.upper()
        else:
            raise ValueError("drive_letter must be a letter from A-Z or auto.")
    if result["disk_number"] is None and result["drive_letter"] in (None, "auto"):
        raise ValueError("Provide a disk number or an existing drive letter.")
    result["state"] = arguments.get("state", "present")
    if result["state"] not in ("present", "absent"):
        raise ValueError("state must be present or absent.")
    result["size"] = _size(arguments.get("partition_size"))
    for name in ("mbr_type", "gpt_type"):
        value = arguments.get(name)
        choices = _MBR if name == "mbr_type" else _GPT
        if value is not None and value not in choices:
            raise ValueError(name + " must be one of " + ", ".join(sorted(choices)))
        result[name] = choices[value] if value is not None else None
    if result["mbr_type"] is not None and result["gpt_type"] is not None:
        raise ValueError("Cannot specify both GPT and MBR partition styles.")
    for name in ("active", "read_only", "hidden", "offline"):
        value = arguments.get(name)
        result[name] = as_bool(value, name) if value is not None else None
    result["preview"] = as_bool(
        arguments.get("_ansible_check_mode", False), "_ansible_check_mode"
    )
    return result


def _letter(value):
    return (chr(value) if value else None) if isinstance(value, int) else value or None


class StoragePartitions:
    """Use native Storage WMI methods without loading the PowerShell cmdlets.

    :param connection: Owning local Storage WMI connection.
    """

    def __init__(self, connection):
        self.connection = connection

    def partitions(self):
        """Return native partition identifiers and their mutable public state.

        :returns: Partition records with normalized numbers and drive letters.
        :rtype: list
        """
        rows = self.connection.query(
            "SELECT * FROM MSFT_Partition", tuple(_FIELDS.values())
        )
        result = []
        for row in rows:
            part = {name: row[field] for name, field in _FIELDS.items()}
            part["drive_letter"] = _letter(part["drive_letter"])
            part["size"] = int(part["size"])
            if part["gpt_type"]:
                part["gpt_type"] = part["gpt_type"].strip("{}").casefold()
            result.append(part)
        return result

    def disk(self, number):
        """Read exactly one disk and its largest free extent before creation.

        :param int number: Native disk number.
        :returns: Native disk properties used for creation validation.
        :rtype: dict
        :raises ValueError: The disk selector has no unique native match.
        """
        rows = self.connection.query(
            "SELECT * FROM MSFT_Disk WHERE Number = " + str(number),
            ("__PATH", "PartitionStyle", "LargestFreeExtent"),
        )
        if len(rows) != 1:
            raise ValueError("Specified disk does not exist or is not unique.")
        return {
            "path": rows[0]["__PATH"],
            "style": rows[0]["PartitionStyle"],
            "maximum": int(rows[0]["LargestFreeExtent"]),
        }

    def call(self, path, method, inputs=None, outputs=()):
        """Invoke one native operation and preserve a meaningful provider failure.

        :param str path: Exact instance path from the native query.
        :param str method: Published Storage method.
        :param inputs: Optional native input properties.
        :type inputs: dict or None
        :param tuple outputs: Additional requested output properties.
        :returns: Native output properties.
        :rtype: dict
        :raises OSError: The native provider returns a failure status.
        """
        result = self.connection.call_method(
            path, method, ("ReturnValue",) + outputs, inputs
        )
        if result["ReturnValue"]:
            raise OSError(
                "Native partition {0} returned {1}.".format(
                    method, result["ReturnValue"]
                )
            )
        return result

    def maximum(self, part):
        """Read the native maximum supported size of one existing partition.

        :param dict part: Exact selected partition record.
        :returns: Maximum supported byte count.
        :rtype: int
        """
        return int(
            self.call(part["path"], "GetSupportedSize", outputs=("SizeMax",))["SizeMax"]
        )

    def create(self, disk, options):
        """Create one partition on the validated native disk.

        :param dict disk: Validated selected disk.
        :param dict options: Validated public request.
        """
        inputs = {"UseMaximumSize": options["size"] == -1}
        if options["size"] != -1:
            inputs["Size"] = str(options["size"])
        letter = options["drive_letter"]
        if letter == "auto":
            inputs["AssignDriveLetter"] = True
        elif letter:
            inputs["DriveLetter"] = ord(letter)
        for name, field in (("mbr_type", "MbrType"), ("gpt_type", "GptType")):
            if options[name] is not None:
                inputs[field] = options[name]
        self.call(disk["path"], "CreatePartition", inputs)

    def remove(self, part):
        """Delete the selected partition and corresponding volume.

        :param dict part: Exact selected native partition.
        """
        self.call(part["path"], "DeleteObject")

    def update(self, part, changes):
        """Apply the selected resize, mount and attribute operations.

        :param dict part: Exact selected native partition.
        :param dict changes: Only properties whose desired values differ.
        """
        if "size" in changes:
            self.call(part["path"], "Resize", {"Size": str(changes["size"])})
        if "drive_letter" in changes:
            self.call(
                part["path"],
                "AddAccessPath",
                {"AccessPath": changes["drive_letter"] + ":\\"},
            )
            if part["drive_letter"]:
                self.call(
                    part["path"],
                    "RemoveAccessPath",
                    {"AccessPath": part["drive_letter"] + ":\\"},
                )
        if "offline" in changes:
            self.call(part["path"], "Offline" if changes["offline"] else "Online")
        attributes = {
            field: changes[name]
            for name, field in _ATTRIBUTES.items()
            if name in changes
        }
        if attributes:
            self.call(part["path"], "SetAttributes", attributes)

    def validate_changes(self, _part, _changes):
        """Leave installed-provider capability validation to its native methods."""


def _select(partitions, options):
    if options["disk_number"] is not None and options["partition_number"] is not None:
        matches = [
            part
            for part in partitions
            if part["disk_number"] == options["disk_number"]
            and part["number"] == options["partition_number"]
        ]
    elif options["drive_letter"] not in (None, "auto"):
        matches = [
            part
            for part in partitions
            if part["disk_number"] is not None
            and part["drive_letter"] == options["drive_letter"]
        ]
    else:
        matches = []
    if len(matches) > 1:
        raise ValueError("The partition selector is ambiguous.")
    return matches[0] if matches else None


def _changes(provider, part, options):
    for name in ("mbr_type", "gpt_type"):
        if options[name] is not None and options[name] != part.get(name):
            raise ValueError(
                name + " is not a valid parameter for existing partitions."
            )
    changes = {}
    if options["size"] is not None:
        maximum = provider.maximum(part)
        desired = maximum if options["size"] == -1 else options["size"]
        if abs(desired - part["size"]) > _TOLERANCE:
            if part["read_only"]:
                raise ValueError("Unable to resize partition: Partition is read only.")
            changes["size"] = desired
        elif desired > maximum:
            raise ValueError("Specified partition size exceeds the supported size.")
    letter = options["drive_letter"]
    if letter not in (None, "auto", part["drive_letter"]):
        changes["drive_letter"] = letter
    for name in ("read_only", "active", "hidden", "offline"):
        if options[name] is not None and options[name] != part.get(name):
            changes[name] = options[name]
    provider.validate_changes(part, changes)
    return changes


def _manage(provider, options):
    partitions = provider.partitions()
    part = _select(partitions, options)
    if options["state"] == "absent":
        if part and not options["preview"]:
            provider.remove(part)
        return {"changed": bool(part)}
    changed = False
    if part is None:
        if options["disk_number"] is None or options["size"] is None:
            raise ValueError(
                "Creating a partition requires disk_number and partition_size."
            )
        disk = provider.disk(options["disk_number"])
        if disk["style"] not in (1, 2):
            raise ValueError("Initialize the disk before creating partitions.")
        if (options["mbr_type"] is not None and disk["style"] != 1) or (
            options["gpt_type"] is not None and disk["style"] != 2
        ):
            raise ValueError("Incorrect partition style specified.")
        if options["active"] is not None and disk["style"] != 1:
            raise ValueError("active applies only to MBR partitions.")
        if options["size"] != -1 and options["size"] > disk["maximum"]:
            raise ValueError(
                "Partition size is not supported by the disk. Use -1 for maximum size."
            )
        if options["preview"]:
            return {"changed": True}
        # Inserting into a gap can renumber later partitions. Their physical
        # offsets remain stable, so never mistake a renumbered partition for new.
        before = {(item["disk_number"], item["offset"]) for item in partitions}
        provider.create(disk, options)
        created = [
            item
            for item in provider.partitions()
            if item["disk_number"] == options["disk_number"]
            and (item["disk_number"], item["offset"]) not in before
        ]
        if len(created) != 1:
            raise OSError(
                "The newly created partition could not be identified uniquely."
            )
        part = created[0]
        changed = True
        # Creation already selected its size; do not resize the new partition.
        options = dict(options, size=None)
    changes = _changes(provider, part, options)
    if changes and not options["preview"]:
        provider.update(part, changes)
    return {"changed": changed or bool(changes)}


def manage(arguments):
    """Manage one partition through a capability-selected native backend.

    :param dict arguments: Released public options and Ansible check-mode flag.
    :returns: Whether a change occurred or would occur.
    :rtype: dict
    :raises ValueError: Invalid input, ambiguous selection or an unsafe request.
    :raises OSError: The installed provider cannot complete the operation.
    """
    options = _options(arguments)
    with ExitStack() as cleanup:
        try:
            connection = cleanup.enter_context(WmiConnection(_NAMESPACE))
            provider = StoragePartitions(connection)
            provider.partitions()
        except OSError as error:
            if getattr(error, "hresult", None) not in (0x8004100E, 0x80041010):
                raise
            provider = LegacyPartitions()
        return _manage(provider, options)
