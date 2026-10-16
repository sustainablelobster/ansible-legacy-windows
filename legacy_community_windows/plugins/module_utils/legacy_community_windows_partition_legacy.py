# -*- coding: utf-8 -*-
# Copyright 2026 sustainablelobster
# SPDX-License-Identifier: GPL-3.0-or-later

"""Use installed DiskPart with native, language-independent state inspection."""

import ctypes
import os
import struct
import subprocess
import tempfile

from legacy_community_windows_disk import Disk  # pylint: disable=import-error
from legacy_community_windows_disk_facts_native import (  # pylint: disable=import-error
    describe_disk,
)
from legacy_windows_owner import ownership_privileges  # pylint: disable=import-error
from legacy_windows_wmi import WmiConnection  # pylint: disable=import-error

_MIB = 1048576
_POINTER = ctypes.c_void_p
_DWORD = ctypes.c_uint32


def _run(commands):
    system = os.environ.get("SystemRoot", r"C:\Windows")
    executable = next(
        (
            path
            for path in (
                os.path.join(system, "Sysnative", "diskpart.exe"),
                os.path.join(system, "System32", "diskpart.exe"),
            )
            if os.path.isfile(path)
        ),
        None,
    )
    if executable is None:
        raise OSError("The installed native DiskPart utility is unavailable.")
    descriptor, filename = tempfile.mkstemp(prefix="legacy-partition-", suffix=".txt")
    try:
        # Every command token is an already validated number, letter, GUID or
        # fixed native verb. No caller text or localized output is interpreted.
        with os.fdopen(descriptor, "w", encoding="ascii", newline="") as script:
            script.write("\r\n".join(commands + ["exit"]) + "\r\n")
        with subprocess.Popen(
            [executable, "/s", filename],
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        ) as child:
            try:
                output, errors = child.communicate(timeout=600)
            except subprocess.TimeoutExpired:
                child.kill()
                child.communicate()
                raise
        if child.returncode:
            raise OSError(
                "DiskPart returned {0}: {1} {2}".format(
                    child.returncode,
                    output.decode("mbcs", "replace"),
                    errors.decode("mbcs", "replace"),
                )
            )
    finally:
        os.remove(filename)


def _volume_kernel():
    kernel = ctypes.WinDLL("kernel32", use_last_error=True)
    kernel.FindFirstVolumeW.argtypes = [ctypes.c_wchar_p, _DWORD]
    kernel.FindFirstVolumeW.restype = _POINTER
    kernel.FindNextVolumeW.argtypes = [_POINTER, ctypes.c_wchar_p, _DWORD]
    kernel.FindNextVolumeW.restype = ctypes.c_int32
    kernel.FindVolumeClose.argtypes = [_POINTER]
    kernel.GetVolumePathNamesForVolumeNameW.argtypes = [
        ctypes.c_wchar_p,
        ctypes.c_wchar_p,
        _DWORD,
        ctypes.POINTER(_DWORD),
    ]
    kernel.GetVolumePathNamesForVolumeNameW.restype = ctypes.c_int32
    return kernel


def _volume_state(path, identity=None):
    # The common disk-handle wrapper also owns volume DeviceIoControl calls.
    # pylint: disable=protected-access
    with Disk(path.rstrip("\\")) as volume:
        if identity is None:
            extents = volume._control(0x560000, output_size=65536)
            count = struct.unpack_from("<I", extents)[0]
            if count != 1:
                return None
            number, offset = struct.unpack_from("<I4xq", extents, 8)
        else:
            number, offset = identity
        attributes = None
        try:
            attributes = struct.unpack("<Q", volume._control(0x560038, output_size=8))[
                0
            ]
        except OSError as error:
            if getattr(error, "winerror", None) not in (1, 21, 50):
                raise
        offline = None
        try:
            volume._control(0x560010)
            offline = True
        except OSError as error:
            status = getattr(error, "winerror", None)
            if status == 31:
                offline = False
            elif status not in (1, 21, 50):
                raise
    # pylint: enable=protected-access
    return {
        "disk_number": number,
        "offset": offset,
        "volume_path": path,
        "offline": offline,
        "read_only": bool(attributes & (1 << 60)) if attributes is not None else None,
        "hidden": bool(attributes & (1 << 62)) if attributes is not None else None,
    }


def _volumes():
    kernel = _volume_kernel()
    name = ctypes.create_unicode_buffer(1024)
    enumeration = kernel.FindFirstVolumeW(name, len(name))
    if enumeration == _POINTER(-1).value:
        if ctypes.get_last_error() == 18:
            return []
        raise ctypes.WinError(ctypes.get_last_error())
    result = []
    try:
        while True:
            path = name.value
            try:
                state = _volume_state(path)
            except OSError as error:
                # An unreadable unrelated removable or protected volume must
                # not hide the selected disk. Missing selected fields remain
                # unknown and are rejected if the request needs those fields.
                if getattr(error, "winerror", None) not in (1, 2, 5, 21, 50):
                    raise
                state = None
            if state is not None:
                mounts, used = ctypes.create_unicode_buffer(32768), _DWORD()
                if not kernel.GetVolumePathNamesForVolumeNameW(
                    path, mounts, len(mounts), ctypes.byref(used)
                ):
                    raise ctypes.WinError(ctypes.get_last_error())
                roots = mounts[: used.value].split("\0")
                state["drive_letter"] = next(
                    (
                        root[0].upper()
                        for root in roots
                        if len(root) == 3 and root[1:] == ":\\"
                    ),
                    None,
                )
                result.append(state)
            if not kernel.FindNextVolumeW(enumeration, name, len(name)):
                if ctypes.get_last_error() != 18:
                    raise ctypes.WinError(ctypes.get_last_error())
                break
    finally:
        kernel.FindVolumeClose(enumeration)
    return result


def _set_offline(part, offline):
    alias = r"\\?\GLOBALROOT\Device\Harddisk{0}\Partition{1}".format(
        part["disk_number"], part["number"]
    )
    # DiskPart refuses to offline a volume that retains drive-letter mounts.
    # The published volume control codes implement the partition operation
    # directly, preserving those mounts for a later online request.
    # pylint: disable=protected-access
    with ownership_privileges(("SeManageVolumePrivilege",)):
        with Disk(alias, writable=True) as volume:
            if offline:
                volume._control(0x90018)  # FSCTL_LOCK_VOLUME.
                volume._control(0x90020)  # FSCTL_DISMOUNT_VOLUME.
            volume._control(0x56C00C if offline else 0x56C008)
    # pylint: enable=protected-access


class LegacyPartitions:
    """Inspect native layouts and apply literal DiskPart operations.

    This backend does not parse human-readable output to decide state.
    """

    def _disks(self):
        with WmiConnection() as connection:
            return connection.query(
                "SELECT * FROM Win32_DiskDrive", ("Index", "DeviceID")
            )

    def partitions(self):
        """Return real partition numbers, layout types, mounts and attributes.

        :returns: Native partition records on local physical disks.
        :rtype: list
        :raises OSError: A required native device or volume query fails.
        """
        result, volumes = [], _volumes()
        for row in self._disks():
            description = describe_disk(row["DeviceID"])
            for entry in description["partitions"]:
                part = dict(
                    entry,
                    disk_number=row["Index"],
                    path=row["DeviceID"],
                    drive_letter=None,
                    read_only=None,
                    offline=None,
                )
                for volume in volumes:
                    if (
                        volume["disk_number"] == row["Index"]
                        and volume["offset"] == entry["offset"]
                    ):
                        part.update(volume)
                        break
                else:
                    # Hidden partitions lose their mount-manager GUID links.
                    # The native disk/partition device alias remains usable,
                    # including for the special offline-state control code.
                    alias = r"\\?\GLOBALROOT\Device\Harddisk{0}\Partition{1}".format(
                        row["Index"], entry["number"]
                    )
                    try:
                        state = _volume_state(alias, (row["Index"], entry["offset"]))
                        part.update(state)
                    except OSError as error:
                        if getattr(error, "winerror", None) not in (1, 2, 5, 21, 50):
                            raise
                part.setdefault("active", False)
                part.setdefault("hidden", bool(part.get("mbr_type", 0) & 0x10))
                if part.get("gpt_type"):
                    part["gpt_type"] = part["gpt_type"].strip("{}").casefold()
                result.append(part)
        return result

    def _description(self, number):
        matches = [row for row in self._disks() if row["Index"] == number]
        if len(matches) != 1:
            raise ValueError("Specified disk does not exist or is not unique.")
        return describe_disk(matches[0]["DeviceID"])

    def disk(self, number):
        """Read layout and the largest aligned free extent on one basic disk.

        :param int number: Local physical disk number.
        :returns: Native layout style and usable free byte count.
        :rtype: dict
        :raises OSError: The native disk driver cannot report its usable size.
        """
        description = self._description(number)
        if description["size"] is None:
            raise OSError("The disk driver cannot report its usable size.")
        end = description["size"] - _MIB
        position, gaps = _MIB, []
        for part in sorted(description["partitions"], key=lambda part: part["offset"]):
            gaps.append(max(0, part["offset"] - position))
            position = max(position, part["offset"] + part["size"])
        gaps.append(max(0, end - position))
        return {
            "style": {"mbr": 1, "gpt": 2}.get(description["layout"]["style"], 0),
            "maximum": max(gaps),
            "number": number,
        }

    def maximum(self, part):
        """Read contiguous growth space without parsing localized CLI output.

        :param dict part: Exact native partition record.
        :returns: Largest aligned contiguous size in bytes.
        :rtype: int
        """
        description = self._description(part["disk_number"])
        following = [
            other["offset"]
            for other in description["partitions"]
            if other["offset"] > part["offset"]
        ]
        end = min(following) if following else description["size"] - _MIB
        return max(part["size"], (end - part["offset"]) // _MIB * _MIB)

    def create(self, disk, options):
        """Create one literal partition on the selected disk.

        :param dict disk: Validated selected basic disk.
        :param dict options: Validated upstream options.
        :raises ValueError: The requested size cannot fit DiskPart's MiB units.
        """
        kind = "extended" if options["mbr_type"] == 5 else "primary"
        command = "create partition " + kind
        if options["size"] != -1:
            mib = options["size"] // _MIB
            if mib == 0:
                raise ValueError(
                    "The installed DiskPart utility requires at least one MiB."
                )
            command += " size=" + str(mib)
        if disk["style"] == 1 and kind != "extended":
            command += " id={0:02x}".format(options["mbr_type"] or 6)
        elif options["gpt_type"]:
            command += " id=" + options["gpt_type"]
        commands = ["select disk " + str(options["disk_number"]), command]
        if options["drive_letter"]:
            commands.append(
                "assign"
                if options["drive_letter"] == "auto"
                else "assign letter=" + options["drive_letter"]
            )
        _run(commands)

    def remove(self, part):
        """Delete only the explicitly selected partition.

        :param dict part: Exact native partition record.
        """
        _run(
            [
                "select disk " + str(part["disk_number"]),
                "select partition " + str(part["number"]),
                "delete partition override",
            ]
        )

    def validate_changes(self, part, changes):
        """Reject unknown attributes and prevent collateral basic-MBR changes.

        :param dict part: Exact native partition record.
        :param dict changes: Differing desired settings.
        :raises ValueError: An attribute cannot be read or changed independently.
        """
        for name in ("read_only", "hidden", "offline"):
            if name in changes and part.get(name) is None:
                raise ValueError(
                    "The installed provider cannot read " + name + " on this partition."
                )
        if "active" in changes and part.get("gpt_type"):
            raise ValueError("active applies only to MBR partitions.")
        if not part.get("gpt_type") and set(changes).intersection(
            ("read_only", "hidden")
        ):
            others = [
                row
                for row in self.partitions()
                if row["disk_number"] == part["disk_number"]
                and row["number"] != part["number"]
            ]
            if others:
                raise ValueError(
                    "The legacy provider applies these MBR attributes to all volumes on the disk."
                )

    def update(self, part, changes):
        """Apply only changed properties and verify them using native queries.

        :param dict part: Exact native partition record.
        :param dict changes: Validated differing settings.
        :raises OSError: Native readback does not match the requested state.
        """
        commands = [
            "select disk " + str(part["disk_number"]),
            "select partition " + str(part["number"]),
        ]
        if "size" in changes:
            difference = changes["size"] - part["size"]
            amount = abs(difference) // _MIB
            commands.append(
                "extend size=" + str(amount)
                if difference > 0
                else "shrink desired={0} minimum={0}".format(amount)
            )
        if "drive_letter" in changes:
            if part["drive_letter"]:
                commands.append("remove letter=" + part["drive_letter"])
            commands.append("assign letter=" + changes["drive_letter"])
        if "active" in changes:
            commands.append("active" if changes["active"] else "inactive")
        for name, attribute in (("read_only", "readonly"), ("hidden", "hidden")):
            if name in changes:
                commands.append(
                    "attributes volume "
                    + ("set " if changes[name] else "clear ")
                    + attribute
                )
        if len(commands) > 2:
            _run(commands)
        if "offline" in changes:
            _set_offline(part, changes["offline"])
        current = next(
            (
                row
                for row in self.partitions()
                if row["disk_number"] == part["disk_number"]
                and row["number"] == part["number"]
            ),
            None,
        )
        if current is None:
            raise OSError(
                "The updated partition was not returned by its native provider."
            )
        for name, wanted in changes.items():
            equal = (
                abs(current[name] - wanted) <= 1049000
                if name == "size"
                else current.get(name) == wanted
            )
            if not equal:
                raise OSError(
                    "The native provider did not apply the requested "
                    + name
                    + " value."
                )
