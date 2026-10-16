#!/usr/bin/python
# -*- coding: utf-8 -*-
# Copyright 2019 rnsc (@rnsc) <github@rnsc.be>
# Copyright 2026 sustainablelobster
# SPDX-License-Identifier: GPL-3.0-or-later

"""Manage data deduplication through the installed native Windows provider."""

# WANT_JSON

import re
from contextlib import ExitStack

import legacy_windows_feature_manage as features  # pylint: disable=import-error
import legacy_windows_wmi as wmi  # pylint: disable=import-error
from legacy_windows_module import (  # pylint: disable=import-error
    as_bool,
    as_string,
    read_arguments,
    run_module,
)

DOCUMENTATION = r"""
module: win_data_deduplication
short_description: Module to enable Data Deduplication on a volume.
description:
  - This module can be used to enable Data Deduplication on a Windows volume.
  - The module installs the C(FS-Data-Deduplication) feature when necessary.
options:
  drive_letter:
    description: Windows drive letter on which to enable data deduplication.
    required: true
    type: str
  state:
    description: Whether to enable or disable data deduplication on the selected volume.
    default: present
    type: str
    choices: [present, absent]
  settings:
    description: Settings for the selected deduplication volume.
    type: dict
    suboptions:
      minimum_file_size:
        description:
          - Minimum file size targeted for deduplication, in bytes.
          - Values below 32768 are raised to 32768.
        type: int
        default: 32768
      minimum_file_age_days:
        description: Minimum file age targeted for deduplication.
        type: int
        default: 2
      no_compress:
        description: Whether to disable compression of deduplicated data.
        type: bool
        default: false
      optimize_in_use_files:
        description: Whether the server attempts to optimize currently open files.
        type: bool
        default: false
      verify:
        description: Whether to verify duplicate chunks byte for byte instead of using only their hash.
        type: bool
        default: false
notes:
  - Requires the native Data Deduplication role service and a volume accepted by that provider.
  - Windows without that role service fails with the native capability error; no OS-version allowlist is used.
  - The role service is installed even for I(state=absent), matching the released module.
  - Check mode never installs features or changes a volume. Reading a volume still requires the installed provider.
  - An installation requiring a restart returns C(reboot_required=true) and fails before changing volume settings.
  - Disabling deduplication stops further optimization; it does not expand existing deduplicated files.
author:
  - rnsc (@rnsc)
"""

EXAMPLES = r"""
- name: Enable deduplication on an existing data volume
  sustainablelobster.legacy_community_windows.win_data_deduplication:
    drive_letter: D

- name: Configure deduplication on the data volume
  sustainablelobster.legacy_community_windows.win_data_deduplication:
    drive_letter: D
    settings:
      minimum_file_age_days: 1
      minimum_file_size: 65536
      no_compress: true
"""

RETURN = r"""
# The released module does not declare module-specific return documentation.
"""

_NAMESPACE = r"ROOT\Microsoft\Windows\Deduplication"
_FIELDS = {
    "minimum_file_size": ("MinimumFileSize", 32768),
    "minimum_file_age_days": ("MinimumFileAgeDays", 2),
    "no_compress": ("NoCompress", False),
    "optimize_in_use_files": ("OptimizeInUseFiles", False),
    "verify": ("Verify", False),
}


def _settings(value):
    if value is None:
        return None
    if not isinstance(value, dict):
        raise ValueError("settings must be a dictionary.")
    unknown = set(value).difference(_FIELDS)
    if unknown:
        raise ValueError("Unsupported settings: " + ", ".join(sorted(unknown)))
    result = {}
    for name, (property_name, default) in _FIELDS.items():
        supplied = value.get(name, default)
        if isinstance(default, bool):
            result[property_name] = as_bool(supplied, "settings." + name)
        else:
            if isinstance(supplied, bool):
                raise ValueError("settings." + name + " must be an integer.")
            number = int(supplied)
            if name == "minimum_file_size":
                number = max(number, 32768)
            if not 0 <= number <= 0xFFFFFFFF:
                raise ValueError(
                    "settings." + name + " must fit an unsigned 32-bit value."
                )
            result[property_name] = number
    return result


def _set_settings(connection, object_path, changes):
    # DedupVolume exposes writable properties, not a Set method. Keep the
    # single native instance update here, beside the provider that needs it.
    # pylint: disable=protected-access
    with ExitStack() as cleanup:
        instance = wmi._get_object(
            connection._services, connection._automation, cleanup, object_path
        )
        for name, value in changes.items():
            if isinstance(value, bool):
                wmi._put_boolean(instance, connection._automation, name, value)
            else:
                # WMI represents unsigned CIM integers as decimal BSTRs when
                # their full range cannot fit Automation's signed VT_I4.
                wmi._put_string(instance, connection._automation, name, str(value))
        wmi._update_instance(connection._services, instance)
    # pylint: enable=protected-access


def _volumes(connection):
    properties = ["__PATH", "Volume", "VolumeId", "Enabled"]
    properties.extend(property_name for property_name, _default in _FIELDS.values())
    return connection.query("SELECT * FROM MSFT_DedupVolume", properties)


def _find_volume(connection, volume_id):
    return next(
        (
            row
            for row in _volumes(connection)
            if str(row["VolumeId"]).rstrip("\\").casefold()
            == volume_id.rstrip("\\").casefold()
        ),
        None,
    )


def _change_state(connection, letter, enabled):
    method = "Enable" if enabled else "Disable"
    result = connection.call_method(
        "MSFT_DedupVolume", method, ("ReturnValue",), {"Volume": [letter]}
    )
    if result["ReturnValue"]:
        raise OSError(
            "Data Deduplication {0} returned {1} for {2}.".format(
                method, result["ReturnValue"], letter
            )
        )


def _manage(arguments):
    letter = as_string(arguments.get("drive_letter"), "drive_letter")
    if not letter or not re.match(r"^[A-Za-z]$", letter):
        raise ValueError("drive_letter must be a single letter from A through Z.")
    letter = letter.upper() + ":"
    state = arguments.get("state", "present")
    if state not in ("present", "absent"):
        raise ValueError("state must be present or absent.")
    settings = _settings(arguments.get("settings"))
    preview = as_bool(
        arguments.get("_ansible_check_mode", False), "_ansible_check_mode"
    )
    result = {"changed": False, "reboot_required": False, "msg": ""}
    if not preview:
        installation = features.manage(
            {
                "names": ["FS-Data-Deduplication"],
                "state": "present",
                "include_sub_features": False,
                "include_management_tools": False,
                "source": None,
            },
            False,
        )
        if installation.get("failed") or not installation.get("success", True):
            result.update(installation)
            result["failed"] = True
            return result
        if installation.get("reboot_required"):
            result.update(
                changed=installation.get("changed", False),
                reboot_required=True,
                failed=True,
                msg=(
                    "FS-Data-Deduplication was installed but requires Windows "
                    "to be rebooted to work."
                ),
            )
            return result
    with wmi.WmiConnection() as storage:
        volumes = storage.query(
            "SELECT * FROM Win32_Volume WHERE DriveLetter = '" + letter + "'",
            ("DeviceID",),
        )
        if len(volumes) != 1:
            raise ValueError("No unique local volume has drive letter " + letter)
        volume_id = volumes[0]["DeviceID"]
    with wmi.WmiConnection(_NAMESPACE) as connection:
        current = _find_volume(connection, volume_id)
        enabled = bool(current and current["Enabled"])
        if enabled != (state == "present"):
            if not preview:
                _change_state(connection, letter, state == "present")
                current = _find_volume(connection, volume_id)
            result["changed"] = True
        if state == "present" and settings is not None:
            changes = {
                name: value
                for name, value in settings.items()
                if current is None or current.get(name) != value
            }
            if changes:
                if not preview:
                    if current is None:
                        raise OSError(
                            "The enabled deduplication volume was not returned by its provider."
                        )
                    _set_settings(connection, current["__PATH"], changes)
                result["changed"] = True
    return result


def execute():
    """Bind the released interface and configure the explicitly selected volume.

    :returns: Change, restart and failure information from the native provider.
    :rtype: dict
    """
    return _manage(
        read_arguments(
            ("drive_letter", "state", "settings"),
            "sustainablelobster.legacy_community_windows.win_data_deduplication",
        )
    )


if __name__ == "__main__":
    run_module(execute)
