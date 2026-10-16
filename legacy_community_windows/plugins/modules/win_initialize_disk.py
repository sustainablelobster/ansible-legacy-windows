#!/usr/bin/python
# -*- coding: utf-8 -*-
# Copyright: (c) 2019, Brant Evans <bevans@redhat.com>
# Copyright 2026 sustainablelobster
# SPDX-License-Identifier: GPL-3.0-or-later

"""Initialize exactly one selected disk while preserving existing layouts by default."""

# WANT_JSON

import re

# The action stages the native disk helper next to the target payload.
# pylint: disable=import-error
from legacy_community_windows_disk import Disk, select_disk

# pylint: enable=import-error
from legacy_windows_module import (  # pylint: disable=import-error
    as_bool,
    as_string,
    read_arguments,
    run_module,
)

DOCUMENTATION = """
---
module: win_initialize_disk
short_description: Initializes disks on Windows Server
description:
    - "The M(sustainablelobster.legacy_community_windows.win_initialize_disk) module initializes disks"
options:
    disk_number:
        description:
            - Used to specify the disk number of the disk to be initialized.
        type: int
    uniqueid:
        description:
            - Used to specify the uniqueid of the disk to be initialized.
        type: str
    path:
        description:
            - Used to specify the path to the disk to be initialized.
        type: str
    style:
        description:
            - The partition style to use for the disk. Valid options are mbr or gpt.
        type: str
        choices: [ gpt, mbr ]
        default: gpt
    online:
        description:
            - If the disk is offline and/or readonly update the disk to be online and not readonly.
        type: bool
        default: true
    force:
        description:
            - Specify if initializing should be forced for disks that are already initialized.
        type: bool
        default: no

notes:
    - One of three parameters (I(disk_number), I(uniqueid), and I(path)) are mandatory to identify the target disk, but
      more than one cannot be specified at the same time.
    - Requires the installed native disk-management API and permission to change the selected disk.
    - Without the modern storage provider, I(path) selects a physical-device path and I(uniqueid) selects the MBR signature or GPT disk GUID.
    - Existing initialized disks are not reinitialized merely because they were offline; bringing them online preserves their partition table.
    - A forced clear reports a change even when I(online=false) leaves the disk uninitialized.
    - This module is idempotent if I(force) is not specified.

seealso:
    - module: sustainablelobster.legacy_community_windows.win_disk_facts
    - module: sustainablelobster.legacy_community_windows.win_partition
    - module: sustainablelobster.legacy_community_windows.win_format

author:
    - Brant Evans (@branic)
"""

EXAMPLES = """
- name: Initialize a disk
  sustainablelobster.legacy_community_windows.win_initialize_disk:
    disk_number: 1

- name: Initialize a disk with an MBR partition style
  sustainablelobster.legacy_community_windows.win_initialize_disk:
    disk_number: 1
    style: mbr

- name: Forcefully initialize a disk
  sustainablelobster.legacy_community_windows.win_initialize_disk:
    disk_number: 2
    force: true
"""

RETURN = """
#
"""


def _arguments(arguments):
    selectors = {
        name: arguments[name]
        for name in ("disk_number", "uniqueid", "path")
        if arguments.get(name) is not None
    }
    if len(selectors) != 1:
        raise ValueError("Exactly one of disk_number, uniqueid and path is required")
    if "disk_number" in selectors:
        value = selectors["disk_number"]
        if isinstance(value, bool) or not isinstance(value, (int, str)):
            raise ValueError("disk_number must be a nonnegative integer")
        if isinstance(value, str) and not re.match(r"\A[+-]?[0-9]+\Z", value.strip()):
            raise ValueError("disk_number must be a nonnegative integer")
        try:
            number = int(value)
        except (ValueError, TypeError, OverflowError) as error:
            raise ValueError("disk_number must be a nonnegative integer") from error
        if not 0 <= number <= 2147483647:
            raise ValueError("disk_number must be a nonnegative integer")
        selectors["disk_number"] = number
    else:
        name = next(iter(selectors))
        selectors[name] = as_string(selectors[name], name)
        if not selectors[name]:
            raise ValueError(name + " must not be empty")
    style = as_string(arguments.get("style", "gpt"), "style")
    if style not in ("gpt", "mbr"):
        raise ValueError("style must be gpt or mbr")
    return (
        selectors,
        style,
        {
            name: as_bool(arguments.get(name, default), name)
            for name, default in (
                ("online", True),
                ("force", False),
                ("_ansible_check_mode", False),
            )
        },
    )


def _manage(arguments):
    selectors, style, options = _arguments(arguments)
    path = select_disk(selectors)
    with Disk(path) as disk:
        layout = disk.read_layout()
    if layout["style"] not in ("mbr", "gpt", "raw"):
        raise ValueError("The disk provider returned an unrecognized partition style")
    if layout["style"] not in ("raw", style) and not options["force"]:
        raise ValueError("force must be true to change the current partition style")
    attributes = layout["attributes"] or 0
    clear = options["force"] and layout["style"] != "raw"
    initialize = layout["style"] == "raw" or (clear and options["online"])
    if (clear or initialize) and attributes & 2 and not options["online"]:
        raise ValueError("Unable to initialize disk as it is read-only")
    online = bool(attributes & 3 and options["online"])
    if initialize and attributes & 1 and not options["online"]:
        # The released interface predicts initialization but leaves an offline
        # disk untouched when the caller explicitly disables bringing it online.
        return {"changed": True}
    changed = clear or initialize or online
    if not changed or options["_ansible_check_mode"]:
        return {"changed": changed}
    with Disk(path, writable=True) as disk:
        if online:
            disk.bring_online()
        if clear:
            disk.clear()
        if initialize:
            disk.initialize(style)
    return {"changed": True}


def main():
    """Read the disk-selection interface and report native layout changes."""
    run_module(
        lambda: _manage(
            read_arguments(
                ("disk_number", "uniqueid", "path", "style", "online", "force"),
                "sustainablelobster.legacy_community_windows.win_initialize_disk",
            )
        )
    )


if __name__ == "__main__":
    main()
