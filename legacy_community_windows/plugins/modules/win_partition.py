#!/usr/bin/python
# -*- coding: utf-8 -*-
# Copyright 2018 Varun Chopra (@chopraaa) <v@chopraaa.com>
# Copyright 2026 sustainablelobster
# SPDX-License-Identifier: GPL-3.0-or-later

"""Manage an explicitly selected native disk partition."""

# WANT_JSON

from legacy_community_windows_partition import manage  # pylint: disable=import-error
from legacy_windows_module import (  # pylint: disable=import-error
    read_arguments,
    run_module,
)

DOCUMENTATION = r"""
module: win_partition
short_description: Creates, changes and removes partitions on Windows Server
description:
  - Creates, modifies or deletes a partition on an explicitly selected local disk.
options:
  state:
    description: Whether the partition should exist.
    type: str
    choices: [absent, present]
    default: present
  drive_letter:
    description:
      - Selects an existing partition when disk and partition numbers are not both given.
      - Assigns a letter A-Z to a new partition, or uses C(auto) for automatic assignment.
      - Omit this option to create without assigning a letter.
    type: str
  disk_number:
    description: Disk number, required when creating a partition.
    type: int
  partition_number:
    description: Partition number, used with I(disk_number) to identify an existing partition.
    type: int
  partition_size:
    description:
      - Size in B, KB, KiB, MB, MiB, GB, GiB, TB or TiB, or C(-1) for the largest supported size.
      - Required for creation; optional for modification and deletion.
      - Decimal units use powers of 1000 and binary units use powers of 1024.
    type: str
  read_only:
    description: Whether the selected partition is read only.
    type: bool
  active:
    description: Whether an MBR partition is active and can start the system.
    type: bool
  hidden:
    description: Whether the mount manager should hide the partition.
    type: bool
  offline:
    description:
      - Whether the partition is offline.
      - Assigning a mount point can bring a partition online again.
    type: bool
    required: false
  mbr_type:
    description: MBR partition type for creation, independent of file-system formatting.
    type: str
    choices: [fat12, fat16, extended, huge, ifs, fat32]
  gpt_type:
    description: GPT partition type for creation, independent of file-system formatting.
    type: str
    choices: [system_partition, microsoft_reserved, basic_data, microsoft_recovery]
notes:
  - Uses native Storage WMI methods when available, otherwise installed DiskPart with native layout and volume queries.
  - DiskPart sizes are rounded to whole MiB; the released module's size tolerance is preserved.
  - Shrinking requires the installed provider or utility to support the selected file system.
  - Read-only, hidden and offline state require the corresponding installed volume capability.
  - The Storage provider can reject taking a mounted volume offline with native error C(42014),
    just as the upstream Storage cmdlet does. Remove its access paths separately when the provider requires it.
  - The legacy utility applies read-only and hidden volume attributes to every volume on a basic MBR disk.
    Those changes are rejected when another partition could be affected; other operations remain available.
  - Does not remove drive letters, initialize disks or format file systems.
  - Use a drive letter or disk and partition numbers for idempotence. A disk number alone creates another partition.
  - A native operation can leave partial changes when a later step fails; no automatic rollback is performed.
seealso:
  - module: sustainablelobster.legacy_community_windows.win_initialize_disk
  - module: sustainablelobster.legacy_community_windows.win_format
  - module: sustainablelobster.legacy_community_windows.win_disk_facts
author:
  - Varun Chopra (@chopraaa) <v@chopraaa.com>
"""

EXAMPLES = r"""
- name: Create a five-GiB partition on an initialized disk
  sustainablelobster.legacy_community_windows.win_partition:
    disk_number: 1
    drive_letter: D
    partition_size: 5 GiB

- name: Extend a selected partition to its maximum size
  sustainablelobster.legacy_community_windows.win_partition:
    disk_number: 1
    partition_number: 1
    partition_size: -1

- name: Delete a selected partition
  sustainablelobster.legacy_community_windows.win_partition:
    disk_number: 1
    partition_number: 1
    state: absent
"""

RETURN = r"""
# The released module does not declare module-specific returns.
"""


def execute():
    """Bind the released interface and manage the selected native partition.

    :returns: Whether a native partition change occurred or would occur.
    :rtype: dict
    """
    return manage(
        read_arguments(
            (
                "state",
                "drive_letter",
                "disk_number",
                "partition_number",
                "partition_size",
                "read_only",
                "active",
                "hidden",
                "offline",
                "mbr_type",
                "gpt_type",
            ),
            "sustainablelobster.legacy_community_windows.win_partition",
        )
    )


if __name__ == "__main__":
    run_module(execute)
