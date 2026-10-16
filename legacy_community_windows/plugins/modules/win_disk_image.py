#!/usr/bin/python
# -*- coding: utf-8 -*-
# Copyright: (c) 2017, Red Hat, Inc.
# Copyright 2026 sustainablelobster
# SPDX-License-Identifier: GPL-3.0-or-later

"""Manage native virtual-disk attachment without a PowerShell storage dependency."""

# WANT_JSON

import os
import time

# The action stages this native helper next to the standalone target payload.
# pylint: disable=import-error
from legacy_community_windows_disk_image import DiskImage

# pylint: enable=import-error
from legacy_windows_module import (  # pylint: disable=import-error
    as_bool,
    as_string,
    read_arguments,
    run_module,
)

DOCUMENTATION = r"""
module: win_disk_image
short_description: Manage ISO/VHD/VHDX mounts on Windows hosts
description:
     - Manages mount behavior for a specified ISO, VHD, or VHDX image on a Windows host. When C(state) is C(present),
       the image will be mounted under a system-assigned drive letter, which will be returned in the C(mount_paths) value
       of the module result.
     - Requires an installed native virtual-disk provider for the selected image format.
     - VHD support is available through older providers; ISO and VHDX support depend on the installed provider.
options:
  image_path:
    description:
      - Path to an ISO, VHD, or VHDX image on the target Windows host (the file cannot reside on a network share)
    type: str
    required: yes
  state:
    description:
      - Whether the image should be present as a drive-letter mount or not.
    type: str
    choices: [ absent, present ]
    default: present
author:
    - Matt Davis (@nitzmahone)
"""

EXAMPLES = r"""
# Run installer from mounted ISO, then unmount
- name: Ensure an ISO is mounted
  sustainablelobster.legacy_community_windows.win_disk_image:
    image_path: C:\install.iso
    state: present
  register: disk_image_out

- name: Run installer from mounted ISO
  sustainablelobster.legacy_windows.win_package:
    path: '{{ disk_image_out.mount_paths[0] }}setup\setup.exe'
    product_id: 35a4e767-0161-46b0-979f-e61f282fee21
    state: present

- name: Unmount ISO
  sustainablelobster.legacy_community_windows.win_disk_image:
    image_path: C:\install.iso
    state: absent
"""

RETURN = r"""
mount_paths:
    description: A list of filesystem paths mounted from the target image.
    returned: when C(state) is C(present)
    type: list
    sample: [ 'E:\', 'F:\' ]
"""


def _manage(arguments):
    path = as_string(arguments.get("image_path"), "image_path")
    if not path:
        raise ValueError("Missing required argument: image_path")
    state = as_string(arguments.get("state", "present"), "state")
    if state not in ("present", "absent"):
        raise ValueError("state must be present or absent")
    check = as_bool(arguments.get("_ansible_check_mode", False), "_ansible_check_mode")
    if path.startswith("\\\\") and not path.startswith("\\\\?\\"):
        raise ValueError("image_path must identify a local image, not a network share")
    if path.lower().startswith("\\\\?\\unc\\"):
        raise ValueError("image_path must identify a local image, not a network share")
    path = os.path.abspath(path)
    result = {"changed": False}
    with DiskImage(path) as image:
        attached = image.physical_path() is not None
        if state == "absent":
            result["changed"] = attached
            if attached and not check:
                image.detach()
            return result
        if not attached:
            result["changed"] = True
            if check:
                return result
            image.attach()
        for attempt in range(6):
            if image.physical_path() is not None:
                paths = image.mount_paths()
                if paths:
                    result["mount_paths"] = paths
                    return result
            if attempt < 5:
                time.sleep(1)
    result.update(
        failed=True, msg="Unable to retrieve a drive letter from the mounted image"
    )
    return result


def main():
    """Read a WANT_JSON request and return native image state."""
    run_module(
        lambda: _manage(
            read_arguments(
                ("image_path", "state"),
                "sustainablelobster.legacy_community_windows.win_disk_image",
                allow_unknown=True,
            )
        )
    )


if __name__ == "__main__":
    main()
