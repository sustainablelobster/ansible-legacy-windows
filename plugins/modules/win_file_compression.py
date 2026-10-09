#!/usr/bin/python
# -*- coding: utf-8 -*-
# Copyright 2026 Joe Lustri
# SPDX-License-Identifier: GPL-3.0-or-later

"""Manage filesystem compression with native Windows WMI and Python 3.4.4."""

# WANT_JSON

import os

# The action stages these Python 3.4-compatible helpers beside the payload.
import legacy_windows_compression as compression  # pylint: disable=import-error
import legacy_windows_file as filesystem  # pylint: disable=import-error
from legacy_windows_module import (  # pylint: disable=import-error
    as_bool,
    as_path,
    as_string,
    read_arguments,
    run_module,
)

DOCUMENTATION = r"""
---
module: win_file_compression
short_description: Manage compression of Windows files and directories
version_added: '1.0.0'
description:
  - Sets or clears filesystem compression on existing files and directories.
  - Uses Python 3.4.4 and native Windows WMI.
options:
  path:
    description:
      - Literal path to an existing file or directory.
      - The filesystem must support file-based compression, such as NTFS.
    type: path
    required: true
  state:
    description:
      - V(present) enables compression and V(absent) disables it.
    type: str
    choices: [absent, present]
    default: present
  recurse:
    description:
      - Apply a required change to the directory's descendants as well as the directory itself.
      - Has no effect for a file; the module returns a warning when enabled for a file.
    type: bool
    default: false
  force:
    description:
      - With O(recurse=true), check descendants even when the directory already has the requested state.
      - With V(false), an unchanged directory leaves its descendants untouched.
      - Has no effect unless O(path) is a directory and O(recurse=true).
    type: bool
    default: true
attributes:
  check_mode:
    support: full
    description: Reads the current compression state and predicts changes without modifying it.
  diff_mode:
    support: none
notes:
  - Filesystem compression does not create a ZIP archive or change the file's contents.
  - The Windows provider also changes a directory's immediate files when O(recurse=false).
    Recursion controls whether it descends into subdirectories.
  - Recursive changes are not transactional. A failure can leave some entries changed.
  - WMI and the target filesystem must provide the requested operation.
author:
  - Joe Lustri
"""

EXAMPLES = r"""
- name: Enable compression on a file
  sustainablelobster.legacy_windows.win_file_compression:
    path: C:\Application\archive.log

- name: Disable compression throughout a directory tree
  sustainablelobster.legacy_windows.win_file_compression:
    path: C:\Application\logs
    state: absent
    recurse: true

- name: Compress a tree only when the root directory is not compressed
  sustainablelobster.legacy_windows.win_file_compression:
    path: C:\Application\reports
    recurse: true
    force: false
"""

RETURN = r"""
rc:
  description:
    - Return code reported by the compression operation.
    - Zero when the operation succeeds, no change is needed, or check mode predicts a change.
  returned: after argument validation
  type: int
  sample: 0
msg:
  description: Status message corresponding to RV(rc), or the reason an earlier check failed.
  returned: after argument validation
  type: str
  sample: The request was successful.
"""

_MODULE_NAME = "sustainablelobster.legacy_windows.win_file_compression"
_PARAMETERS = ("path", "state", "recurse", "force")
_DIRECTORY = 0x10
_COMPRESSED = 0x800
_RETURN_MESSAGES = {
    0: "The request was successful.",
    2: "Access was denied.",
    8: "An unspecified failure occurred.",
    9: "The name specified was not valid.",
    10: "The object specified already exists.",
    11: "The file system is not NTFS.",
    12: "The platform is not Windows.",
    13: "The drive is not the same.",
    14: "The directory is not empty.",
    15: "There has been a sharing violation.",
    16: "The start file specified was not valid.",
    17: "A privilege required for the operation is not held.",
    21: "A parameter specified is not valid.",
}


def _parameters(arguments):
    if "path" not in arguments:
        raise ValueError("missing required arguments: path")
    state = as_string(arguments.get("state", "present"), "state")
    if state is not None and state.lower() not in ("absent", "present"):
        raise ValueError(
            "value of state must be one of: absent, present. Got no match for: " + state
        )
    recurse = arguments.get("recurse", False)
    force = arguments.get("force", True)
    # Upstream preserves null; its conditions and measured provider calls
    # treat these nullable booleans as false.
    return {
        "path": as_path(arguments["path"], "path"),
        "state": state.lower() if state is not None else None,
        "recurse": False if recurse is None else as_bool(recurse, "recurse"),
        "force": False if force is None else as_bool(force, "force"),
    }


def _descendant_needs_change(path, compressed):
    pending = [path]
    while pending:
        directory = pending.pop()
        for name in os.listdir(directory):
            child = os.path.join(directory, name)
            info = filesystem.file_info(child)
            if info is None:
                raise ValueError("Filesystem entry no longer exists: " + child)
            attributes = info["attributes"]
            if bool(attributes & _COMPRESSED) != compressed:
                return True
            if attributes & _DIRECTORY:
                pending.append(child)
    return False


def _manage(parameters, check_mode=False):
    result = {"changed": False, "rc": 0}
    path = parameters["path"]
    compressed = parameters["state"] == "present"
    recurse = parameters["recurse"]
    try:
        info = filesystem.file_info(path) if path else None
        if info is None:
            raise ValueError("Path to item, {0}, does not exist.".format(path or ""))
        is_directory = bool(info["attributes"] & _DIRECTORY)
        if recurse and not is_directory:
            result["warnings"] = [
                "The recurse option has no effect when path is not a folder."
            ]
        volume = compression.volume_info(path)
        if not volume["supports_compression"]:
            # Preserve the upstream failure message's spelling for parity.
            raise ValueError(
                (
                    "Path, {0}, is not on a filesystemi '{1}' "  # codespell:ignore filesystemi
                    "that supports file based compression."
                ).format(path, volume["filesystem"])
            )
        needs_change = bool(info["attributes"] & _COMPRESSED) != compressed
        if not needs_change and parameters["force"] and recurse and is_directory:
            needs_change = _descendant_needs_change(path, compressed)
        result["changed"] = needs_change
        if needs_change and not check_mode:
            result["rc"] = compression.set_compression(
                path, is_directory, compressed, recurse
            )
        result["msg"] = _RETURN_MESSAGES.get(result["rc"])
        if result["rc"]:
            result["failed"] = True
    except (OSError, ValueError) as error:
        result.update({"failed": True, "msg": str(error)})
    return result


def _execute():
    arguments = read_arguments(_PARAMETERS, _MODULE_NAME)
    parameters = _parameters(arguments)
    check_mode = as_bool(
        arguments.get("_ansible_check_mode", False), "_ansible_check_mode"
    )
    return _manage(parameters, check_mode)


def main():
    """Read Ansible arguments and emit the module's JSON result.

    :raises SystemExit: After reporting success or failure to Ansible.
    """
    run_module(_execute)


if __name__ == "__main__":
    main()
