#!/usr/bin/python
# -*- coding: utf-8 -*-
# Copyright 2026 sustainablelobster
# SPDX-License-Identifier: GPL-3.0-or-later

"""Manage Windows file ownership through native APIs on Python 3.4.4."""

# WANT_JSON

import os
import traceback

# The action stages these Python 3.4-compatible helpers beside the payload.
import legacy_windows_file as filesystem  # pylint: disable=import-error
import legacy_windows_owner as ownership  # pylint: disable=import-error
from legacy_windows_module import (  # pylint: disable=import-error
    as_bool,
    as_path,
    as_string,
    read_arguments,
    run_module,
)

# Ansible interfaces must be self-contained; repeated option/return text is
# interface documentation, not duplicated execution logic.
# pylint: disable=duplicate-code
DOCUMENTATION = r"""
---
module: win_owner
short_description: Set the owner of Windows files and directories
version_added: '1.0.0'
description:
  - Changes the owner of existing files and directories.
  - Uses Python 3.4.4 and native Windows security APIs.
options:
  path:
    description: Literal path to an existing file or directory.
    type: path
    required: true
  user:
    description:
      - User or group that should own the entry.
      - Accepts an account name, a C(DOMAIN\User) name, a UPN such as C(user@example.com), or a SID string.
    type: str
    required: true
  recurse:
    description:
      - Change ownership of descendants when O(path) is a directory.
      - Has no effect when O(path) is a file.
    type: bool
    default: false
attributes:
  check_mode:
    support: full
    description: Reads ownership and predicts changes without writing security descriptors.
  diff_mode:
    support: none
notes:
  - Preserves existing permission entries and file contents.
  - Windows can refresh inherited ACL metadata on descendants when a directory
    owner changes, even when O(recurse=false).
  - The executing account needs sufficient rights to read and change ownership.
    Available ownership-related privileges are enabled for the operation and then restored.
  - Recursive changes are not transactional. A failure can leave earlier entries changed.
seealso:
  - module: sustainablelobster.legacy_windows.win_file
  - module: sustainablelobster.legacy_windows.win_stat
author:
  - sustainablelobster
"""

EXAMPLES = r"""
- name: Set the owner of a directory without changing descendants
  sustainablelobster.legacy_windows.win_owner:
    path: C:\Application\logs
    user: SYSTEM

- name: Assign an entire tree to the local Administrators group
  sustainablelobster.legacy_windows.win_owner:
    path: C:\Application\data
    user: S-1-5-32-544
    recurse: true
"""

RETURN = r"""
{}
"""
# pylint: enable=duplicate-code

_MODULE_NAME = "sustainablelobster.legacy_windows.win_owner"
_PARAMETERS = ("path", "user", "recurse")
_DIRECTORY = 0x10


def _parameters(arguments):
    missing = [name for name in ("path", "user") if name not in arguments]
    if missing:
        raise ValueError("missing required arguments: " + ", ".join(missing))
    recurse = arguments.get("recurse", False)
    return {
        "path": as_path(arguments["path"], "path"),
        "user": as_string(arguments["user"], "user"),
        "recurse": False if recurse is None else as_bool(recurse, "recurse"),
    }


def _entries(path, recurse, is_directory):
    yield path
    if not recurse or not is_directory:
        return
    pending = [path]
    while pending:
        directory = pending.pop()
        for name in os.listdir(directory):
            child = os.path.join(directory, name)
            info = filesystem.file_info(child)
            if info is None:
                raise ValueError("Filesystem entry no longer exists: " + child)
            yield child
            if info["attributes"] & _DIRECTORY:
                pending.append(child)


def _manage(parameters, check_mode=False):
    result = {"changed": False}
    path, user = parameters["path"], parameters["user"]
    info = filesystem.file_info(path) if path else None
    if info is None:
        result.update(
            failed=True,
            msg="{0} file or directory does not exist on the host".format(path or ""),
        )
        return result
    try:
        sid = ownership.resolve_owner(user)
    except (OSError, ValueError) as error:
        message = str(error)
        if getattr(error, "winerror", None) == 1332:  # ERROR_NONE_MAPPED
            # Match the measured upstream translation failure; the exception
            # retains the native error and traceback for diagnosis.
            message = (
                "Failed to translate '{0}' to a SecurityIdentifier: "
                "Some or all identity references could not be translated."
            ).format(user)
        result.update(failed=True, msg=message, exception=traceback.format_exc())
        return result
    try:
        with ownership.ownership_privileges():
            for entry in _entries(
                path, parameters["recurse"], bool(info["attributes"] & _DIRECTORY)
            ):
                if ownership.get_owner(entry) != sid:
                    if not check_mode:
                        ownership.set_owner(entry, sid)
                    result["changed"] = True
    # Upstream catches traversal and security failures together. Keep successful
    # earlier writes visible even if a later operation raises an unexpected error.
    except Exception as error:  # pylint: disable=broad-exception-caught
        result.update(
            failed=True,
            msg=(
                "an error occurred when attempting to change owner on {0} "
                "for {1}: {2}"
            ).format(path, user, error),
            exception=traceback.format_exc(),
        )
    return result


def _execute():
    # Bind this module's arguments and core check mode before native ownership.
    # pylint: disable=duplicate-code
    arguments = read_arguments(_PARAMETERS, _MODULE_NAME)
    parameters = _parameters(arguments)
    check_mode = as_bool(
        arguments.get("_ansible_check_mode", False), "_ansible_check_mode"
    )
    # pylint: enable=duplicate-code
    return _manage(parameters, check_mode)


def main():
    """Read Ansible arguments and emit the module's JSON result.

    :raises SystemExit: After reporting success or failure to Ansible.
    """
    run_module(_execute)


# Each independently staged payload needs its own executable entry guard.
# pylint: disable=duplicate-code
if __name__ == "__main__":
    main()
# pylint: enable=duplicate-code
