#!/usr/bin/python
# -*- coding: utf-8 -*-
# Copyright 2026 Joe Lustri
# SPDX-License-Identifier: GPL-3.0-or-later

"""Copy controller or target-local files using a Python 3.4.4 Windows payload."""

# WANT_JSON

from legacy_windows_copy import execute_copy  # pylint: disable=import-error
from legacy_windows_module import (  # pylint: disable=import-error
    as_bool,
    as_path,
    as_string,
    read_arguments,
    run_module,
)

DOCUMENTATION = r"""
---
module: win_copy
short_description: Copy files and directories to Windows targets
version_added: '1.0.0'
description:
  - Copies controller files, inline content, or target-local files and directories.
  - Uses Python 3.4.4 and native Windows APIs.
options:
  src:
    description:
      - Source path on the controller, or the target with O(remote_src=true).
      - A directory is copied recursively, including its name unless the source ends with a slash.
      - Required unless O(content) is supplied.
    type: path
  content:
    description: Text to write instead of copying a source file.
    type: str
  dest:
    description:
      - Literal target path. An absolute path avoids dependence on the remote process working directory.
      - An existing directory or trailing slash retains the source filename.
      - A file destination requires an existing parent unless O(dest) ends with a slash.
      - Directory copies create missing destination directories.
    type: path
    required: true
  backup:
    description:
      - Preserve an overwritten file beside the destination with a process ID and timestamp suffix.
      - Controller copies of multiple files do not create backups.
    type: bool
    default: false
  force:
    description:
      - Compare SHA1 checksums and replace differing files when V(true).
      - Copy only missing files, without computing checksums, when V(false).
    type: bool
    default: true
  local_follow:
    description: Follow links in the controller's source tree. The action plugin defaults to V(false).
    type: bool
    default: false
  remote_src:
    description: Read O(src) on the Windows target instead of the controller.
    type: bool
    default: false
  decrypt:
    description: Automatically decrypt controller source files protected with Ansible Vault.
    type: bool
    default: true
attributes:
  async:
    support: none
    description: Background jobs are rejected before target staging.
  check_mode:
    support: partial
    description: Predicts file changes. A remote file copy to a missing directory with a trailing slash creates its parent.
  diff_mode:
    support: partial
    description: Shows content or target-local path changes. A controller directory copy with one changed file and no changed directories fails in diff mode, matching the pinned upstream action.
notes:
  - Source symbolic links are not preserved as symbolic links.
  - Archive extraction rejects traversal and destination reparse points.
author:
  - Joe Lustri
"""

EXAMPLES = r"""
- name: Copy a configuration file and preserve its previous contents
  sustainablelobster.legacy_windows.win_copy:
    src: files/application.ini
    dest: C:\Application\application.ini
    backup: true

- name: Copy a directory's contents
  sustainablelobster.legacy_windows.win_copy:
    src: files/resources/
    dest: C:\Application\resources

- name: Copy a file already on the target
  sustainablelobster.legacy_windows.win_copy:
    src: C:\Application\defaults.ini
    dest: C:\Application\current.ini
    remote_src: true

- name: Write a short text file
  sustainablelobster.legacy_windows.win_copy:
    content: ready
    dest: C:\Application\ready.txt
"""

RETURN = r"""
backup_file:
  description: Backup filename, or null when no prior destination file existed.
  returned: backup requested for a changed single file
  type: str
dest:
  description: Destination path reported by the copy operation.
  returned: success
  type: str
src:
  description: Controller or target source path, or null for inline content.
  returned: success
  type: str
checksum:
  description: Source SHA1 digest, or null with O(force=false).
  returned: source is a file
  type: str
size:
  description: File size, or target-local tree size; null for a missing check-mode destination.
  returned: source is a file, or a target-local directory
  type: int
operation:
  description: V(file_copy) or V(folder_copy).
  returned: success
  type: str
original_basename:
  description: The source filename before any destination rename.
  returned: source is a file
  type: str
"""

_PARAMETERS = (
    "src",
    "dest",
    "content",
    "backup",
    "force",
    "local_follow",
    "remote_src",
    "decrypt",
    "_copy_mode",
    "_original_basename",
    "files",
    "directories",
    "symlinks",
)


def _manifest(value, name):
    if value is None:
        return []
    if not isinstance(value, list) or any(
        not isinstance(entry, dict) for entry in value
    ):
        raise ValueError(name + " must be a list of file manifest dictionaries.")
    for entry in value:
        if not isinstance(entry.get("dest"), str):
            raise ValueError(name + " entries require a string dest.")
        if name == "files" and not isinstance(entry.get("src"), str):
            raise ValueError("files entries require a string src.")
    return value


def _parameters(arguments):
    mode = as_string(arguments.get("_copy_mode", "single"), "_copy_mode")
    if mode is None or mode.lower() not in ("query", "single", "explode", "remote"):
        raise ValueError("_copy_mode must be one of: explode, query, remote, single.")
    mode = mode.lower()
    parameters = {"_copy_mode": mode}
    for name in ("src", "dest"):
        value = as_path(arguments.get(name), name)
        if not value and (name == "dest" or mode in ("single", "explode")):
            raise ValueError("missing required argument: " + name)
        parameters[name] = value
    for name, default in (("backup", False), ("force", True)):
        parameters[name] = as_bool(arguments.get(name, default), name)
    parameters["_original_basename"] = as_string(
        arguments.get("_original_basename"), "_original_basename"
    )
    for name in ("files", "directories"):
        parameters[name] = _manifest(arguments.get(name), name)
    return parameters


def _execute():
    arguments = read_arguments(
        _PARAMETERS, "sustainablelobster.legacy_windows.win_copy", allow_unknown=True
    )
    return execute_copy(
        _parameters(arguments),
        as_bool(arguments.get("_ansible_check_mode", False), "_ansible_check_mode"),
        as_bool(arguments.get("_ansible_diff", False), "_ansible_diff"),
    )


def main():
    """Read the action plugin's arguments and emit its JSON copy result.

    :raises SystemExit: After reporting the operation's result.
    """
    run_module(_execute)


if __name__ == "__main__":
    main()
