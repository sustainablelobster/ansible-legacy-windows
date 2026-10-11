#!/usr/bin/python
# -*- coding: utf-8 -*-
# Copyright 2026 sustainablelobster
# SPDX-License-Identifier: GPL-3.0-or-later

"""Create a uniquely named Windows file or directory through native Python."""

# WANT_JSON

import ctypes
import os

# The action plugin stages this Python 3.4-compatible helper beside the payload.
from legacy_windows_module import (  # pylint: disable=import-error
    as_bool,
    as_path,
    as_string,
    expand_environment,
    read_arguments,
    run_module,
)

DOCUMENTATION = r"""
---
module: win_tempfile
short_description: Create a temporary file or directory on Windows
version_added: '1.0.0'
description:
  - Creates a new empty file or directory with a random name.
  - The target requires Python 3.4.4 or newer.
options:
  path:
    description:
      - Directory in which to create the temporary object.
      - Defaults to the Windows temporary directory for the executing account.
      - Missing parent directories are created for O(state=directory), but not for files.
    type: path
    aliases: [dest]
  state:
    description:
      - Whether to create a file or directory.
    type: str
    choices: [directory, file]
    default: file
  prefix:
    description:
      - Text before the random part of the name.
      - An explicit null value is treated as empty text.
    type: str
    default: ansible.
  suffix:
    description:
      - Text after the random part of the name.
      - An omitted or null value is treated as empty text.
    type: str
attributes:
  check_mode:
    support: full
    description: Returns a proposed path without creating a file or directory.
  diff_mode:
    support: none
notes:
  - Each successful invocation reports a change and returns a new random path.
  - Path, prefix, and suffix expand Windows percent-delimited environment variables.
  - The caller is responsible for removing the created file or directory.
author:
  - sustainablelobster
"""

EXAMPLES = r"""
- name: Allocate an empty temporary file
  sustainablelobster.legacy_windows.win_tempfile:

- name: Allocate a directory for a build
  sustainablelobster.legacy_windows.win_tempfile:
    state: directory
    prefix: build-

- name: Allocate a log file in a specified directory
  sustainablelobster.legacy_windows.win_tempfile:
    path: C:\Windows\Temp
    suffix: .log
"""

RETURN = r"""
path:
  description: Absolute path of the created object, or its proposed path in check mode.
  returned: success
  type: str
  sample: C:\Windows\Temp\ansible.abcdefgh.ijk
state:
  description: The requested object type, preserving the supplied letter case.
  returned: after argument validation
  type: str
  sample: file
"""

_MODULE_NAME = "sustainablelobster.legacy_windows.win_tempfile"
_PARAMETERS = ("path", "dest", "state", "prefix", "suffix")


def _parameters(arguments):
    path = as_path(arguments.get("dest", arguments.get("path")), "path")
    if path is not None and not path.strip():
        raise ValueError("path must not be empty or contain only whitespace.")
    state = as_string(arguments.get("state", "file"), "state")
    if state is not None and state.lower() not in ("directory", "file"):
        raise ValueError("state must be one of: directory, file.")
    return {
        "path": path,
        "state": state,
        "prefix": as_string(arguments.get("prefix", "ansible."), "prefix"),
        "suffix": as_string(arguments.get("suffix"), "suffix"),
    }


def _temporary_directory():
    kernel = ctypes.WinDLL("kernel32", use_last_error=True)
    get_temp_path = kernel.GetTempPathW
    get_temp_path.argtypes = [ctypes.c_ulong, ctypes.c_wchar_p]
    get_temp_path.restype = ctypes.c_ulong
    buffer = ctypes.create_unicode_buffer(261)
    length = get_temp_path(len(buffer), buffer)
    if length >= len(buffer):
        buffer = ctypes.create_unicode_buffer(length + 1)
        length = get_temp_path(len(buffer), buffer)
    if not length:
        raise ctypes.WinError()
    return buffer.value


def _full_path(path):
    absolute = os.path.abspath(path)
    kernel = ctypes.WinDLL("kernel32", use_last_error=True)
    get_long_path = kernel.GetLongPathNameW
    get_long_path.argtypes = [ctypes.c_wchar_p, ctypes.c_wchar_p, ctypes.c_ulong]
    get_long_path.restype = ctypes.c_ulong
    candidate = absolute
    missing_parts = []
    # Check mode has no final object; expand any existing short-name ancestors.
    while candidate:
        size = get_long_path(candidate, None, 0)
        if size:
            buffer = ctypes.create_unicode_buffer(size)
            if get_long_path(candidate, buffer, size):
                return os.path.join(buffer.value, *reversed(missing_parts))
        parent, name = os.path.split(candidate)
        if parent == candidate or not name:
            break
        missing_parts.append(name)
        candidate = parent
    return absolute


def _random_name():
    alphabet = "abcdefghijklmnopqrstuvwxyz012345"
    characters = "".join(alphabet[value & 31] for value in os.urandom(11))
    return characters[:8] + "." + characters[8:]


def _create_item(path, state):
    if state.lower() == "directory":
        os.makedirs(path)
    else:
        flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_BINARY", 0)
        descriptor = os.open(path, flags)
        os.close(descriptor)


def _create_temporary(parameters, check_mode):
    directory = parameters["path"] or _temporary_directory()
    prefix = expand_environment(parameters["prefix"] or "")
    suffix = expand_environment(parameters["suffix"] or "")
    state = parameters["state"]
    last_error = None
    for _attempt in range(5):
        child = (prefix + _random_name() + suffix).lstrip("\\/")
        try:
            # Reject invalid names and alternate streams even without creation.
            if any(
                ord(character) < 32 or character in '<>:"|?*' for character in child
            ):
                raise ValueError("Invalid Windows characters in the temporary name.")
            candidate = os.path.join(directory, child)
            if state is None:
                raise ValueError("state must not be null.")
            if not check_mode:
                _create_item(candidate, state)
            return {"path": _full_path(candidate)}
        except (OSError, ValueError) as error:
            last_error = error
    return {
        "failed": True,
        "msg": "No random temporary file worked in 5 attempts. Error: "
        + str(last_error),
    }


def _response():
    arguments = read_arguments(_PARAMETERS, _MODULE_NAME)
    parameters = _parameters(arguments)
    check_mode = as_bool(
        arguments.get("_ansible_check_mode", False), "_ansible_check_mode"
    )
    result = {"changed": True, "state": parameters["state"]}
    result.update(_create_temporary(parameters, check_mode))
    if as_bool(
        arguments.get("_ansible_inject_invocation", False), "_ansible_inject_invocation"
    ):
        invocation = {
            name: value
            for name, value in arguments.items()
            if not name.startswith("_ansible_")
        }
        invocation.update(parameters)
        result["invocation"] = {"module_args": invocation}
    return result


def main():
    """Read Ansible arguments and emit the module's JSON result.

    :raises SystemExit: After reporting success or failure to Ansible.
    """
    run_module(_response)


if __name__ == "__main__":
    main()
