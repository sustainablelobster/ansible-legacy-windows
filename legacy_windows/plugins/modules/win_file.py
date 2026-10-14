#!/usr/bin/python
# -*- coding: utf-8 -*-
# Copyright 2026 sustainablelobster
# SPDX-License-Identifier: GPL-3.0-or-later

"""Manage Windows filesystem entries."""

# WANT_JSON

import os

# The action plugin stages these Python 3.4-compatible helpers beside the payload.
import legacy_windows_datetime as timestamps  # pylint: disable=import-error
import legacy_windows_file as filesystem  # pylint: disable=import-error
import legacy_windows_time as native_time  # pylint: disable=import-error
from legacy_windows_module import (  # pylint: disable=import-error
    DOTNET_WHITESPACE,
    as_bool,
    as_path,
    as_string,
    read_arguments,
    run_module,
)

DOCUMENTATION = r"""
---
module: win_file
short_description: Manage files, directories, and timestamps on Windows
version_added: '1.0.0'
description:
  - Creates directories and empty files, removes filesystem entries, and updates timestamps.
  - Uses Python 3.4.4 and native Windows APIs.
options:
  path:
    description: Literal path to the entry to manage.
    type: path
    required: true
    aliases: [dest, name]
  state:
    description:
      - V(directory) creates missing directories, including parents.
      - V(file) requires an existing file and does not create it.
      - V(touch) creates an empty file if missing and updates its timestamps.
      - V(absent) removes a file or recursively removes a directory.
      - Without a state, existing entries are unchanged and a missing file is not created.
    type: str
    choices: [absent, directory, file, touch]
  access_time:
    description:
      - Requested local access time, V(now), or V(preserve).
      - Defaults to V(now) for O(state=touch), otherwise V(preserve).
      - Applies to touched entries and newly created directories.
    type: str
  access_time_format:
    description: Date and time pattern used to parse O(access_time).
    type: str
    default: yyyy-MM-dd HH:mm:ss
  modification_time:
    description:
      - Requested local modification time, V(now), or V(preserve).
      - Defaults to V(now) for O(state=touch), otherwise V(preserve).
      - Applies to touched entries and newly created directories.
    type: str
  modification_time_format:
    description: Date and time pattern used to parse O(modification_time).
    type: str
    default: yyyy-MM-dd HH:mm:ss
attributes:
  check_mode:
    support: full
    description: Predicts changes without creating, changing, or removing entries.
  diff_mode:
    support: none
notes:
  - Timestamp patterns follow the upstream ParseExact interface and the target account's locale.
  - Numeric patterns support seven fractional-second digits. Unsupported locale metadata fails explicitly.
  - Existing files and directories ignore valid timestamps unless O(state=touch).
  - Timestamp validation occurs even for removal and check mode.
  - Removal does not traverse directory links or junctions.
author:
  - sustainablelobster
"""

EXAMPLES = r"""
- name: Create a directory and its parents
  sustainablelobster.legacy_windows.win_file:
    path: C:\Application\logs
    state: directory

- name: Ensure an empty file exists without changing existing timestamps
  sustainablelobster.legacy_windows.win_file:
    path: C:\Application\ready
    state: touch
    access_time: preserve
    modification_time: preserve

- name: Remove a directory tree
  sustainablelobster.legacy_windows.win_file:
    path: C:\Application\old
    state: absent
"""

RETURN = r"""
{}
"""

_MODULE_NAME = "sustainablelobster.legacy_windows.win_file"
_TIME_FIELDS = ("access_time", "modification_time")
_PARAMETERS = (
    "path",
    "dest",
    "name",
    "state",
    "access_time",
    "access_time_format",
    "modification_time",
    "modification_time_format",
    "_original_basename",
    "_diff_peek",
)


def _parameters(arguments):
    peek = arguments.get("_diff_peek")
    if peek is not None:
        peek = as_bool(peek, "_diff_peek")
    parameters = {"_diff_peek": peek}
    for field in _TIME_FIELDS:
        parameters[field] = as_string(arguments.get(field), field)
        parameters[field + "_format"] = as_string(
            arguments.get(field + "_format", "yyyy-MM-dd HH:mm:ss"),
            field + "_format",
        )
    for alias in ("path", "dest", "name"):
        if alias in arguments:
            path = as_path(arguments[alias], "path")
            break
    else:
        raise ValueError("missing required argument: path")
    if path is None or path == "":
        raise ValueError("path must not be null or empty.")
    state = as_string(arguments.get("state"), "state")
    if "state" in arguments and (
        state is None or state.lower() not in ("absent", "directory", "file", "touch")
    ):
        raise ValueError("state must be one of: absent, directory, file, touch.")
    parameters["path"] = path
    parameters["state"] = state.lower() if state is not None else None
    parameters["_original_basename"] = as_string(
        arguments.get("_original_basename"), "_original_basename"
    )
    for field in _TIME_FIELDS:
        if parameters[field] is None:
            parameters[field] = "now" if parameters["state"] == "touch" else "preserve"
    return parameters


def _requested_times(parameters):
    requested = {}
    for field in _TIME_FIELDS:
        value = parameters[field]
        if value.lower() == "preserve":
            requested[field] = None
        elif value.lower() == "now":
            requested[field] = native_time.current_local_ticks()
        else:
            try:
                requested[field] = timestamps.parse_local_ticks(
                    value, parameters[field + "_format"]
                )
            except ValueError as error:
                raise ValueError("Invalid {0} '{1}'".format(field, value)) from error
    return requested


def _update_times(path, requested, check_mode):
    info = filesystem.file_info(path)
    changed = False
    for field in ("modification_time", "access_time"):
        desired = requested[field]
        if desired is None:
            continue
        actual = native_time.file_time_to_local_ticks(info[field]) if info else None
        if desired == actual:
            continue
        if not check_mode:
            if info is None:
                raise ValueError("The filesystem entry no longer exists.")
            filesystem.set_file_time(
                path,
                bool(info["attributes"] & 0x10),
                field,
                native_time.local_ticks_to_file_time(desired),
            )
            # A setter invalidates the upstream object's cached metadata. Read
            # again before comparing access time, including for link targets.
            info = filesystem.file_info(path)
        changed = True
    return changed


def _peek(path, native_path, info):
    try:
        binary = b"\0" in filesystem.read_prefix(native_path, 8192)
    except (OSError, ValueError):
        binary = False
    return {
        "path": path,
        "state": "file" if info is not None else "absent",
        "appears_binary": binary,
        "change": False,
        "changed": False,
    }


def _ensure_entry(path, state, info, check_mode):
    if info is not None:
        is_directory = bool(info["attributes"] & 0x10)
        if state == "directory" and not is_directory:
            raise ValueError("path {0} is not a directory".format(path))
        if state == "file" and is_directory:
            raise ValueError("path {0} is not a file".format(path))
        return False
    if state not in ("touch", "directory"):
        raise ValueError("path {0} will not be created".format(path))
    if not check_mode:
        if state == "directory":
            os.makedirs(path)
        else:
            filesystem.create_empty_file(path)
    return True


def _manage(parameters, check_mode=False):
    result = {"changed": False}
    path = parameters["path"]
    state = parameters["state"]
    try:
        # The upstream filesystem provider resolves whitespace-only paths to
        # its current directory; retain the supplied spelling in results.
        native_path = path if path.strip(DOTNET_WHITESPACE) else "."
        info = filesystem.file_info(native_path)
        basename = parameters["_original_basename"]
        if info and info["attributes"] & 0x10 and basename is not None:
            path = os.path.join(path, basename.lstrip("\\/"))
            native_path = path
            info = filesystem.file_info(native_path)
        requested = _requested_times(parameters)
        if parameters["_diff_peek"] is not None:
            return _peek(path, native_path, info)
        if state == "absent":
            if info is not None:
                try:
                    filesystem.remove_path(native_path, check_mode=check_mode)
                except (OSError, ValueError) as error:
                    raise ValueError(
                        "Failed to delete {0}: {1}".format(
                            getattr(error, "filename", None) or path, error
                        )
                    ) from error
                result["changed"] = True
            return result
        result["changed"] = _ensure_entry(native_path, state, info, check_mode)
        if state == "touch" or (state == "directory" and info is None):
            try:
                updated = _update_times(native_path, requested, check_mode)
            except (OSError, ValueError) as error:
                raise ValueError(
                    "Failed to update timestamps on {0}: {1}".format(path, error)
                ) from error
            result["changed"] = result["changed"] or updated
    except (OSError, ValueError, NotImplementedError) as error:
        result.update({"failed": True, "msg": str(error)})
    return result


def _execute():
    arguments = read_arguments(_PARAMETERS, _MODULE_NAME, allow_unknown=True)
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
