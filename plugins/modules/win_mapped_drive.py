#!/usr/bin/python
# -*- coding: utf-8 -*-
# Copyright 2026 sustainablelobster
# SPDX-License-Identifier: GPL-3.0-or-later

"""Manage persistent Windows network drives using Python 3.4.4."""

# WANT_JSON

import re

import legacy_windows_environment as environment  # pylint: disable=import-error
import legacy_windows_mapped_drive as mapped_drive  # pylint: disable=import-error
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
module: win_mapped_drive
short_description: Manage persistent network drive mappings
version_added: '1.0.0'
description:
  - Creates, changes, and removes a user's remembered network drive mappings.
  - Uses Python 3.4.4 and native Windows network APIs.
options:
  letter:
    description: Single drive letter to manage, without a colon.
    type: str
    required: true
  path:
    description:
      - UNC network location, required when O(state=present).
      - When removing a mapping, a supplied path must match its existing target.
      - WebDAV locations use UNC notation and require the Windows WebDAV client.
    type: path
  state:
    description: Whether the remembered mapping should exist.
    type: str
    choices: [absent, present]
    default: present
  username:
    description: Optional account used to authenticate the initial connection.
    type: str
  password:
    description: Optional initial-connection password; it is not saved with the mapping.
    type: str
attributes:
  check_mode:
    support: full
    description: Predicts changes without connecting to or disconnecting a network target.
  diff_mode:
    support: full
    description: Reports the requested letter and existing or predicted UNC target.
notes:
  - Mappings belong to user logon sessions. A mapping is not a way to access a drive in later Ansible tasks.
  - A changed mapping with explicit credentials clears its saved username so future logons can use cached credentials.
  - Replacing a target disconnects the old mapping first. A failed new connection does not restore the old target.
author:
  - sustainablelobster
"""

EXAMPLES = r"""
- name: Remember a network folder
  sustainablelobster.legacy_windows.win_mapped_drive:
    letter: M
    path: '\\fileserver\documents'

- name: Remove a matching mapping
  sustainablelobster.legacy_windows.win_mapped_drive:
    letter: M
    path: '\\fileserver\documents'
    state: absent
"""

RETURN = r"""
{}
"""
# pylint: enable=duplicate-code

_PARAMETERS = ("letter", "password", "path", "state", "username")
_MODULE_NAME = "sustainablelobster.legacy_windows.win_mapped_drive"


class _NativeCallError(ValueError):
    """A failure that escapes the original module's PowerShell call boundary."""


def _parameters(arguments):
    unsupported = sorted(
        name
        for name in arguments
        if name not in _PARAMETERS and not name.startswith("_ansible_")
    )
    if unsupported and not as_bool(
        arguments.get("_ansible_ignore_unknown_opts", False),
        "_ansible_ignore_unknown_opts",
    ):
        raise ValueError(
            "Unsupported parameters for ("
            + _MODULE_NAME
            + ") module: "
            + ", ".join(unsupported)
            + ". Supported parameters include: "
            + ", ".join(sorted(_PARAMETERS))
        )
    if "letter" not in arguments:
        raise ValueError("missing required arguments: letter")
    result = {
        name: as_string(arguments.get(name), name)
        for name in ("letter", "username", "password")
    }
    # Match the pinned module's measured path-binding failures before diff setup.
    path_error = (
        "argument for path is of type System.String and we were unable to "
        "convert to path: "
    )
    try:
        result["path"] = as_path(arguments.get("path"), "path")
    except ValueError as error:
        if str(error) != "Invalid Windows path characters in path.":
            raise
        raise ValueError(
            path_error
            + "string value contains invalid path characters, cannot convert to path"
        ) from error
    if result["path"] == "":
        raise ValueError(path_error + "The path is not of a legal form.")
    state = as_string(arguments.get("state", "present"), "state")
    if state is not None and not any(
        environment.values_equal(state, allowed) for allowed in ("absent", "present")
    ):
        raise ValueError(
            "value of state must be one of: absent, present. Got no match for: " + state
        )
    if environment.values_equal(state, "present") and "path" not in arguments:
        raise ValueError("state is present but all of the following are missing: path")
    result["state"] = state
    if not re.search(r"^[a-zA-z]{1}$", result["letter"] or ""):
        raise ValueError(
            "letter must be a single letter from A-Z, was: " + (result["letter"] or "")
        )
    return result


def _native_call(method, name, arguments):
    try:
        return method(*arguments)
    except OSError as error:
        # Both the direct removal and MethodInfo.Invoke receive two upstream
        # arguments, independently of the native Python method's signature.
        raise _NativeCallError(
            'Unhandled exception while executing module: Exception calling "{0}" '
            'with "2" argument(s): "{1}"'.format(name, error.strerror)
        ) from error


def _manage(parameters, check_mode, result):
    letter, path = parameters["letter"], parameters["path"]
    drive = letter + ":"
    with mapped_drive.open_mappings() as mappings:
        existing = next(
            (
                entry
                for entry in mappings.remembered()
                if environment.values_equal(entry["drive"], drive)
            ),
            None,
        )
        if existing and "diff" in result:
            result["diff"]["before"] = {"letter": letter, "path": existing["path"]}
        if environment.values_equal(parameters["state"], "absent"):
            if existing:
                if path is not None and not environment.values_equal(
                    existing["path"], path
                ):
                    raise ValueError(
                        "did not delete mapped drive {0}, the target path is pointing "
                        "to a different location at {1}".format(
                            letter, existing["path"]
                        )
                    )
                if not check_mode:
                    _native_call(mappings.remove, "RemoveMappedDrive", (drive,))
                result["changed"] = True
            return
        if not existing and any(
            environment.values_equal(letter, occupied)
            for occupied in mapped_drive.logical_drives()
        ):
            raise ValueError(
                "failed to create mapped drive {0}, this letter is in use and is "
                "pointing to a non UNC path".format(letter)
            )
        if not existing or not environment.values_equal(existing["path"], path):
            if not check_mode:
                if existing:
                    _native_call(mappings.remove, "RemoveMappedDrive", (drive,))
                _native_call(
                    mappings.add,
                    "Invoke",
                    (drive, path, parameters["username"], parameters["password"]),
                )
            result["changed"] = True
        if parameters["username"] is not None and result["changed"] and not check_mode:
            mapped_drive.clear_username(letter)
        if "diff" in result:
            result["diff"]["after"] = {"letter": letter, "path": path}


def _response():
    result = {"changed": False}
    password = None
    try:
        # Capture the no-log value before a validation error can echo argument names.
        arguments = read_arguments(_PARAMETERS, _MODULE_NAME, allow_unknown=True)
        password = as_string(arguments.get("password"), "password")
        parameters = _parameters(arguments)
        # Modules initialize their own requested Ansible diff envelope.
        # pylint: disable=duplicate-code
        if as_bool(arguments.get("_ansible_diff", False), "_ansible_diff"):
            result["diff"] = {"before": "", "after": ""}
        # pylint: enable=duplicate-code
        _manage(
            parameters,
            as_bool(arguments.get("_ansible_check_mode", False), "_ansible_check_mode"),
            result,
        )
    except Exception as error:  # pylint: disable=broad-exception-caught
        if isinstance(error, _NativeCallError):
            # The upstream outer wrapper reports these failures without the
            # module's pending diff, including after a failed real retarget.
            result = {"changed": False}
        message = error.strerror if isinstance(error, OSError) else str(error)
        if password:
            message = (
                "VALUE_SPECIFIED_IN_NO_LOG_PARAMETER"
                if message == password
                else message.replace(password, "********")
            )
        result.update(failed=True, msg=message, exception="(traceback unavailable)")
    return result


def main():
    """Read the Ansible request and report mapping results.

    :raises SystemExit: After returning success or failure JSON.
    """
    run_module(_response)


# Each independently staged payload needs its own executable entry guard.
# pylint: disable=duplicate-code
if __name__ == "__main__":
    main()
# pylint: enable=duplicate-code
