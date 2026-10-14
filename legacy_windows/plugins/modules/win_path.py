#!/usr/bin/python
# -*- coding: utf-8 -*-
# Copyright 2026 sustainablelobster
# SPDX-License-Identifier: GPL-3.0-or-later

"""Manage elements of Windows path variables with a Python 3.4.4 payload."""

# WANT_JSON

import legacy_windows_environment as environment  # pylint: disable=import-error
import legacy_windows_path as paths  # pylint: disable=import-error
from legacy_windows_module import (  # pylint: disable=import-error
    as_bool,
    as_string,
    as_string_list,
    read_arguments,
    run_module,
)

DOCUMENTATION = r"""
---
module: win_path
short_description: Manage elements of Windows path environment variables
version_added: '1.0.0'
description:
  - Adds, orders, or removes elements of persistent path-like environment variables.
  - Uses Python 3.4.4 and native Windows APIs.
options:
  name:
    description:
      - Environment variable to manage. Tests and application-specific paths should use a dedicated name.
      - Avoid C((default)); this module applies the registry provider's unnamed-value alias on writes, but its raw reads treat the name literally.
    type: str
    default: PATH
  elements:
    description:
      - One path element or a list of elements to add or remove.
      - String input is split on commas; use a list for an element containing a comma.
      - With O(state=present), elements are placed in the requested relative order.
      - Missing elements are appended. Existing elements may move to the end to satisfy ordering.
      - Other existing elements retain their relative order.
      - Environment references such as C(%SystemRoot%) are stored without expansion.
      - Comparison is case-insensitive and ignores surrounding double quotes, then leading and trailing backslashes.
      - Whitespace is significant in element comparison.
    type: list
    elements: str
    required: true
  state:
    description: Whether the requested elements should be present or absent.
    type: str
    choices: [absent, present]
    default: present
  scope:
    description:
      - C(user) manages the connection account's persistent environment.
      - C(machine) manages the global persistent environment and requires suitable registry permissions.
    type: str
    choices: [machine, user]
    default: machine
attributes:
  check_mode:
    support: full
    description: Predicts the returned path and change status without writing or notifying applications.
  diff_mode:
    support: none
notes:
  - Changed values are stored as C(REG_EXPAND_SZ), even when removing the last element leaves an empty string.
  - Each requested removal deletes only the first matching element. Repeat the element to remove additional duplicates.
  - Empty stored path segments are omitted from the returned value; without an element change, the stored value is not rewritten.
  - Actual writes broadcast an environment-change notification, matching the pinned upstream implementation.
  - Existing processes may need restarting to observe persistent changes; the current module environment is not updated.
  - Native Windows Unicode comparison tables vary by Windows version.
seealso:
  - module: sustainablelobster.legacy_windows.win_environment
author:
  - sustainablelobster
"""

EXAMPLES = r"""
- name: Order two application search directories
  sustainablelobster.legacy_windows.win_path:
    name: APPLICATION_PATH
    scope: user
    elements:
      - '%USERPROFILE%\Application\bin'
      - C:\Application\tools

- name: Remove an obsolete directory from the machine path
  sustainablelobster.legacy_windows.win_path:
    elements: C:\Obsolete\bin
    state: absent
"""

RETURN = r"""
path_value:
  description: Calculated path string, including in check mode. An unchanged result need not match the stored spelling of empty segments.
  returned: success
  type: str
removed_idx:
  description: Index of the last requested removal in the evolving list, or -1 when that element was not found.
  returned: success with state absent and at least one requested element
  type: int
"""

_MODULE_NAME = "sustainablelobster.legacy_windows.win_path"
_PARAMETERS = ("name", "elements", "state", "scope")


def _parameters(arguments):
    if "elements" not in arguments:
        raise ValueError("missing required arguments: elements")
    result = {
        "name": as_string(arguments.get("name", "PATH"), "name"),
        "elements": as_string_list(arguments["elements"], "elements") or [],
    }
    for name, default, choices in (
        ("state", "present", ("absent", "present")),
        ("scope", "machine", ("machine", "user")),
    ):
        value = as_string(arguments.get(name, default), name)
        if value is not None:
            value = value.lower()
            if value not in choices:
                raise ValueError(name + " must be one of: " + ", ".join(choices) + ".")
        result[name] = value
    return result


def _edit(parameters, check):
    current = paths.read_value(parameters["name"], parameters["scope"])
    result = paths.edit_value(current, parameters["elements"], parameters["state"])
    if result["changed"] and not check:
        paths.set_value(parameters["name"], result["path_value"], parameters["scope"])
        environment.broadcast_change()
    return result


def _response():
    arguments = read_arguments(_PARAMETERS, _MODULE_NAME)
    parameters = _parameters(arguments)
    check = as_bool(arguments.get("_ansible_check_mode", False), "_ansible_check_mode")
    return _edit(parameters, check)


def main():
    """Read an Ansible request and emit the native module result."""
    run_module(_response)


if __name__ == "__main__":
    main()
