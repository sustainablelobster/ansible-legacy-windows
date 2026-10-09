#!/usr/bin/python
# -*- coding: utf-8 -*-
# Copyright 2026 Joe Lustri
# SPDX-License-Identifier: GPL-3.0-or-later

"""Manage Windows ACL inheritance through native APIs on Python 3.4.4."""

# WANT_JSON

import traceback

# The action stages these Python 3.4-compatible helpers beside the payload.
import legacy_windows_acl_inheritance as inheritance  # pylint: disable=import-error
from legacy_windows_module import (  # pylint: disable=import-error
    as_bool,
    as_string,
    read_arguments,
    run_module,
)

# Ansible interfaces must be self-contained; repeated option/return text is
# interface documentation, not duplicated execution logic.
# pylint: disable=duplicate-code
DOCUMENTATION = r"""
---
module: win_acl_inheritance
short_description: Change inheritance of Windows access permissions
version_added: '1.0.0'
description:
  - Enables or disables inherited access permissions on a file, directory, or registry key.
  - Uses Python 3.4.4 and native Windows security APIs.
options:
  path:
    description:
      - Literal path to the existing file, directory, or registry key.
      - Environment variables in the path are expanded except for paths beginning with C(\\?\).
    type: str
    required: true
  state:
    description:
      - V(present) enables inheritance and V(absent) disables it.
    type: str
    choices: [absent, present]
    default: absent
  reorganize:
    description:
      - With O(state=absent), preserve inherited permission entries as explicit entries.
      - With O(state=present), request removal of explicit entries matching inherited entries in the ACL being changed.
      - Only takes effect when the inheritance state changes.
    type: bool
    default: false
attributes:
  check_mode:
    support: full
    description: Predicts inheritance changes without writing security descriptors.
  diff_mode:
    support: full
    description: Reports the inheritance state before and after the operation.
notes:
  - The executing account needs sufficient rights to read and change access permissions.
  - Windows applies directory and registry inheritance changes to affected descendants.
  - Reorganization when enabling inheritance writes the ACL twice. An error can leave the first write applied.
author:
  - Joe Lustri
"""

EXAMPLES = r"""
- name: Disable inheritance and remove inherited permission entries
  sustainablelobster.legacy_windows.win_acl_inheritance:
    path: C:\Application\private

- name: Disable inheritance while retaining the current inherited permissions
  sustainablelobster.legacy_windows.win_acl_inheritance:
    path: C:\Application\data
    state: absent
    reorganize: true

- name: Enable registry permission inheritance
  sustainablelobster.legacy_windows.win_acl_inheritance:
    path: HKLM:\SOFTWARE\Application
    state: present
"""

RETURN = r"""
{}
"""
# pylint: enable=duplicate-code

_MODULE_NAME = "sustainablelobster.legacy_windows.win_acl_inheritance"
_PARAMETERS = ("path", "state", "reorganize")


def _parameters(arguments):
    if "path" not in arguments:
        raise ValueError("missing required arguments: path")
    state = as_string(arguments.get("state", "absent"), "state")
    if state is not None and state.lower() not in ("absent", "present"):
        raise ValueError(
            "value of state must be one of: absent, present. Got no match for: " + state
        )
    reorganize = arguments.get("reorganize", False)
    try:
        reorganize = False if reorganize is None else as_bool(reorganize, "reorganize")
    except ValueError as error:
        if not isinstance(reorganize, str):
            raise
        raise ValueError(
            (
                "argument for reorganize is of type System.String and we were "
                "unable to convert to bool: The value '{0}' is not a valid boolean. "
                "Valid booleans include: y, yes, on, 1, true, t, 1.0, "
                "n, no, off, 0, false, f, 0.0"
            ).format(reorganize)
        ) from error
    path = as_string(arguments["path"], "path")
    if path is None:
        raise ValueError(
            "Unhandled exception while executing module: "
            "You cannot call a method on a null-valued expression."
        )
    path = inheritance.normalize_path(path)
    if not path:
        raise ValueError(
            "Unhandled exception while executing module: "
            "Cannot bind argument to parameter 'Path' because it is an empty string."
        )
    return {
        "path": path,
        "state": state.lower() if state is not None else None,
        "reorganize": reorganize,
    }


def _failure(result, message):
    result.update(failed=True, msg=message, exception=traceback.format_exc())
    return result


def _state(acl):
    return "absent" if acl["protected"] else "present"


def _manage(parameters, check_mode=False):
    result = {"changed": False}
    path = parameters["path"]
    try:
        acl = inheritance.read_acl(path)
    except (OSError, ValueError) as error:
        if getattr(error, "winerror", None) in (2, 3, 123):
            result.update(failed=True, msg="{0} does not exist".format(path))
            return result
        return _failure(result, "Failed to find '{0}': {1}".format(path, error))

    result["diff"] = {"before": {"state": _state(acl)}}
    state, reorganize = parameters["state"], parameters["reorganize"]
    if state is not None and state != _state(acl):
        try:
            acl = inheritance.set_protection(
                acl, state == "absent", reorganize if state == "absent" else False
            )
        except (OSError, ValueError) as error:
            operation = "disable" if state == "absent" else "enable"
            return _failure(
                result,
                "Failed to {0} inheritance of '{1}': {2}".format(
                    operation, path, error
                ),
            )
        try:
            if state == "present" and reorganize:
                if not check_mode:
                    inheritance.write_acl(path, acl)
                # Upstream removes duplicates from this snapshot after its first
                # write; it does not reread the newly inherited entries first.
                acl = inheritance.remove_explicit_duplicates(acl)
            if not check_mode:
                inheritance.write_acl(path, acl)
        except (OSError, ValueError) as error:
            return _failure(result, str(error))
        result["changed"] = True

    if not check_mode:
        try:
            acl = inheritance.read_acl(path)
        except (OSError, ValueError) as error:
            return _failure(
                result, "Failed to get acl of '{0}': {1}".format(path, error)
            )
    result["diff"]["after"] = {"state": _state(acl)}
    return result


def _execute():
    arguments = read_arguments(_PARAMETERS, _MODULE_NAME)
    parameters = _parameters(arguments)
    check_mode = as_bool(
        arguments.get("_ansible_check_mode", False), "_ansible_check_mode"
    )
    result = _manage(parameters, check_mode)
    if not as_bool(arguments.get("_ansible_diff", False), "_ansible_diff"):
        result.pop("diff", None)
    return result


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
