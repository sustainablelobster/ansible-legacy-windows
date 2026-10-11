#!/usr/bin/python
# -*- coding: utf-8 -*-
# Copyright 2026 sustainablelobster
# SPDX-License-Identifier: GPL-3.0-or-later

"""Request a Windows computer rename using Python 3.4.4 and native WMI."""

# WANT_JSON

# The action stages these target-compatible helpers beside this payload.
import legacy_windows_environment as environment  # pylint: disable=import-error
import legacy_windows_hostname as hostname  # pylint: disable=import-error
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
module: win_hostname
short_description: Request a Windows computer name change
version_added: '1.0.0'
description:
  - Reads the active DNS hostname and requests a local computer rename.
  - Uses Python 3.4.4 and native Windows interfaces.
  - A successful rename requires a reboot before the new name becomes active.
options:
  name:
    description:
      - Computer name to request.
    type: str
    required: true
attributes:
  check_mode:
    support: full
    description: Checks parameter binding and predicts a differing rename without provider hostname validation or writes.
  diff_mode:
    support: full
    description: Returns the active and requested names without appended newlines.
notes:
  - Names are compared without case. The diff retains the requested spelling.
  - A pending rename does not change RV(old_name). Repeating the request before reboot can report another change.
  - This module does not restart the machine.
author:
  - sustainablelobster
"""

EXAMPLES = r"""
- name: Request a new computer name
  sustainablelobster.legacy_windows.win_hostname:
    name: application-01
  register: computer_name

- name: Show whether a restart is needed
  ansible.builtin.debug:
    var: computer_name.reboot_required
"""

RETURN = r"""
old_name:
  description: Active DNS hostname read before applying or predicting the request.
  returned: success
  type: str
reboot_required:
  description: Whether this request applied or predicted a rename requiring a restart.
  returned: success
  type: bool
"""
# pylint: enable=duplicate-code

_MODULE_NAME = "sustainablelobster.legacy_windows.win_hostname"
_PARAMETERS = ("name",)


def _parameters(arguments):
    if "name" not in arguments:
        raise ValueError("missing required arguments: name")
    return as_string(arguments["name"], "name")


def _failure(result, message):
    result.update(
        {"failed": True, "msg": message, "exception": "(traceback unavailable)"}
    )
    return result


def _manage(requested, check_mode=False, diff_mode=False):
    current = hostname.read_hostname()
    result = {"changed": False, "old_name": current, "reboot_required": False}
    if diff_mode:
        result["diff"] = {"before": current, "after": requested}
    if not environment.values_equal(current, requested):
        try:
            hostname.rename_hostname(requested, check_mode=check_mode)
        except (ValueError, OSError) as error:
            return _failure(
                result,
                "Failed to rename computer to '"
                + (requested or "")
                + "': "
                + str(error),
            )
        result.update({"changed": True, "reboot_required": True})
    return result


def _response():
    try:
        arguments = read_arguments(_PARAMETERS, _MODULE_NAME)
        requested = _parameters(arguments)
        # Core check/diff flags are bound locally before hostname management.
        # pylint: disable=duplicate-code
        check_mode = as_bool(
            arguments.get("_ansible_check_mode", False), "_ansible_check_mode"
        )
        diff_mode = as_bool(arguments.get("_ansible_diff", False), "_ansible_diff")
        # pylint: enable=duplicate-code
    except ValueError as error:
        return _failure({"changed": False}, str(error))
    return _manage(requested, check_mode, diff_mode)


def main():
    """Read an Ansible request and emit the hostname module's JSON result.

    :raises SystemExit: After reporting success or failure to Ansible.
    """
    run_module(_response)


# Each independently staged payload needs its own executable entry guard.
# pylint: disable=duplicate-code
if __name__ == "__main__":
    main()
# pylint: enable=duplicate-code
