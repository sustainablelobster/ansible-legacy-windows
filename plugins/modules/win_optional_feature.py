#!/usr/bin/python
# -*- coding: utf-8 -*-
# Copyright 2026 Joe Lustri
# SPDX-License-Identifier: GPL-3.0-or-later

"""Manage online Windows optional features through the shipped DISM executable."""

# WANT_JSON

import os

import legacy_windows_optional_feature as features  # pylint: disable=import-error
from legacy_windows_module import (  # pylint: disable=import-error
    as_bool,
    as_string,
    as_string_list,
    read_arguments,
    run_module,
)

# Ansible interfaces must be self-contained; repeated option/return text is
# interface documentation, not duplicated execution logic.
# pylint: disable=duplicate-code
DOCUMENTATION = r"""
---
module: win_optional_feature
short_description: Manage optional Windows features
version_added: '1.0.0'
description:
  - Enables or disables optional features in the running Windows installation.
  - Uses Python 3.4.4 and the shipped native DISM executable.
options:
  name:
    description:
      - Literal feature names to install or uninstall.
      - All names are checked in supplied order before any feature change.
    type: list
    elements: str
    required: true
  state:
    description: Whether the requested features should be present or absent.
    type: str
    choices: [absent, present]
    default: present
  include_parent:
    description: Whether enabling also enables required parent features and their dependencies.
    type: bool
    default: false
  source:
    description:
      - Literal local or UNC path supplying feature payload files.
      - Checked only when enabling is needed, including in check mode.
      - Ignored when disabling or when no requested feature needs enabling.
    type: str
attributes:
  check_mode:
    support: full
    description: Validates names and any needed source, predicting changes without servicing them.
  diff_mode:
    support: none
notes:
  - DISM and online optional-feature servicing must be available on the target.
  - Windows is never restarted. Use C(reboot_required) to decide whether to reboot.
  - Disabling preserves the feature payload; this module does not remove payload files.
  - A servicing failure can leave partial changes. No automatic feature rollback is performed.
  - The configured source does not prevent Windows Update access, matching the pinned upstream behavior.
  - If the installed DISM enable-feature command lacks C(/All) or C(/Source), meaningful O(include_parent=true) or O(source) requests fail before servicing, including in check mode. Already-satisfied and absent requests do not need these switches.
  - On a case-sensitive DISM installation, feature names are resolved against the actual native catalogue before servicing.
author:
  - Joe Lustri
"""

EXAMPLES = r"""
- name: Enable the Telnet client
  sustainablelobster.legacy_windows.win_optional_feature:
    name: TelnetClient
    state: present
  register: telnet_feature

- name: Disable two optional features
  sustainablelobster.legacy_windows.win_optional_feature:
    name: [TelnetClient, TFTP]
    state: absent

- name: Supply staged installation files
  sustainablelobster.legacy_windows.win_optional_feature:
    name: NetFx3
    source: D:\sources\sxs
    include_parent: true
"""

RETURN = r"""
reboot_required:
  description: Whether successful servicing requires a reboot; false in check mode or without changes.
  returned: after argument validation
  type: bool
"""
# pylint: enable=duplicate-code

_PARAMETERS = ("name", "state", "include_parent", "source")


def _parameters(arguments):
    if "name" not in arguments:
        raise ValueError("missing required arguments: name")
    names = as_string_list(arguments["name"], "name")
    state = as_string(arguments.get("state", "present"), "state")
    if state is not None and state.lower() not in ("absent", "present"):
        raise ValueError(
            "value of state must be one of: absent, present. Got no match for: " + state
        )
    include_parent = arguments.get("include_parent", False)
    return {
        "names": names,
        "state": state.lower() if state is not None else None,
        "include_parent": (
            as_bool(include_parent, "include_parent")
            if include_parent is not None
            else False
        ),
        "source": as_string(arguments.get("source"), "source"),
    }


def _manage(parameters, result, check_mode):
    with features.OptionalFeatures() as native:
        changed = []
        for name in parameters["names"] or []:
            current = native.state(name)
            if current is None:
                result.update(failed=True, msg="Failed to find feature '" + name + "'")
                return
            if parameters["state"] == "present" and not current.lower().startswith(
                "enabled"
            ):
                changed.append(name)
            elif parameters["state"] == "absent" and not current.lower().startswith(
                "disabled"
            ):
                changed.append(name)
        if not changed:
            return
        if parameters["state"] == "present":
            source = parameters["source"]
            if source and not os.path.exists(source):
                result.update(
                    failed=True, msg="Path could not be found '" + source + "'"
                )
                return
            native.validate_enable(parameters["include_parent"], source)
            if not check_mode:
                result["reboot_required"] = native.enable(
                    changed, parameters["include_parent"], source
                )
        elif not check_mode:
            result["reboot_required"] = native.disable(changed)
        result["changed"] = True


def _response():
    arguments = read_arguments(
        _PARAMETERS, "sustainablelobster.legacy_windows.win_optional_feature"
    )
    parameters = _parameters(arguments)
    result = {"changed": False, "reboot_required": False}
    try:
        # Dispatch passes this module's arguments and core check-mode flag only.
        # pylint: disable=duplicate-code
        _manage(
            parameters,
            result,
            as_bool(arguments.get("_ansible_check_mode", False), "_ansible_check_mode"),
        )
        # pylint: enable=duplicate-code
    except (OSError, ValueError) as error:
        result.update(failed=True, msg=str(error))
    return result


def main():
    """Execute native optional-feature management and emit its public result.

    :raises SystemExit: With zero on success or one on failure.
    """
    run_module(_response)


# Each independently staged payload needs its own executable entry guard.
# pylint: disable=duplicate-code
if __name__ == "__main__":
    main()
# pylint: enable=duplicate-code
