#!/usr/bin/python
# -*- coding: utf-8 -*-
# Copyright: (c) 2017, Ansible Project
# Copyright 2026 sustainablelobster
# SPDX-License-Identifier: GPL-3.0-or-later

"""Activate an installed power plan through the native power-policy APIs."""

# WANT_JSON

import uuid

import legacy_community_windows_power as native  # pylint: disable=import-error
from legacy_windows_module import (  # pylint: disable=import-error
    as_bool,
    as_string,
    read_arguments,
    run_module,
)

DOCUMENTATION = r"""
---
module: win_power_plan
short_description: Changes the power plan of a Windows system
description:
  - This module will change the power plan of a Windows system to the defined string.
  - Windows defaults to C(balanced) which will cause CPU throttling. In some cases it can be preferable
    to change the mode to C(high performance) to increase CPU performance.
  - One of I(name) or I(guid) must be provided.
options:
  name:
    description:
      - String value that indicates the desired power plan by name.
      - The power plan must already be present on the system.
      - Commonly there will be options for C(balanced) and C(high performance).
    type: str
    required: false
  guid:
    description:
      - String value that indicates the desired power plan by guid.
      - The power plan must already be present on the system.
      - For out of box guids see U(https://docs.microsoft.com/en-us/windows/win32/power/power-policy-settings).
    type: str
    required: false
    version_added: 1.0.0

notes:
  - Systems exposing only the older numeric power-scheme API support selection by name, not GUID.

author:
  - Noah Sparks (@nwsparks)
"""

EXAMPLES = r"""
- name: Change power plan to high performance
  sustainablelobster.legacy_community_windows.win_power_plan:
    name: high performance

- name: Change power plan to high performance
  sustainablelobster.legacy_community_windows.win_power_plan:
    guid: 8c5e7fda-e8bf-4a96-9a85-a6e23a8c635c
"""

RETURN = r"""
power_plan_name:
  description: Value of the intended power plan.
  returned: always
  type: str
  sample: balanced
power_plan_enabled:
  description: State of the intended power plan.
  returned: success
  type: bool
  sample: true
all_available_plans:
  description: The name and enabled state of all power plans.
  returned: always
  type: dict
  sample: |
    {
        "High performance":  false,
        "Balanced":  true,
        "Power saver":  false
    }
"""


def _manage(arguments):
    name = as_string(arguments.get("name"), "name")
    guid = as_string(arguments.get("guid"), "guid")
    if name is None and guid is None:
        raise ValueError("one of name or guid must be provided")
    check = as_bool(arguments.get("_ansible_check_mode", False), "_ansible_check_mode")
    plans, active, modern = native.read_plans()
    result = {
        "changed": False,
        "power_plan_name": name,
        "power_plan_enabled": None,
        "all_available_plans": {
            label: identity == active for label, identity in plans.items()
        },
    }
    selected = None
    if name is not None:
        selected = next(
            (
                identity
                for label, identity in plans.items()
                if label.casefold() == name.casefold()
            ),
            None,
        )
        if selected is None:
            result.update(
                failed=True,
                msg="Defined power_plan: ({0}) is not available".format(name),
            )
            return result
    if guid is not None:
        if not modern:
            result.update(
                failed=True,
                msg="This installed power API uses numeric scheme identifiers; "
                "select an available plan by name instead of GUID.",
            )
            return result
        try:
            selected = str(uuid.UUID(guid))
        except (ValueError, AttributeError):
            result.update(failed=True, msg="guid must be a valid power-plan GUID.")
            return result
        if selected not in plans.values():
            result.update(
                failed=True,
                msg="Defined power_plan: ({0}) is not available".format(guid),
            )
            return result
    result["power_plan_enabled"] = selected == active
    if selected != active:
        if not check:
            try:
                native.activate(selected, modern)
            except OSError as error:
                result.update(failed=True, msg=str(error))
                return result
        result["changed"] = True
        result["power_plan_enabled"] = True
        result["all_available_plans"] = {
            label: identity == selected for label, identity in plans.items()
        }
    return result


def main():
    """Read the request and return the selected power-plan state."""
    run_module(
        lambda: _manage(
            read_arguments(
                ("name", "guid"),
                "sustainablelobster.legacy_community_windows.win_power_plan",
            )
        )
    )


if __name__ == "__main__":
    main()
