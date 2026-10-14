#!/usr/bin/python
# -*- coding: utf-8 -*-
# Copyright 2026 sustainablelobster
# SPDX-License-Identifier: GPL-3.0-or-later

"""Set Windows description and registration labels using Python 3.4.4."""

# WANT_JSON

# The action stages these target-compatible helpers beside this payload.
import legacy_windows_computer_description as computer  # pylint: disable=import-error
from legacy_windows_module import (  # pylint: disable=import-error
    as_bool,
    as_string,
    read_arguments,
    run_module,
)

DOCUMENTATION = r"""
---
module: win_computer_description
short_description: Set Windows description and registration names
version_added: '1.0.0'
description:
  - Changes the Windows system description and the registered installation owner and organization names.
  - Uses Python 3.4.4 and native Windows interfaces.
options:
  description:
    description:
      - Description displayed in Windows system properties.
      - An empty string clears the description.
    type: str
  owner:
    description:
      - Registered installation owner name displayed by C(winver).
      - An empty string clears the name.
    type: str
  organization:
    description:
      - Registered organization name displayed by C(winver).
      - An empty string clears the name.
    type: str
attributes:
  check_mode:
    support: full
    description: Reads requested properties and predicts changes without writing them.
  diff_mode:
    support: none
notes:
  - Supply at least one of O(owner), O(organization), or O(description).
  - Omitted or null fields are left untouched. Comparison of supplied strings is case-sensitive.
  - Existing registration values are read before writing. A missing requested owner or organization value causes failure.
  - Changes are applied in description, owner, organization order. A later failure can leave earlier writes applied.
author:
  - sustainablelobster
"""

EXAMPLES = r"""
- name: Set installation metadata
  sustainablelobster.legacy_windows.win_computer_description:
    description: Application server
    owner: Operations
    organization: Example Company

- name: Clear the registered owner while retaining other fields
  sustainablelobster.legacy_windows.win_computer_description:
    owner: ''
"""

RETURN = r"""
{}
"""

_MODULE_NAME = "sustainablelobster.legacy_windows.win_computer_description"
_PARAMETERS = ("owner", "organization", "description")


def _parameters(arguments):
    parameters = {name: as_string(arguments.get(name), name) for name in _PARAMETERS}
    if not any(name in arguments for name in _PARAMETERS):
        raise ValueError(
            "one of the following is required: owner, organization, description"
        )
    return parameters


def _manage(parameters, check_mode=False):
    result = {"changed": False}
    description = parameters["description"]
    if description is not None and description != computer.read_description():
        if not check_mode:
            computer.write_description(description)
        result["changed"] = True
    for field, registration in (
        ("owner", "RegisteredOwner"),
        ("organization", "RegisteredOrganization"),
    ):
        value = parameters[field]
        if value is not None and value != computer.read_registration(registration):
            if not check_mode:
                computer.write_registration(registration, value)
            result["changed"] = True
    return result


def _response():
    try:
        arguments = read_arguments(_PARAMETERS, _MODULE_NAME)
        parameters = _parameters(arguments)
        check_mode = as_bool(
            arguments.get("_ansible_check_mode", False), "_ansible_check_mode"
        )
        return _manage(parameters, check_mode)
    except ValueError as error:
        return {
            "changed": False,
            "failed": True,
            "msg": str(error),
            "exception": "(traceback unavailable)",
        }


def main():
    """Read an Ansible request and emit the metadata module's JSON result.

    :raises SystemExit: After reporting success or failure to Ansible.
    """
    run_module(_response)


if __name__ == "__main__":
    main()
