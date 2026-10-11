#!/usr/bin/python
# -*- coding: utf-8 -*-
# Copyright 2026 sustainablelobster
# SPDX-License-Identifier: GPL-3.0-or-later

"""Manage advanced Windows system audit policy with Python 3.4.4."""

# WANT_JSON

# The action stages these standard-library/native helpers beside this payload.
import legacy_windows_audit_policy as audit_policy  # pylint: disable=import-error
import legacy_windows_environment as environment  # pylint: disable=import-error
from legacy_windows_module import (  # pylint: disable=import-error
    as_bool,
    as_string,
    as_string_list,
    read_arguments,
    run_module,
)

DOCUMENTATION = r"""
---
module: win_audit_policy_system
short_description: Configure advanced system audit policy
version_added: '1.0.0'
description:
  - Enables or disables success and failure auditing for an installed category or subcategory.
  - Uses Python 3.4.4 and the native C(auditpol.exe) utility.
options:
  category:
    description:
      - Installed audit category display name.
      - Changes all subcategories in that category.
      - Exactly one of O(category) and O(subcategory) must be supplied.
    type: str
  subcategory:
    description:
      - Installed audit subcategory display name.
      - Cannot be combined with O(category).
    type: str
  audit_type:
    description:
      - Auditing flags to enable. Both flags are set on every real change.
      - C(none) does not override C(success) or C(failure) when combined with them.
      - An empty list or explicit null disables both flags, as in the pinned upstream module.
    type: list
    elements: str
    required: true
    choices: [failure, none, success]
attributes:
  check_mode:
    support: full
    description: Predicts changes without writing policy; the returned policy remains the current native state.
  diff_mode:
    support: none
notes:
  - Requires the advanced audit-policy feature and permission to query and change system policy.
  - Category names are validated against the target's installed catalogue and matched without case.
  - The pinned upstream CSV contract uses English column names and auditing-setting text.
  - A supplied empty or null selector preserves the upstream unchanged result containing native error text.
  - Back up system audit policy before changing it. This module does not perform automatic rollback.
author:
  - sustainablelobster
"""

EXAMPLES = r"""
- name: Audit failed filesystem access
  sustainablelobster.legacy_windows.win_audit_policy_system:
    subcategory: File System
    audit_type: failure

- name: Audit success and failure for the whole System category
  sustainablelobster.legacy_windows.win_audit_policy_system:
    category: System
    audit_type: [success, failure]

- name: Disable filesystem auditing
  sustainablelobster.legacy_windows.win_audit_policy_system:
    subcategory: File System
    audit_type: none
"""

RETURN = r"""
current_audit_policy:
  description:
    - Selected subcategory names and auditing settings, both in lowercase.
    - In check mode this is the existing policy, not the predicted policy.
    - A supplied empty or null selector returns native error text instead of a mapping.
  returned: success, or when a real setter fails
  type: raw
"""

_MODULE_NAME = "sustainablelobster.legacy_windows.win_audit_policy_system"
_PARAMETERS = ("category", "subcategory", "audit_type")


def _failure(result, message):
    result.update({"failed": True, "msg": message})
    return result


def _parameters(arguments):
    if "audit_type" not in arguments:
        raise ValueError("missing required arguments: audit_type")
    audit_types = as_string_list(arguments["audit_type"], "audit_type") or []
    for value in audit_types:
        if not any(
            environment.values_equal(value, choice)
            for choice in ("failure", "none", "success")
        ):
            raise ValueError(
                "value of audit_type must be one or more of: failure, none, success. "
                "Got no match for: " + value
            )
    if "category" in arguments and "subcategory" in arguments:
        raise ValueError("parameters are mutually exclusive: subcategory, category")
    if "category" not in arguments and "subcategory" not in arguments:
        raise ValueError("one of the following is required: subcategory, category")
    return {
        "category": as_string(arguments.get("category"), "category"),
        "subcategory": as_string(arguments.get("subcategory"), "subcategory"),
        "success": any(
            environment.values_equal(value, "success") for value in audit_types
        ),
        "failure": any(
            environment.values_equal(value, "failure") for value in audit_types
        ),
    }


def _manage(parameters, check_mode):
    result = {"changed": False}
    categories, subcategories = audit_policy.catalogue()
    for selector, catalogue in (
        ("category", categories),
        ("subcategory", subcategories),
    ):
        requested = parameters[selector]
        if requested and not any(
            environment.values_equal(requested, name) for name in catalogue
        ):
            return _failure(
                result,
                (
                    "Invalid category provided"
                    if selector == "category"
                    else "Invalid sub category provided"
                ),
            )
    selector = "category" if parameters["category"] else "subcategory"
    name = parameters[selector] or ""
    previous = audit_policy.get_policy(selector, name)
    flags = parameters["success"], parameters["failure"]
    wanted = {
        (True, True): "success and failure",
        (True, False): "success",
        (False, True): "failure",
        (False, False): "no auditing",
    }[flags]
    values = previous.values() if isinstance(previous, dict) else []
    if all(environment.values_equal(value, wanted) for value in values):
        result["current_audit_policy"] = previous
        return result
    if not check_mode:
        written = audit_policy.set_policy(selector, name, *flags)
        if written["rc"]:
            result["current_audit_policy"] = audit_policy.get_policy(selector, name)
            return _failure(
                result, "Failed to set audit policy " + written.get("stderr", "")
            )
    result["changed"] = True
    result["current_audit_policy"] = audit_policy.get_policy(selector, name)
    return result


def _response():
    try:
        arguments = read_arguments(_PARAMETERS, _MODULE_NAME)
        parameters = _parameters(arguments)
        check_mode = as_bool(
            arguments.get("_ansible_check_mode", False), "_ansible_check_mode"
        )
        return _manage(parameters, check_mode)
    except (OSError, ValueError) as error:
        return _failure({"changed": False}, str(error))


def main():
    """Read the Ansible argument file and emit the audit-policy result.

    :raises SystemExit: After reporting success or failure as JSON.
    """
    run_module(_response)


if __name__ == "__main__":
    main()
