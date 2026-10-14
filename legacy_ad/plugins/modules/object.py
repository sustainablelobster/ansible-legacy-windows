#!/usr/bin/python
# -*- coding: utf-8 -*-
# Copyright 2026 sustainablelobster
# Interface documentation derived from microsoft.ad, Copyright 2023 Ansible Project.
# SPDX-License-Identifier: GPL-3.0-or-later

"""Manage generic AD objects through native authenticated Windows LDAP."""

# WANT_JSON

import traceback

from legacy_ad_object import (  # pylint: disable=import-error
    COMMON_PARAMETERS,
    manage_object,
    object_arguments,
)
from legacy_ad_result import sanitize_result  # pylint: disable=import-error
from legacy_windows_module import (  # pylint: disable=import-error
    as_string,
    read_arguments,
    run_module,
)

# Ansible module interface strings must remain self-contained and discoverable.
# pylint: disable=duplicate-code
DOCUMENTATION = r"""
---
module: object
short_description: Manage Active Directory objects
version_added: '1.0.0'
description:
  - Creates, updates, moves and removes objects using native Windows LDAP APIs.
  - Prefer a type-specific module when one exists; this module does not fill in type-specific defaults.
options:
  type:
    description: Structural object class, required when O(state=present). An existing object's type cannot be changed.
    type: str
extends_documentation_fragment:
  - sustainablelobster.legacy_ad.ad_object
  - ansible.builtin.action_common_attributes
attributes:
  check_mode:
    support: full
  diff_mode:
    support: full
  platform:
    platforms: [windows]
notes:
  - Deletion recursively removes child objects, including protected objects.
  - Operations are not transactional; completed writes remain if a later operation fails.
author:
  - sustainablelobster
  - Jordan Borean (@jborean93)
"""

EXAMPLES = r"""
- name: Create a contact
  sustainablelobster.legacy_ad.object:
    name: My Contact
    type: contact
    description: Support contact

- name: Set a container attribute
  sustainablelobster.legacy_ad.object:
    name: Applications
    type: container
    attributes:
      set:
        wWWHomePage: https://example.test

- name: Remove an object
  sustainablelobster.legacy_ad.object:
    identity: '{{ managed_object.object_guid }}'
    state: absent
"""

RETURN = r"""
object_guid:
  description: Object GUID, null for a missing absent object, or all zeros for predicted creation.
  returned: always
  type: str
distinguished_name:
  description: Distinguished name of the managed object, or null for a missing absent object.
  returned: always
  type: str
"""
# pylint: enable=duplicate-code


def execute():
    """Manage the requested object and retain completed writes on failure.

    :returns: Ansible object lifecycle result.
    :rtype: dict
    """
    result = {"changed": False, "distinguished_name": None, "object_guid": None}
    raw, arguments = {}, None
    try:
        raw = read_arguments(
            COMMON_PARAMETERS + ("type",),
            "sustainablelobster.legacy_ad.object",
            allow_unknown=True,
        )
        arguments = object_arguments("sustainablelobster.legacy_ad.object", ("type",))
        object_type = as_string(arguments["type"], "type")
        if arguments["state"] == "present" and not object_type:
            raise ValueError("type is required when state=present.")
        manage_object(
            arguments,
            object_type or "object",
            {"description": "description", "display_name": "displayName"},
            result,
        )
        if arguments["state"] == "present" and arguments["diff_mode"]:
            result["diff"]["after"]["type"] = object_type
            if result["diff"]["before"] is not None:
                result["diff"]["before"]["type"] = object_type
    # Each module keeps its own JSON entry point and completed-change result.
    # pylint: disable=duplicate-code
    except (OSError, ValueError, UnicodeError) as error:
        result.update({"failed": True, "msg": str(error)})
    # Unexpected boundary errors must also pass through credential redaction.
    except Exception as error:  # pylint: disable=broad-exception-caught
        result.update(
            failed=True,
            msg="Unhandled exception while executing module: " + str(error),
            exception=traceback.format_exc(),
        )
    return sanitize_result(result, raw, arguments)


def main():
    """Run the generic object payload through the Ansible JSON contract."""
    run_module(execute)


if __name__ == "__main__":
    main()
# pylint: enable=duplicate-code
