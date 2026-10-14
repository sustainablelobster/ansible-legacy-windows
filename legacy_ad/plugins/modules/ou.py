#!/usr/bin/python
# -*- coding: utf-8 -*-
# Copyright 2026 sustainablelobster
# Interface documentation derived from microsoft.ad, Copyright 2023 Ansible Project.
# SPDX-License-Identifier: GPL-3.0-or-later

"""Manage organizational units through Windows' authenticated LDAP APIs."""

# WANT_JSON

import traceback

from legacy_ad_object import (  # pylint: disable=import-error
    COMMON_PARAMETERS,
    manage_object,
    object_arguments,
)
from legacy_ad_result import sanitize_result  # pylint: disable=import-error
from legacy_windows_module import (  # pylint: disable=import-error
    read_arguments,
    run_module,
)

DOCUMENTATION = r"""
---
module: ou
short_description: Manage Active Directory organizational units
version_added: '1.0.0'
description:
  - Creates, updates, moves and removes organizational units using native Windows LDAP APIs.
options:
  city:
    description: City stored in the C(l) LDAP attribute.
    type: str
  country:
    description: Two-character country code stored in the C(c) LDAP attribute.
    type: str
  managed_by:
    description:
      - User or group responsible for the OU, stored in C(managedBy).
      - Accepts a DN, GUID, SID, account name, UPN, or a dictionary with C(name) and optional C(server).
    type: raw
  postal_code:
    description: Postal code stored in C(postalCode).
    type: str
  state_province:
    description: State or province stored in C(st).
    type: str
  street:
    description: Street address stored in C(street).
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
  - New OUs default to protection from accidental deletion unless explicitly disabled.
  - Deletion recursively removes child objects, including protected objects.
  - Operations are not transactional; completed writes remain if a later operation fails.
  - Existing deletion protection is restored after a failed move or deletion attempt.
author:
  - sustainablelobster
  - Jordan Borean (@jborean93)
"""

EXAMPLES = r"""
- name: Create a protected OU
  sustainablelobster.legacy_ad.ou:
    name: Deployment
    description: Managed application accounts

- name: Move an existing OU
  sustainablelobster.legacy_ad.ou:
    identity: '{{ deployment_ou.object_guid }}'
    path: OU=Services,DC=example,DC=test

- name: Remove an OU and its children
  sustainablelobster.legacy_ad.ou:
    identity: '{{ deployment_ou.object_guid }}'
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

_PROPERTIES = {
    "description": "description",
    "display_name": "displayName",
    "city": "l",
    "country": "c",
    "managed_by": "managedBy",
    "postal_code": "postalCode",
    "state_province": "st",
    "street": "street",
}
_PARAMETERS = (
    "city",
    "country",
    "managed_by",
    "postal_code",
    "state_province",
    "street",
)


def execute():
    """Manage the requested OU while retaining completed changes on failure.

    :returns: Ansible object lifecycle result.
    :rtype: dict
    """
    result = {"changed": False, "distinguished_name": None, "object_guid": None}
    raw, arguments = {}, None
    try:
        raw = read_arguments(
            COMMON_PARAMETERS + _PARAMETERS,
            "sustainablelobster.legacy_ad.ou",
            allow_unknown=True,
        )
        arguments = object_arguments("sustainablelobster.legacy_ad.ou", _PARAMETERS)
        manage_object(
            arguments,
            "organizationalUnit",
            _PROPERTIES,
            result,
            expected_class="organizationalUnit",
        )
    # Keep each payload's JSON entry point and partial-change reporting local.
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
    """Run the OU payload through the shared Ansible JSON contract."""
    run_module(execute)


if __name__ == "__main__":
    main()
# pylint: enable=duplicate-code
