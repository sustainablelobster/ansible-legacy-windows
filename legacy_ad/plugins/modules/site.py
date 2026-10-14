#!/usr/bin/python
# -*- coding: utf-8 -*-
# Copyright 2026 sustainablelobster
# Interface documentation derived from microsoft.ad, Copyright 2026 Ansible Project.
# SPDX-License-Identifier: GPL-3.0-or-later

"""Manage Active Directory replication sites with native Windows LDAP."""

# WANT_JSON

from legacy_ad_result import sanitize_result  # pylint: disable=import-error
from legacy_ad_topology import (  # pylint: disable=import-error
    manage_topology,
    topology_arguments,
)
from legacy_windows_module import (  # pylint: disable=import-error
    read_arguments,
    run_module,
)

# Public module documentation and result fields intentionally share the upstream contract.
# pylint: disable=duplicate-code
DOCUMENTATION = r"""
---
module: site
short_description: Manage Active Directory replication sites
version_added: '1.0.0'
description:
  - Creates, updates and removes replication sites using native Windows LDAP APIs.
  - Sites control replication traffic and help clients discover nearby domain controllers.
options:
  managed_by:
    description:
      - User or group that manages the site, stored in C(managedBy).
      - Accepts a DN, GUID, SID, account name, UPN, or a dictionary with C(name) and optional C(server).
    type: raw
  automatic_inter_site_topology_generation_enabled:
    description: Whether the KCC automatically generates inter-site replication connections.
    type: bool
  automatic_topology_generation_enabled:
    description: Whether the KCC automatically generates intra-site replication connections.
    type: bool
  universal_group_caching_enabled:
    description: Whether Universal Group Membership Caching is enabled for this site.
    type: bool
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
  - The default path is C(CN=Sites) in the directory configuration partition.
  - The directory schema does not allow sites to move to another container.
  - Sites include their C(Servers) and C(NTDS Site Settings) child objects; missing children are created on a repeated request.
  - Deletion recursively removes child objects, including protected objects.
  - Operations are not transactional; completed writes remain if a later operation fails.
author:
  - sustainablelobster
  - Ron Gershburg (@rgershbu)
"""

EXAMPLES = r"""
- name: Create a replication site
  sustainablelobster.legacy_ad.site:
    name: London-Branch
    description: London branch office

- name: Enable group membership caching
  sustainablelobster.legacy_ad.site:
    name: London-Branch
    universal_group_caching_enabled: true

- name: Remove a site and its children
  sustainablelobster.legacy_ad.site:
    name: London-Branch
    state: absent
"""

RETURN = r"""
object_guid:
  description: Object GUID, null for a missing absent object, or all zeros for predicted creation.
  returned: always
  type: str
distinguished_name:
  description: Distinguished name of the managed site, or null for a missing absent object.
  returned: always
  type: str
"""


def execute():
    """Manage a site while retaining completed writes in failures.

    :returns: Ansible lifecycle result.
    :rtype: dict
    """
    result = {"changed": False, "distinguished_name": None, "object_guid": None}
    raw = read_arguments((), "sustainablelobster.legacy_ad.site", allow_unknown=True)
    arguments = None
    try:
        arguments = topology_arguments("site")
        manage_topology(arguments, "site", result)
    # The payload keeps its JSON entry point and partial-change reporting local.
    # pylint: disable=duplicate-code
    except (OSError, ValueError, UnicodeError) as error:
        result.update({"failed": True, "msg": str(error)})
    return sanitize_result(result, raw, arguments)


def main():
    """Run the site payload through the shared Ansible JSON contract."""
    run_module(execute)


if __name__ == "__main__":
    main()
# pylint: enable=duplicate-code
