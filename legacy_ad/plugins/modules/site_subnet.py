#!/usr/bin/python
# -*- coding: utf-8 -*-
# Copyright 2026 sustainablelobster
# Interface documentation derived from microsoft.ad, Copyright 2026 Ansible Project.
# SPDX-License-Identifier: GPL-3.0-or-later

"""Manage Active Directory replication subnets with native Windows LDAP."""

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
module: site_subnet
short_description: Manage Active Directory replication subnets
version_added: '1.0.0'
description:
  - Creates, updates and removes replication subnets through native Windows LDAP APIs.
  - Subnets associate network ranges with sites for domain-controller discovery.
options:
  site:
    description: Name of the replication site associated with this subnet.
    type: str
  location:
    description: Physical location of the subnet.
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
  - The default path is C(CN=Subnets,CN=Sites) in the configuration partition.
  - The directory schema does not allow subnets to move to another container.
  - Names must use valid IPv4 or IPv6 CIDR notation; their spelling is preserved.
  - An omitted site preserves the existing association; an empty site clears it.
  - Operations are not transactional; completed writes remain if a later operation fails.
author:
  - sustainablelobster
  - Ron Gershburg (@rgershbu)
"""

EXAMPLES = r"""
- name: Associate a subnet with a site
  sustainablelobster.legacy_ad.site_subnet:
    name: 10.10.0.0/16
    site: London-Branch
    location: London

- name: Create a subnet without a site association
  sustainablelobster.legacy_ad.site_subnet:
    name: 192.168.1.0/24

- name: Remove a subnet
  sustainablelobster.legacy_ad.site_subnet:
    name: 192.168.1.0/24
    state: absent
"""

RETURN = r"""
object_guid:
  description: Object GUID, null for a missing absent object, or all zeros for predicted creation.
  returned: always
  type: str
distinguished_name:
  description: Distinguished name of the managed subnet, or null for a missing absent object.
  returned: always
  type: str
"""


def execute():
    """Manage a subnet while retaining completed writes in failures.

    :returns: Ansible lifecycle result.
    :rtype: dict
    """
    result = {"changed": False, "distinguished_name": None, "object_guid": None}
    raw = read_arguments(
        (), "sustainablelobster.legacy_ad.site_subnet", allow_unknown=True
    )
    arguments = None
    try:
        arguments = topology_arguments("site_subnet")
        manage_topology(arguments, "site_subnet", result)
    # The payload keeps its JSON entry point and partial-change reporting local.
    # pylint: disable=duplicate-code
    except (OSError, ValueError, UnicodeError) as error:
        result.update({"failed": True, "msg": str(error)})
    return sanitize_result(result, raw, arguments)


def main():
    """Run the subnet payload through the shared Ansible JSON contract."""
    run_module(execute)


if __name__ == "__main__":
    main()
# pylint: enable=duplicate-code
