#!/usr/bin/python
# -*- coding: utf-8 -*-
# Copyright 2026 sustainablelobster
# Interface documentation derived from microsoft.ad, Copyright 2026 Ansible Project.
# SPDX-License-Identifier: GPL-3.0-or-later

"""Manage Active Directory replication links with native Windows LDAP."""

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
module: site_link
short_description: Manage Active Directory replication site links
version_added: '1.0.0'
description:
  - Creates, updates and removes links between replication sites through native Windows LDAP APIs.
options:
  cost:
    description: Relative replication cost of the link. New links default to 100.
    type: int
  replication_frequency:
    description: Replication interval in minutes. New links default to 180 minutes.
    type: int
  sites_included:
    description:
      - Names of the replication sites included in the link.
      - Replaces the existing membership when supplied.
      - Creating a link requires at least two different sites.
    type: list
    elements: str
  intersite_transport_protocol:
    description:
      - Transport protocol for a new site link.
      - An existing link keeps its protocol and warns if a different protocol is requested.
    type: str
    choices: [IP, SMTP]
    default: IP
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
  - The default path is the selected transport container under C(CN=Inter-Site Transports,CN=Sites) in the configuration partition.
  - Site references are validated before changing the link.
  - Operations are not transactional; completed writes remain if a later operation fails.
author:
  - sustainablelobster
  - Ron Gershburg (@rgershbu)
"""

EXAMPLES = r"""
- name: Create an IP replication link
  sustainablelobster.legacy_ad.site_link:
    name: London-NewYork
    sites_included: [London-Branch, NYC-HQ]
    cost: 100
    replication_frequency: 15

- name: Change the sites in a link
  sustainablelobster.legacy_ad.site_link:
    name: London-NewYork
    sites_included: [London-Branch, Boston]

- name: Remove a replication link
  sustainablelobster.legacy_ad.site_link:
    name: London-NewYork
    state: absent
"""

RETURN = r"""
object_guid:
  description: Object GUID, null for a missing absent object, or all zeros for predicted creation.
  returned: always
  type: str
distinguished_name:
  description: Distinguished name of the managed link, or null for a missing absent object.
  returned: always
  type: str
"""


def execute():
    """Manage a site link while retaining completed writes in failures.

    :returns: Ansible lifecycle result.
    :rtype: dict
    """
    result = {"changed": False, "distinguished_name": None, "object_guid": None}
    raw = read_arguments(
        (), "sustainablelobster.legacy_ad.site_link", allow_unknown=True
    )
    arguments = None
    try:
        arguments = topology_arguments("site_link")
        manage_topology(arguments, "site_link", result)
    # The payload keeps its JSON entry point and partial-change reporting local.
    # pylint: disable=duplicate-code
    except (OSError, ValueError, UnicodeError) as error:
        result.update({"failed": True, "msg": str(error)})
    return sanitize_result(result, raw, arguments)


def main():
    """Run the site-link payload through the shared Ansible JSON contract."""
    run_module(execute)


if __name__ == "__main__":
    main()
# pylint: enable=duplicate-code
