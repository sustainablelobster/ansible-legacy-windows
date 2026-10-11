#!/usr/bin/python
# -*- coding: utf-8 -*-
# Copyright 2026 sustainablelobster
# SPDX-License-Identifier: GPL-3.0-or-later
"""Manage Windows Server DNS zones through the native DNS WMI provider."""

# WANT_JSON

import re

import legacy_windows_dns_zone as dns  # pylint: disable=import-error
from legacy_windows_module import (  # pylint: disable=import-error
    DOTNET_WHITESPACE,
    as_bool,
    as_string,
    as_string_list,
    read_arguments,
    run_module,
)

DOCUMENTATION = r"""
---
module: win_dns_zone
short_description: Manage Windows Server DNS zones
version_added: '1.0.0'
description:
  - Creates, updates and removes primary, secondary, stub and conditional forwarder zones.
  - Uses Python 3.4.4 and the native DNS Server WMI provider.
options:
  name:
    description: Fully qualified name of the DNS zone.
    type: str
    required: true
  type:
    description:
      - Zone type. When omitted for an existing zone, its current type is retained.
      - Secondary creation requests a zone transfer; this module does not verify that transfer.
    type: str
    choices: [primary, secondary, stub, forwarder]
  dynamic_update:
    description:
      - How a primary zone accepts dynamic updates.
      - Secure updates require an Active Directory-integrated zone.
    type: str
    choices: [secure, none, nonsecureandsecure]
  state:
    description: Whether the zone and its records should exist.
    type: str
    choices: [present, absent]
    default: present
  forwarder_timeout:
    description:
      - Seconds to wait for a forwarding server.
      - Creation accepts nonzero values from 1 through 15; zero is ignored like pinned 3.8.0.
      - Invalid creation values warn; an existing-zone setter can still reject them.
    type: int
  replication:
    description:
      - Active Directory replication scope, or V(none) for a file-backed zone.
      - Changing between file-backed and Active Directory storage is unsupported.
    type: str
    choices: [forest, domain, legacy, none]
  directory_partition:
    description:
      - Name of an existing custom Active Directory application partition.
      - Mutually exclusive with V(forest), V(domain) and V(legacy) replication.
    type: str
  dns_servers:
    description:
      - Primary server addresses for secondary, stub and forwarder zones.
      - Required and nonempty when creating those types; ignored for primary zones.
    type: list
    elements: str
attributes:
  check_mode:
    support: partial
    description:
      - Preserves pinned 3.8.0 behavior rather than predicting a changed flag.
      - Existing zones remain unchanged; a missing zone can fail final lookup after validation.
  diff_mode:
    support: full
requirements:
  - Windows Server with the installed native DNS Server management provider.
  - Administrative permission to manage DNS zones.
notes:
  - The installed modern DNS provider is preferred; the classic MicrosoftDNS provider supplies an older backend without PowerShell.
  - Selecting an Active Directory replication partition on the classic backend additionally requires the installed dnscmd utility and genuine directory storage on the DNS server.
  - The classic DNS service rejects loopback addresses as conditional forwarders; native server address validation is preserved.
  - An unavailable provider fails explicitly before zone writes.
  - The pinned upstream module requires Windows Server 2012 R2 or newer.
  - Existing-zone check mode can return a proposed diff while reporting no change.
  - Check-mode removal reports no change and does not remove the zone.
  - Conversion is supported only to primary or secondary, subject to provider restrictions.
  - Operations are sequential, not transactional; a later failure can retain an earlier write.
author:
  - sustainablelobster
"""

EXAMPLES = r"""
- name: Create a file-backed primary zone
  sustainablelobster.legacy_windows.win_dns_zone:
    name: example.invalid
    type: primary
    replication: none

- name: Configure a conditional forwarder
  sustainablelobster.legacy_windows.win_dns_zone:
    name: internal.example
    type: forwarder
    dns_servers: [192.0.2.53]
    forwarder_timeout: 3

- name: Remove an owned zone and its records
  sustainablelobster.legacy_windows.win_dns_zone:
    name: example.invalid
    state: absent
"""

RETURN = r"""
zone:
  description:
    - New zone properties after a changed present operation.
    - Field presence follows the zone type and provider; unchanged requests omit this object.
  returned: changed present operation
  type: dict
  contains:
    name:
      description: Lowercase zone name.
      type: str
    type:
      description: Lowercase zone type.
      type: str
    paused:
      description: Whether the zone is paused.
      type: bool
    shutdown:
      description: Whether the zone is shut down.
      type: bool
    replication:
      description: Storage replication scope, including custom partitions.
      type: str
    dynamic_update:
      description: Dynamic update mode when supplied by the provider.
      type: str
    reverse_lookup:
      description: Present and true for reverse zones.
      type: bool
    forwarder_timeout:
      description: Forwarder timeout in seconds.
      type: int
    zone_file:
      description: File-backed zone filename, or null where the provider supplies none.
      type: str
    directory_partition:
      description: Custom directory partition name.
      type: str
    dns_servers:
      description: Primary server addresses; one address is a scalar, multiple addresses a list.
      type: raw
"""

_MODULE = "sustainablelobster.legacy_windows.win_dns_zone"
_CHOICES = {
    "type": ("primary", "secondary", "forwarder", "stub"),
    "replication": ("forest", "domain", "legacy", "none"),
    "dynamic_update": ("secure", "none", "nonsecureandsecure"),
    "state": ("absent", "present"),
}
_PARAMETERS = tuple(_CHOICES) + (
    "name",
    "forwarder_timeout",
    "dns_servers",
    "directory_partition",
)


def _timeout(value):
    if value is None:
        return None
    text = as_string(value, "forwarder_timeout").strip(DOTNET_WHITESPACE)
    if not re.match(r"^[+-]?[0-9]+$", text):
        raise ValueError("forwarder_timeout must be a signed 32-bit integer")
    number = int(text)
    if not -(2**31) <= number < 2**31:
        raise ValueError("forwarder_timeout must be a signed 32-bit integer")
    return number


def _parameters(arguments):
    if "name" not in arguments:
        raise ValueError("missing required arguments: name")
    parameters = {"name": as_string(arguments["name"], "name")}
    for name, choices in _CHOICES.items():
        value = as_string(
            arguments.get(name, "present" if name == "state" else None), name
        )
        if value is not None:
            value = value.lower()
            if value not in choices:
                raise ValueError(
                    "{0} must be one of: {1}".format(name, ", ".join(choices))
                )
        parameters[name] = value
    parameters["forwarder_timeout"] = _timeout(arguments.get("forwarder_timeout"))
    parameters["dns_servers"] = as_string_list(
        arguments.get("dns_servers"), "dns_servers"
    )
    parameters["directory_partition"] = as_string(
        arguments.get("directory_partition"), "directory_partition"
    )
    if parameters["directory_partition"] and parameters["replication"] in (
        "forest",
        "domain",
        "legacy",
    ):
        raise ValueError(
            "The directory_partition option is mutually exclusive with replication "
            "values of 'forest', 'domain', and 'legacy'"
        )
    return parameters


def _response():
    arguments = read_arguments(_PARAMETERS, _MODULE)
    return dns.manage(
        _parameters(arguments),
        as_bool(arguments.get("_ansible_check_mode", False), "_ansible_check_mode"),
        as_bool(arguments.get("_ansible_diff", False), "_ansible_diff"),
    )


def main():
    """Read one Ansible request and emit the DNS zone result.

    :raises SystemExit: After reporting a success or actionable failure.
    """
    run_module(_response)


if __name__ == "__main__":
    main()
