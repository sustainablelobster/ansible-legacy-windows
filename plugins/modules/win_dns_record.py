#!/usr/bin/python
# -*- coding: utf-8 -*-
# Copyright 2026 sustainablelobster
# SPDX-License-Identifier: GPL-3.0-or-later

"""Manage records in an existing Windows DNS Server zone."""

# WANT_JSON

import legacy_windows_dns_record as dns  # pylint: disable=import-error
from legacy_windows_module import (  # pylint: disable=import-error
    as_bool,
    as_string,
    as_string_list,
    read_arguments,
    run_module,
)

DOCUMENTATION = r"""
---
module: win_dns_record
short_description: Manage Windows Server DNS records
version_added: '1.0.0'
description:
  - Adds, updates and removes records in an existing Windows DNS Server zone.
  - Uses the native DNS Server management provider with Python 3.4.4.
  - Uses the installed classic MicrosoftDNS provider when the newer DNS provider is absent.
options:
  name:
    description: Record owner name within the zone.
    type: str
    required: true
  port:
    description: Service port for O(type=SRV).
    type: int
  priority:
    description: Service priority for O(type=SRV).
    type: int
  state:
    description: Whether the selected record type should exist.
    type: str
    choices: [absent, present]
    default: present
  ttl:
    description: Record time to live in seconds, between 1 and 31557600.
    type: int
    default: 3600
  aging:
    description: Whether newly created records receive a scavenging timestamp.
    type: bool
    default: false
  allow_update_any:
    description: Allow any authenticated user to update newly created records.
    type: bool
    default: false
  type:
    description: DNS record type to manage.
    type: str
    required: true
    choices: [A, AAAA, CNAME, DHCID, NS, PTR, SRV, TXT]
  value:
    description:
      - Desired record values; nonempty when O(state=present).
      - Must be omitted or empty when O(state=absent).
    type: list
    elements: str
    aliases: [values]
    default: []
  weight:
    description: Service weight for O(type=SRV).
    type: int
  zone:
    description: Existing zone containing the record.
    type: str
    required: true
  zone_scope:
    description: Optional existing scope within the zone.
    type: str
  computer_name:
    description: DNS server hostname or address; the provider defaults to the local server.
    type: str
attributes:
  check_mode:
    support: full
    description: Predicts changes without writing records.
  diff_mode:
    support: full
    description: Returns the released textual record differences.
requirements:
  - An available native Windows DNS Server management provider.
  - Classic DHCID records, aging, update permissions and Unicode TXT creation require installed C(dnscmd.exe) DNS management tools.
notes:
  - Unlike C(ansible.windows) 3.8.0, SRV creation applies O(ttl) immediately rather than requiring an identical repeat to correct a nondefault lifetime.
  - Classic DNS has no zone scopes; O(zone_scope) requests fail before any record mutation.
  - DHCID support is detected from the installed administration tool, not the Windows version.
  - Classic DHCID and UTF-8 TXT lifetime edits use the native tool and refresh an aged record's timestamp.
  - If an installed DNS tool crashes after a DHCID write, success requires a fresh native confirmation of the exact requested value, lifetime and aging, or its removal.
  - Classic TXT records use UTF-8 where valid; existing non-UTF-8 provider text is retained.
author:
  - sustainablelobster
"""

EXAMPLES = r"""
- name: Manage an address in an existing zone
  sustainablelobster.legacy_windows.win_dns_record:
    name: database
    zone: example.test
    type: A
    value: 192.0.2.10

- name: Remove the address records for a name
  sustainablelobster.legacy_windows.win_dns_record:
    name: database
    zone: example.test
    type: A
    state: absent
"""

RETURN = r"""
debug_splat_args:
  description: Released diagnostic mapping for the last requested addition.
  returned: when adding or previewing a record
  type: dict
"""

_MODULE = "sustainablelobster.legacy_windows.win_dns_record"
_PARAMETERS = (
    "name",
    "port",
    "priority",
    "state",
    "ttl",
    "aging",
    "allow_update_any",
    "type",
    "value",
    "values",
    "weight",
    "zone",
    "zone_scope",
    "computer_name",
)
_TYPES = ("A", "AAAA", "CNAME", "DHCID", "NS", "PTR", "SRV", "TXT")


def _integer_kind(value):
    if isinstance(value, str):
        kind = "String"
    elif isinstance(value, bool):
        kind = "Boolean"
    elif isinstance(value, float):
        kind = "Double" if "e" in repr(value) else "Decimal"
    elif isinstance(value, int):
        if -(2**31) <= value < 2**31:
            kind = "Int32"
        elif -(2**63) <= value < 2**63:
            kind = "Int64"
        elif abs(value) <= 79228162514264337593543950335:
            kind = "Decimal"
        else:
            kind = "Double"
    elif isinstance(value, list):
        kind = "Object[]"
    else:
        kind = "Collections.Hashtable"
    return kind


def _integer(value, name):
    if value is None:
        return None
    # Basic's signed decimal parser accepts ASCII whitespace and trailing nulls,
    # not the broader whitespace accepted by Python or string argument binding.
    text = as_string(value, name).lstrip(" \t\r\n\v\f")
    text = text.rstrip("\x00").rstrip(" \t\r\n\v\f")
    digits = text[1:] if text.startswith(("+", "-")) else text
    detail = "Input string was not in a correct format."
    if digits and all(character in "0123456789" for character in digits):
        number = int(text)
        if -(2**31) <= number < 2**31:
            return number
        detail = "Value was either too large or too small for an Int32."
    raise ValueError(
        "argument for {0} is of type System.{1} and we were unable to convert "
        "to int: {2}".format(name, _integer_kind(value), detail)
    )


def _parameters(arguments):
    missing = [name for name in ("name", "type", "zone") if name not in arguments]
    if missing:
        raise ValueError("missing required arguments: {0}".format(", ".join(missing)))
    result = {
        name: as_string(arguments.get(name), name)
        for name in ("name", "type", "zone", "zone_scope", "computer_name")
    }
    kind = result["type"]
    if kind is not None and kind.upper() not in _TYPES:
        raise ValueError(
            "value of type must be one of: {0}. Got no match for: {1}".format(
                ", ".join(_TYPES), kind
            )
        )
    # The original validates choices without rewriting the user's supplied case.
    result["state"] = as_string(arguments.get("state", "present"), "state")
    if result["state"] is not None and result["state"].lower() not in (
        "absent",
        "present",
    ):
        raise ValueError(
            "value of state must be one of: absent, present. Got no match for: {0}".format(
                result["state"]
            )
        )
    for name in ("port", "priority", "weight", "ttl"):
        result[name] = _integer(
            arguments.get(name, 3600 if name == "ttl" else None), name
        )
    for name in ("aging", "allow_update_any"):
        value = arguments.get(name, False)
        result[name] = None if value is None else as_bool(value, name)
    result["value"] = as_string_list(
        arguments.get("values", arguments.get("value", [])), "value"
    )
    if kind == "SRV":
        missing = [
            name for name in ("port", "priority", "weight") if name not in arguments
        ]
        if missing:
            raise ValueError(
                "type is SRV but all of the following are missing: {0}".format(
                    ", ".join(missing)
                )
            )
    if result["state"] is not None and result["state"].lower() == "present":
        if not result["value"]:
            raise ValueError(
                "Parameter 'values' must be non-empty when state='present'"
            )
    elif result["value"]:
        raise ValueError(
            "Parameter 'values' must be undefined or empty when state='absent'"
        )
    if result["ttl"] is None or not 1 <= result["ttl"] <= 31557600:
        raise ValueError("Parameter 'ttl' must be between 1 and 31557600")
    return result


def _response():
    arguments = read_arguments(_PARAMETERS, _MODULE)
    return dns.manage(
        _parameters(arguments),
        as_bool(arguments.get("_ansible_check_mode", False), "_ansible_check_mode"),
        as_bool(arguments.get("_ansible_diff", False), "_ansible_diff"),
    )


def main():
    """Read one Ansible request and report record changes or an actionable failure.

    :raises SystemExit: After emitting the Ansible JSON response.
    """
    run_module(_response)


if __name__ == "__main__":
    main()
