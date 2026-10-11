#!/usr/bin/python
# -*- coding: utf-8 -*-
# Copyright 2026 sustainablelobster
# SPDX-License-Identifier: GPL-3.0-or-later

"""Manage Windows hosts entries with a Python 3.4.4 payload."""

# WANT_JSON

import errno

# The action stages these target-compatible helpers beside this payload.
import legacy_windows_hosts as hosts  # pylint: disable=import-error
from legacy_windows_module import (  # pylint: disable=import-error
    as_bool,
    as_string,
    as_string_list,
    read_arguments,
    run_module,
)

# Ansible interfaces must be self-contained; repeated option/return text is
# interface documentation, not duplicated execution logic.
# pylint: disable=duplicate-code
DOCUMENTATION = r"""
---
module: win_hosts
short_description: Manage Windows hosts file entries
version_added: '1.0.0'
description:
  - Associates IPv4 or IPv6 addresses with host names in C(%SystemRoot%\System32\drivers\etc\hosts).
  - Adds, replaces, or removes aliases for a canonical host name.
  - Uses Python 3.4.4.
options:
  state:
    description:
      - Whether matching entries should exist.
      - With V(absent), O(canonical_name) and O(ip_address) select entries to remove.
      - Omit both selectors with V(absent) to remove all host entries. Comments and lines with fewer than two fields before a comment remain.
    type: str
    choices: [absent, present]
    default: present
  canonical_name:
    description:
      - Canonical host name for the entry.
      - Required with O(state=present).
      - With O(state=absent), matches the canonical name rather than an alias.
    type: str
  ip_address:
    description:
      - IPv4 or IPv6 address for the entry.
      - Required with O(state=present).
      - The requested spelling is retained when creating an entry.
    type: str
  aliases:
    description:
      - Additional names associated with the canonical host name.
      - Applies only with O(state=present).
      - String input is split on commas; use a list for a name containing a comma.
    type: list
    elements: str
  action:
    description:
      - How to manage O(aliases) with O(state=present).
      - V(add) adds the requested aliases and retains existing ones.
      - V(remove) removes the requested aliases.
      - V(set) replaces existing aliases with the requested list.
    type: str
    choices: [add, remove, set]
    default: set
attributes:
  check_mode:
    support: full
    description: Predicts the edited hosts entries without writing the file.
  diff_mode:
    support: full
    description: Returns the file's lines before and after editing, joined with LF and a final LF.
notes:
  - The hosts file must already exist, and the executing account needs permission to read it and to write changes.
  - A line with at least two fields before a comment must begin with a parseable IP address. A malformed address causes failure before writing.
  - Changed files are written with the Windows ANSI code page and CRLF line endings. An original Unicode encoding or BOM is not retained; unrepresentable characters can be replaced.
  - Existing addresses are normalized before comparison with O(ip_address). Use normalized address spelling for repeated tasks.
  - Moving a canonical name to another address of the same family removes its old entry. O(action) controls which aliases move with it.
  - Alias conflicts are removed from other entries of the same address family. The pinned upstream implementation leaves the other family unchanged.
  - Host-name matching escapes periods; other regular-expression characters retain their upstream meaning.
author:
  - sustainablelobster
"""

EXAMPLES = r"""
- name: Associate a host name with an IPv4 address and two aliases
  sustainablelobster.legacy_windows.win_hosts:
    canonical_name: application.example.test
    ip_address: 192.0.2.10
    aliases: [application, app]

- name: Remove one alias without replacing the remaining aliases
  sustainablelobster.legacy_windows.win_hosts:
    canonical_name: application.example.test
    ip_address: 192.0.2.10
    action: remove
    aliases: [app]

- name: Remove entries with a given canonical name
  sustainablelobster.legacy_windows.win_hosts:
    state: absent
    canonical_name: application.example.test
"""

RETURN = r"""
{}
"""
# pylint: enable=duplicate-code

_MODULE_NAME = "sustainablelobster.legacy_windows.win_hosts"
_PARAMETERS = ("state", "aliases", "canonical_name", "ip_address", "action")


def _aliases(value):
    if isinstance(value, list) and any(entry is None for entry in value):
        raise ValueError(
            'Unhandled exception while executing module: Exception calling "Create" '
            'with "2" argument(s): "Object reference not set to an instance of an object."'
        )
    kind = None
    if isinstance(value, bool):
        kind = "System.Boolean"
    elif isinstance(value, dict):
        kind = "System.Collections.Hashtable"
    elif isinstance(value, float):
        # Basic binds dotted JSON numbers as Decimal and exponent tokens as Double.
        kind = "System.Double" if "e" in repr(value) else "System.Decimal"
    elif isinstance(value, int) and not -(2**63) <= value < 2**63:
        kind = "System.Decimal" if abs(value) < 2**96 else "System.Double"
    if kind is not None:
        raise ValueError(
            "argument for aliases is of type {0} and we were unable to convert "
            "to list: {0} cannot be converted to a list".format(kind)
        )
    return as_string_list(value, "aliases")


def _parameters(arguments):
    result = {
        "state": as_string(arguments.get("state", "present"), "state"),
        "aliases": _aliases(arguments.get("aliases")),
        "canonical_name": as_string(arguments.get("canonical_name"), "canonical_name"),
        "ip_address": as_string(arguments.get("ip_address"), "ip_address"),
        "action": as_string(arguments.get("action", "set"), "action"),
    }
    for name, choices in (
        ("state", ("absent", "present")),
        ("action", ("add", "remove", "set")),
    ):
        value = result[name]
        if value is not None:
            if value.lower() not in choices:
                raise ValueError(
                    "value of "
                    + name
                    + " must be one of: "
                    + ", ".join(choices)
                    + ". Got no match for: "
                    + value
                )
            result[name] = value.lower()
    if result["state"] == "present":
        missing = [
            name for name in ("canonical_name", "ip_address") if name not in arguments
        ]
        if missing:
            raise ValueError(
                "state is present but all of the following are missing: "
                + ", ".join(missing)
            )
    address = result["ip_address"]
    if address and hosts.parse_address(address) is None:
        raise ValueError(
            "win_hosts: Argument ip_address needs to be a valid ip address, but was "
            + address
        )
    return result


def _manage(parameters, check_mode=False, diff_mode=False):
    before = hosts.read_hosts()
    after, changed = hosts.edit_lines(before, parameters)
    result = {"changed": changed}
    if diff_mode:
        result["diff"] = {
            "before": "\n".join(before) + "\n",
            "after": "\n".join(after) + "\n",
        }
    if changed and not check_mode:
        hosts.write_hosts(after)
    return result


def _response():
    try:
        arguments = read_arguments(_PARAMETERS, _MODULE_NAME)
        parameters = _parameters(arguments)
        check_mode = as_bool(
            arguments.get("_ansible_check_mode", False), "_ansible_check_mode"
        )
        diff_mode = as_bool(arguments.get("_ansible_diff", False), "_ansible_diff")
        return _manage(parameters, check_mode, diff_mode)
    except (OSError, ValueError) as error:
        prefix = "Unhandled exception while executing module: "
        message = str(error)
        if isinstance(error, OSError):
            if error.errno != errno.EACCES or error.filename is None:
                raise
            message = prefix + "Access to the path '{0}' is denied.".format(
                error.filename
            )
        elif not message.startswith(prefix):
            raise
        return {
            "changed": False,
            "failed": True,
            "msg": message,
            "exception": "(traceback unavailable)",
        }


def main():
    """Read an Ansible request and emit the hosts module's JSON result.

    :raises SystemExit: After reporting success or failure to Ansible.
    """
    run_module(_response)


if __name__ == "__main__":
    main()
