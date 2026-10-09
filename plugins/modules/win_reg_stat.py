#!/usr/bin/python
# -*- coding: utf-8 -*-
# Copyright 2026 Joe Lustri
# SPDX-License-Identifier: GPL-3.0-or-later

"""Read Windows registry keys and values with a Python 3.4.4 payload."""

# WANT_JSON

import re

# The action stages these Python 3.4-compatible helpers beside the payload.
import legacy_windows_reg_stat as registry  # pylint: disable=import-error
from legacy_windows_module import (  # pylint: disable=import-error
    as_string,
    read_arguments,
    run_module,
)

DOCUMENTATION = r"""
---
module: win_reg_stat
short_description: Read Windows registry keys and values
version_added: '1.0.0'
description:
  - Reports whether a registry key or value exists, without changing the registry.
  - Returns the immediate subkeys and values when no value name is selected.
  - Uses Python 3.4.4 and native Windows APIs.
options:
  path:
    description:
      - Registry key path starting with C(HKCC:\), C(HKCR:\), C(HKCU:\), C(HKLM:\), or C(HKU:\).
      - Registry key names are literal; wildcard characters are not expanded.
      - When both O(path) and its alias are supplied, O(path) takes precedence, including a null value.
    type: str
    required: true
    aliases: [key]
  name:
    description:
      - Name of a single registry value to read.
      - Omit this option or supply null to list the key's values and immediate subkeys.
      - An empty string selects the unnamed default value; C((Default)) selects that literal named value.
      - O(name) takes precedence over C(entry), which takes precedence over C(value), including null values.
    type: str
    aliases: [entry, value]
attributes:
  check_mode:
    support: full
    description: Reads the same current state as normal execution, without making changes.
  diff_mode:
    support: none
notes:
  - Uses the registry view of the target Python process; there is no option to select another view.
  - Expandable strings use the module process's environment for RV(value), while RV(raw_value) retains the stored text.
  - An unset default value is absent; an explicitly stored empty default value exists.
  - As upstream, the unnamed default value is reported as C(REG_SZ) regardless of its stored registry kind.
  - The upstream documentation lists C(property) as an alias, but the implementation ignores it. Use O(name), C(entry), or C(value).
author:
  - Joe Lustri
"""

EXAMPLES = r"""
- name: Read an application's registry key
  sustainablelobster.legacy_windows.win_reg_stat:
    path: HKCU:\Software\Application

- name: Read a named value
  sustainablelobster.legacy_windows.win_reg_stat:
    path: HKLM:\Software\Application
    name: InstallationPath

- name: Read the unnamed default value
  sustainablelobster.legacy_windows.win_reg_stat:
    path: HKCU:\Software\Application
    name: ''
"""

RETURN = r"""
exists:
  description: Whether the requested key or selected value exists.
  returned: success
  type: bool
properties:
  description:
    - Mapping of value names to their C(type), C(value), and C(raw_value) fields.
    - Values with unsupported stored registry kinds have null entries; selecting one directly reports RV(exists=false).
    - The empty name represents the unnamed default value and is included only when set.
  returned: success when the key exists and no value name is selected
  type: dict
sub_keys:
  description: Names of the key's immediate subkeys, without their parent path.
  returned: success when the key exists and no value name is selected
  type: list
  elements: str
type:
  description: Registry kind of the selected value, except that the unnamed default always reports C(REG_SZ).
  returned: success when a selected value exists
  type: str
value:
  description:
    - Selected value as text, an integer, a list of strings, or a list of integer bytes.
    - Expandable strings are expanded using the module process's environment.
    - Named DWORD and QWORD values are unsigned integers.
  returned: success when a selected value exists
  type: raw
raw_value:
  description:
    - Selected value before environment expansion.
    - Named binary and C(REG_NONE) values are lists of lowercase hexadecimal byte strings, such as C(0x01).
    - String-list and integer values use the same representation as RV(value).
  returned: success when a selected value exists
  type: raw
"""

_MODULE_NAME = "sustainablelobster.legacy_windows.win_reg_stat"
_PARAMETERS = ("path", "key", "name", "entry", "value")
_REGISTRY_PREFIX = re.compile(r"^(HK(?:CC|CR|CU|LM|U)):\\", re.IGNORECASE)


def _parameters(arguments):
    if "path" not in arguments and "key" not in arguments:
        raise ValueError("Get-AnsibleParam: Missing required argument: path")
    path = as_string(arguments.get("path", arguments.get("key")), "path")
    name = as_string(
        arguments.get("name", arguments.get("entry", arguments.get("value"))), "name"
    )
    prefix = _REGISTRY_PREFIX.match(path) if path is not None else None
    if prefix is None:
        raise ValueError(
            "path: "
            + (path or "")
            + " is not a valid registry path, see module documentation for examples."
        )
    return {
        "hive": prefix.group(1).upper(),
        "subkey": path[prefix.end() :],
        "name": name,
    }


def _response():
    arguments = read_arguments(_PARAMETERS, _MODULE_NAME, allow_unknown=True)
    parameters = _parameters(arguments)
    result = {"changed": False}
    result.update(
        registry.query_key(parameters["hive"], parameters["subkey"], parameters["name"])
    )
    return result


def main():
    """Read Ansible arguments and emit the module's JSON result.

    :raises SystemExit: After reporting success or failure to Ansible.
    """
    run_module(_response)


if __name__ == "__main__":
    main()
