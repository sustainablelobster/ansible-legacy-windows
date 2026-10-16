#!/usr/bin/python
# -*- coding: utf-8 -*-
# Copyright: (c) 2018, Ansible, inc
# Copyright: (c) 2017, Ansible Project
# Copyright 2026 sustainablelobster
# SPDX-License-Identifier: GPL-3.0-or-later

"""Configure the installed Windows SNMP service through its native registry."""

# WANT_JSON

try:
    import winreg
except ImportError:
    winreg = None

from legacy_windows_module import (  # pylint: disable=import-error
    as_bool,
    as_string,
    as_string_list,
    read_arguments,
    run_module,
)

DOCUMENTATION = r"""
---
module: win_snmp
short_description: Configures the Windows SNMP service
description:
    - This module configures the Windows SNMP service.
options:
    permitted_managers:
        description:
        - The list of permitted SNMP managers.
        type: list
        elements: str
    community_strings:
        description:
        - The list of read-only SNMP community strings.
        type: list
        elements: str
    action:
        description:
        - C(add) will add new SNMP community strings and/or SNMP managers
        - C(set) will replace SNMP community strings and/or SNMP managers. An
          empty list for either C(community_strings) or C(permitted_managers)
          will result in the respective lists being removed entirely.
        - C(remove) will remove SNMP community strings and/or SNMP managers
        type: str
        choices: [ add, set, remove ]
        default: set
author:
    - Michael Cassaniti (@mcassaniti)
"""

EXAMPLES = r"""
- name: Replace SNMP communities and managers
  sustainablelobster.legacy_community_windows.win_snmp:
    community_strings:
      - public
    permitted_managers:
      - 192.168.1.2
    action: set

- name: Replace SNMP communities and clear managers
  sustainablelobster.legacy_community_windows.win_snmp:
    community_strings:
      - public
    permitted_managers: []
    action: set
"""

RETURN = r"""
community_strings:
    description: The list of community strings for this machine.
    type: list
    returned: always
    sample:
      - public
      - snmp-ro
permitted_managers:
    description: The list of permitted managers for this machine.
    type: list
    returned: always
    sample:
      - 192.168.1.1
      - 192.168.1.2
"""

_BASE = r"SYSTEM\CurrentControlSet\Services\SNMP\Parameters"


def _read(key):
    values = [
        winreg.EnumValue(key, index) for index in range(winreg.QueryInfoKey(key)[1])
    ]
    return [item for item in values if item[0] and item[0].lower() != "(default)"]


def _desired(existing, requested, action, managers):
    pending = None if requested is None else list(requested)
    retained, removed = [], []
    for name, value, kind in existing:
        candidate = value if managers else name
        remove = False
        if pending is not None and candidate in pending:
            if action == "remove":
                remove = True
            else:
                pending.remove(candidate)
        elif action == "set" and pending is not None:
            remove = True
        if remove:
            removed.append(name)
        else:
            retained.append((name, value, kind))
    added = []
    if action != "remove" and pending is not None:
        indices = {int(name) for name, _, _ in retained} if managers else set()
        index = 0
        for value in pending:
            if managers:
                index += 1
                while index in indices:
                    index += 1
                added.append((str(index), value, winreg.REG_SZ))
            else:
                added.append((value, 4, winreg.REG_DWORD))
    return retained, removed, added


def _apply(key, desired, check_mode):
    retained, removed, added = desired
    if not check_mode:
        for name in removed:
            winreg.DeleteValue(key, name)
        for name, value, kind in added:
            winreg.SetValueEx(key, name, 0, kind, value)
    return retained + added


def _manage(arguments):
    action = (as_string(arguments.get("action", "set"), "action") or "").lower()
    if action not in ("add", "set", "remove"):
        raise ValueError("action must be add, set or remove.")
    managers = as_string_list(arguments.get("permitted_managers"), "permitted_managers")
    communities = as_string_list(
        arguments.get("community_strings"), "community_strings"
    )
    check_mode = as_bool(
        arguments.get("_ansible_check_mode", False), "_ansible_check_mode"
    )
    if winreg is None:
        raise OSError("SNMP configuration requires a Windows target.")
    access = winreg.KEY_READ | (0 if check_mode else winreg.KEY_SET_VALUE)
    with winreg.OpenKey(
        winreg.HKEY_LOCAL_MACHINE, _BASE + r"\PermittedManagers", 0, access
    ) as manager_key:
        with winreg.OpenKey(
            winreg.HKEY_LOCAL_MACHINE, _BASE + r"\ValidCommunities", 0, access
        ) as community_key:
            # Read and validate both lists before changing either registry key.
            manager_plan = _desired(_read(manager_key), managers, action, True)
            community_plan = _desired(_read(community_key), communities, action, False)
            result = {
                "changed": bool(
                    manager_plan[1]
                    or manager_plan[2]
                    or community_plan[1]
                    or community_plan[2]
                ),
                "failed": False,
                "permitted_managers": [],
                "community_strings": [],
            }
            try:
                current_managers = _apply(manager_key, manager_plan, check_mode)
                result["permitted_managers"] = [
                    value for _, value, _ in current_managers
                ]
                current_communities = _apply(community_key, community_plan, check_mode)
                result["community_strings"] = [
                    name for name, _, _ in current_communities
                ]
            except OSError as error:
                result.update(failed=True, msg=str(error))
            return result


def main():
    """Read a module request and emit the SNMP configuration result."""
    run_module(
        lambda: _manage(
            read_arguments(
                ("action", "permitted_managers", "community_strings"),
                "sustainablelobster.legacy_community_windows.win_snmp",
                allow_unknown=True,
            )
        )
    )


if __name__ == "__main__":
    main()
