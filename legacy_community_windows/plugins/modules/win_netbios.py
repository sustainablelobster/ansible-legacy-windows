#!/usr/bin/python
# -*- coding: utf-8 -*-
# Copyright: (c) 2019, Thomas Moore (@tmmruk)
# Copyright 2026 sustainablelobster
# SPDX-License-Identifier: GPL-3.0-or-later

"""Configure NetBIOS through the installed native network adapter provider."""

# WANT_JSON

from legacy_windows_module import (  # pylint: disable=import-error
    as_bool,
    as_string,
    as_string_list,
    read_arguments,
    run_module,
)
from legacy_windows_wmi import WmiConnection  # pylint: disable=import-error

DOCUMENTATION = r"""
---
module: win_netbios
short_description: Manage NetBIOS over TCP/IP settings on Windows.
description:
  - Enables or disables NetBIOS on Windows network adapters.
  - Can be used to protect a system against NBT-NS poisoning and avoid NBNS broadcast storms.
  - Settings can be applied system wide or per adapter.
options:
  state:
    description:
      - Whether NetBIOS should be enabled, disabled, or default (use setting from DHCP server or if static IP address is assigned enable NetBIOS).
    choices:
      - enabled
      - disabled
      - default
    required: yes
    type: str
  adapter_names:
    description:
      - List of adapter names for which to manage NetBIOS settings. If this option is omitted then configuration is applied to all adapters on the system.
      - The adapter name used is the connection caption in the Network Control Panel or via C(Get-NetAdapter), eg C(Ethernet 2).
    type: list
    elements: str
    required: no

author:
  - Thomas Moore (@tmmruk)
notes:
  - Changing NetBIOS settings does not usually require a reboot and will take effect immediately.
  - UDP port 137/138/139 will no longer be listening once NetBIOS is disabled.
"""

EXAMPLES = r"""
- name: Disable NetBIOS system wide
  sustainablelobster.legacy_community_windows.win_netbios:
    state: disabled

- name: Disable NetBIOS on Ethernet2
  sustainablelobster.legacy_community_windows.win_netbios:
    state: disabled
    adapter_names:
      - Ethernet2

- name: Enable NetBIOS on Public and Backup adapters
  sustainablelobster.legacy_community_windows.win_netbios:
    state: enabled
    adapter_names:
      - Public
      - Backup

- name: Set NetBIOS to system default on all adapters
  sustainablelobster.legacy_community_windows.win_netbios:
    state: default
"""

RETURN = r"""
reboot_required:
    description: Boolean value stating whether a system reboot is required.
    returned: always
    type: bool
    sample: true
"""

_STATES = {"default": 0, "enabled": 1, "disabled": 2}
_PROPERTIES = ("Index", "MacAddress", "TcpipNetbiosOptions", "__PATH")


def _parameters(arguments):
    state = as_string(arguments.get("state"), "state")
    if state is None or state.lower() not in _STATES:
        raise ValueError("state must be enabled, disabled or default.")
    names = as_string_list(arguments.get("adapter_names"), "adapter_names")
    return state.lower(), names


def _select(connection, names):
    if not names:
        return connection.query(
            "SELECT * FROM Win32_NetworkAdapterConfiguration WHERE IPEnabled=TRUE",
            _PROPERTIES,
        )
    adapters = connection.query(
        "SELECT DeviceID, NetConnectionID FROM Win32_NetworkAdapter",
        ("DeviceID", "NetConnectionID"),
    )
    requested = [name.casefold() for name in names]
    indices = {
        int(adapter["DeviceID"])
        for adapter in adapters
        if (adapter["NetConnectionID"] or "").casefold() in requested
    }
    selected = [
        adapter
        for adapter in connection.query(
            "SELECT * FROM Win32_NetworkAdapterConfiguration", _PROPERTIES
        )
        if adapter["Index"] in indices
    ]
    if len(selected) != len(names):
        raise ValueError(
            "Not all of the target adapter names could be found on the system. "
            "No configuration changes have been made: " + ", ".join(names)
        )
    return selected


def _manage(arguments):
    state, names = _parameters(arguments)
    check_mode = as_bool(
        arguments.get("_ansible_check_mode", False), "_ansible_check_mode"
    )
    result = {"changed": False, "reboot_required": False}
    with WmiConnection() as connection:
        adapters = _select(connection, names)
        for adapter in adapters:
            if adapter["TcpipNetbiosOptions"] == _STATES[state]:
                continue
            if not check_mode:
                try:
                    # WMI coerces this decimal BSTR to the method's CIM_UINT32
                    # input, retaining the existing shared helper's contract.
                    response = connection.call_method(
                        adapter["__PATH"],
                        "SetTcpipNetbios",
                        ("ReturnValue",),
                        {"TcpipNetbiosOptions": str(_STATES[state])},
                    )
                except OSError as error:
                    result.update(failed=True, msg=str(error))
                    return result
                code = response["ReturnValue"]
                if code == 1:
                    result["reboot_required"] = True
                elif code == 100:
                    result.setdefault("warnings", []).append(
                        "DHCP not enabled on adapter {0}. Unable to set default. "
                        "Try using disabled or enabled options instead.".format(
                            adapter["MacAddress"]
                        )
                    )
                elif code != 0:
                    result.update(
                        failed=True,
                        msg="An error occurred while setting TcpipNetbios options "
                        "on adapter {0}. Return code {1}.".format(
                            adapter["MacAddress"], code
                        ),
                    )
                    return result
            result["changed"] = True
    return result


def _response():
    return _manage(
        read_arguments(
            ("state", "adapter_names"),
            "sustainablelobster.legacy_community_windows.win_netbios",
        )
    )


def main():
    """Read the module request and emit its JSON result."""
    run_module(_response)


if __name__ == "__main__":
    main()
