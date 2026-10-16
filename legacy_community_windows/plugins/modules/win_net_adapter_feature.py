#!/usr/bin/python
# -*- coding: utf-8 -*-

# Copyright: (c) 2020, ライトウェルの人 <jiro.higuchi@shi-g.com>
# Copyright 2026 sustainablelobster
# SPDX-License-Identifier: GPL-3.0-or-later

"""Manage installed adapter components through native binding paths."""

# WANT_JSON

from legacy_community_windows_net_adapter_feature_native import (  # pylint: disable=import-error
    NetworkBindings,
)
from legacy_windows_module import (  # pylint: disable=import-error
    as_bool,
    as_string,
    as_string_list,
    read_arguments,
    run_module,
)

DOCUMENTATION = r"""
---
module: win_net_adapter_feature
short_description: Enable or disable network adapter components
description:
  - Enable or disable some network components of a certain network adapter or all the network adapters.
options:
  interface:
    description:
      - Name of Network Adapter Interface. For example, C(Ethernet0) or C(*).
    type: list
    elements: str
    required: yes
  state:
    description:
      - Requested state of each component binding on the selected interfaces.
    type: str
    choices: [ enabled, disabled ]
    default: enabled
    required: no
  component_id:
    description:
      - Specify the below component_id of network adapters.
      - component_id (DisplayName)
      - C(ms_implat) (Microsoft Network Adapter Multiplexor Protocol)
      - C(ms_lltdio) (Link-Layer Topology Discovery Mapper I/O Driver)
      - C(ms_tcpip6) (Internet Protocol Version 6 (TCP/IPv6))
      - C(ms_tcpip) (Internet Protocol Version 4 (TCP/IPv4))
      - C(ms_lldp) (Microsoft LLDP Protocol Driver)
      - C(ms_rspndr) (Link-Layer Topology Discovery Responder)
      - C(ms_msclient) (Client for Microsoft Networks)
      - C(ms_pacer) (QoS Packet Scheduler)
      - If you'd like to set custom adapters like 'Juniper Network Service', get the I(component_id) by running the C(Get-NetAdapterBinding) cmdlet.
    type: list
    elements: str
    required: yes
notes:
  - Requires administrative access to the installed native network configuration service. The requested components must be installed and have binding paths to the selected adapters.
  - Uses native binding paths rather than requiring NetAdapter cmdlets. Adapter names are connection names, matched case-insensitively; C(*) selects all named adapters.
  - A component with multiple native paths to an adapter has all of those paths set to the requested state. Missing adapter bindings fail before any changes are applied.
  - Check mode only reads configuration and predicts changes. Normal changes acquire the system network configuration lock and are applied together.
  - Binding changes can interrupt networking. Windows may require a restart; the module warns when the native API reports this and does not restart Windows.
  - Use asynchronous execution for changes that may interrupt the connection. Native network rebinding can also drop its launch acknowledgment, so prefer an adapter separate from the Ansible connection and arrange out-of-band recovery for connectivity changes.
author:
  - sustainablelobster
  - ライトウェルの人 (@jirolin)
"""

EXAMPLES = r"""
- name: Enable components on two adapters
  sustainablelobster.legacy_community_windows.win_net_adapter_feature:
    interface:
      - Ethernet0
      - Ethernet1
    state: enabled
    component_id:
      - ms_tcpip6
      - ms_server

- name: Enable IPv6 on all named adapters
  sustainablelobster.legacy_community_windows.win_net_adapter_feature:
    interface: '*'
    state: enabled
    component_id:
      - ms_tcpip6
"""

RETURN = """"""


def _select_adapters(adapters, interfaces):
    if "*" in interfaces:
        return adapters
    names = {name.lower(): name for name in adapters}
    selected = {}
    for name in interfaces:
        if name.lower() not in names:
            raise ValueError("Invalid network adapter name: " + name)
        canonical = names[name.lower()]
        selected[canonical] = adapters[canonical]
    return selected


def _changed_paths(bindings, adapters, components, enabled):
    changes = []
    for component in components:
        paths = bindings.paths(component, adapters)
        for name in adapters:
            if not paths[name]:
                raise ValueError(
                    "Component " + component + " has no binding on adapter " + name
                )
            changes.extend(path for path in paths[name] if path["enabled"] != enabled)
    return changes


def _manage(arguments):
    interfaces = as_string_list(arguments.get("interface"), "interface")
    components = as_string_list(arguments.get("component_id"), "component_id")
    if interfaces is None or components is None:
        raise ValueError("interface and component_id are required")
    state = as_string(arguments.get("state", "enabled"), "state")
    if state not in ("enabled", "disabled"):
        raise ValueError("state must be enabled or disabled")
    enabled = state == "enabled"
    check_mode = as_bool(arguments.get("_ansible_check_mode", False), "check mode")
    with NetworkBindings(not check_mode) as bindings:
        adapters = _select_adapters(bindings.adapters(), interfaces)
        changes = _changed_paths(bindings, adapters, components, enabled)
        result = {"changed": bool(changes)}
        if changes and not check_mode:
            for path in changes:
                bindings.enable(path, enabled)
            try:
                if bindings.apply():
                    result["warnings"] = [
                        "Windows reports that these binding changes require a restart."
                    ]
            except OSError as error:
                result.update(failed=True, msg=str(error))
        return result


def _execute():
    return _manage(
        read_arguments(
            ("interface", "component_id", "state"),
            "sustainablelobster.legacy_community_windows.win_net_adapter_feature",
        )
    )


def main():
    """Run adapter binding management using the JSON module protocol."""
    run_module(_execute)


if __name__ == "__main__":
    main()
