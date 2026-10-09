#!/usr/bin/python
# -*- coding: utf-8 -*-
# Copyright 2026 Joe Lustri
# SPDX-License-Identifier: GPL-3.0-or-later

"""Manage installed Windows Firewall profile settings through native APIs."""

# WANT_JSON

import legacy_windows_firewall as firewall  # pylint: disable=import-error
from legacy_windows_module import (  # pylint: disable=import-error
    as_bool,
    as_string,
    as_string_list,
    read_arguments,
    run_module,
)

DOCUMENTATION = r"""
---
module: win_firewall
short_description: Enable or disable Windows Firewall profiles
version_added: '1.0.0'
description:
  - Manages the configured Domain, Private, and Public Windows Firewall profiles.
  - Uses the native configured-profile provider when available, otherwise the installed firewall policy API.
options:
  profiles:
    description: Profiles to consider, preserving their supplied order and spelling in the result.
    type: list
    elements: str
    choices: [Domain, Private, Public]
    default: [Domain, Private, Public]
  state:
    description: Desired enabled or disabled state for the selected profiles.
    required: true
    type: str
    choices: [enabled, disabled]
  inbound_action:
    description:
      - Configured default action for inbound traffic when O(state=enabled).
      - V(not_configured) restores the unset policy value, not the effective traffic default.
    type: str
    choices: [allow, block, not_configured]
  outbound_action:
    description:
      - Configured default action for outbound traffic when O(state=enabled).
      - V(not_configured) restores the unset policy value, not the effective traffic default.
    type: str
    choices: [allow, block, not_configured]
attributes:
  check_mode:
    support: full
    description: Predicts enabled-state and action changes without writing profile settings.
  diff_mode:
    support: none
notes:
  - Profiles are read and changed in Domain, Private, Public order, regardless of O(profiles) order.
  - Each result records the enabled enum read before changing that profile. In check mode, C(enabled) predicts the requested change.
  - Action options are ignored with O(state=disabled). The configured provider's enabled-state enum of NotConfigured is left unchanged by either state request.
  - Earlier profile or property writes can remain after a later failure. No restart is requested.
  - The older three-profile policy API supports enabled state and allow/block actions, but not a NotConfigured action reset.
  - Older policy APIs report C(currentstate) as 0 or 1; they do not expose the configured provider's unset enabled-state enum.
  - Classic Domain/Standard firewalls support explicit C(profiles=[Domain]) enabled-state changes. Private/Public profiles and configurable default actions are unavailable.
  - Older policy APIs reject unavailable selected profiles and enabled-state action settings before any profile write.
  - Classic Standard cannot be selected through this module's upstream profile choices and is not an alias for Private/Public. Unavailable profile objects are omitted from results.
  - Changing active firewall settings can affect connectivity.
author:
  - Joe Lustri
"""

EXAMPLES = r"""
- name: Enable all three profiles
  sustainablelobster.legacy_windows.win_firewall:
    state: enabled

- name: Configure the inactive Domain profile
  sustainablelobster.legacy_windows.win_firewall:
    profiles: [Domain]
    state: enabled
    inbound_action: block
    outbound_action: allow

- name: Enable the Domain profile on a classic firewall
  sustainablelobster.legacy_windows.win_firewall:
    profiles: [Domain]
    state: enabled
"""

RETURN = r"""
profiles:
  description: Requested profile list, retaining its order, duplicates, and spelling.
  returned: always after argument validation
  type: list
  elements: str
state:
  description: Requested state, retaining its supplied spelling.
  returned: always after argument validation
  type: str
restart_required:
  description: Whether a restart is needed; always false.
  returned: always after argument validation
  type: bool
Domain:
  description: Domain profile observation and predicted enabled state.
  returned: success, or failure after reading this profile
  type: dict
  contains: &profile_result
    currentstate:
      description: Enabled enum read before this profile's changes; 0 is False, 1 is True, and 2 is NotConfigured.
      type: int
    enabled:
      description: Whether the profile is enabled after any successful or predicted state change.
      type: bool
    considered:
      description: Whether the requested profile list selects this profile.
      type: bool
Private:
  description: Private profile observation and predicted enabled state.
  returned: success, or failure after reading this profile
  type: dict
  contains: *profile_result
Public:
  description: Public profile observation and predicted enabled state.
  returned: success, or failure after reading this profile
  type: dict
  contains: *profile_result
"""

_PARAMETERS = ("profiles", "state", "inbound_action", "outbound_action")


def _choices(values, name, choices, multiple=False):
    if values is None:
        return
    entries = values if multiple else [values]
    invalid = []
    for value in entries:
        if value.lower() not in [choice.lower() for choice in choices]:
            if value.lower() not in [entry.lower() for entry in invalid]:
                invalid.append(value)
    if invalid:
        raise ValueError(
            "value of {0} must be {1}: {2}. Got no match for: {3}".format(
                name,
                "one or more of" if multiple else "one of",
                ", ".join(choices),
                ", ".join(invalid),
            )
        )


def _parameters(arguments):
    if "state" not in arguments:
        raise ValueError("missing required arguments: state")
    state = as_string(arguments["state"], "state")
    profiles = as_string_list(
        arguments.get("profiles", list(firewall.PROFILES)), "profiles"
    )
    _choices(state, "state", ("disabled", "enabled"))
    _choices(profiles, "profiles", firewall.PROFILES, True)
    parameters = {"state": state, "profiles": profiles}
    for name in ("inbound_action", "outbound_action"):
        value = as_string(arguments.get(name), name)
        _choices(value, name, ("allow", "block", "not_configured"))
        parameters[name] = value.lower() if value is not None else None
    return parameters


def _set_property(native, profile, name, value, check_mode):
    if not check_mode:
        native.set_property(profile, name, value)


def _enable(native, profile, parameters, result, check_mode):
    if profile["Enabled"] == 0:
        _set_property(native, profile, "Enabled", 1, check_mode)
        result["changed"] = True
        result[profile["Name"]]["enabled"] = True
    for option, property_name in (
        ("inbound_action", "DefaultInboundAction"),
        ("outbound_action", "DefaultOutboundAction"),
    ):
        desired = parameters[option]
        if desired is None:
            continue
        value = firewall.ACTION_VALUES[desired]
        if value != profile[property_name]:
            _set_property(native, profile, property_name, value, check_mode)
            result["changed"] = True


def _manage(parameters, result, check_mode):
    with firewall.FirewallProfiles() as native:
        native.validate_request(parameters)
        for name in native.available_profiles:
            try:
                profile = native.read(name)
                current = profile["Enabled"]
                selected = any(
                    requested.lower() == name.lower()
                    for requested in parameters["profiles"] or []
                )
                observation = {
                    "currentstate": current,
                    "enabled": current == 1,
                    "considered": selected,
                }
                result[name] = observation
                if not selected:
                    continue
                if parameters["state"] and parameters["state"].lower() == "enabled":
                    _enable(native, profile, parameters, result, check_mode)
                elif current == 1:
                    _set_property(native, profile, "Enabled", 0, check_mode)
                    result["changed"] = True
                    observation["enabled"] = False
            except (OSError, ValueError) as error:
                result.update(
                    failed=True,
                    msg="an error occurred when attempting to change firewall status "
                    "for profile {0} {1}".format(name, error),
                )
                return


def _response():
    arguments = read_arguments(
        _PARAMETERS,
        "sustainablelobster.legacy_windows.win_firewall",
    )
    parameters = _parameters(arguments)
    result = {
        "changed": False,
        "restart_required": False,
        "profiles": parameters["profiles"],
        "state": parameters["state"],
    }
    try:
        _manage(
            parameters,
            result,
            as_bool(arguments.get("_ansible_check_mode", False), "_ansible_check_mode"),
        )
    except (OSError, ValueError) as error:
        result.update(failed=True, msg=str(error))
    return result


def main():
    """Execute native profile management and emit the public Ansible result.

    :raises SystemExit: With zero on success or one on failure.
    """
    run_module(_response)


if __name__ == "__main__":
    main()
