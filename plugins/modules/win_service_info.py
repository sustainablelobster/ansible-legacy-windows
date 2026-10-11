#!/usr/bin/python
# -*- coding: utf-8 -*-
# Copyright 2026 sustainablelobster
# SPDX-License-Identifier: GPL-3.0-or-later

"""Read Windows service information with a Python 3.4.4 payload."""

# WANT_JSON

# The action stages the native reader and its dependencies beside the payload.
import legacy_windows_service_info as service_info  # pylint: disable=import-error
from legacy_windows_module import (  # pylint: disable=import-error
    as_bool,
    as_string,
    read_arguments,
    run_module,
)

# Ansible interfaces must be self-contained; repeated option/return text is
# interface documentation, not duplicated execution logic.
# pylint: disable=duplicate-code
DOCUMENTATION = r"""
---
module: win_service_info
short_description: Read Windows service configuration and status
version_added: '1.0.0'
description:
  - Reads installed services without starting, stopping, or configuring them.
  - Uses Python 3.4.4 and native Windows APIs.
options:
  name:
    description:
      - Service key name, display name, or wildcard pattern to select.
      - Omitted, null, and empty values select all ordinary Win32 services.
      - An exact ordinary service key takes precedence over wildcard interpretation.
      - Wildcards match service keys only, not display names or drivers.
      - Literal key or display-name lookup can also select a driver.
    type: str
attributes:
  check_mode:
    support: full
    description: Performs the same read as normal execution and reports no change.
  diff_mode:
    support: none
notes:
  - Targets that reject newer service information levels with error 124 return null for the affected fields and explicit warnings.
  - On such targets, automatic startup has a null RV(services.start_mode) when delayed-start information cannot be read. Other start modes remain available.
  - An unavailable NUMA preferred node reported with error 87 returns null without a warning.
  - Services whose initial open or configuration/status read fails with error 2 or 5 are skipped with a warning.
  - A failed description, dependent-service, or account getter returns null. A failed failure-action getter returns an empty list and null scalar fields.
  - Fatal errors discard partial service results; the module never changes service configuration.
  - Matching and sorting use native language tables, which can differ across Windows versions. Equal sort keys retain enumeration order.
author:
  - sustainablelobster
"""

EXAMPLES = r"""
- name: Read all ordinary services
  sustainablelobster.legacy_windows.win_service_info:
  register: service_info

- name: Read the Remote Procedure Call service
  sustainablelobster.legacy_windows.win_service_info:
    name: RpcSs

- name: Read services whose keys start with Rpc
  sustainablelobster.legacy_windows.win_service_info:
    name: Rpc*

- name: Read a driver by its exact key
  sustainablelobster.legacy_windows.win_service_info:
    name: Tcpip
"""

RETURN = r"""
exists:
  description: Whether at least one selected service was read rather than skipped.
  returned: success
  type: bool
services:
  description:
    - Selected service records in current-culture, case-insensitive name order.
    - An empty list means no selected service could be returned.
  returned: success
  type: list
  elements: dict
  contains:
    checkpoint:
      description: Progress counter reported during a pending service operation.
      type: int
    controls_accepted:
      description: Recognized control requests currently accepted by the service.
      type: list
      elements: str
    dependencies:
      description: Stored dependency names, including load-order groups with their leading plus sign.
      type: list
      elements: str
    dependency_of:
      description: Dependent service keys in native enumeration order, or null if that read fails.
      type: list
      elements: str
    description:
      description: Service description, or null when absent or unreadable.
      type: str
    desktop_interact:
      description: Whether the service type includes the interactive-desktop flag.
      type: bool
    display_name:
      description: Display label stored for the service.
      type: str
    error_control:
      description: Startup error policy; C(ignore), C(normal), C(severe), C(critical), or an unrecognized numeric value as text.
      type: str
    failure_actions:
      description: Configured recovery actions in their stored order; empty when none are available.
      type: list
      elements: dict
      contains:
        type:
          description: C(none), C(restart), C(reboot), or C(run_command); an unmapped action is an empty dictionary.
          type: raw
        delay_ms:
          description: Delay in milliseconds before the action is attempted.
          type: int
    failure_actions_on_non_crash_failure:
      description: Whether recovery actions also apply to qualifying non-crash failures, or null when unavailable.
      type: bool
    failure_command:
      description: Recovery command line, or null when not configured or unreadable.
      type: str
    failure_reboot_msg:
      description: Recovery reboot message, or null when not configured or unreadable.
      type: str
    failure_reset_period_sec:
      description: Seconds before the failure counter resets, or null when the recovery configuration cannot be read.
      type: int
    launch_protection:
      description: C(none), C(windows), C(windows_light), or C(antimalware_light); null when unavailable, or an empty dictionary for an unmapped value.
      type: raw
    load_order_group:
      description: Startup ordering group; an empty string means no group is assigned.
      type: str
    name:
      description: Selected service key name.
      type: str
    path:
      description: Stored executable command line, including arguments and quoting.
      type: str
    pre_shutdown_timeout_ms:
      description: Allowed preshutdown processing time in milliseconds, or null when unavailable.
      type: int
    preferred_node:
      description: Preferred NUMA node number, or null when no value is available.
      type: int
    process_id:
      description: Process identifier reported by the service-control manager.
      type: int
    required_privileges:
      description: Configured privilege names in stored order, or null when unavailable.
      type: list
      elements: str
    service_exit_code:
      description: Service-specific exit status reported by the service-control manager.
      type: int
    service_flags:
      description: Recognized status flags, currently C(runs_in_system_process).
      type: list
      elements: str
    service_type:
      description: Service or driver category after removing interactive and instance flags; an unmapped category is an empty dictionary.
      type: raw
    sid_info:
      description: Service SID token policy as C(none), C(unrestricted), C(restricted), or numeric text; null when unavailable.
      type: str
    start_mode:
      description: C(boot), C(system), C(auto), C(manual), C(disabled), or C(delayed); null when delayed-start information is unsupported, or an empty dictionary when no mode can be mapped.
      type: raw
    state:
      description: C(stopped), C(start_pending), C(stop_pending), C(started), C(continue_pending), C(pause_pending), or C(paused); an unmapped value is an empty dictionary.
      type: raw
    triggers:
      description: Configured service triggers in stored order, or null when unavailable.
      type: list
      elements: dict
      contains:
        action:
          description: C(start_service) or C(stop_service), or an empty dictionary for an unmapped value.
          type: raw
        type:
          description: Recognized event category, such as C(device_interface_arrival), C(network_endpoint), or C(custom); an unmapped category is an empty dictionary.
          type: raw
        sub_type:
          description: Recognized event subtype name, or C(custom) for other GUIDs.
          type: str
        sub_type_guid:
          description: Event subtype GUID in hyphenated text form.
          type: str
        data_items:
          description: Additional trigger values in their stored order.
          type: list
          elements: dict
          contains:
            type:
              description: C(binary), C(string), C(level), C(keyword_any), or C(keyword_all); an unmapped value is an empty dictionary.
              type: raw
            data:
              description: Text, a string list, an unsigned keyword integer, or base64 text for binary and level values.
              type: raw
    username:
      description: Configured account name, with LocalSystem translated to its localized name; null when absent or unreadable.
      type: str
    wait_hint_ms:
      description: Estimated milliseconds needed for a pending operation.
      type: int
    win32_exit_code:
      description: Win32 exit status reported by the service-control manager.
      type: int
warnings:
  description: Messages identifying skipped services or unavailable newer information fields.
  returned: success when a warning was recorded
  type: list
  elements: str
"""
# pylint: enable=duplicate-code

_MODULE_NAME = "sustainablelobster.legacy_windows.win_service_info"


def _services(name):
    services, warnings = [], []
    for selected_name in service_info.select_names(name):
        try:
            entry = service_info.query_service(selected_name, warnings)
        except service_info.ServiceOpenError as error:
            if error.winerror not in (2, 5):
                raise
            warnings.append(
                "Failed to open service '{0} to get more info, ignoring: {1}".format(
                    selected_name, error
                )
            )
        else:
            services.append(entry)
    result = {"changed": False, "exists": bool(services), "services": services}
    if warnings:
        result["warnings"] = warnings
    return result


def _response():
    arguments = read_arguments(("name",), _MODULE_NAME)
    name = as_string(arguments.get("name"), "name")
    try:
        result = _services(name)
    except (OSError, ValueError) as error:
        # The upstream wrapper discards module results on an unhandled read error.
        raise RuntimeError(str(error)) from error
    if as_bool(
        arguments.get("_ansible_inject_invocation", False), "_ansible_inject_invocation"
    ):
        result["invocation"] = {"module_args": {"name": name}}
    return result


def main():
    """Read Ansible arguments and emit the read-only service query result.

    :raises SystemExit: After reporting success or failure as JSON.
    """
    run_module(_response)


if __name__ == "__main__":
    main()
