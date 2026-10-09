#!/usr/bin/python
# -*- coding: utf-8 -*-
# Copyright 2026 Joe Lustri
# SPDX-License-Identifier: GPL-3.0-or-later

"""Manage classic Windows event logs with Python 3.4.4 and native APIs."""

# WANT_JSON

import re

import legacy_windows_environment as environment  # pylint: disable=import-error
import legacy_windows_eventlog as eventlog  # pylint: disable=import-error
from legacy_windows_module import (  # pylint: disable=import-error
    as_bool,
    as_path,
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
module: win_eventlog
short_description: Manage local classic Windows event logs and sources
version_added: '1.0.0'
description:
  - Creates, configures, clears, and removes local classic event logs and sources.
  - Uses Python 3.4.4, the registry, and native Windows event-log APIs.
options:
  name:
    description: Name of the classic event log to manage.
    type: str
    required: true
  state:
    description:
      - Desired state of the log or specified sources.
      - V(clear) removes all event entries from the log.
      - With O(sources), V(absent) removes those sources; otherwise it removes the whole log.
    type: str
    choices: [absent, clear, present]
    default: present
  sources:
    description:
      - Sources to create or remove. Creating a new log requires at least one source.
      - Resource paths apply to every specified source.
    type: list
    elements: str
  category_file:
    description: Custom category resource path for specified sources.
    type: path
  message_file:
    description: Custom event-message resource path for specified sources.
    type: path
  parameter_file:
    description: Custom parameter resource path for specified sources.
    type: path
  maximum_size:
    description:
      - Maximum log size expressed in KB, MB, or GB, for example V(16MB).
      - Must be at least 64KB, less than 4GB, and divisible by 64KB.
    type: str
  overflow_action:
    description: Whether to retain all events, overwrite oldest events, or overwrite older events.
    type: str
    choices: [DoNotOverwrite, OverwriteAsNeeded, OverwriteOlder]
  retention_days:
    description: Retention from 1 through 365 days, valid only with V(OverwriteOlder).
    type: int
attributes:
  check_mode:
    support: full
    description: Predicts changed without writing; returned details describe the actual log.
  diff_mode:
    support: none
notes:
  - Changing a resource path removes and recreates that source. Omitted resource paths reset to creation defaults.
  - The default source has the same name as its log. Remove the whole log to remove or change that source.
  - Changes happen in source order before maximum-size validation; earlier writes can remain after a later failure.
  - Log removal clears entries and removes registration. An open log file can remain on disk until the Event Log service or host restarts.
  - Default message-resource paths are registered without loading managed code. On legacy hosts without the resource DLL, supply O(message_file) for event-message rendering.
  - This module manages classic logs, not manifest event channels.
author:
  - Joe Lustri
"""

EXAMPLES = r"""
- name: Create a classic log with two sources
  sustainablelobster.legacy_windows.win_eventlog:
    name: Deployment
    sources: [DeploymentAgent, DeploymentInstaller]
    maximum_size: 16MB
    overflow_action: OverwriteOlder
    retention_days: 7

- name: Clear the owned log
  sustainablelobster.legacy_windows.win_eventlog:
    name: Deployment
    state: clear

- name: Remove the log and all of its sources
  sustainablelobster.legacy_windows.win_eventlog:
    name: Deployment
    state: absent
"""

RETURN = r"""
name:
  description: Requested event-log name.
  returned: always
  type: str
exists:
  description: Whether the log currently exists.
  returned: success
  type: bool
entries:
  description: Current event-entry count.
  returned: success when the log exists
  type: int
maximum_size_kb:
  description: Configured maximum size in kilobytes.
  returned: success when the log exists
  type: int
overflow_action:
  description: Configured overflow action.
  returned: success when the log exists
  type: str
retention_days:
  description: Configured minimum retention days; 0 or -1 for the other overflow policies.
  returned: success when the log exists
  type: int
sources:
  description: Current registered source names in registry enumeration order.
  returned: success when the log exists
  type: list
  elements: str
sources_changed:
  description: Sources created, recreated, or removed. Empty in check mode.
  returned: always after argument parsing
  type: list
  elements: str
"""
# pylint: enable=duplicate-code

_PARAMETERS = (
    "name",
    "state",
    "sources",
    "category_file",
    "message_file",
    "parameter_file",
    "maximum_size",
    "overflow_action",
    "retention_days",
)
_ACTIONS = ("OverwriteOlder", "OverwriteAsNeeded", "DoNotOverwrite")


def _choice(arguments, name, default, choices):
    value = as_string(arguments.get(name, default), name)
    for candidate in choices:
        if environment.values_equal(value, candidate):
            return candidate
    if value is None:
        return None
    raise ValueError(
        "Get-AnsibleParam: Argument "
        + name
        + " needs to be one of "
        + ",".join(choices)
        + " but was "
        + value
        + "."
    )


def _parameters(arguments):
    if "name" not in arguments:
        raise ValueError("Get-AnsibleParam: Missing required argument: name")
    name = as_string(arguments["name"], "name")
    if not name:
        raise ValueError("Get-AnsibleParam: Missing required argument: name")
    parameters = {
        "name": name,
        "state": _choice(arguments, "state", "present", ("present", "clear", "absent")),
        "sources": as_string_list(arguments.get("sources"), "sources") or [],
        "maximum_size": as_string(arguments.get("maximum_size"), "maximum_size"),
        "overflow_action": _choice(arguments, "overflow_action", None, _ACTIONS),
    }
    for option in ("category_file", "message_file", "parameter_file"):
        parameters[option] = as_path(arguments.get(option), option)
    days = arguments.get("retention_days")
    parameters["retention_days"] = None if days is None else int(round(float(days)))
    return parameters


def _maximum_size(value):
    if not re.match(r"^\d+(\.\d+)?(KB|MB|GB)$", value, re.IGNORECASE):
        raise ValueError("Maximum size " + value + " is not properly specified")
    size = (
        float(value[:-2])
        * {"KB": 1024, "MB": 1048576, "GB": 1073741824}[value[-2:].upper()]
    )
    if size < 65536 or size >= 4294967296:
        raise ValueError("Maximum size must be between 64KB and 4GB")
    if size % 65536:
        raise ValueError("Maximum size must be divisible by 64KB")
    return int(size)


def _source_exists(name, source, log_exists):
    registered = eventlog.source_log(source)
    if registered and not log_exists:
        raise ValueError("Source " + source + " already exists and cannot be created")
    if registered and not environment.values_equal(registered, name):
        raise ValueError(
            "Source "
            + source
            + " does not belong to log "
            + name
            + " and cannot be modified"
        )
    return registered is not None


def _present(parameters, details, result, check_mode):
    name = parameters["name"]
    resources = {option: parameters[option] for option, _ in eventlog.RESOURCE_VALUES}
    for source in parameters["sources"]:
        if _source_exists(name, source, details["exists"]):
            existing = next(
                (
                    data
                    for key, data in details["sources"].items()
                    if environment.values_equal(key, source)
                ),
                {},
            )
            if not any(
                value and not environment.values_equal(existing.get(option), value)
                for option, value in resources.items()
            ):
                continue
            if not check_mode:
                eventlog.remove_source(name, source)
        if not check_mode:
            eventlog.create_source(name, source, resources)
            result["sources_changed"].append(source)
        result["changed"] = True
    maximum = (
        _maximum_size(parameters["maximum_size"])
        if parameters["maximum_size"]
        else None
    )
    if any(
        (
            maximum is not None and details.get("maximum_size_kb") != maximum // 1024,
            parameters["overflow_action"]
            and details.get("overflow_action") != parameters["overflow_action"],
            parameters["retention_days"]
            and details.get("retention_days") != parameters["retention_days"],
        )
    ):
        eventlog.validate_limit(
            name,
            parameters["overflow_action"],
            parameters["retention_days"] or None,
            check_mode,
        )
        if not check_mode:
            eventlog.limit_log(
                name,
                maximum,
                parameters["overflow_action"],
                parameters["retention_days"] or None,
            )
        result["changed"] = True


def _validate_existing(parameters, details):
    name, state, sources = (
        parameters["name"],
        parameters["state"],
        parameters["sources"],
    )
    default_requested = any(
        environment.values_equal(name, source) for source in sources
    )
    if state == "present" and not details["exists"] and not sources:
        raise ValueError(
            "You must specify one or more sources when creating a log for the first time"
        )
    if (
        state == "present"
        and details["exists"]
        and default_requested
        and any(parameters[option] for option, _ in eventlog.RESOURCE_VALUES)
    ):
        raise ValueError(
            "Cannot modify default source "
            + name
            + " of log "
            + name
            + " - you must remove the log"
        )
    if state == "clear" and not details["exists"]:
        raise ValueError("Cannot clear log " + name + " as it does not exist")
    if state == "absent" and default_requested:
        raise ValueError(
            "Cannot remove default source "
            + name
            + " from log "
            + name
            + " - you must remove the log"
        )


def _manage(parameters, result, check_mode):
    name, state, sources = (
        parameters["name"],
        parameters["state"],
        parameters["sources"],
    )
    details = eventlog.log_details(name)
    _validate_existing(parameters, details)
    if state == "present":
        _present(parameters, details, result, check_mode)
    elif state == "clear" and details.get("entries", 0):
        if not check_mode:
            eventlog.clear_log(name)
        result["changed"] = True
    elif state == "absent" and details["exists"]:
        if sources:
            for source in sources:
                if _source_exists(name, source, True):
                    if not check_mode:
                        eventlog.remove_source(name, source)
                        result["sources_changed"].append(source)
                    result["changed"] = True
        else:
            if not check_mode:
                eventlog.remove_log(name)
                result["sources_changed"].extend(details["sources"])
            result["changed"] = True
    final = eventlog.log_details(name)
    if "sources" in final:
        final["sources"] = list(final["sources"])
    result.update(final)


def _response():
    arguments = read_arguments(
        _PARAMETERS,
        "sustainablelobster.legacy_windows.win_eventlog",
        allow_unknown=True,
    )
    parameters = _parameters(arguments)
    result = {"changed": False, "name": parameters["name"], "sources_changed": []}
    try:
        # Dispatch passes this module's arguments and core check-mode flag only.
        # pylint: disable=duplicate-code
        _manage(
            parameters,
            result,
            as_bool(arguments.get("_ansible_check_mode", False), "_ansible_check_mode"),
        )
        # pylint: enable=duplicate-code
    except (OSError, ValueError) as error:
        # This shared failure envelope leaves native event-log logic independent.
        # pylint: disable=duplicate-code
        result.update(failed=True, msg=str(error))
        # pylint: enable=duplicate-code
    return result


def main():
    """Execute the native classic-event-log payload and emit its Ansible result.

    :raises SystemExit: With zero on success or one on failure.
    """
    run_module(_response)


# Each independently staged payload needs its own executable entry guard.
# pylint: disable=duplicate-code
if __name__ == "__main__":
    main()
# pylint: enable=duplicate-code
