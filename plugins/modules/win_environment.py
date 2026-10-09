#!/usr/bin/python
# -*- coding: utf-8 -*-
# Copyright 2026 Joe Lustri
# SPDX-License-Identifier: GPL-3.0-or-later

"""Manage Windows environment variables with a Python 3.4.4 payload."""

# WANT_JSON

from collections import OrderedDict

# The action stages these Python 3.4-compatible helpers beside the payload.
import legacy_windows_environment as environment  # pylint: disable=import-error
from legacy_windows_module import (  # pylint: disable=import-error
    as_bool,
    as_dictionary,
    as_string,
    read_arguments,
    run_module,
)

# Ansible interfaces must be self-contained; repeated option/return text is
# interface documentation, not duplicated execution logic.
# pylint: disable=duplicate-code
DOCUMENTATION = r"""
---
module: win_environment
short_description: Manage Windows environment variables
version_added: '1.0.0'
description:
  - Sets or removes complete environment-variable values at machine, user, or process level.
  - Uses Python 3.4.4 and native Windows APIs.
options:
  level:
    description:
      - C(machine) changes persistent settings for all users and requires suitable registry permissions.
      - C(user) changes persistent settings for the account running the module.
      - C(process) changes only the module process and does not persist into subsequent tasks.
    type: str
    choices: [machine, process, user]
    required: true
  name:
    description:
      - Name of a single environment variable.
      - Supply either this option or O(variables).
    type: str
  value:
    description:
      - Complete value for O(name).
      - An omitted, null, or empty value removes the variable when O(state) is omitted.
      - Must be nonempty with O(state=present); omit it with O(state=absent).
    type: str
  state:
    description:
      - Explicitly set or remove O(name).
      - When omitted, a nonempty value means C(present); an empty value means C(absent).
      - Cannot be supplied with O(variables).
    type: str
    choices: [absent, present]
  variables:
    description:
      - Mapping of names to complete values, all at O(level).
      - Null and empty string values remove their variables.
      - Mutually exclusive with O(name), O(value), and O(state), including explicit null options.
      - An empty mapping makes no changes.
      - A mapping cannot contain names differing only in letter case.
    type: dict
attributes:
  check_mode:
    support: full
    description: Predicts changes without writing values or broadcasting notifications.
  diff_mode:
    support: full
    description: Reports nonempty before and requested after values grouped by level.
notes:
  - Value comparison is case-insensitive. A case-only value change is not written.
  - Actual writes broadcast an environment-change notification, including at process level.
  - Existing processes may still require a restart to observe persistent changes.
  - Changes do not update the controller, the connection service, or other existing process environments directly.
  - Multi-variable requests are not transactional. Earlier writes remain if a later operation fails.
  - Do not depend on multi-variable processing order or the final variable represented by top-level return values.
  - A notification failure can occur after a value has already been written.
  - Native Windows Unicode comparison tables vary by Windows version.
author:
  - Joe Lustri
"""

EXAMPLES = r"""
- name: Set an application directory for all users
  sustainablelobster.legacy_windows.win_environment:
    level: machine
    name: APPLICATION_HOME
    value: C:\Application
    state: present

- name: Set and remove settings for the current account
  sustainablelobster.legacy_windows.win_environment:
    level: user
    variables:
      APPLICATION_MODE: production
      OLD_APPLICATION_MODE: null
"""

RETURN = r"""
before_value:
  description:
    - Previous value for the last processed variable, or null if absent.
    - Omitted for an empty O(variables) mapping. Use RV(env_values) for multi-variable requests.
  returned: success with at least one variable
  type: str
value:
  description:
    - Requested value for the last processed variable; normally empty text for removal.
    - With O(state=absent), an unnecessarily supplied value is returned even though the variable is removed.
    - Omitted for an empty O(variables) mapping.
  returned: success with at least one variable
  type: str
env_values:
  description:
    - Mapping from each processed name to its C(before), requested C(after), and C(changed) values.
    - Names considered equal by Windows invariant case-insensitive comparison share an entry, as upstream.
    - A shared entry retains the first key spelling and the last processed status; each variable is still processed.
  returned: success
  type: dict
values:
  description: Compatibility alias of RV(env_values).
  returned: success
  type: dict
"""
# pylint: enable=duplicate-code

_MODULE_NAME = "sustainablelobster.legacy_windows.win_environment"
_PARAMETERS = ("level", "name", "value", "state", "variables")
_PRESENT_VALUE_REQUIRED = (
    "When state=present, value must be defined and not an empty string, "
    "if you wish to remove the envvar, set state=absent"
)


def _parameters(arguments):
    variables = arguments.get("variables")
    if isinstance(variables, dict):
        # Raw JSON mappings are checked by the upstream wrapper before module
        # validation. Dictionary strings are parsed later and keep distinct keys.
        names = set()
        for name in variables:
            key = environment.name_key(name)
            if key in names:
                raise ValueError(
                    "Variable names in a mapping must not differ only in case: " + name
                )
            names.add(key)
    for other in ("name", "value", "state"):
        if "variables" in arguments and other in arguments:
            raise ValueError("parameters are mutually exclusive: variables, " + other)
    if "level" not in arguments:
        raise ValueError("missing required arguments: level")
    parameters = {
        name: as_string(arguments.get(name), name)
        for name in ("level", "name", "value", "state")
    }
    for name, choices in (
        ("level", ("machine", "process", "user")),
        ("state", ("absent", "present")),
    ):
        value = parameters[name]
        if value is not None and value.lower() not in choices:
            raise ValueError(name + " must be one of: " + ", ".join(choices) + ".")
    parameters["variables"] = as_dictionary(arguments.get("variables"), "variables")
    if "name" not in arguments and "variables" not in arguments:
        raise ValueError("one of the following is required: name, variables")
    return parameters


def _bound_value(value):
    if isinstance(value, list):
        raise ValueError("An array cannot be bound to an environment variable string.")
    return as_string(value, "variables value") or ""


def _status(name, value, level, state, check_mode):
    if not name:
        raise ValueError("The environment variable name must not be empty.")
    value = _bound_value(value)
    before = environment.get_value(name, level)
    present = state == "present" or (not state and bool(value))
    changed = (
        not environment.values_equal(before, value) if present else before is not None
    )
    if changed and not check_mode:
        environment.set_value(name, value if present else None, level)
        environment.broadcast_change()
    return {"before": before, "after": value, "changed": changed}


def _assign_result(mapping, name, value):
    # PowerShell's result hashtables use linguistic invariant comparison, unlike
    # the wrapper's raw JSON keys. Preserve each map's first inserted spelling.
    for existing in mapping:
        if environment.values_equal(existing, name):
            mapping[existing] = value
            return
    mapping[name] = value


def _environment(parameters, check_mode=False, diff_mode=False):
    level = parameters["level"]
    if level is None:
        raise ValueError("level must not be null.")
    variables = parameters["variables"]
    if variables is None:
        if parameters["name"] is None:
            raise ValueError(
                "name must not be null when variables is not a dictionary."
            )
        variables = OrderedDict(((parameters["name"], parameters["value"]),))
    result = {"changed": False, "values": {}, "env_values": {}}
    before = {}
    after = {}
    if diff_mode:
        result["diff"] = {"before": {level: before}, "after": {level: after}}
    state = (parameters["state"] or "").lower()
    for name, value in variables.items():
        if state == "absent" and value:
            result.setdefault("warnings", []).append(
                "When removing environment variable '"
                + name
                + "' it should not have a value '"
                + value
                + "' set"
            )
        elif state == "present" and not value:
            result.update({"failed": True, "msg": _PRESENT_VALUE_REQUIRED})
            return result
        status = _status(name, value, level.lower(), state, check_mode)
        if status["before"]:
            _assign_result(before, name, status["before"])
        if status["after"]:
            _assign_result(after, name, status["after"])
        _assign_result(result["values"], name, status)
        _assign_result(result["env_values"], name, status)
        result["changed"] = result["changed"] or status["changed"]
        result["before_value"] = status["before"]
        result["value"] = status["after"]
    return result


def _response():
    arguments = read_arguments(_PARAMETERS, _MODULE_NAME)
    parameters = _parameters(arguments)
    result = _environment(
        parameters,
        as_bool(arguments.get("_ansible_check_mode", False), "_ansible_check_mode"),
        as_bool(arguments.get("_ansible_diff", False), "_ansible_diff"),
    )
    if as_bool(
        arguments.get("_ansible_inject_invocation", False), "_ansible_inject_invocation"
    ):
        result["invocation"] = {"module_args": parameters}
    return result


def main():
    """Read Ansible arguments and emit the module's JSON result.

    :raises SystemExit: After reporting success or failure to Ansible.
    """
    run_module(_response)


if __name__ == "__main__":
    main()
