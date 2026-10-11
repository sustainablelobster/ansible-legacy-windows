#!/usr/bin/python
# -*- coding: utf-8 -*-
# Copyright 2026 sustainablelobster
# SPDX-License-Identifier: GPL-3.0-or-later

"""Configure automatic Windows logon with registry and native LSA calls."""

# WANT_JSON

import re

import legacy_windows_auto_logon as auto_logon  # pylint: disable=import-error
import legacy_windows_environment as environment  # pylint: disable=import-error
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
module: win_auto_logon
short_description: Configure automatic Windows logon
version_added: '1.0.0'
description:
  - Configures Winlogon properties and stores the password in the local LSA private store.
  - Uses Python 3.4.4 and native Windows interfaces.
options:
  username:
    description:
      - Account used for automatic logon, resolved to its canonical domain and username.
      - Required when O(state=present).
    type: str
  password:
    description:
      - Password to store for automatic logon. Required when O(state=present).
      - The LSA secret is encrypted at rest but remains accessible to local administrators.
    type: str
  logon_count:
    description:
      - Number of automatic logons before Windows disables the setting.
      - Omit or set to null to remove the existing count.
    type: int
  state:
    description:
      - Whether to configure or remove automatic logon.
    type: str
    choices: [absent, present]
    default: present
attributes:
  check_mode:
    support: full
    description: Reads the registry and LSA secret and predicts changes without writing.
  diff_mode:
    support: full
    description: Reports state, domain, username and count, never the stored password.
notes:
  - Requires administrative access to Winlogon and the local LSA private store.
  - Removes any plaintext C(DefaultPassword) registry value in both states.
  - Registry updates precede the LSA update. A later failure can leave earlier changes applied.
  - Does not validate the supplied password or restart the machine.
author:
  - sustainablelobster
"""

EXAMPLES = r"""
- name: Configure a bounded number of automatic logons
  sustainablelobster.legacy_windows.win_auto_logon:
    username: application_user
    password: '{{ application_password }}'
    logon_count: 2

- name: Remove automatic logon configuration
  sustainablelobster.legacy_windows.win_auto_logon:
    state: absent
"""

RETURN = r"""
{}
"""
# pylint: enable=duplicate-code

_MODULE_NAME = "sustainablelobster.legacy_windows.win_auto_logon"
_PARAMETERS = ("logon_count", "password", "state", "username")
_MAPPING = (
    ("DefaultUserName", "username"),
    ("DefaultDomainName", "domain"),
    ("AutoLogonCount", "logon_count"),
)


def _logon_count(value):
    if value is None:
        return None
    kind = {
        bool: "System.Boolean",
        str: "System.String",
        list: "System.Object[]",
        dict: "System.Collections.Hashtable",
    }.get(type(value))
    if isinstance(value, float):
        kind = "System.Double" if "e" in repr(value) else "System.Decimal"
    elif isinstance(value, int) and not isinstance(value, bool):
        kind = "System.Int64"
        if not -(2**63) <= value < 2**63:
            kind = "System.Decimal" if abs(value) < 2**96 else "System.Double"
    # Basic parses the string representation; it does not round fractions or
    # convert Boolean values to 0/1. Int32 accepts only signed decimal digits.
    text = str(value).strip(" \t\r\n\v\f")
    reason = "Input string was not in a correct format."
    if re.match(r"^[+-]?[0-9]+\Z", text):
        count = int(text)
        if -(2**31) <= count < 2**31:
            return count
        reason = "Value was either too large or too small for an Int32."
    raise ValueError(
        "argument for logon_count is of type {0} and we were unable to "
        "convert to int: {1}".format(kind, reason)
    )


def _parameters(arguments):
    # This module owns its option set while using core's unknown-option flag.
    # pylint: disable=duplicate-code
    unsupported = sorted(
        name
        for name in arguments
        if name not in _PARAMETERS and not name.startswith("_ansible_")
    )
    if unsupported and not as_bool(
        arguments.get("_ansible_ignore_unknown_opts", False),
        "_ansible_ignore_unknown_opts",
    ):
        raise ValueError(
            "Unsupported parameters for ({0}) module: {1}. "
            "Supported parameters include: {2}".format(
                _MODULE_NAME, ", ".join(unsupported), ", ".join(_PARAMETERS)
            )
        )
    # pylint: enable=duplicate-code
    result = {
        name: as_string(arguments.get(name), name) for name in ("username", "password")
    }
    state = as_string(arguments.get("state", "present"), "state")
    if state is not None and not any(
        environment.values_equal(state, choice) for choice in ("absent", "present")
    ):
        raise ValueError(
            "value of state must be one of: absent, present. Got no match for: " + state
        )
    if environment.values_equal(state, "present"):
        missing = [name for name in ("username", "password") if name not in arguments]
        if missing:
            raise ValueError(
                "state is present but all of the following are missing: "
                + ", ".join(missing)
            )
    result.update(state=state, logon_count=_logon_count(arguments.get("logon_count")))
    return result


def _equal(previous, requested):
    if previous is None or requested is None:
        return previous is requested
    if isinstance(previous, str):
        return previous == as_string(requested, "registry value")
    return previous == requested


def _registry_changes(values, requested, before):
    present = environment.values_equal(requested["state"], "present")
    changes = []
    if "DefaultPassword" in values:
        changes.append(("DefaultPassword", None))
    if not environment.values_equal(requested["state"], before["state"]):
        changes.append(("AutoAdminLogon", 1 if present else 0))
    for name, field in _MAPPING:
        old_value, new_value = before.get(field), requested[field]
        if present and not _equal(old_value, new_value):
            changes.append((name, new_value))
        elif (
            environment.values_equal(requested["state"], "absent")
            and old_value is not None
        ):
            changes.append((name, None))
    return changes


def _manage(parameters, check_mode=False, diff_mode=False):
    requested = dict(parameters)
    requested["domain"] = None
    if requested["username"]:
        requested["domain"], requested["username"] = auto_logon.resolve_account(
            requested["username"]
        )
    present = environment.values_equal(requested["state"], "present")
    if environment.values_equal(requested["state"], "absent"):
        requested["password"] = None
    values = auto_logon.read_values()
    before = {
        "state": "present" if _equal(values.get("AutoAdminLogon"), 1) else "absent"
    }
    before.update({field: values[name] for name, field in _MAPPING if name in values})
    changes = _registry_changes(values, requested, before)
    result = {"changed": bool(changes)}
    if diff_mode:
        result["diff"] = {"before": before}
    if not check_mode:
        for name, value in changes:
            if value is None:
                auto_logon.delete_value(name)
            else:
                auto_logon.write_value(name, value)
    with auto_logon.SecretStore() as secret:
        if secret.read() != requested["password"]:
            if not check_mode:
                secret.write(requested["password"])
            result["changed"] = True
    if diff_mode:
        after = {"state": requested["state"]}
        if present:
            after.update(username=requested["username"], domain=requested["domain"])
            if requested["logon_count"] is not None:
                after["logon_count"] = requested["logon_count"]
        result["diff"]["after"] = after
    return result


def _redact(value, password):
    if not password:
        return value
    if isinstance(value, dict):
        return {key: _redact(entry, password) for key, entry in value.items()}
    if isinstance(value, list):
        return [_redact(entry, password) for entry in value]
    # Password redaction is result-safety plumbing, not autologon management.
    # pylint: disable=duplicate-code
    if isinstance(value, str):
        return (
            "VALUE_SPECIFIED_IN_NO_LOG_PARAMETER"
            if value == password
            else value.replace(password, "********")
        )
    # pylint: enable=duplicate-code
    if value is not None and password in as_string(value, "password redaction"):
        return "VALUE_SPECIFIED_IN_NO_LOG_PARAMETER"
    return value


def _response():
    arguments = read_arguments(_PARAMETERS, _MODULE_NAME, allow_unknown=True)
    password = as_string(arguments.get("password"), "password")
    try:
        parameters = _parameters(arguments)
        result = _manage(
            parameters,
            as_bool(arguments.get("_ansible_check_mode", False), "_ansible_check_mode"),
            as_bool(arguments.get("_ansible_diff", False), "_ansible_diff"),
        )
    # Basic sanitizes failure messages and invocation values, not result keys,
    # protocol booleans or the independently constructed diff dictionaries.
    except Exception as error:  # pylint: disable=broad-exception-caught
        result = {
            "changed": False,
            "failed": True,
            "msg": _redact(str(error), password),
            "exception": "(traceback unavailable)",
        }
    if as_bool(
        arguments.get("_ansible_inject_invocation", False), "_ansible_inject_invocation"
    ):
        invocation = {
            name: value
            for name, value in arguments.items()
            if not name.startswith("_ansible_")
        }
        # Basic sanitizes the coerced password, not the original list or mapping.
        if "password" in invocation:
            invocation["password"] = password
        result["invocation"] = {"module_args": _redact(invocation, password)}
    return result


def main():
    """Read the Ansible request and emit a JSON result with scoped redaction.

    :raises SystemExit: After reporting success or failure to Ansible.
    """
    run_module(_response)


# Each independently staged payload needs its own executable entry guard.
# pylint: disable=duplicate-code
if __name__ == "__main__":
    main()
# pylint: enable=duplicate-code
