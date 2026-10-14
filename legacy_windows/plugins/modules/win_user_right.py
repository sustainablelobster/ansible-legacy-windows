#!/usr/bin/python
# -*- coding: utf-8 -*-
# Copyright 2026 sustainablelobster
# SPDX-License-Identifier: GPL-3.0-or-later

"""Manage local Windows user-right assignments with a Python 3.4.4 payload."""

# WANT_JSON

import legacy_windows_account as accounts  # pylint: disable=import-error
import legacy_windows_owner as owner  # pylint: disable=import-error
import legacy_windows_user_right as user_right  # pylint: disable=import-error
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
module: win_user_right
short_description: Manage Windows user-right assignments
version_added: '1.0.0'
description:
  - Adds, removes, or replaces the accounts assigned a local Windows user right.
  - Uses Python 3.4.4 and native LSA APIs.
options:
  name:
    description: Windows privilege or logon-right constant, such as C(SeServiceLogonRight).
    type: str
    required: true
  users:
    description:
      - Accounts or SID strings to add, remove, or retain as the complete assignment.
      - Accepts local and domain accounts, C(.\account), and SDDL SID aliases.
      - An empty list with O(action=set) removes all assigned accounts.
    type: list
    elements: str
    required: true
  action:
    description:
      - V(add) assigns the right to missing accounts.
      - V(remove) removes the right from specified accounts that currently hold it.
      - V(set) makes the assigned accounts exactly match O(users).
    type: str
    choices: [add, remove, set]
    default: set
attributes:
  check_mode:
    support: full
    description: Resolves accounts and predicts assignments without changing policy.
  diff_mode:
    support: full
    description: Reports before and predicted after account lists under the requested right name.
notes:
  - Requires administrator access to the local LSA policy, including in check mode.
  - Domain Group Policy may overwrite local assignments.
  - Accounts are compared by SID. Results use account names or literal SIDs when no name is mapped.
  - Additions precede removals. Completed changes remain if a later native operation fails.
author:
  - sustainablelobster
"""

EXAMPLES = r"""
- name: Permit a service account to log on as a service
  sustainablelobster.legacy_windows.win_user_right:
    name: SeServiceLogonRight
    users: ['.\ApplicationService']
    action: add

- name: Remove a service account's logon right
  sustainablelobster.legacy_windows.win_user_right:
    name: SeServiceLogonRight
    users: ['.\ApplicationService']
    action: remove

- name: Clear explicit assignments of a right
  sustainablelobster.legacy_windows.win_user_right:
    name: SeBatchLogonRight
    users: []
    action: set
"""

RETURN = r"""
added:
  description: Accounts assigned the right, in first-occurrence request order.
  returned: success
  type: list
  elements: str
  sample: ['SERVER\ApplicationService']
removed:
  description: Accounts removed, in request order for remove or native enumeration order for set.
  returned: success
  type: list
  elements: str
  sample: ['BUILTIN\Guests']
"""
# pylint: enable=duplicate-code

_MODULE_NAME = "sustainablelobster.legacy_windows.win_user_right"
_PARAMETERS = ("action", "name", "users")


def _failure(result, message):
    result.update(
        {"failed": True, "msg": message, "exception": "(traceback unavailable)"}
    )
    return result


def _parameters(arguments):
    missing = [name for name in ("users", "name") if name not in arguments]
    if missing:
        raise ValueError("missing required arguments: " + ", ".join(missing))
    name = as_string(arguments["name"], "name") or ""
    users = arguments["users"]
    kind = None
    if isinstance(users, bool):
        kind = "System.Boolean"
    elif isinstance(users, dict):
        kind = "System.Collections.Hashtable"
    elif isinstance(users, float):
        # PowerShell reads dotted JSON tokens as Decimal, exponents as Double.
        kind = "System.Double" if "e" in repr(users) else "System.Decimal"
    elif isinstance(users, int) and not -(2**63) <= users < 2**63:
        kind = "System.Decimal" if abs(users) < 2**96 else "System.Double"
    if kind:
        raise ValueError(
            "argument for users is of type {0} and we were unable to convert "
            "to list: {0} cannot be converted to a list".format(kind)
        )
    if isinstance(users, list) and any(user is None for user in users):
        raise ValueError(
            'Unhandled exception while executing module: Exception calling "Create" '
            'with "2" argument(s): "Object reference not set to an instance of an object."'
        )
    users = as_string_list(users, "users")
    action = as_string(arguments.get("action", "set"), "action")
    if action is not None and action.lower() not in ("add", "remove", "set"):
        raise ValueError(
            "value of action must be one of: add, remove, set. Got no match for: "
            + action
        )
    return name, users, (action or "set").lower()


def _unique(values):
    seen = set()
    result = []
    for value in values:
        if value not in seen:
            seen.add(value)
            result.append(value)
    return result


# Keep the open policy and partial result explicit across the ordered writes.
# pylint: disable-next=too-many-arguments,too-many-positional-arguments
def _assign(policy, name, requested, action, check_mode, result):
    try:
        existing = policy.accounts(name)
    except ValueError:
        return _failure(
            result, "the specified right {0} is not a valid right".format(name)
        )
    except OSError as error:
        return _failure(
            result,
            "failed to enumerate eixsting accounts with the right {0}: {1}".format(
                name, error.strerror or str(error)
            ),
        )
    names = [accounts.sid_to_name(sid) for sid in existing]
    if "diff" in result:
        result["diff"]["before"] = {name: list(names)}
    additions = (
        [sid for sid in requested if sid not in existing] if action != "remove" else []
    )
    removals = (
        [sid for sid in requested if sid in existing]
        if action == "remove"
        else (
            [sid for sid in _unique(existing) if sid not in requested]
            if action == "set"
            else []
        )
    )
    for operation, sids in (("add", additions), ("remove", removals)):
        for sid in sids:
            display = accounts.sid_to_name(sid)
            if not check_mode:
                try:
                    getattr(policy, operation)(sid, name)
                except OSError as error:
                    return _failure(
                        result,
                        "Failed to {0} account {1} {2} right {3}: {4}".format(
                            operation,
                            display,
                            "to" if operation == "add" else "from",
                            name,
                            error.strerror or str(error),
                        ),
                    )
            result["added" if operation == "add" else "removed"].append(display)
            if operation == "add":
                names.append(display)
            else:
                names.remove(display)
            result["changed"] = True
    if "diff" in result:
        result["diff"]["after"] = {name: names}
    return result


def _response():
    try:
        arguments = read_arguments(_PARAMETERS, _MODULE_NAME)
        name, users, action = _parameters(arguments)
        check_mode = as_bool(
            arguments.get("_ansible_check_mode", False), "_ansible_check_mode"
        )
        diff_mode = as_bool(arguments.get("_ansible_diff", False), "_ansible_diff")
    except ValueError as error:
        return _failure({"changed": False}, str(error))
    result = {"changed": False, "added": [], "removed": []}
    if diff_mode:
        result["diff"] = {"before": "", "after": ""}
    with user_right.open_policy() as policy:
        requested = []
        for user in [""] if users is None else users:
            if not user:
                # Upstream pipeline-binding failures discard initialized result fields.
                return _failure(
                    {"changed": False},
                    "Unhandled exception while executing module: Cannot bind "
                    "argument to parameter 'InputObject' because it is an empty string.",
                )
            try:
                requested.append(owner.resolve_owner(user))
            except (OSError, ValueError):
                return _failure(
                    result,
                    "Failed to translate the account '{0}' to a SID".format(user),
                )
        return _assign(policy, name, _unique(requested), action, check_mode, result)


def main():
    """Run the user-right module's argument-file and JSON response protocol."""
    run_module(_response)


# Each independently staged payload needs its own executable entry guard.
# pylint: disable=duplicate-code
if __name__ == "__main__":
    main()
# pylint: enable=duplicate-code
