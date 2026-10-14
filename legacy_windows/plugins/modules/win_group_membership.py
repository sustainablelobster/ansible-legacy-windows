#!/usr/bin/python
# -*- coding: utf-8 -*-
# Copyright 2026 sustainablelobster
# SPDX-License-Identifier: GPL-3.0-or-later

"""Manage local-group members with a Python 3.4.4 payload."""

# WANT_JSON

import os

# The action stages these Python 3.4-compatible helpers beside the payload.
import legacy_windows_account as accounts  # pylint: disable=import-error
import legacy_windows_environment as environment  # pylint: disable=import-error
import legacy_windows_group as groups  # pylint: disable=import-error
from legacy_windows_module import (  # pylint: disable=import-error
    DOTNET_WHITESPACE,
    as_string,
    read_arguments,
    run_module,
)

DOCUMENTATION = r"""
---
module: win_group_membership
short_description: Manage members of existing local Windows groups
version_added: '1.0.0'
description:
  - Adds or removes members of an existing local Windows group.
  - Uses Python 3.4.4 and native Windows APIs.
options:
  name:
    description: Name of the existing local group.
    type: str
    required: true
  members:
    description:
      - Accounts to add, remove, or retain as the complete membership.
      - Accepts unqualified names, C(.\user), C(SERVER\user), C(DOMAIN\user), UPNs, and SID strings.
      - Unqualified names matching a local user select that local account.
      - An empty list with O(state=pure) removes every current member.
    type: list
    elements: str
    required: true
  state:
    description:
      - V(present) adds the requested members and V(absent) removes them.
      - V(pure) adds missing requested members and removes all other members.
    type: str
    choices: [present, absent, pure]
    default: present
attributes:
  check_mode:
    support: full
    description: Predicts membership changes without modifying the group.
  diff_mode:
    support: none
notes:
  - The group must already exist, including in check mode.
  - Requested accounts are resolved before changes begin. Duplicate accounts are matched by SID.
  - Requested SID strings must resolve to account names. Existing unmapped members are returned as literal SIDs
    and can be removed with O(state=pure) by omitting them from O(members).
  - Additions precede removals in V(pure) state. Completed changes remain if a later operation fails.
seealso:
  - module: sustainablelobster.legacy_windows.win_group
author:
  - sustainablelobster
"""

EXAMPLES = r"""
- name: Add an application account
  sustainablelobster.legacy_windows.win_group_membership:
    name: Deployment
    members:
      - .\ApplicationUser

- name: Remove a service account
  sustainablelobster.legacy_windows.win_group_membership:
    name: Deployment
    members:
      - NT AUTHORITY\NETWORK SERVICE
    state: absent

- name: Clear every member of a group
  sustainablelobster.legacy_windows.win_group_membership:
    name: Deployment
    members: []
    state: pure
"""

RETURN = r"""
name:
  description: Supplied name of the local group.
  returned: success
  type: str
  sample: Deployment
added:
  description: Accounts added, in first-occurrence request order.
  returned: success and state is present or pure
  type: list
  elements: str
  sample: ['SERVER\ApplicationUser']
removed:
  description: Accounts removed, in request order for absent or native enumeration order for pure.
  returned: success and state is absent or pure
  type: list
  elements: str
  sample: ['NT AUTHORITY\NETWORK SERVICE']
members:
  description:
    - Members at completion, in native enumeration order.
    - Check mode appends predicted additions before filtering removals.
    - Following check-mode removals, a single remaining member is a string and no remaining members is null.
  returned: success
  type: list
  elements: str
  sample: ['SERVER\ApplicationUser']
"""

_MODULE_NAME = "sustainablelobster.legacy_windows.win_group_membership"
_PARAMETERS = ("name", "members", "state")


def _pipeline_string(value, name):
    if isinstance(value, list):
        return " ".join(_pipeline_string(entry, name) or "" for entry in value)
    return as_string(value, name)


def _parameters(arguments):
    for name in ("name", "members"):
        if name not in arguments:
            raise ValueError("Get-AnsibleParam: Missing required argument: " + name)
    name = as_string(arguments["name"], "name")
    members = arguments["members"]
    if isinstance(members, str):
        members = [part.strip(DOTNET_WHITESPACE) for part in members.split(",")]
    elif isinstance(members, int) and not isinstance(members, bool):
        if -(2**31) <= members < 2**31:
            members = [members]
    if members is not None and not isinstance(members, list):
        raise ValueError("Get-AnsibleParam: Parameter 'members' is not a YAML list.")
    state = arguments.get("state", "present")
    if (_pipeline_string(state, "state") or "").lower() not in (
        "present",
        "absent",
        "pure",
    ):
        raise ValueError(
            "Get-AnsibleParam: Argument state needs to be one of "
            "present,absent,pure but was {0}.".format(
                _pipeline_string(state, "state") or ""
            )
        )
    # Legacy validates the original value before calling its ToString method.
    # A singleton state array can validate but then becomes System.Object[].
    return name, members, as_string(state, "state").lower()


def _account_sid(name, local_groups):
    try:
        return accounts.parse_sid(name)
    except (OSError, ValueError):
        pass
    computer = os.environ["COMPUTERNAME"]
    if "\\" in name:
        domain, username = name.split("\\")[:2]
        if environment.values_equal(domain, "."):
            domain = computer
        if domain:
            local_group = environment.values_equal(domain, computer) and any(
                environment.values_equal(group["name"], username)
                for group in local_groups
            )
            lookup = username if local_group else domain + "\\" + username
        else:
            lookup = _unqualified_name(username, computer)
    else:
        lookup = _unqualified_name(name, computer)
    try:
        return accounts.account_name_to_sid(lookup)
    except OSError as error:
        raise ValueError(
            "account_name {0} is not a valid account, cannot get SID: {1}".format(
                name, error
            )
        ) from error


def _unqualified_name(name, computer):
    if any(
        environment.values_equal(user, name) for user in accounts.local_user_names()
    ):
        return computer + "\\" + name
    return name


def _requested_name(sid):
    try:
        name = accounts.sid_to_name(sid)
        if name == sid:
            raise ValueError(
                "No mapping between account names and security IDs was done."
            )
        return name
    except (OSError, ValueError) as error:
        raise ValueError(
            "failed to convert sid '{0}' to a logon name: {1}".format(sid, error)
        ) from error


def _bound_members(value):
    if value is None:
        raise RuntimeError(
            "Cannot bind argument to parameter 'Member' because it is null."
        )
    values = value if isinstance(value, list) else [value]
    if not values:
        raise RuntimeError(
            "Cannot bind argument to parameter 'Member' because it is an empty array."
        )
    names = [_pipeline_string(entry, "members") for entry in values]
    for name in names:
        if not name:
            raise RuntimeError(
                "Cannot bind argument to parameter 'Member' because it is {0}.".format(
                    "null" if name is None else "an empty string"
                )
            )
    return names


def _input_members(members, local_groups):
    resolved = []
    seen = set()
    for value in [None] if members is None else members:
        for name in _bound_members(value):
            sid = _account_sid(name, local_groups)
            if sid not in seen:
                resolved.append((sid, _requested_name(sid)))
                seen.add(sid)
    return resolved


def _current_members(name):
    return [(sid, accounts.sid_to_name(sid)) for sid in groups.member_sids(name)]


def _change_member(result, group, member, adding, check_mode):
    sid, account = member
    try:
        if not check_mode:
            if adding:
                groups.add_member(group, sid)
            else:
                groups.remove_member(group, sid)
    # Upstream catches every mutation failure and retains completed changes.
    except Exception as error:  # pylint: disable=broad-exception-caught
        result.update(failed=True, msg=str(error))
        return False
    result["added" if adding else "removed"].append(account)
    result["changed"] = True
    return True


def _predicted_members(names, added, removed):
    names.extend(added)
    if not removed:
        return names
    names = [
        account
        for account in names
        if not any(environment.values_equal(account, old) for old in removed)
    ]
    # The reference's removal pipeline unwraps zero or one output values.
    return names if len(names) > 1 else (names[0] if names else None)


def _remove_extra_members(result, group, requested, check_mode):
    wanted = set(sid for sid, unused_name in requested)
    for member in _current_members(group):
        if member[0] not in wanted:
            if not _change_member(result, group, member, False, check_mode):
                return False
    return True


def _membership(name, members, state, check_mode):
    result = {"changed": False, "name": name}
    if state in ("present", "pure"):
        result["added"] = []
    if state in ("absent", "pure"):
        result["removed"] = []
    local_groups = groups.list_groups()
    matching = [
        group for group in local_groups if environment.values_equal(group["name"], name)
    ]
    if not matching:
        result.update(failed=True, msg="Could not find local group " + (name or ""))
        return result
    if len(matching) > 1:
        raise ValueError("More than one local group matches the supplied name.")
    group = matching[0]["name"]
    requested = _input_members(members, local_groups)
    current_sids = set(sid for sid, unused_name in _current_members(group))
    for member in requested:
        if state in ("present", "pure") and member[0] not in current_sids:
            adding = True
        elif state == "absent" and member[0] in current_sids:
            adding = False
        else:
            continue
        if not _change_member(result, group, member, adding, check_mode):
            return result
    if state == "pure" and not _remove_extra_members(
        result, group, requested, check_mode
    ):
        return result
    final_names = [account for unused_sid, account in _current_members(group)]
    if check_mode:
        final_names = _predicted_members(
            final_names, result.get("added", []), result.get("removed", [])
        )
    result["members"] = final_names
    return result


def _response():
    arguments = read_arguments(_PARAMETERS, _MODULE_NAME, allow_unknown=True)
    name, members, state = _parameters(arguments)
    check = arguments.get("_ansible_check_mode", False)
    check_mode = (as_string(check, "_ansible_check_mode") or "").lower() in (
        "true",
        "yes",
        "on",
        "1",
    )
    return _membership(name, members, state, check_mode)


def main():
    """Read Ansible arguments and emit the membership result.

    :raises SystemExit: After reporting success or failure to Ansible.
    """
    run_module(_response)


if __name__ == "__main__":
    main()
