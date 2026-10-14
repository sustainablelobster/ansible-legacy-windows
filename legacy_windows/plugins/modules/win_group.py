#!/usr/bin/python
# -*- coding: utf-8 -*-
# Copyright 2026 sustainablelobster
# SPDX-License-Identifier: GPL-3.0-or-later

"""Manage local Windows groups with a Python 3.4.4 payload."""

# WANT_JSON

from collections import OrderedDict

# The action stages these Python 3.4-compatible helpers beside the payload.
import legacy_windows_account as accounts  # pylint: disable=import-error
import legacy_windows_environment as environment  # pylint: disable=import-error
import legacy_windows_group as groups  # pylint: disable=import-error
from legacy_windows_module import (  # pylint: disable=import-error
    as_bool,
    as_dictionary,
    as_string,
    as_string_list,
    read_arguments,
    run_module,
)

DOCUMENTATION = r"""
---
module: win_group
short_description: Manage local Windows groups and their members
version_added: '1.0.0'
description:
  - Creates or removes local Windows groups and manages their descriptions and membership.
  - Uses Python 3.4.4 and native Windows APIs.
options:
  name:
    description: Name of the local group.
    type: str
    required: true
  description:
    description:
      - Description to assign to the group.
      - Omit this option or supply null to preserve the existing description.
      - Supply an empty string to clear the description.
    type: str
  members:
    description:
      - Members to add, remove, or replace. Omit this option to preserve membership.
      - Members can be local users, domain users, or domain groups; another local group cannot be added.
      - Account names accept C(SERVER\user), C(DOMAIN\user), C(.\user), an unqualified name, a UPN, or a SID string.
      - O(members.add) and O(members.remove) may be combined; O(members.set) is mutually exclusive with both.
    type: dict
    suboptions:
      add:
        description: Members to add without removing other existing members.
        type: list
        elements: str
        default: []
      remove:
        description: Members to remove while preserving other existing members.
        type: list
        elements: str
        default: []
      set:
        description:
          - Complete membership to assign, replacing the existing membership.
          - An empty list clears all members.
        type: list
        elements: str
  state:
    description: Whether the local group should exist.
    type: str
    choices: [absent, present]
    default: present
attributes:
  check_mode:
    support: full
    description: Predicts changes without creating, deleting, or modifying groups.
  diff_mode:
    support: full
    description: Reports the requested group name, description, and sorted member account names.
notes:
  - Group names and descriptions are compared case-insensitively. A case-only description change is not written.
  - Creating a group in check mode skips member resolution and reports an empty membership in the after diff.
  - Group creation and description updates precede member resolution. Additions precede removals.
  - Operations are not transactional; completed changes remain if a later operation fails.
  - Diffs retain supplied name and description spelling, even when an unchanged stored value has different casing.
seealso:
  - module: ansible.builtin.group
author:
  - sustainablelobster
"""

EXAMPLES = r"""
- name: Create a deployment group
  sustainablelobster.legacy_windows.win_group:
    name: Deployment
    description: Application deployment users

- name: Add a local account
  sustainablelobster.legacy_windows.win_group:
    name: Deployment
    members:
      add:
        - .\ApplicationUser

- name: Clear the description and membership
  sustainablelobster.legacy_windows.win_group:
    name: Deployment
    description: ''
    members:
      set: []

- name: Remove the group
  sustainablelobster.legacy_windows.win_group:
    name: Deployment
    state: absent
"""

RETURN = r"""
sid:
  description:
    - SID of the group managed with O(state=present).
    - A new group in check mode returns C(S-1-5-0000).
    - Removing a group returns null, whether or not the group previously existed.
  returned: success
  type: str
  sample: S-1-5-21-2528685370-1724360342-165486190-1208
"""

_MODULE_NAME = "sustainablelobster.legacy_windows.win_group"
_PARAMETERS = ("name", "description", "members", "state")
_MEMBER_OPTIONS = ("add", "remove", "set")


def _members(value, ignore_unknown=False):
    value = as_dictionary(value, "members")
    if value is None:
        return None
    normalized = {}
    for key, entry in value.items():
        name = key.lower() if key.lower() in _MEMBER_OPTIONS else key
        if name in normalized:
            raise ValueError("Member option names must not differ only in case: " + key)
        normalized[name] = entry
    value = normalized
    unsupported = sorted(key for key in value if key not in _MEMBER_OPTIONS)
    if unsupported and not ignore_unknown:
        raise ValueError(
            "Unsupported parameters for ("
            + _MODULE_NAME
            + ") module: "
            + ", ".join(unsupported)
            + " found in members. Supported parameters include: add, remove, set"
        )
    for other in ("add", "remove"):
        if "set" in value and other in value:
            raise ValueError(
                "parameters are mutually exclusive: set, " + other + " found in members"
            )
    return {
        name: as_string_list(
            value.get(name, None if name == "set" else []), "members." + name
        )
        for name in _MEMBER_OPTIONS
    }


def _parameters(arguments):
    if "name" not in arguments:
        raise ValueError("missing required arguments: name")
    state = as_string(arguments.get("state", "present"), "state")
    if state is not None and state.lower() not in ("absent", "present"):
        raise ValueError("state must be one of: absent, present.")
    return {
        "name": as_string(arguments["name"], "name"),
        "description": as_string(arguments.get("description"), "description"),
        "state": state,
        "members": _members(
            arguments.get("members"),
            as_bool(
                arguments.get("_ansible_ignore_unknown_opts", False),
                "_ansible_ignore_unknown_opts",
            ),
        ),
    }


def _member_names(sids, unique=False):
    return accounts.sort_names([accounts.sid_to_name(sid) for sid in sids], unique)


def _translate_members(names):
    sids = []
    for name in names:
        if not name:
            raise ValueError(
                "Cannot bind argument to parameter 'InputObject' because it is an empty string."
            )
        try:
            sids.append(accounts.name_to_sid(name))
        except OSError as error:
            raise ValueError(
                "Failed to translate '{0}' to a SecurityIdentifier: {1}".format(
                    name, error
                )
            ) from error
    return list(OrderedDict.fromkeys(sids))


def _member_list_is_true(names):
    # PowerShell unwraps a single-element collection when testing truthiness.
    return bool(names[0]) if names and len(names) == 1 else bool(names)


def _member_changes(members, existing):
    members = members or {}
    if members.get("set") is not None:
        desired = _translate_members(members["set"])
        return (
            [sid for sid in desired if sid not in existing],
            [sid for sid in existing if sid not in desired],
        )
    add = (
        _translate_members(members["add"])
        if _member_list_is_true(members.get("add"))
        else []
    )
    remove = (
        _translate_members(members["remove"])
        if _member_list_is_true(members.get("remove"))
        else []
    )
    return (
        [sid for sid in add if sid not in existing],
        [sid for sid in remove if sid in existing],
    )


def _present(parameters, group, existing, check_mode):
    changed = False
    description = parameters["description"]
    if group is None:
        changed = True
        if check_mode:
            return changed, "S-1-5-0000", description, []
        groups.create_group(parameters["name"])
        # ADSI and NetAPI store only the name prefix before its first NUL.
        group = {"name": parameters["name"].split("\0", 1)[0], "description": ""}

    name = group["name"]
    sid = accounts.local_group_sid(name)
    if description is None:
        description = group["description"]
    elif not environment.values_equal(group["description"], description):
        if not check_mode:
            groups.set_description(name, description)
        changed = True

    add, remove = _member_changes(parameters["members"], existing)
    after = list(existing)
    for member in add:
        if not check_mode:
            groups.add_member(name, member)
        changed = True
        after.append(member)
    for member in remove:
        if not check_mode:
            groups.remove_member(name, member)
        changed = True
        after.remove(member)
    return changed, sid, description, _member_names(after, unique=True)


def _group(parameters, check_mode=False, diff_mode=False):
    name = parameters["name"]
    matching = [
        candidate
        for candidate in groups.list_groups()
        if environment.values_equal(candidate["name"], name)
    ]
    if len(matching) > 1:
        raise ValueError("More than one local group matches the supplied name.")
    group = matching[0] if matching else None
    result = {"changed": False, "sid": None}
    diff = {"before": None, "after": None}
    existing = []
    if group is not None:
        existing = groups.member_sids(group["name"])
        diff["before"] = {
            "name": name,
            "description": group["description"],
            "members": _member_names(existing),
        }
    state = (parameters["state"] or "").lower()
    if state == "present":
        changed, sid, description, members = _present(
            parameters, group, existing, check_mode
        )
        result.update(changed=changed, sid=sid)
        diff["after"] = {"name": name, "description": description, "members": members}
    elif state == "absent" and group is not None:
        if not check_mode:
            groups.delete_group(group["name"])
        result["changed"] = True
    if diff_mode:
        result["diff"] = diff
    return result


def _response():
    arguments = read_arguments(_PARAMETERS, _MODULE_NAME)
    parameters = _parameters(arguments)
    result = _group(
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
