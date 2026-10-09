#!/usr/bin/python
# -*- coding: utf-8 -*-
# Copyright 2026 Joe Lustri
# SPDX-License-Identifier: GPL-3.0-or-later

"""Manage SMB shares and their access rules with native Python APIs."""

# WANT_JSON

import ntpath
import os
import sys

import legacy_windows_environment as environment  # pylint: disable=import-error
import legacy_windows_share as shares  # pylint: disable=import-error
from legacy_windows_module import (  # pylint: disable=import-error
    DOTNET_WHITESPACE,
    as_path,
    as_string,
    read_arguments,
    run_module,
)

DOCUMENTATION = r"""
---
module: win_share
short_description: Manage local SMB shares and share permissions
version_added: '1.0.0'
description:
  - Creates, updates, or removes local filesystem shares and their share-level access rules.
  - Uses Python 3.4.4 and native Windows APIs.
options:
  name:
    description: Share name.
    type: str
    required: true
  path:
    description: Existing filesystem path. Required when O(state=present).
    type: path
    required: true
  state:
    description: Whether the share should exist.
    type: str
    choices: [absent, present]
    default: present
  description:
    description: Share description. Omission clears the description.
    type: str
  list:
    description: Allow unrestricted listing instead of access-based enumeration.
    type: bool
    default: false
  read:
    description: Comma-separated accounts to grant read access.
    type: str
  change:
    description: Comma-separated accounts to grant read and write access.
    type: str
  full:
    description: Comma-separated accounts to grant full access.
    type: str
  deny:
    description: Comma-separated accounts to deny access.
    type: str
  caching_mode:
    description: Offline caching policy for the share.
    type: str
    choices: [BranchCache, Documents, Manual, None, Programs, Unknown]
    default: Manual
  scope_name:
    description: Scope used to select a share for updates. Clustered resources are unverified.
    type: str
  encrypt:
    description: Require SMB encryption for access to this share.
    type: bool
    default: false
  rule_action:
    description: Replace access rules or add to existing rules.
    type: str
    choices: [set, add]
    default: set
attributes:
  check_mode:
    support: full
    description: Predicts ordered operations without creating, updating, or deleting shares.
  diff_mode:
    support: none
notes:
  - Share permissions do not replace filesystem permissions.
  - Removing a share leaves its directory and contents intact and does not require O(path).
  - A missing share in check mode reports only its creation action and skips subsequent property and permission updates.
  - Properties omitted for a present share reset to their defaults. Empty permission lists with O(rule_action=set) remove existing access grants.
  - Operations run in order and are not transactional. Completed changes remain if a later operation fails.
  - Access-based enumeration requires Windows Server 2003 SP1 or later. On Windows XP, set O(list=true); the default access-based listing request fails before writing.
  - Encryption requires Windows 8 or Windows Server 2012 or later. BranchCache requires Windows 7 or Windows Server 2008 R2 or later. Unsupported requests fail in both normal and check mode.
author:
  - Joe Lustri
"""

EXAMPLES = r"""
- name: Share an existing deployment directory
  sustainablelobster.legacy_windows.win_share:
    name: Deployment
    path: C:\Deployment
    description: Deployment files
    full: Administrators
    read: Users

- name: Add read access without removing existing grants
  sustainablelobster.legacy_windows.win_share:
    name: Deployment
    path: C:\Deployment
    read: ApplicationReaders
    rule_action: add

- name: Remove the share without deleting its files
  sustainablelobster.legacy_windows.win_share:
    name: Deployment
    state: absent
"""

RETURN = r"""
actions:
  description: Ordered source-compatible action descriptions for performed or predicted operations.
  returned: success
  type: list
  elements: str
  sample: ['New-SmbShare -Name Deployment -Path C:\Deployment']
"""

_PARAMETERS = (
    "name",
    "path",
    "state",
    "description",
    "list",
    "read",
    "change",
    "full",
    "deny",
    "caching_mode",
    "scope_name",
    "encrypt",
    "rule_action",
)
_RIGHT_NAMES = (("read", "Read"), ("change", "Change"), ("full", "Full"))
_CACHING = ("BranchCache", "Documents", "Manual", "None", "Programs", "Unknown")


def _legacy_boolean(value):
    if value is None:
        return None
    return as_string(value, "boolean").lower() in ("yes", "on", "1", "true")


def _choice(arguments, name, default, choices):
    value = arguments.get(name, default)
    if not isinstance(value, str) or not any(
        environment.values_equal(value, candidate) for candidate in choices
    ):
        raise ValueError(
            "Get-AnsibleParam: Argument "
            + name
            + " needs to be one of "
            + ",".join(choices)
            + " but was "
            + (as_string(value, name) or "")
            + "."
        )
    return value


def _required(arguments, name):
    if name not in arguments:
        raise ValueError("Get-AnsibleParam: Missing required argument: " + name)
    return as_string(arguments[name], name)


def _accounts(value):
    if value is None:
        raise ValueError(
            "Unhandled exception while executing module: "
            "You cannot call a method on a null-valued expression."
        )
    text = value.strip(DOTNET_WHITESPACE)
    return [shares.normalize_account(name) for name in text.split(",")] if text else []


def _parameters(arguments):
    name = _required(arguments, "name")
    state = _choice(arguments, "state", "present", ("present", "absent"))
    rule_action = _choice(arguments, "rule_action", "set", ("set", "add"))
    if name is None:
        raise ValueError(
            "Unhandled exception while executing module: Cannot validate argument "
            "on parameter 'Name'. The argument is null. Provide a valid value for "
            "the argument, and then try running the command again."
        )
    result = {"name": name, "state": state, "rule_action": rule_action}
    if state.lower() == "absent":
        return result
    path = _required(arguments, "path")
    result.update(
        path=as_path(path, "path"),
        description=as_string(arguments.get("description", ""), "description"),
        scope_name=as_string(arguments.get("scope_name"), "scope_name"),
        list=_legacy_boolean(arguments.get("list", False)),
        encrypt=_legacy_boolean(arguments.get("encrypt", False)),
    )
    for option in ("read", "change", "full", "deny"):
        result[option] = _accounts(as_string(arguments.get(option, ""), option))
    result["caching_mode"] = _choice(arguments, "caching_mode", "Manual", _CACHING)
    return result


def _action(result, command, check_mode, function, *arguments):
    if not check_mode:
        function(*arguments)
    result["actions"].append(command)
    result["changed"] = True


def _remove_first(values, value):
    if value in values:
        values.remove(value)


def _access(parameters, share, result, check_mode):
    requested = {
        key: list(parameters[key]) for key in ("read", "change", "full", "deny")
    }
    for user in requested["full"]:
        _remove_first(requested["change"], user)
        _remove_first(requested["read"], user)
    for user in requested["change"]:
        _remove_first(requested["read"], user)
    permissions = shares.access_entries(share)
    for entry in permissions:
        user = entry["account"]
        kind = "deny" if entry["control"] == "Deny" else entry["right"].lower()
        if parameters["rule_action"].lower() == "set":
            if kind == "deny" and user == "Everyone" and len(permissions) == 1:
                continue
            if user not in requested[kind]:
                verb = "Unblock" if kind == "deny" else "Revoke"
                command = (
                    verb
                    + "-SmbShareAccess -Force -Name "
                    + parameters["name"]
                    + " -AccountName "
                    + user
                )
                _action(
                    result,
                    command,
                    check_mode,
                    shares.change_access,
                    parameters["name"],
                    user,
                    entry["right"],
                    entry["control"],
                    True,
                )
                continue
        _remove_first(requested[kind], user)
    for kind, right in _RIGHT_NAMES + (("deny", "Full"),):
        for user in requested[kind]:
            control = "Deny" if kind == "deny" else "Allow"
            verb = "Block" if kind == "deny" else "Grant"
            command = (
                verb
                + "-SmbShareAccess -Force -Name "
                + parameters["name"]
                + " -AccountName "
                + user
            )
            if kind != "deny":
                command += " -AccessRight " + right
            _action(
                result,
                command,
                check_mode,
                shares.change_access,
                parameters["name"],
                user,
                right,
                control,
            )


def _unsupported_setting(parameters):
    # Windows provides this function; the Linux development interpreter does not.
    version = sys.getwindowsversion()  # pylint: disable=no-member
    release = (version.major, version.minor)
    if not parameters["list"] and (
        release < (5, 2)
        or (
            release == (5, 2)
            and (version.product_type == 1 or version.service_pack_major < 1)
        )
    ):
        return (
            "Access-based enumeration requires Windows Server 2003 SP1 or later; "
            "set list=true on this target."
        )
    if parameters["encrypt"] and release < (6, 2):
        return "Share encryption requires Windows 8 or Windows Server 2012 or later."
    if parameters["caching_mode"].lower() == "branchcache" and release < (6, 1):
        return "BranchCache requires Windows 7 or Windows Server 2008 R2 or later."
    return None


def _present(parameters, share, result, check_mode):
    path = parameters["path"]
    if path is None:
        raise ValueError(
            "Unhandled exception while executing module: Cannot bind argument "
            "to parameter 'LiteralPath' because it is null."
        )
    if not path or not os.path.exists(path):
        result.update(
            failed=True, msg=(path or "") + " directory does not exist on the host"
        )
        return result
    unsupported = _unsupported_setting(parameters)
    if unsupported is not None:
        result.update(failed=True, msg=unsupported)
        return result
    path = ntpath.normpath(os.path.abspath(path))
    name = parameters["name"]
    create = "New-SmbShare -Name " + name + " -Path " + path
    if share is None:
        _action(result, create, check_mode, shares.create_share, name, path)
        if check_mode:
            return result
        share = shares.get_share(name)
    if not environment.values_equal(share["path"], path):
        _action(
            result,
            "Remove-SmbShare -Force -Name " + name,
            check_mode,
            shares.delete_share,
            name,
        )
        _action(result, create, check_mode, shares.create_share, name, path)
        if not check_mode:
            share = shares.get_share(name)
    properties = (
        ("description", "Description", parameters["description"]),
        (
            "list",
            "FolderEnumerationMode",
            "Unrestricted" if parameters["list"] else "AccessBased",
        ),
        ("caching_mode", "CachingMode", parameters["caching_mode"]),
        ("encrypt", "EncryptData", parameters["encrypt"]),
        ("scope_name", "ScopeName", parameters["scope_name"]),
    )
    for field, parameter, text in properties:
        value = parameters[field]
        if field == "scope_name" and not value:
            continue
        equal = (
            share[field] == value
            if field in ("list", "encrypt")
            else environment.values_equal(share[field], value)
        )
        if not equal:
            command = (
                "Set-SmbShare -Force -Name "
                + name
                + " -"
                + parameter
                + " "
                + (as_string(text, field) or "")
            )
            _action(
                result, command, check_mode, shares.set_property, name, field, value
            )
    if not check_mode:
        share = shares.get_share(name)
    _access(parameters, share, result, check_mode)
    return result


def _manage(arguments):
    parameters = _parameters(arguments)
    check_mode = _legacy_boolean(arguments.get("_ansible_check_mode", False))
    result = {"changed": False, "actions": []}
    share = shares.get_share(parameters["name"])
    if parameters["state"].lower() == "absent":
        if share is not None:
            _action(
                result,
                "Remove-SmbShare -Force -Name " + parameters["name"],
                check_mode,
                shares.delete_share,
                parameters["name"],
            )
        return result
    return _present(parameters, share, result, check_mode)


def _response():
    try:
        # The pinned Legacy utility accepts unknown options rather than rejecting them.
        arguments = read_arguments(
            _PARAMETERS, "sustainablelobster.legacy_windows.win_share", True
        )
        return _manage(arguments)
    except ValueError as error:
        return {
            "changed": False,
            "failed": True,
            "msg": str(error),
            "exception": "(traceback unavailable)",
        }


def main():
    """Read Ansible arguments and emit the share module's JSON result.

    :raises SystemExit: After returning success or failure to Ansible.
    """
    run_module(_response)


if __name__ == "__main__":
    main()
