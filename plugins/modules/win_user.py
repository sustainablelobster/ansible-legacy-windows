#!/usr/bin/python
# -*- coding: utf-8 -*-
# Copyright 2026 Joe Lustri
# SPDX-License-Identifier: GPL-3.0-or-later

"""Manage local Windows users with a Python 3.4.4 payload."""

# WANT_JSON

import traceback
from collections import OrderedDict

# The action stages these Python 3.4-compatible helpers beside the payload.
import legacy_windows_account as accounts  # pylint: disable=import-error
import legacy_windows_datetime as dates  # pylint: disable=import-error
import legacy_windows_environment as environment  # pylint: disable=import-error
import legacy_windows_group as groups  # pylint: disable=import-error
import legacy_windows_user as users  # pylint: disable=import-error
import legacy_windows_user_time as user_time  # pylint: disable=import-error
from legacy_windows_module import (  # pylint: disable=import-error
    DOTNET_WHITESPACE,
    as_bool,
    as_string,
    as_string_list,
    read_arguments,
    run_module,
)

DOCUMENTATION = r"""
---
module: win_user
short_description: Manage local Windows user accounts
version_added: '1.0.0'
description:
  - Creates, updates, queries, or removes local Windows user accounts.
  - Uses Python 3.4.4 and native Windows APIs.
options:
  name:
    description: Local user name to create, update, query, or remove.
    type: str
    required: true
  state:
    description:
      - V(present) creates or updates the account.
      - V(absent) removes the account if it exists.
      - V(query) returns the current account without changing it.
    type: str
    choices: [present, absent, query]
    default: present
  password:
    description: Optional plaintext password, excluded from diagnostic messages and invocation values.
    type: str
  update_password:
    description:
      - V(always) updates a supplied password when it differs.
      - V(on_create) sets the password only when creating the account.
    type: str
    choices: [always, on_create]
    default: always
  fullname:
    description: Full name of the user. An empty string clears it.
    type: str
  description:
    description: Account description. An empty string clears it.
    type: str
  home_directory:
    description: Home directory assigned to the user. An empty string clears it.
    type: str
  login_script:
    description: Login script assigned to the user. An empty string clears it.
    type: str
  profile:
    description: Profile path assigned to the user. An empty string clears it.
    type: str
  account_disabled:
    description: Whether the account is disabled.
    type: bool
  account_expires:
    description:
      - Expiration date in C(yyyy-MM-dd) or C(yyyy-MM-ddTHH:mm:ss.FFFFFFFK) form.
      - The long form accepts up to seven fractional digits and a timezone of C(Z), C(±HHMM), or C(±HH:MM).
      - An omitted timezone means UTC. V(never) clears expiration.
    type: str
  account_locked:
    description: Only V(false) is accepted; clears an existing account lockout.
    type: bool
  password_expired:
    description: Whether the user must change their password at next login.
    type: bool
  password_never_expires:
    description: Whether the user's password is exempt from expiration.
    type: bool
  user_cannot_change_password:
    description: Whether the user is prevented from changing their own password.
    type: bool
  groups:
    description:
      - Existing local groups identified by name or SID.
      - Also accepts a comma-separated string.
      - An empty list or string with O(groups_action=replace) removes every membership.
    type: list
    elements: str
  groups_action:
    description:
      - V(add) adds missing memberships and V(remove) removes requested memberships.
      - V(replace) makes the requested groups the complete membership.
    type: str
    choices: [add, remove, replace]
    default: replace
attributes:
  check_mode:
    support: full
    description: Predicts changes; returned account fields continue to describe actual stored state.
  diff_mode:
    support: full
    description: Returns the pinned upstream before and proposed after account fields, with password markers.
notes:
  - Password updates precede other property updates, which precede group changes.
  - Completed changes remain if a subsequent operation fails.
  - Disabled accounts and accounts with expired passwords force a supplied password update with O(update_password=always).
  - New accounts in check mode skip property changes and group lookups, but still validate arguments and expiration input.
  - Diffs preserve the upstream group-name behavior; removed qualified group names can remain in the proposed diff.
seealso:
  - module: sustainablelobster.legacy_windows.win_group
  - module: sustainablelobster.legacy_windows.win_group_membership
author:
  - Joe Lustri
"""

EXAMPLES = r"""
- name: Create an application user
  sustainablelobster.legacy_windows.win_user:
    name: ApplicationUser
    password: '{{ application_password }}'
    groups: [Users]
    password_never_expires: true

- name: Query an account
  sustainablelobster.legacy_windows.win_user:
    name: ApplicationUser
    state: query

- name: Clear an account expiration date
  sustainablelobster.legacy_windows.win_user:
    name: ApplicationUser
    account_expires: never

- name: Remove an account
  sustainablelobster.legacy_windows.win_user:
    name: ApplicationUser
    state: absent
"""

RETURN = r"""
name:
  description: Supplied user name.
  returned: success
  type: str
  sample: ApplicationUser
state:
  description: Requested state, or the account's present or absent state for a query.
  returned: success
  type: str
  sample: present
fullname:
  description: Stored full name.
  returned: user exists after execution
  type: str
  sample: Application User
description:
  description: Stored account description.
  returned: user exists after execution
  type: str
  sample: Application account
path:
  description: WinNT provider path for the local user.
  returned: user exists after execution
  type: str
  sample: 'WinNT://WORKGROUP/SERVER/ApplicationUser'
sid:
  description: Account security identifier.
  returned: user exists after execution
  type: str
  sample: S-1-5-21-2528685370-1724360342-165486190-1208
groups:
  description: Direct group memberships, each with name and WinNT path.
  returned: user exists after execution
  type: list
  elements: dict
  sample: [{name: Users, path: 'WinNT://WORKGROUP/SERVER/Users'}]
account_disabled:
  description: Whether the stored account is disabled.
  returned: user exists after execution
  type: bool
  sample: false
account_locked:
  description: Whether the stored account is locked out.
  returned: user exists after execution
  type: bool
  sample: false
password_expired:
  description: Whether the stored password must be changed at next login.
  returned: user exists after execution
  type: bool
  sample: false
password_never_expires:
  description: Whether the stored password is exempt from expiration.
  returned: user exists after execution
  type: bool
  sample: false
user_cannot_change_password:
  description: Whether the user is prevented from changing their own password.
  returned: user exists after execution
  type: bool
  sample: false
"""

_MODULE_NAME = "sustainablelobster.legacy_windows.win_user"
_BOOLEANS = (
    "account_disabled",
    "account_locked",
    "password_expired",
    "password_never_expires",
    "user_cannot_change_password",
)
_STRINGS = {
    "fullname": "full_name",
    "description": "comment",
    "home_directory": "home_dir",
    "login_script": "script_path",
    "profile": "profile",
}
_CHOICES = {
    "state": ("present", "absent", "query"),
    "groups_action": ("add", "remove", "replace"),
    "update_password": ("always", "on_create"),
}
_DEFAULTS = {
    "state": "present",
    "groups_action": "replace",
    "update_password": "always",
}
_PARAMETERS = tuple(
    sorted(
        tuple(_STRINGS)
        + _BOOLEANS
        + tuple(_CHOICES)
        + ("name", "password", "account_expires", "groups")
    )
)
_FLAGS = {
    "account_disabled": 2,
    "account_locked": 16,
    "password_never_expires": 65536,
    "user_cannot_change_password": 64,
}
_EXPIRATION_ERROR = (
    "Failed to parse account_expires as datetime string. Expecting datetime in "
    "yyyy-MM-dd or yyyy-MM-ddTHH:mm:ss.FFFFFFFK format."
)


def _parameters(arguments):
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
    if "name" not in arguments:
        raise ValueError("missing required arguments: name")
    parameters = {}
    for name in _PARAMETERS:
        value = arguments.get(name, _DEFAULTS.get(name))
        if value is None:
            parameters[name] = None
        elif name in _BOOLEANS:
            parameters[name] = as_bool(value, name)
        elif name == "groups":
            parameters[name] = as_string_list(value, name)
        else:
            parameters[name] = as_string(value, name)
        choices = _CHOICES.get(name)
        if (
            choices
            and parameters[name] is not None
            and parameters[name].lower() not in choices
        ):
            raise ValueError(
                "value of {0} must be one of: {1}. Got no match for: {2}".format(
                    name, ", ".join(choices), parameters[name]
                )
            )
    return parameters


def _find_user(name):
    if not name:
        raise RuntimeError(
            "Cannot bind argument to parameter 'Name' because it is an empty string."
        )
    matching = [
        candidate
        for candidate in accounts.local_user_names()
        if environment.values_equal(candidate, name)
    ]
    if len(matching) > 1:
        raise ValueError("More than one local user matches the supplied name.")
    if not matching:
        return None
    raw = users.read_user(matching[0])
    if raw is None:
        return None
    user = {name: raw[field] for name, field in _STRINGS.items()}
    user.update(
        name=raw["name"],
        sid=raw["sid"],
        flags=raw["flags"],
        path=users.account_path(raw["name"]),
        password_expired=bool(raw["password_expired"]),
        account_expires=user_time.account_expiration_ticks(raw["acct_expires"]),
    )
    user.update((name, bool(raw["flags"] & flag)) for name, flag in _FLAGS.items())
    user["groups"] = [
        {
            "name": group,
            "sid": accounts.local_group_sid(group),
            "path": users.account_path(group),
        }
        for group in users.local_group_names(raw["name"])
    ]
    return user


def _user_diff(user):
    if user is None:
        return ""
    result = {name: user[name] for name in tuple(_STRINGS) + _BOOLEANS + ("name",)}
    result["password"] = "REDACTED"
    result["account_expires"] = (
        "never"
        if user["account_expires"] is None
        else dates.format_account_expiration(user["account_expires"])
    )
    result["groups"] = []
    for group in user["groups"]:
        translated = accounts.sid_to_name(group["sid"])
        result["groups"].append(
            group["name"] if translated == group["sid"] else translated
        )
    return result


def _fail(result, message):
    result.update(failed=True, msg=message)
    return False


def _password(parameters, user, result, after, check_mode):
    password = parameters["password"]
    if password is None or (parameters["update_password"] or "").lower() != "always":
        return True
    matches = False
    if not user["account_disabled"] and not user["password_expired"]:
        if password == "":
            raise RuntimeError(
                "Cannot bind argument to parameter 'Password' because it is an empty string."
            )
        try:
            matches = users.password_matches(user["name"], password)
        except OSError as error:
            return _fail(
                result, "Failed to validate the user's credentials: " + str(error)
            )
    if not matches:
        if not check_mode:
            users.set_password(user["name"], password)
        result["changed"] = True
        after["password"] = "CHANGED REDACTED"
    return True


def _properties(parameters, expiration, user, result, after):
    changes = {}
    flags = user["flags"]
    for name in (
        "account_disabled",
        "account_expires",
        "account_locked",
        "fullname",
        "description",
        "home_directory",
        "login_script",
        "password_expired",
        "password_never_expires",
        "profile",
        "user_cannot_change_password",
    ):
        value = parameters[name]
        if name == "account_expires":
            if expiration is None:
                continue
            ticks, offset = expiration
            if ticks == user["account_expires"]:
                continue
            changes["acct_expires"] = (
                0xFFFFFFFF
                if ticks is None
                else user_time.account_expiration_seconds(ticks)
            )
            after[name] = (
                "never"
                if ticks is None
                else dates.format_account_expiration(ticks, offset)
            )
        else:
            if value is None:
                continue
            unchanged = (
                environment.values_equal(user[name], value)
                if name in ("home_directory", "login_script", "profile")
                else user[name] == value
            )
            if unchanged:
                continue
            if name in _FLAGS:
                flag = _FLAGS[name]
                flags = flags | flag if value else flags & ~flag
                changes["flags"] = flags
            elif name == "password_expired":
                changes[name] = int(value)
            else:
                changes[_STRINGS[name]] = value
            after[name] = value
        result["changed"] = True
    return changes


def _resolve_group(name, local_groups):
    # NTAccount in win_user does not expand the dot domain used by other modules.
    if name.startswith(".\\"):
        return None
    try:
        sid = accounts.name_to_sid(name)
    except OSError as error:
        if getattr(error, "winerror", error.errno) == 1332:
            return None
        raise
    return sid if sid in local_groups else None


def _requested_groups(requested, result):
    local = {
        accounts.local_group_sid(group["name"]): group["name"]
        for group in groups.list_groups()
    }
    desired = OrderedDict()
    for name in requested:
        if not name.strip(DOTNET_WHITESPACE):
            continue
        sid = _resolve_group(name, local)
        if sid is None:
            _fail(result, "group '{0}' not found".format(name))
            return None
        desired[sid] = local[sid]
    return desired


def _change_groups(parameters, user, result, after, check_mode):
    if parameters["groups"] is None:
        return True
    desired = _requested_groups(parameters["groups"], result)
    if desired is None:
        return False
    existing = OrderedDict((group["sid"], group["name"]) for group in user["groups"])
    action = (parameters["groups_action"] or "").lower()
    add = [] if action == "remove" else [sid for sid in desired if sid not in existing]
    remove = (
        [sid for sid in desired if sid in existing]
        if action == "remove"
        else (
            [] if action == "add" else [sid for sid in existing if sid not in desired]
        )
    )
    for adding, entries in ((True, add), (False, remove)):
        for sid in entries:
            group = desired[sid] if sid in desired else existing[sid]
            if not check_mode:
                try:
                    (groups.add_member if adding else groups.remove_member)(
                        group, user["sid"]
                    )
                # The pinned module retains completed changes for any membership failure.
                except Exception as error:  # pylint: disable=broad-exception-caught
                    return _fail(
                        result,
                        "Failed to {0} {1}: {2}".format(
                            "add" if adding else "remove", group, error
                        ),
                    )
            result["changed"] = True
            if adding:
                after["groups"].append(group)
            elif group in after["groups"]:
                # Upstream removes the unqualified name from a qualified-name list.
                after["groups"].remove(group)
    return True


def _present(parameters, expiration, user, result, check_mode):
    diff = result["diff"]
    if user is None:
        diff["after"] = {"name": parameters["name"]}
        if parameters["password"] is not None:
            diff["after"]["password"] = "REDACTED"
        if not check_mode:
            users.create_user(parameters["name"], parameters["password"], 513)
            user = _find_user(parameters["name"])
        result["changed"] = True
    if user is not None:
        diff["after"] = _user_diff(user)
        if not _password(parameters, user, result, diff["after"], check_mode):
            return False
        changes = _properties(parameters, expiration, user, result, diff["after"])
        if result["changed"] and not check_mode:
            users.update_user(user["name"], changes)
        if not _change_groups(parameters, user, result, diff["after"], check_mode):
            return False
    result["state"] = "present"
    return True


def _manage_user(parameters, check_mode):
    diff = {"before": "", "after": ""}
    result = {"changed": False, "diff": diff}
    if parameters["account_locked"] is True:
        _fail(result, "account_locked must be set to 'no' if provided")
        return result
    expiration = None
    raw_expiration = parameters["account_expires"]
    if raw_expiration:
        try:
            expiration = (
                (None, None)
                if raw_expiration.lower() == "never"
                else dates.parse_account_expiration(raw_expiration)
            )
        except ValueError:
            _fail(result, _EXPIRATION_ERROR)
            return result
    user = _find_user(parameters["name"])
    diff["before"] = _user_diff(user)
    state = (parameters["state"] or "").lower()
    if state == "present":
        if not _present(parameters, expiration, user, result, check_mode):
            return result
    elif state == "absent":
        if user is not None:
            if not check_mode:
                users.delete_user(user["name"])
            result.update(
                changed=True, msg="User '{0}' deleted successfully".format(user["name"])
            )
        else:
            result["msg"] = "User '{0}' was not found".format(parameters["name"])
        result["state"] = "absent"
    else:
        result.update(
            msg="Querying user '{0}'".format(parameters["name"]),
            state="present" if user is not None else "absent",
        )
        diff["after"] = diff["before"]
    current = _find_user(parameters["name"])
    result["name"] = parameters["name"]
    if current is not None:
        result.update(
            (name, current[name])
            for name in ("fullname", "path", "description", "sid") + _BOOLEANS
        )
        result["groups"] = [
            {"name": group["name"], "path": group["path"]}
            for group in current["groups"]
        ]
    return result


def _user(parameters, check_mode=False, diff_mode=False):
    result = _manage_user(parameters, check_mode)
    if not diff_mode:
        result.pop("diff")
    return result


def _redact(value, password):
    if not password:
        return value
    if isinstance(value, dict):
        return {
            _redact(key, password): _redact(entry, password)
            for key, entry in value.items()
        }
    if isinstance(value, list):
        return [_redact(entry, password) for entry in value]
    if value is None:
        return value
    text = as_string(value, "password redaction")
    if text == password or (not isinstance(value, str) and password in text):
        return "VALUE_SPECIFIED_IN_NO_LOG_PARAMETER"
    return text.replace(password, "********") if isinstance(value, str) else value


def _response():
    arguments = read_arguments(_PARAMETERS, _MODULE_NAME, allow_unknown=True)
    password = as_string(arguments.get("password"), "password")
    parameters = None
    try:
        parameters = _parameters(arguments)
        check_mode = as_bool(
            arguments.get("_ansible_check_mode", False), "_ansible_check_mode"
        )
        diff_mode = as_bool(arguments.get("_ansible_diff", False), "_ansible_diff")
    except (ValueError, OSError) as error:
        result = {"changed": False, "failed": True, "msg": str(error)}
    else:
        try:
            result = _user(parameters, check_mode, diff_mode)
        # Uncaught upstream failures discard partial result/diff while preserving writes.
        except Exception as error:  # pylint: disable=broad-exception-caught
            result = {
                "changed": False,
                "failed": True,
                "msg": "Unhandled exception while executing module: " + str(error),
                "exception": traceback.format_exc(),
            }
    for name in ("msg", "exception"):
        if name in result:
            result[name] = _redact(result[name], password)
    if as_bool(
        arguments.get("_ansible_inject_invocation", False), "_ansible_inject_invocation"
    ):
        invocation = (
            parameters
            if parameters is not None
            else {
                name: value
                for name, value in arguments.items()
                if not name.startswith("_ansible_")
            }
        )
        result["invocation"] = {"module_args": _redact(invocation, password)}
    return result


def main():
    """Read Ansible arguments and emit the local-user result.

    :raises SystemExit: After reporting success or failure to Ansible.
    """
    run_module(_response)


if __name__ == "__main__":
    main()
