#!/usr/bin/python
# -*- coding: utf-8 -*-
# Copyright 2026 Joe Lustri
# SPDX-License-Identifier: GPL-3.0-or-later

"""Manage Windows profiles with Python 3.4.4 and native Userenv calls."""

# WANT_JSON

# The action stages these Python 3.4-compatible helpers beside the payload.
import legacy_windows_account as accounts  # pylint: disable=import-error
import legacy_windows_environment as environment  # pylint: disable=import-error
import legacy_windows_user_profile as profiles  # pylint: disable=import-error
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
module: win_user_profile
short_description: Create or remove Windows user profiles
version_added: '1.0.0'
description:
  - Creates profiles before first logon and removes existing profiles.
  - Uses Python 3.4.4 and native Windows interfaces.
options:
  name:
    description:
      - Base directory name for a new profile, defaulting to the account name.
      - With O(state=absent) and no O(username), selects registered profiles by the resulting profile path.
      - Windows chooses a collision suffix when creating a profile whose requested directory already exists.
    type: str
  remove_multiple:
    description: Allow removal when O(name) selects multiple registered profiles.
    type: bool
    default: false
  state:
    description: Whether the profile should exist.
    type: str
    choices: [absent, present]
    default: present
  username:
    description:
      - Account name or SID identifying the profile.
      - Required for O(state=present); a new profile needs a SID that maps to an account.
      - Removal accepts a deleted account's SID. Supply O(name) or O(username) for O(state=absent).
    type: sid
attributes:
  check_mode:
    support: full
    description: Predicts changes; a creation preview does not predict collision suffixes.
  diff_mode:
    support: none
notes:
  - Requires administrative rights for profile creation or removal.
  - Does not create, remove, or change the corresponding user account.
  - Removal of multiple profiles is not transactional; earlier removals remain if a later removal fails.
  - Creating a new profile uses CreateProfile; Windows versions without that entry point reject an actual creation.
seealso:
  - module: sustainablelobster.legacy_windows.win_user
author:
  - Joe Lustri
"""

EXAMPLES = r"""
- name: Create a profile before the account's first logon
  sustainablelobster.legacy_windows.win_user_profile:
    username: application-user

- name: Remove a profile after deleting its account
  sustainablelobster.legacy_windows.win_user_profile:
    username: S-1-5-21-123-456-789-1001
    state: absent
"""

RETURN = r"""
path:
  description: Resolved, predicted, created, or last removed profile directory; null when no profile is selected.
  returned: success and some failures after argument validation
  type: str
  sample: C:\Users\application-user
"""
# pylint: enable=duplicate-code

_MODULE_NAME = "sustainablelobster.legacy_windows.win_user_profile"
_PARAMETERS = ("name", "remove_multiple", "state", "username")


def _sid(username):
    if isinstance(username, str):
        kind = "System.String"
    elif isinstance(username, bool):
        kind = "System.Boolean"
    elif isinstance(username, int):
        kind = "System.Int32" if -(2**31) <= username < 2**31 else "System.Int64"
    elif isinstance(username, float):
        kind = "System.Decimal"
    elif isinstance(username, list):
        kind = "System.Object[]"
    else:
        kind = "System.Collections.Generic.Dictionary`2[System.String,System.Object]"
    username = as_string(username, "username")
    try:
        # The original SID binder treats '.' as a literal domain, not shorthand.
        if username.startswith(".\\"):
            raise ValueError("Some or all identity references could not be translated.")
        return accounts.name_to_sid(username)
    except (OSError, ValueError) as error:
        detail = str(error)
        if username == "":
            detail = "String cannot be of zero length.\r\nParameter name: name"
        elif (
            getattr(
                error, "winerror", error.errno if isinstance(error, OSError) else None
            )
            == 1332
        ):
            detail = "Some or all identity references could not be translated."
        raise ValueError(
            "argument for username is of type "
            + kind
            + " and we were unable to convert to sid: "
            + detail
        ) from error


def _failure(result, message):
    result.update({"failed": True, "msg": message})
    return result


def _parameters(arguments):
    name = as_string(arguments.get("name"), "name")
    multiple = arguments.get("remove_multiple", False)
    multiple = False if multiple is None else as_bool(multiple, "remove_multiple")
    state = as_string(arguments.get("state", "present"), "state")
    if state is not None and state.lower() not in ("absent", "present"):
        raise ValueError(
            "value of state must be one of: absent, present. Got no match for: "
            + str(state)
        )
    username = arguments.get("username")
    sid = None if username is None else _sid(username)
    if state == "present" and "username" not in arguments:
        raise ValueError(
            "state is present but all of the following are missing: username"
        )
    if state == "absent" and not any(key in arguments for key in ("name", "username")):
        raise ValueError(
            "state is absent but any of the following are missing: name, username"
        )
    return {
        "name": name,
        "sid": sid,
        "state": state.lower() if state is not None else None,
        "remove_multiple": multiple,
    }


def _expected_path(name):
    root = profiles.profiles_directory()
    child = (name or "").replace("/", "\\")
    # Join-Path treats even drive-qualified ChildPath text as provider-relative,
    # removing only one leading separator and retaining other components.
    if child.startswith("\\"):
        child = child[1:]
    return root + ("" if root.endswith("\\") else "\\") + child


def _remove(selected, check_mode, result):
    for sid in selected:
        path = profiles.profile_path(sid)
        if not check_mode:
            try:
                profiles.delete_profile(sid)
            except OSError as error:
                code = getattr(error, "winerror", error.errno)
                detail = "{0} (Win32 ErrorCode {1} - 0x{1:08X})".format(
                    error.strerror, code
                )
                return _failure(
                    result,
                    "Failed to delete the profile for " + sid + ": " + detail,
                )
        result.update({"changed": True, "path": path})
    return result


def _present(sid, name, selected, check_mode, result):
    if selected:
        result["path"] = profiles.profile_path(selected[0])
        return result
    account = accounts.sid_to_name(sid)
    if account == sid:
        return _failure(result, "Fail to map the account '" + sid + "' to a valid user")
    if name is None:
        name = account.split("\\", 1)[-1]
    if check_mode:
        path = _expected_path(name)
    else:
        try:
            path = profiles.create_profile(sid, name)
        except OSError as error:
            return _failure(
                result, "Failed to create profile for user '" + sid + "': " + str(error)
            )
    result.update({"changed": True, "path": path})
    return result


def _manage(parameters, check_mode):
    result = {"changed": False, "path": None}
    entries = profiles.profile_sids()
    if parameters["state"] is None:
        return result
    sid, name = parameters["sid"], parameters["name"]
    if parameters["state"] == "present" and sid is None:
        # Upstream accepts an explicit null selector, then loses its initialized
        # result when the null SID's Translate method fails.
        return _failure(
            {"changed": False, "exception": "(traceback unavailable)"},
            "Unhandled exception while executing module: "
            "You cannot call a method on a null-valued expression.",
        )
    if sid is not None:
        selected = [entry for entry in entries if environment.values_equal(entry, sid)]
    else:
        expected = _expected_path(name)
        selected = [
            entry
            for entry in entries
            if environment.values_equal(profiles.profile_path(entry), expected)
        ]
        if len(selected) > 1 and not parameters["remove_multiple"]:
            return _failure(
                result,
                "Found multiple profiles matching the path '"
                + expected
                + "', set 'remove_multiple=True' to remove all the profiles for this match",
            )
    if parameters["state"] == "absent":
        return _remove(selected, check_mode, result)
    return _present(sid, name, selected, check_mode, result)


def _response():
    arguments = read_arguments(_PARAMETERS, _MODULE_NAME)
    parameters = _parameters(arguments)
    check_mode = as_bool(
        arguments.get("_ansible_check_mode", False), "_ansible_check_mode"
    )
    return _manage(parameters, check_mode)


def main():
    """Read an Ansible JSON request and emit the profile-management result.

    :raises SystemExit: After reporting success or failure to Ansible.
    """
    run_module(_response)


# Each independently staged payload needs its own executable entry guard.
# pylint: disable=duplicate-code
if __name__ == "__main__":
    main()
# pylint: enable=duplicate-code
