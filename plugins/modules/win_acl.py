#!/usr/bin/python
# -*- coding: utf-8 -*-
# Copyright 2026 Joe Lustri
# SPDX-License-Identifier: GPL-3.0-or-later

"""Manage Windows access rules through native APIs on Python 3.4.4."""

# WANT_JSON

# The action stages these Python 3.4-compatible helpers beside the payload.
import legacy_windows_acl as acl  # pylint: disable=import-error
import legacy_windows_certificate_acl as certificate  # pylint: disable=import-error
from legacy_windows_module import (  # pylint: disable=import-error
    as_string,
    read_arguments,
    run_module,
)

# Ansible interfaces must be self-contained; repeated option/return text is
# interface documentation, not duplicated execution logic.
# pylint: disable=duplicate-code
DOCUMENTATION = r"""
---
module: win_acl
short_description: Add or remove Windows access rules
version_added: '1.0.0'
description:
  - Manages access rules on existing files, directories, registry keys, and certificate private keys.
  - Uses Python 3.4.4 and native Windows security APIs.
options:
  path:
    description:
      - Literal path to the file, directory, registry key, or certificate.
      - Certificate paths use C(Cert:\LocalMachine\My\THUMBPRINT) or C(Cert:\CurrentUser\My\THUMBPRINT).
      - Percent-delimited environment variables are not expanded.
    type: str
    required: true
  user:
    description:
      - User or group whose access rule should be managed.
      - Accepts an account name, a qualified name such as C(DOMAIN\User), or a SID string.
    type: str
    required: true
  rights:
    description:
      - Comma-separated names from the Windows FileSystemRights or RegistryRights enumeration for the target.
      - Certificate private keys accept V(Read) and V(FullControl).
    type: str
    required: true
  type:
    description: Whether the rule allows or denies the requested rights.
    type: str
    required: true
    choices: [allow, deny]
  state:
    description: Add the specified rule with V(present) or remove it with V(absent).
    type: str
    choices: [absent, present]
    default: present
  inherit:
    description:
      - Inheritance flags as a comma-separated combination of C(ContainerInherit) and C(ObjectInherit), or C(None).
      - Defaults to C(ContainerInherit, ObjectInherit) on directories and registry keys.
      - Files and certificate private keys always use C(None).
    type: str
  propagation:
    description: How the access rule propagates to inherited children.
    type: str
    choices: [InheritOnly, None, NoPropagateInherit]
    default: None
  follow:
    description: Resolve filesystem symbolic links and junctions before changing permissions.
    type: bool
    default: false
attributes:
  check_mode:
    support: full
    description: Predicts the upstream rule match without changing permissions; write-time errors can still occur outside check mode.
  diff_mode:
    support: none
notes:
  - File and registry matching includes identity, rights, allow or deny type, inheritance, and propagation. Inherited entries do not match explicit rules.
  - Certificate matching requires the requested native rights. Unlike upstream, an existing Read rule does not satisfy a FullControl request.
  - CAPI supports complete Read and FullControl rules. Partial removals that the provider would round back to FullControl fail before writing. CNG supports granular native rights removal.
  - Windows can combine compatible rules when adding access. A broader existing file or registry rule does not count as an exact match.
  - Changing an inheritable rule can update permissions on descendants.
  - Ordinary access-rule insertion preserves unrelated object and callback ACE bytes and keeps their canonical position before inherited entries.
  - The module constructs ordinary access rules only. It does not construct object GUID restrictions or callback conditions, or rewrite existing condition and GUID data.
  - Matching recognizes common callback allow and deny entries, including conditional entries, by their ordinary rule fields on files, registry keys, and certificate keys. An exact match prevents an unconditional rule from being inserted.
  - Once an exact match is found, C(state=absent) subtracts the requested rights from overlapping ordinary and common callback entries with the same identity and allow or deny type. Remaining callback entries retain their condition bytes; inherited entries are preserved.
  - Object and callback-object entries do not satisfy ordinary-rule matching. Adding an ordinary rule for the same principal and allow or deny type is rejected before writing because it could bypass their restrictions.
  - An unmatched conditional certificate rule similarly prevents unconditional insertion for its principal. Use a condition-aware tool to change those restrictions.
  - The executing account needs sufficient rights to read and change permissions.
seealso:
  - module: sustainablelobster.legacy_windows.win_acl_inheritance
  - module: sustainablelobster.legacy_windows.win_owner
author:
  - Joe Lustri
"""

EXAMPLES = r"""
- name: Grant a group read access to an application directory
  sustainablelobster.legacy_windows.win_acl:
    path: C:\Application\reports
    user: BUILTIN\Users
    rights: ReadAndExecute
    type: allow

- name: Remove a registry query permission
  sustainablelobster.legacy_windows.win_acl:
    path: HKCU:\Software\Application
    user: BUILTIN\Users
    rights: QueryValues
    type: allow
    state: absent

- name: Allow certificate private-key reads
  sustainablelobster.legacy_windows.win_acl:
    path: Cert:\LocalMachine\My\0123456789ABCDEF0123456789ABCDEF01234567
    user: BUILTIN\Users
    rights: Read
    type: allow
"""

RETURN = r"""
{}
"""
# pylint: enable=duplicate-code

_MODULE_NAME = "sustainablelobster.legacy_windows.win_acl"
_PARAMETERS = (
    "path",
    "user",
    "rights",
    "type",
    "state",
    "inherit",
    "propagation",
    "follow",
)


def _legacy_bool(value):
    # The upstream legacy parser recognizes these four strings and treats all
    # other values as false; it neither trims strings nor rejects invalid ones.
    return as_string(value, "boolean") in ("True", "1") or (
        isinstance(value, str) and value.lower() in ("yes", "on", "1", "true")
    )


def _choice(arguments, name, choices, default=None):
    value = arguments.get(name, default)
    if not isinstance(value, str) or value.lower() not in (
        choice.lower() for choice in choices
    ):
        raise ValueError(
            "Get-AnsibleParam: Argument {0} needs to be one of {1} but was {2}.".format(
                name, ",".join(choices), "" if value is None else as_string(value, name)
            )
        )
    return value


def _parameters(arguments):
    result = {}
    for name in ("path", "user", "rights", "type"):
        if name not in arguments:
            raise ValueError("Get-AnsibleParam: Missing required argument: " + name)
        result[name] = as_string(arguments[name], name)
    result["type"] = _choice(arguments, "type", ("allow", "deny")).lower()
    result["state"] = _choice(arguments, "state", ("absent", "present"), "present")
    result["inherit"] = as_string(arguments.get("inherit"), "inherit")
    result["propagation"] = _choice(
        arguments, "propagation", ("InheritOnly", "None", "NoPropagateInherit"), "None"
    )
    result["follow"] = _legacy_bool(arguments.get("follow", False))
    return result


def _failure(message):
    return {"changed": False, "failed": True, "msg": message}


def _user_sid(user):
    if not user:
        raise ValueError(
            'Unhandled exception while executing module: Exception calling ".ctor" '
            'with "1" argument(s): "String cannot be of zero length.\r\n'
            'Parameter name: name"'
        )
    try:
        sid = acl.resolve_user(user)
    except OSError as error:
        if getattr(error, "winerror", None) != 1332:
            raise
        raise ValueError(
            "account_name {0} is not a valid account, cannot get SID: Exception "
            'calling "Translate" with "1" argument(s): "Some or all identity '
            'references could not be translated."'.format(user)
        ) from error
    if not sid:
        raise ValueError(
            "{0} is not a valid user or group on the host machine or domain".format(
                user
            )
        )
    return sid


def _change_rule(parameters, snapshot, writer, rule, check_mode):
    matched = acl.has_rule(snapshot, rule)
    present = parameters["state"].lower() == "present"
    if matched == present:
        return {"changed": False}
    try:
        if present:
            acl.validate_addition(snapshot, rule)
        if check_mode and snapshot.get("kind") == "certificate" and not present:
            acl.remove_rule(snapshot, rule)
        if not check_mode:
            operation = acl.add_rule if present else acl.remove_rule
            writer(operation(snapshot, rule))
    except (OSError, ValueError) as error:
        return _failure(
            "an exception occurred when {0} the specified rule - {1}".format(
                "adding" if present else "removing", error
            )
        )
    return {"changed": True}


def _manage(parameters, check_mode=False):
    path, user = parameters["path"], parameters["user"]
    if not path:
        return _failure(
            "Unhandled exception while executing module: Cannot bind argument "
            "to parameter 'Path' because it is {0}.".format(
                "null" if path is None else "an empty string"
            )
        )
    backend = certificate if path.lower().startswith("cert:") else acl
    try:
        target = (
            certificate.resolve_target(path)
            if backend is certificate
            else acl.resolve_target(path, parameters["follow"])
        )
    except (OSError, ValueError) as error:
        return _failure(str(error))
    if target is None:
        return {
            "changed": False,
            "failed": True,
            "msg": "{0} file or directory does not exist on the host".format(
                path or ""
            ),
        }
    path = target["path"]
    try:
        sid = _user_sid(user)
    except (OSError, ValueError) as error:
        return _failure(str(error))
    rule_arguments = (
        sid,
        parameters["rights"],
        parameters["type"],
        parameters["inherit"],
        parameters["propagation"],
    )
    try:
        with acl.acl_privileges():
            rule = (
                None
                if backend is certificate
                else acl.make_rule(target, *rule_arguments)
            )
            with backend.open_acl(target) as (snapshot, writer):
                if backend is certificate:
                    rule = acl.make_rule(snapshot, *rule_arguments)
                return _change_rule(parameters, snapshot, writer, rule, check_mode)
    except (OSError, ValueError) as error:
        return _failure(
            (
                "an error occurred when attempting to {0} {1} "
                "permission(s) on {2} for {3} - {4}"
            ).format(
                parameters["state"], parameters["rights"] or "", path, user or "", error
            )
        )


def _execute():
    arguments = read_arguments(_PARAMETERS, _MODULE_NAME, allow_unknown=True)
    return _manage(
        _parameters(arguments),
        _legacy_bool(arguments.get("_ansible_check_mode", False)),
    )


def main():
    """Read Ansible arguments and emit the access-rule result.

    :raises SystemExit: After reporting success or failure to Ansible.
    """
    run_module(_execute)


if __name__ == "__main__":
    main()
