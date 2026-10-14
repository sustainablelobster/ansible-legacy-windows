#!/usr/bin/python
# -*- coding: utf-8 -*-
# Copyright 2026 sustainablelobster
# SPDX-License-Identifier: GPL-3.0-or-later

"""Manage filesystem and registry audit rules with Python 3.4.4."""

# WANT_JSON

import legacy_windows_acl as acl  # pylint: disable=import-error
import legacy_windows_audit_rule as audit  # pylint: disable=import-error
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
module: win_audit_rule
short_description: Manage Windows filesystem and registry audit rules
version_added: '1.0.0'
description:
  - Adds audit rules to existing files, directories, and registry keys, or removes a principal's explicit rules.
  - Uses Python 3.4.4 and native Windows security APIs.
options:
  path:
    description:
      - Filesystem or registry provider path such as C(HKLM:\Software\Application).
      - The original literal name must exist. ACL operations then expand provider wildcards, including bracket ranges, as in the pinned upstream release.
    type: str
    required: true
    aliases: [dest, destination]
  user:
    description:
      - User or group account name, optionally qualified by a domain.
      - SID text can identify existing rules for matching and removal, but an unmatched add translates the original string as an account name and can fail.
    type: str
    required: true
  rights:
    description:
      - Names from FileSystemRights or RegistryRights for the target type.
      - Required with O(state=present); ignored with O(state=absent).
    type: list
    elements: str
  inheritance_flags:
    description:
      - Objects that inherit the rule from a directory or registry key.
      - Files require V(None).
    type: list
    elements: str
    choices: [None, ContainerInherit, ObjectInherit]
    default: [ContainerInherit, ObjectInherit]
  propagation_flags:
    description: How an inheritable rule propagates to descendants; ignored without inheritance flags.
    type: str
    choices: [None, InheritOnly, NoPropagateInherit]
    default: None
  audit_flags:
    description: Whether to audit successful access, failed access, or both.
    type: list
    elements: str
    choices: [failure, success]
    default: [success]
  state:
    description: Add the requested rule, or remove all explicit audit rules for O(user).
    type: str
    choices: [absent, present]
    default: present
attributes:
  check_mode:
    support: full
    description: Predicts whether the upstream match requires a write and reports the rules currently stored on disk.
  diff_mode:
    support: none
notes:
  - Inherited rules are reported but neither match an explicit request nor get removed by O(state=absent).
  - Matching uses the displayed rights and flags names, as in the pinned upstream release, rather than bit-mask containment. Some broader rules can therefore produce repeated changed results.
  - Compatible audit entries can be merged by Windows ACL semantics. Inheritable changes can affect descendants.
  - A wildcard path can select a sibling instead of the literal object. No-match and multiple-match requests retain the upstream null or array binding failures; an existing matching rule can return before that write boundary.
  - Provider escape handling and repeated path resolution can read an ACL from one object and write it to another. Returned rules describe the getter's selection, so some escaped requests repeatedly report changed without changing that selected object.
  - The executing account needs access to the object and the held SeSecurityPrivilege privilege.
  - Filesystem writes reapply the read DACL unchanged to retain Windows inheritance metadata, as the upstream setter does. They require permission to write that DACL as well as the SACL.
  - On XP and Server 2003, registry writes also reapply the unchanged DACL and require permission to write it. This preserves inherited access entries and descendant protection on these Windows versions.
  - Ordinary rules can be added alongside object, callback, and callback-object audit entries without rebuilding their opaque data. Unknown explicit ACE types or malformed SID and object-flag layouts fail before writing.
  - The module constructs ordinary audit rules only; it does not create or change object GUID restrictions or callback conditions.
  - Common callback audit entries are reported and matched using ordinary audit fields; their condition data is not included in the public result. Object and callback-object entries are excluded from that public projection, as in the pinned upstream getter, but retained in the stored ACL.
  - When a projected explicit rule triggers O(state=absent), all explicit audit ACEs for that identity are removed, including its object and callback entries. Object-only entries do not trigger removal; inherited entries remain unchanged.
  - Audit-policy configuration determines whether these rules produce Security events; this module does not change policy or promise an event.
author:
  - sustainablelobster
"""

EXAMPLES = r"""
- name: Audit successful and failed writes to a directory
  sustainablelobster.legacy_windows.win_audit_rule:
    path: C:\Application\reports
    user: BUILTIN\Users
    rights: [Write, Delete]
    audit_flags: [success, failure]

- name: Audit registry reads
  sustainablelobster.legacy_windows.win_audit_rule:
    path: HKCU:\Software\Application
    user: BUILTIN\Users
    rights: [ReadKey]

- name: Remove a principal's explicit file audit rules
  sustainablelobster.legacy_windows.win_audit_rule:
    path: C:\Application\reports\daily.txt
    user: BUILTIN\Users
    state: absent
"""

RETURN = r"""
path_type:
  description: Target kind, reported after existence and identity validation.
  returned: after resolving the target and identity
  type: str
  sample: directory
current_audit_rules:
  description:
    - Stored rules, including inherited entries, read after the operation.
    - An empty dictionary means no rules. One rule is a dictionary; multiple rules are a list of dictionaries.
    - Each rule contains string fields C(user), C(rights), C(audit_flags), C(is_inherited), C(inheritance_flags), and C(propagation_flags). C(is_inherited) is C(True) or C(False), not a boolean.
    - A failed final ACL read returns an error string instead of rules.
    - Object and callback-object ACEs are not included; common callback ACEs use the same fields as ordinary audit rules.
  returned: success and some write failures
  type: raw
"""
# pylint: enable=duplicate-code

_MODULE = "sustainablelobster.legacy_windows.win_audit_rule"
_DEFAULTS = {
    "path": None,
    "user": None,
    "rights": None,
    "inheritance_flags": ["ContainerInherit", "ObjectInherit"],
    "propagation_flags": "None",
    "audit_flags": ["success"],
    "state": "present",
}
_PARAMETERS = tuple(_DEFAULTS) + ("destination", "dest")


def _choices(value, name, choices, multiple=False):
    if value is None:
        return
    values = value if multiple else [value]
    invalid = [
        item
        for item in values
        if item.lower() not in [choice.lower() for choice in choices]
    ]
    if invalid:
        raise ValueError(
            "value of {0} must be one of: {1}. Got no match for: {2}".format(
                name, ", ".join(choices), ", ".join(invalid)
            )
        )


def _parameters(arguments):
    supplied = dict(arguments)
    for alias in ("destination", "dest"):
        if alias in supplied:
            supplied["path"] = supplied[alias]
    missing = [name for name in ("path", "user") if name not in supplied]
    if missing:
        raise ValueError("missing required arguments: " + ", ".join(missing))
    result = {}
    for name, default in _DEFAULTS.items():
        converter = (
            as_string_list
            if name in ("rights", "inheritance_flags", "audit_flags")
            else as_string
        )
        result[name] = converter(supplied.get(name, default), name)
    _choices(result["state"], "state", ("absent", "present"))
    _choices(
        result["inheritance_flags"],
        "inheritance_flags",
        ("None", "ContainerInherit", "ObjectInherit"),
        True,
    )
    _choices(
        result["propagation_flags"],
        "propagation_flags",
        ("None", "InheritOnly", "NoPropagateInherit"),
    )
    _choices(result["audit_flags"], "audit_flags", ("failure", "success"), True)
    # Basic's required_if compares strings exactly and tests key presence, not
    # the later converted value; explicit null therefore reaches the constructor.
    if result["state"] == "present" and "rights" not in supplied:
        raise ValueError(
            "state is present but all of the following are missing: rights"
        )
    for alias in ("destination", "dest"):
        if alias in supplied:
            result[alias] = supplied[alias]
    return result


def _fail(result, message, exception=False):
    result.update(failed=True, msg=message)
    if exception:
        result["exception"] = "(traceback unavailable)"


def _current(target):
    try:
        rules = []
        for selected in audit.audit_targets(target):
            current = audit.current_rules(audit.read_sacl(selected))
            rules.extend(
                current if isinstance(current, list) else [current] if current else []
            )
        return rules[0] if len(rules) == 1 else rules or {}
    except (OSError, ValueError):
        return "Unable to retrieve the ACL on " + target["path"]


def _resolve_user(user):
    try:
        return acl.resolve_user(user)
    except (OSError, ValueError) as error:
        # The pinned SID utility calls an unavailable Fail-Json on an unknown
        # account. Keep that measured diagnostic at the identity boundary.
        detail = (
            "The term 'Fail-Json' is not recognized as the name of a cmdlet, "
            "function, script file, or operable program. Check the spelling "
            "of the name, or if a path was included, verify that the path is "
            "correct and try again."
            if getattr(error, "winerror", None) == 1332
            else str(error)
        )
        raise ValueError(
            "Failed to lookup the identity ({0}): {1}".format(user, detail)
        ) from error


def _invalid_file_inheritance(target, flags):
    # PowerShell's null comparison is true; an empty array comparison is false.
    return (
        target["kind"] == "file"
        and not target["container"]
        and (flags is None or any(name.lower() != "none" for name in flags))
    )


def _requested_rule(parameters, result, target, sid):
    audit.validate_rights(target, parameters["rights"])
    if _invalid_file_inheritance(target, parameters["inheritance_flags"]):
        _fail(
            result,
            "The target type is a file. inheritance_flags must be changed to 'none'",
        )
        return None
    try:
        return audit.make_rule(
            target,
            sid,
            parameters["rights"],
            parameters["inheritance_flags"],
            parameters["propagation_flags"],
            parameters["audit_flags"],
        )
    except (OSError, ValueError) as error:
        # Uncaught constructor errors use the wrapper's fresh result,
        # unlike FailJson validation which retains path_type.
        result.clear()
        result["changed"] = False
        _fail(result, "Unhandled exception while executing module: " + str(error))
        return None


def _add_failure(result, error):
    detail = (
        'Exception calling "AddAuditRule" with "1" argument(s): '
        '"Some or all identity references could not be translated."'
        if getattr(error, "winerror", None) == 1332
        else str(error)
    )
    _fail(result, "Failed to set the audit rule: " + detail, True)


# The provider can return null or an ACL array. Neither binds to Set-Acl's
# single-object argument, but validation and matching still precede that call.
# Early returns retain each measured failure's fields before that final binder.
def _manage_unbound(  # pylint: disable=too-many-arguments,too-many-positional-arguments,too-many-return-statements
    parameters, result, check_mode, target, sid, snapshots
):
    if parameters["state"] and parameters["state"].lower() == "absent":
        if not any(audit.current_rules(snapshot) for snapshot in snapshots):
            result.clear()
            result["changed"] = False
            _fail(
                result,
                "Unhandled exception while executing module: "
                "You cannot call a method on a null-valued expression.",
                True,
            )
            return
        if not any(audit.has_user(snapshot, sid) for snapshot in snapshots):
            result["current_audit_rules"] = _current(target)
            return
        try:
            for snapshot in snapshots:
                audit.remove_user(snapshot, sid)
        except (OSError, ValueError) as error:
            result["current_audit_rules"] = _current(target)
            _fail(result, "Failed to remove audit rule: " + str(error), True)
            return
    else:
        rule = _requested_rule(parameters, result, target, sid)
        if rule is None:
            return
        if any(audit.has_rule(snapshot, rule) for snapshot in snapshots):
            result["current_audit_rules"] = _current(target)
            return
        if not check_mode:
            if not snapshots:
                _fail(
                    result,
                    "Failed to set the audit rule: "
                    "You cannot call a method on a null-valued expression.",
                    True,
                )
                return
            try:
                rule = audit.translate_rule_user(rule, parameters["user"])
                for snapshot in snapshots:
                    audit.add_rule(snapshot, rule)
            except (OSError, ValueError) as error:
                _add_failure(result, error)
                return
    result["current_audit_rules"] = _current(target)
    detail = (
        "AclObject"
        if snapshots
        else "Cannot bind argument to parameter 'AclObject' because it is null."
    )
    _fail(result, "Failed to apply audit change: " + detail, True)


# Distinct validation, constructor, read and write boundaries preserve the fields
# present on each failure; merging them would hide the public result differences.
def _manage(
    parameters, result, check_mode
):  # pylint: disable=too-many-return-statements,too-many-branches
    path, user = parameters["path"], parameters["user"]
    target = acl.resolve_target(path, False) if path else None
    if target is None:
        _fail(result, "defined path ({0}) is not found/invalid".format(path or ""))
        return
    sid = _resolve_user(user)
    result["path_type"] = (
        "registry"
        if target["kind"] == "registry"
        else "directory" if target["container"] else "file"
    )
    with audit.audit_privileges():
        try:
            snapshots = [
                audit.read_sacl(selected) for selected in audit.audit_targets(target)
            ]
        except (OSError, ValueError) as error:
            _fail(
                result,
                "Unable to retrieve the ACL on {0}: {1}".format(path, error),
                True,
            )
            return
        if len(snapshots) != 1:
            _manage_unbound(parameters, result, check_mode, target, sid, snapshots)
            return
        snapshot = snapshots[0]
        if parameters["state"] and parameters["state"].lower() == "absent":
            if not audit.has_user(snapshot, sid):
                result["current_audit_rules"] = _current(target)
                return
            try:
                updated = audit.remove_user(snapshot, sid)
            except (OSError, ValueError) as error:
                result["current_audit_rules"] = _current(target)
                _fail(result, "Failed to remove audit rule: " + str(error), True)
                return
        else:
            rule = _requested_rule(parameters, result, target, sid)
            if rule is None:
                return
            if audit.has_rule(snapshot, rule):
                result["current_audit_rules"] = _current(target)
                return
            updated = snapshot
            if not check_mode:
                try:
                    rule = audit.translate_rule_user(rule, user)
                    updated = audit.add_rule(snapshot, rule)
                except (OSError, ValueError) as error:
                    _add_failure(result, error)
                    return
        if not check_mode:
            try:
                for selected in audit.audit_write_targets(target):
                    audit.write_sacl(dict(updated, **selected))
            except (OSError, ValueError) as error:
                result["current_audit_rules"] = _current(target)
                _fail(result, "Failed to apply audit change: " + str(error), True)
                return
        result["current_audit_rules"] = _current(target)
        result["changed"] = True


def _response():
    arguments = read_arguments(_PARAMETERS, _MODULE)
    result = {"changed": False}
    parameters = None
    try:
        parameters = _parameters(arguments)
        _manage(
            parameters,
            result,
            as_bool(arguments.get("_ansible_check_mode", False), "_ansible_check_mode"),
        )
    except (OSError, ValueError) as error:
        _fail(result, str(error))
    if as_bool(
        arguments.get("_ansible_inject_invocation", False), "_ansible_inject_invocation"
    ):
        result["invocation"] = {
            "module_args": parameters
            or {
                name: value
                for name, value in arguments.items()
                if not name.startswith("_ansible_")
            }
        }
    return result


def main():
    """Emit the public JSON result after native audit-rule management.

    :raises SystemExit: With zero for success or one for failure.
    """
    run_module(_response)


# Each independently staged payload needs its own executable entry guard.
# pylint: disable=duplicate-code
if __name__ == "__main__":
    main()
# pylint: enable=duplicate-code
