#!/usr/bin/python
# -*- coding: utf-8 -*-
# Copyright 2026 Joe Lustri
# SPDX-License-Identifier: GPL-3.0-or-later

"""Edit Windows registry keys and values with a Python 3.4.4 payload."""

# WANT_JSON

import os
import re

# The action stages these Python 3.4-compatible helpers beside the payload.
import legacy_windows_regedit as registry  # pylint: disable=import-error
import legacy_windows_regedit_data as values  # pylint: disable=import-error
from legacy_windows_module import (  # pylint: disable=import-error
    as_bool,
    as_path,
    as_string,
    read_arguments,
    run_module,
)
from legacy_windows_reg_stat import read_value  # pylint: disable=import-error

# Registry modules share mandatory Ansible option fields. Keep each module's
# documentation self-contained instead of abstracting its public interface.
# pylint: disable=duplicate-code
DOCUMENTATION = r"""
---
module: win_regedit
short_description: Add, change, or remove Windows registry keys and values
version_added: '1.0.0'
description:
  - Manages live registry keys and values, or an offline registry hive.
  - Uses Python 3.4.4 and native Windows APIs.
options:
  path:
    description:
      - Registry key path beginning with C(HKCC:\), C(HKCR:\), C(HKCU:\), C(HKLM:\), or C(HKU:\).
      - Key and value names are literal, not wildcard patterns.
    type: str
    required: true
    aliases: [key]
  name:
    description:
      - Registry value name. An empty string selects the unnamed default value.
      - Omit this option to manage the key itself or its default string value.
      - C((Default)) is a literal named value, not the unnamed default.
    type: str
    aliases: [entry, value]
  data:
    description:
      - Data for the selected value. O(type) determines conversion and storage.
      - Binary data accepts a byte list or comma-separated hexadecimal text, optionally prefixed with C(hex:).
      - Integer types accept integers or hexadecimal strings. String lists accept a list or one scalar value.
      - Omitted or null data creates an empty named string, byte array, or string list, or integer zero.
      - For C(multistring), an explicit empty list leaves the value unchanged; omit O(data) or use null to clear it.
      - With no name and string type, omitted or null data only ensures the key exists.
    type: raw
  type:
    description:
      - Registry storage type.
      - When O(name) is omitted or null, a non-string type is changed to C(string) with a warning.
      - An explicitly empty O(name) allows a non-string default value.
    type: str
    choices: [none, binary, dword, expandstring, multistring, string, qword]
    default: string
    aliases: [datatype]
  state:
    description: Whether the selected key or value should exist.
    type: str
    choices: [present, absent]
    default: present
  delete_key:
    description:
      - With O(state=absent) and an omitted, null, or empty O(name), remove the entire key and its descendants.
      - Set to false to remove only the unnamed default value, keeping the key and other values.
      - A named value is removed regardless of this option.
    type: bool
    default: true
  hive:
    description:
      - Local path to an offline hive file, temporarily mounted at C(HKLM:\ANSIBLE).
      - Use a path under that mount to modify the offline hive.
      - Requires backup and restore privileges already assigned to the connection account.
      - An existing hive at the fixed mount is unloaded with a warning before this file is loaded.
    type: path
attributes:
  check_mode:
    support: full
    description: Predicts registry edits without writing them. Offline hives are still mounted and unloaded.
  diff_mode:
    support: full
    description: Reports the selected key or value before and after the requested edit.
notes:
  - Uses the registry view of the target Python process.
  - String values compare case-sensitively; string-list elements compare case-insensitively, in order.
  - Aliases override their canonical options; C(value) overrides C(entry), which overrides O(name).
  - Changes are not transactional. A key created before a value-write failure remains present.
  - Do not run offline-hive tasks concurrently, because the reference interface uses a fixed mount point.
author:
  - Joe Lustri
"""

# pylint: enable=duplicate-code

# Ansible interfaces must be self-contained; repeated option/return text is
# interface documentation, not duplicated execution logic.
# pylint: disable=duplicate-code
EXAMPLES = r"""
- name: Set an application registry value
  sustainablelobster.legacy_windows.win_regedit:
    path: HKCU:\Software\Application
    name: Enabled
    type: dword
    data: 1

- name: Remove only the default value
  sustainablelobster.legacy_windows.win_regedit:
    path: HKCU:\Software\Application
    state: absent
    delete_key: false

- name: Edit an offline application hive
  sustainablelobster.legacy_windows.win_regedit:
    hive: C:\Backups\Application.hive
    path: HKLM:\ANSIBLE\Settings
    name: Mode
    data: maintenance
"""

RETURN = r"""
data_changed:
  description:
    - Whether comparison found different data in an existing value during O(state=present).
    - False for a newly created value or a deletion.
  returned: success
  type: bool
data_type_changed:
  description:
    - Whether comparison found a different kind in an existing value during O(state=present).
    - False for a newly created value or a deletion.
  returned: success
  type: bool
"""
# pylint: enable=duplicate-code

_MODULE_NAME = "sustainablelobster.legacy_windows.win_regedit"
_PARAMETERS = (
    "path",
    "key",
    "name",
    "entry",
    "value",
    "data",
    "type",
    "datatype",
    "state",
    "delete_key",
    "hive",
)
_PREFIX = re.compile(r"^(HK(?:CC|CR|CU|LM|U)):\\", re.IGNORECASE)
_DEFAULT_WARNING = (
    "the data type when name is not specified can only be 'string', "
    "the type has automatically been converted"
)


def _parameters(arguments):
    arguments = arguments.copy()
    for canonical, aliases in (
        ("path", ("key",)),
        ("name", ("entry", "value")),
        ("type", ("datatype",)),
    ):
        for alias in aliases:
            if alias in arguments:
                arguments[canonical] = arguments[alias]
    if "path" not in arguments:
        raise ValueError("missing required arguments: path")
    parameters = {
        name: as_string(arguments.get(name), name) for name in ("path", "name")
    }
    for name, default, choices in (
        ("type", "string", tuple(registry.KINDS)),
        ("state", "present", ("present", "absent")),
    ):
        value = as_string(arguments.get(name, default), name)
        if value is not None:
            value = value.lower()
            if value not in choices:
                raise ValueError(name + " must be one of: " + ", ".join(choices) + ".")
        parameters[name] = value
    delete_key = arguments.get("delete_key", True)
    parameters["delete_key"] = (
        as_bool(delete_key, "delete_key") if delete_key is not None else False
    )
    parameters["hive"] = as_path(arguments.get("hive"), "hive")
    parameters["data"] = arguments.get("data")
    return parameters


def _failure(result, message):
    result.update(failed=True, msg=message)


def _present(parameters, result, check):
    path = parameters["path"]
    key = registry.open_key(parameters["root"], parameters["subkey"])
    try:
        if key is None:
            if not check:
                try:
                    key = registry.open_key(
                        parameters["root"], parameters["subkey"], create=True
                    )
                except (OSError, ValueError) as error:
                    _failure(
                        result,
                        "failed to create registry key at {0}: {1}".format(path, error),
                    )
                    return
            result["changed"] = True
            result["diff"] = {"before": {}, "after": {path: {}}}
        else:
            result["diff"] = {"before": {path: {}}, "after": {path: {}}}
        if key is None or parameters["data"] is None:
            return
        _set_property(parameters, key, result, check)
    finally:
        if key is not None:
            key.Close()


def _set_property(parameters, key, result, check):
    path, name = parameters["path"], parameters["name"]
    data, kind = parameters["data"], parameters["type"]
    existing, old_kind = read_value(key, name)
    if existing is not None:
        result["data_type_changed"] = old_kind != registry.KINDS[kind]
        result["data_changed"] = not values.values_equal(existing, data)
        change = result["data_type_changed"] or result["data_changed"]
    else:
        change = True
    if change and not check:
        try:
            registry.set_value(key, name, kind, data)
        except (OSError, ValueError, TypeError) as error:
            operation = "change" if existing is not None else "create"
            _failure(
                result,
                "failed to {0} registry property '{1}' at {2}: {3}".format(
                    operation, name, path, error
                ),
            )
            return
    if existing is not None:
        old_type = next(
            (label for label, number in registry.KINDS.items() if number == old_kind),
            "unknown",
        )
        before = values.diff_value(old_type, existing)
        result["diff"]["before"][path][name] = before
        result["diff"]["after"][path][name] = before
    if change:
        result["changed"] = True
        result["diff"]["after"][path][name] = values.diff_value(kind, data)


def _absent(parameters, result, check):
    path, name = parameters["path"], parameters["name"]
    key = registry.open_key(parameters["root"], parameters["subkey"])
    if key is None:
        return
    try:
        if parameters["delete_key"] and not name:
            key.Close()
            key = None
            if not check:
                try:
                    registry.delete_tree(parameters["root"], parameters["subkey"])
                except (OSError, ValueError) as error:
                    _failure(
                        result,
                        "failed to delete registry key at {0}: {1}".format(path, error),
                    )
                    return
            result["changed"] = True
            result["diff"] = {"before": {path: {}}, "after": {}}
            return
        existing, old_kind = read_value(key, name, expand=True)
        if existing is None:
            return
        if not check:
            try:
                registry.delete_value(key, name)
            except OSError as error:
                _failure(
                    result,
                    "failed to delete registry property '{0}' at {1}: {2}".format(
                        name, path, error
                    ),
                )
                return
        result["changed"] = True
        kind = next(
            (label for label, number in registry.KINDS.items() if number == old_kind),
            "unknown",
        )
        result["diff"] = {
            "before": {path: {name: values.diff_value(kind, existing)}},
            "after": {path: {}},
        }
    finally:
        if key is not None:
            key.Close()


def _mount_hive(path, result):
    if not os.path.exists(path):
        _failure(
            result,
            "hive at path '{0}' is not valid or accessible, cannot load hive".format(
                path
            ),
        )
        return False
    try:
        registry.enable_hive_privileges()
    except OSError as error:
        _failure(
            result,
            "failed to enable SeBackupPrivilege and SeRestorePrivilege "
            "for the current process: " + str(error),
        )
        return False
    if registry.hive_mount_exists():
        result.setdefault("warnings", []).append(
            "hive already loaded at HKLM:\\ANSIBLE, had to unload hive for win_regedit to continue"
        )
        try:
            registry.unload_hive()
        except OSError as error:
            _failure(
                result,
                "failed to unload registry hive HKLM:\\ANSIBLE from {0}: {1}".format(
                    path, error
                ),
            )
            return False
    try:
        registry.load_hive(path)
    except OSError as error:
        _failure(
            result,
            "failed to load registry hive from '{0}' to HKLM:\\ANSIBLE: {1}".format(
                path, error
            ),
        )
        return False
    return True


def _edit(parameters, check):
    result = {
        "changed": False,
        "data_changed": False,
        "data_type_changed": False,
        "diff": {"before": "", "after": ""},
    }
    if parameters["name"] is None and parameters["type"] != "string":
        result["warnings"] = [_DEFAULT_WARNING]
        parameters["type"] = "string"
    path = parameters["path"]
    prefix = _PREFIX.match(path) if path is not None else None
    if prefix is None:
        _failure(
            result,
            (
                "path: {0} is not a valid powershell path, "
                "see module documentation for examples."
            ).format(path or ""),
        )
        return result
    parameters["root"] = prefix.group(1).upper()
    parameters["subkey"] = path[prefix.end() :]
    if parameters["name"] is None or values.values_equal(parameters["name"], ""):
        parameters["name"] = ""
    try:
        parameters["data"] = values.convert_data(
            parameters["data"], parameters["type"], bool(parameters["name"])
        )
    except values.DataValidationError as error:
        _failure(result, str(error))
        return result
    if parameters["type"] is None:
        raise ValueError(
            "Registry type must not be null when a value name is supplied."
        )
    mounted = False
    if parameters["hive"]:
        mounted = _mount_hive(parameters["hive"], result)
        if not mounted:
            return result
    try:
        if not parameters["subkey"]:
            raise ValueError("Registry subkey path must not be empty.")
        operation = _present if parameters["state"] == "present" else _absent
        operation(parameters, result, check)
    finally:
        if mounted:
            registry.unload_hive()
    return result


def _response():
    arguments = read_arguments(_PARAMETERS, _MODULE_NAME)
    parameters = _parameters(arguments)
    result = _edit(
        parameters,
        as_bool(arguments.get("_ansible_check_mode", False), "_ansible_check_mode"),
    )
    if not as_bool(arguments.get("_ansible_diff", False), "_ansible_diff"):
        result.pop("diff", None)
    return result


def main():
    """Execute the JSON payload and exit with the Ansible result.

    :raises SystemExit: With the module's success or failure exit code.
    """
    run_module(_response)


if __name__ == "__main__":
    main()
