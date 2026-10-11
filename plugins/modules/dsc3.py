#!/usr/bin/python
# -*- coding: utf-8 -*-
# Copyright 2026 sustainablelobster
# SPDX-License-Identifier: GPL-3.0-or-later
"""Apply a DSC v3 configuration through its external command-line interface."""

# WANT_JSON

import json
import subprocess

from legacy_windows_module import (  # pylint: disable=import-error
    as_bool,
    as_dictionary,
    as_path,
    as_string,
    read_arguments,
    run_module,
)
from legacy_windows_process import (  # pylint: disable=import-error
    resolve_executable,
    run_command,
)

# Ansible interfaces must be self-contained; repeated option/return text is
# interface documentation, not duplicated execution logic.
# pylint: disable=duplicate-code
DOCUMENTATION = r"""
---
module: dsc3
short_description: Apply or preview DSC v3 configurations
version_added: '1.0.0'
description:
  - Runs the external DSC v3 engine to set or test a configuration.
  - The payload and its helpers require Python 3.4.4 or newer.
  - The DSC executable and requested resources retain their own prerequisites.
options:
  config:
    description:
      - Configuration document supplied as a dictionary.
      - An omitted or null C($schema) uses the upstream bundled v3 schema URI.
      - Specify exactly one of O(config) and O(config_file).
    type: dict
  config_file:
    description:
      - Configuration file on the target, or on the controller when
        O(remote_config_file=false).
      - Specify exactly one of O(config) and O(config_file).
    type: path
  parameters:
    description: Runtime configuration parameter values.
    type: dict
  remote_config_file:
    description:
      - Whether O(config_file) is already on the target.
      - The pinned upstream action treats an omitted value as false for file
        transfer, despite the module default of true; this action does likewise.
      - Asynchronous tasks require inline O(config) or an already transferred
        file with O(remote_config_file=true); controller files are rejected.
    type: bool
    default: true
  trace_level:
    description: Logging level passed to the DSC executable.
    type: str
    choices: [error, warn, info, debug, trace]
    default: warn
attributes:
  check_mode:
    support: full
    description: Runs C(dsc config test) instead of C(dsc config set).
  diff_mode:
    support: full
    description: Reports each resource and its changed properties.
notes:
  - The engine must be discoverable as C(dsc.exe) in the target process PATH.
  - Resource discovery also follows the engine's resource-path rules.
  - Use C(async) with C(poll=0), then poll
    C(sustainablelobster.legacy_windows.async_status) explicitly.
  - Automatic polling requires explicit activation of the collection's native
    polling action path; bounded inline and remote-file cases are verified.
author:
  - sustainablelobster
"""

EXAMPLES = r"""
- name: Preview a DSC v3 configuration
  sustainablelobster.legacy_windows.dsc3:
    config:
      resources:
        - name: Inspect operating system
          type: Microsoft/OSInfo
          properties: {}
  check_mode: true

- name: Apply a controller configuration file
  sustainablelobster.legacy_windows.dsc3:
    config_file: files/example.dsc.yaml
    remote_config_file: false
"""

RETURN = r"""
result:
  description: Complete parsed configuration result returned by the DSC engine.
  returned: after successful engine execution
  type: dict
rc:
  description: Exit code of the DSC engine.
  returned: after engine execution
  type: int
stderr_lines:
  description: Engine diagnostics split into lines by Ansible.
  returned: after engine execution
  type: list
  elements: str
"""
# pylint: enable=duplicate-code

_PARAMETERS = (
    "config",
    "config_file",
    "parameters",
    "remote_config_file",
    "trace_level",
)
_SCHEMA = "https://aka.ms/dsc/schemas/v3/bundled/config/document.json"
_EXIT_REASONS = {
    1: "Invalid arguments (ExitCode=1)",
    2: "Resource error (ExitCode=2)",
    3: "JSON serizliation error (ExitCode=3)",
    4: "Input YAML or JSON is invalid (ExitCode=4)",
    5: "Data failed schema validation (ExitCode=5)",
}
_OPERATION_FIELDS = {
    "set": ("beforeState", "afterState", "changedProperties"),
    "test": ("actualState", "desiredState", "differingProperties"),
}


def _truth(value):
    if isinstance(value, (list, tuple)):
        return bool(value) and (len(value) > 1 or _truth(value[0]))
    return True if isinstance(value, dict) else bool(value)


def _property(mapping, name):
    if not isinstance(mapping, dict):
        return None
    for key, value in mapping.items():
        if key.lower() == name.lower():
            return value
    return None


def _selected_properties(state, changed):
    if not isinstance(state, dict):
        return {}
    names = changed if isinstance(changed, list) else [changed]
    properties = {}
    for name in names:
        for key, value in state.items():
            if key.lower() == name.lower():
                properties[name] = value
                break
    return properties


def _creation_failure(execution):
    marker = ": [WinError {0}] ".format(execution["rc"])
    if marker in execution["msg"]:
        description = execution["msg"].rsplit(marker, 1)[1]
        # Upstream assigns rc/stderr only after CreateProcess succeeds.
        return {
            "changed": False,
            "failed": True,
            "msg": (
                "Unhandled exception while executing module: Exception calling "
                '"CreateProcess" with "7" argument(s): "CreateProcessW() failed '
                '({0}, Win32ErrorCode {1} - 0x{1:08X})"'
            ).format(description, execution["rc"]),
        }
    return {
        "changed": False,
        "failed": True,
        "rc": execution["rc"],
        "msg": execution["msg"],
    }


def _configuration_result(execution, diff_mode):
    if execution.get("failed") and "stdout" not in execution:
        return _creation_failure(execution)
    result = {"changed": False, "rc": execution["rc"]}
    if "stderr" in execution:
        result["stderr"] = execution["stderr"]
    if execution.get("failed"):
        result.update(
            failed=True,
            msg=(
                _EXIT_REASONS.get(
                    execution["rc"], "Error: ExitCode={0}".format(execution["rc"])
                )
                if "stdout" in execution
                else execution["msg"]
            ),
        )
        return result
    document = json.loads(execution["stdout"])
    result["result"] = document
    if diff_mode:
        result["diff"] = {"before": {"resources": []}, "after": {"resources": []}}
    operation = _property(
        _property(_property(document, "metadata"), "Microsoft.DSC"), "operation"
    )
    fields = _OPERATION_FIELDS.get(
        operation.lower() if isinstance(operation, str) else None
    )
    if fields is None:
        result.update(
            failed=True,
            msg="Unexpected operation result of type '{0}'".format(operation or ""),
        )
        return result
    for resource in _property(document, "results") or []:
        states = _property(resource, "result")
        before, after, changed = (_property(states, name) for name in fields)
        if _property(before, "_inDesiredState") is False or _truth(changed):
            result["changed"] = True
        if diff_mode:
            identity = {
                "name": _property(resource, "name"),
                "type": _property(resource, "type"),
            }
            for side, state in (("before", before), ("after", after)):
                entry = dict(identity)
                if _truth(changed):
                    entry["properties"] = _selected_properties(state, changed)
                result["diff"][side]["resources"].append(entry)
    return result


def _response():
    arguments = read_arguments(_PARAMETERS, "sustainablelobster.legacy_windows.dsc3")
    config = as_dictionary(arguments.get("config"), "config")
    config_file = as_path(arguments.get("config_file"), "config_file")
    parameters = as_dictionary(arguments.get("parameters"), "parameters")
    as_bool(arguments.get("remote_config_file", True), "remote_config_file")
    trace_level = as_string(arguments.get("trace_level", "warn"), "trace_level")
    if trace_level is not None and trace_level.lower() not in (
        "error",
        "warn",
        "info",
        "debug",
        "trace",
    ):
        raise ValueError(
            "value of trace_level must be one of: error, warn, info, debug, trace. "
            "Got no match for: {0}".format(trace_level)
        )
    if config is not None and config_file is not None:
        raise ValueError("parameters are mutually exclusive: config, config_file")
    if config is None and config_file is None:
        raise ValueError("one of the following is required: config, config_file")
    check_mode = as_bool(
        arguments.get("_ansible_check_mode", False), "_ansible_check_mode"
    )
    diff_mode = as_bool(arguments.get("_ansible_diff", False), "_ansible_diff")
    stdin = None
    if not config_file:
        if config.get("$schema") is None:
            config["$schema"] = _SCHEMA
        stdin = json.dumps(config, ensure_ascii=False, separators=(",", ":"))
        config_file = "-"
    executable = resolve_executable("dsc.exe", None)
    command = [
        executable,
        "--trace-format=plaintext",
        "--progress-format=none",
        "--trace-level=" + (trace_level or ""),
        "config",
    ]
    if _truth(parameters):
        command.append(
            "--parameters="
            + json.dumps(
                {"parameters": parameters}, ensure_ascii=False, separators=(",", ":")
            )
        )
    command.extend(
        [
            "test" if check_mode else "set",
            "--file=" + config_file,
            "--output-format=json",
        ]
    )
    execution = run_command(
        executable,
        subprocess.list2cmdline(command),
        {"chdir": None, "stdin": stdin, "output_encoding_override": None},
    )
    return _configuration_result(execution, diff_mode)


def main():
    """Read the Ansible argument file and emit the configuration result.

    :raises SystemExit: After emitting the module result.
    """
    run_module(_response)


if __name__ == "__main__":
    main()
