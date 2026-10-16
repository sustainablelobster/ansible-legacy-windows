#!/usr/bin/python
# -*- coding: utf-8 -*-
# Copyright 2026 sustainablelobster
# Copyright: (c) 2017, Ansible Project
# SPDX-License-Identifier: GPL-3.0-or-later

"""Wait for Windows process presence or the initial process snapshot's exit."""

# WANT_JSON

import time

# The action stages these Python 3.4-compatible helpers beside the payload.
import legacy_community_windows_process_wait as native  # pylint: disable=import-error
from legacy_windows_module import (  # pylint: disable=import-error
    as_string,
    as_string_list,
    read_arguments,
    run_module,
)

DOCUMENTATION = r"""
---
module: win_wait_for_process
short_description: Waits for a process to exist or not exist before continuing.
description:
- Waiting for a process to start or stop.
- This is useful when Windows services behave poorly and do not enumerate external dependencies in their manifest.
options:
  process_name_exact:
    description:
    - The name of the process(es) for which to wait.  The name of the process(es) should not include the file extension suffix.
    type: list
    elements: str
  process_name_pattern:
    description:
    - RegEx pattern matching desired process(es).
    type: str
  sleep:
    description:
    - Number of seconds to sleep between checks.
    - Only applies when waiting for a process to start. Waiting for a stop
      uses native process handles rather than polling for matching names again.
    type: int
    default: 1
  process_min_count:
    description:
      - Minimum number of process matching the supplied pattern to satisfy C(present) condition.
      - Only applies to C(present).
    type: int
    default: 1
  pid:
    description:
    - The PID of the process.
    default: 0
    type: int
  owner:
    description:
    - The owner of the process.
    - Resolves the account through native Windows APIs and reads process owners through WMI.
    type: str
  pre_wait_delay:
    description:
    - Seconds to wait before checking processes.
    type: int
    default: 0
  post_wait_delay:
    description:
    - Seconds to wait after checking for processes.
    type: int
    default: 0
  state:
    description:
    - When checking for a running process C(present) will block execution
      until the process exists, or until the timeout has been reached.
      C(absent) will block execution until the process no longer exists,
      or until the timeout has been reached.
    - Waiting is read-only and always returns C(changed=false), matching the
      released implementation rather than its conflicting changed-state prose.
    - If, while waiting for C(absent), new processes matching the supplied
      pattern are started, these new processes will not be included in the
      action.
    type: str
    default: present
    choices: [ absent, present ]
  timeout:
    description:
    - The maximum number of seconds to wait for a for a process to start or stop
      before erroring out.
    type: int
    default: 300
seealso:
- module: ansible.builtin.wait_for
- module: sustainablelobster.legacy_windows.win_wait_for
notes:
- Regular expressions use Python C(re) with the shared Windows collection's limited .NET translations; advanced .NET-only expressions are unsupported.
- Check mode performs the same read-only waiting as normal mode.
author:
- Charles Crossan (@crossan007)
"""

EXAMPLES = r"""
- name: Wait for all Oracle VirtualBox processes to stop
  sustainablelobster.legacy_community_windows.win_wait_for_process:
    process_name_pattern: 'v(irtual)?box(headless|svc)?'
    state: absent
    timeout: 500

- name: Wait for three cmd processes with five seconds between checks
  sustainablelobster.legacy_community_windows.win_wait_for_process:
    process_name_exact: cmd
    state: present
    timeout: 500
    sleep: 5
    process_min_count: 3
"""

RETURN = r"""
elapsed:
  description: The elapsed seconds between the start of poll and the end of the module.
  returned: always
  type: float
  sample: 3.14159265
matched_processes:
  description: List of matched processes (either stopped or started).
  returned: always
  type: complex
  contains:
    name:
      description: The name of the matched process.
      returned: always
      type: str
      sample: svchost
    owner:
      description: The owner of the matched process.
      returned: when the process owner is available
      type: str
      sample: NT AUTHORITY\SYSTEM
    pid:
      description: The PID of the matched process.
      returned: always
      type: int
      sample: 7908
"""


_INTEGER_DEFAULTS = {
    "pid": 0,
    "sleep": 1,
    "pre_wait_delay": 0,
    "post_wait_delay": 0,
    "process_min_count": 1,
    "timeout": 300,
}


def _parameters(arguments):
    selectors = ("pid", "process_name_exact", "process_name_pattern")
    provided = [name for name in selectors if arguments.get(name) is not None]
    if len(provided) > 1:
        raise ValueError(
            "pid, process_name_exact and process_name_pattern are mutually exclusive"
        )
    if not provided and arguments.get("owner") is None:
        raise ValueError(
            "Specify owner, pid, process_name_exact or process_name_pattern"
        )
    parameters = {}
    for name, default in _INTEGER_DEFAULTS.items():
        value = arguments.get(name, default)
        try:
            value = int(round(value)) if isinstance(value, float) else int(value)
        except (ValueError, TypeError, OverflowError) as error:
            raise ValueError(name + " must be an integer") from error
        if not -(2**31) <= value < 2**31:
            raise ValueError(name + " must fit in a signed 32-bit integer")
        parameters[name] = value
    for name in ("owner", "process_name_pattern"):
        parameters[name] = as_string(arguments.get(name), name)
    parameters["process_name_exact"] = as_string_list(
        arguments.get("process_name_exact"), "process_name_exact"
    )
    parameters["state"] = as_string(arguments.get("state", "present"), "state")
    if parameters["state"] not in ("present", "absent"):
        raise ValueError("state must be absent or present")
    for name in ("sleep", "pre_wait_delay", "post_wait_delay"):
        if parameters[name] < 0:
            raise ValueError(name + " must not be negative")
    return parameters


def _wait(parameters):
    result = {"changed": False, "elapsed": 0.0, "matched_processes": []}
    warnings = []
    if parameters["state"] == "absent":
        for name in ("sleep", "process_min_count"):
            if parameters[name] != 1:
                warnings.append(
                    "Parameter '"
                    + name
                    + "' has no effect when waiting for a process to stop."
                )
    if warnings:
        result["warnings"] = warnings
    started = time.monotonic()
    try:
        time.sleep(parameters["pre_wait_delay"])
        while True:
            matches = native.processes(parameters)
            result["matched_processes"] = matches
            if parameters["state"] == "absent":
                if not native.wait_for_exit(
                    [row["pid"] for row in matches], parameters["timeout"]
                ):
                    result.update(
                        failed=True, msg="Timeout while waiting for process(es) to stop"
                    )
                break
            if len(matches) >= parameters["process_min_count"]:
                break
            if time.monotonic() - started > parameters["timeout"]:
                result.update(
                    failed=True, msg="Timed out while waiting for process(es) to start"
                )
                break
            time.sleep(parameters["sleep"])
        if not result.get("failed"):
            time.sleep(parameters["post_wait_delay"])
    except (OSError, ValueError) as error:
        result.update(failed=True, msg=str(error))
    result["elapsed"] = time.monotonic() - started
    return result


def main():
    """Read Ansible parameters and report the read-only wait result."""
    run_module(
        lambda: _wait(
            _parameters(
                read_arguments(
                    tuple(_INTEGER_DEFAULTS)
                    + ("process_name_exact", "process_name_pattern", "owner", "state"),
                    "sustainablelobster.legacy_community_windows.win_wait_for_process",
                )
            )
        )
    )


if __name__ == "__main__":
    main()
