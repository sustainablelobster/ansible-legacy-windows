#!/usr/bin/python
# -*- coding: utf-8 -*-
# Copyright: 2017, Dag Wieers (@dagwieers) <dag@wieers.com>
# Copyright 2026 sustainablelobster
# SPDX-License-Identifier: GPL-3.0-or-later

"""Run the installed Windows volume optimizer against the selected volumes."""

# WANT_JSON

import datetime
import shutil
import subprocess

from legacy_windows_module import (  # pylint: disable=import-error
    as_bool,
    as_string,
    read_arguments,
    run_module,
)
from legacy_windows_process import run_command  # pylint: disable=import-error

DOCUMENTATION = r"""
---
module: win_defrag
short_description: Consolidate fragmented files on local volumes
description:
- Locates and consolidates fragmented files on local volumes to improve system performance.
- 'More information regarding C(win_defrag) is available from: U(https://technet.microsoft.com/en-us/library/cc731650%28v%3Dws.11.aspx%29)'
requirements:
- defrag.exe
options:
  include_volumes:
    description:
    - A list of drive letters or mount point paths of the volumes to be defragmented.
    - If this parameter is omitted, all volumes (not excluded) will be defragmented.
    type: list
    elements: str
  exclude_volumes:
    description:
    - A list of drive letters or mount point paths to exclude from defragmentation.
    type: list
    elements: str
  freespace_consolidation:
    description:
    - Perform free space consolidation on the specified volumes.
    type: bool
    default: no
  priority:
    description:
    - Run the operation at low or normal priority.
    type: str
    choices: [ low, normal ]
    default: low
  parallel:
    description:
    - Run the operation on each volume in parallel in the background.
    type: bool
    default: no
notes:
- Check mode invokes the native utility in analysis-only mode rather than skipping it.
- The returned C(changed) flag is true even for analysis-only execution, matching the released module.
- Nonzero native exit codes are returned in C(rc), not converted into an Ansible failure.
- Available operations and command-line flags depend on the installed defrag.exe utility.
author:
- Dag Wieers (@dagwieers)
"""

EXAMPLES = r"""
- name: Defragment all local volumes (in parallel)
  sustainablelobster.legacy_community_windows.win_defrag:
    parallel: true

- name: 'Defragment all local volumes, except C: and D:'
  sustainablelobster.legacy_community_windows.win_defrag:
    exclude_volumes: [C, D]

- name: 'Defragment volume D: with normal priority'
  sustainablelobster.legacy_community_windows.win_defrag:
    include_volumes: D
    priority: normal

- name: Consolidate free space (useful when reducing volumes)
  sustainablelobster.legacy_community_windows.win_defrag:
    freespace_consolidation: true
"""

# The released command-result interface intentionally matches other command
# modules. Keep its documentation self-contained for ansible-doc consumers.
# pylint: disable=duplicate-code
RETURN = r"""
cmd:
    description: The complete command line used by the module.
    returned: always
    type: str
    sample: defrag.exe /C /V
rc:
    description: The return code for the command.
    returned: always
    type: int
    sample: 0
stdout:
    description: The standard output from the command.
    returned: always
    type: str
    sample: Success.
stderr:
    description: The error output from the command.
    returned: always
    type: str
    sample:
msg:
    description: Possible error message on failure.
    returned: failed
    type: str
    sample: Command 'defrag.exe' not found in $env:PATH.
changed:
    description: Whether or not any changes were made.
    returned: always
    type: bool
    sample: true
"""
# pylint: enable=duplicate-code


def _volumes(value, name):
    if value is None:
        return []
    values = value if isinstance(value, list) else str(value).split(",")
    result = []
    for item in values:
        text = as_string(item, name)
        if not text or text.startswith(("/", "-")):
            raise ValueError(name + " must contain drive letters or mount-point paths")
        result.append(text + ":" if len(text) == 1 else text)
    return result


def _optimize(arguments):
    include = _volumes(arguments.get("include_volumes"), "include_volumes")
    exclude = _volumes(arguments.get("exclude_volumes"), "exclude_volumes")
    priority = as_string(arguments.get("priority", "low"), "priority")
    if priority not in ("low", "normal"):
        raise ValueError("priority must be low or normal")
    check = as_bool(arguments.get("_ansible_check_mode", False), "_ansible_check_mode")
    consolidate = as_bool(
        arguments.get("freespace_consolidation", False), "freespace_consolidation"
    )
    parallel = as_bool(arguments.get("parallel", False), "parallel")
    executable = shutil.which("defrag.exe")
    if executable is None:
        raise OSError("The installed Windows defrag.exe utility was not found.")
    options = include or ["/C"]
    if exclude:
        options += ["/E"] + exclude
    if check:
        options.append("/A")
    elif consolidate:
        options.append("/X")
    if priority == "normal":
        options.append("/H")
    if parallel:
        options.append("/M")
    options.append("/V")
    command = subprocess.list2cmdline([executable] + options)
    started = datetime.datetime.now(datetime.timezone.utc)
    response = run_command(
        executable,
        command,
        {"chdir": None, "stdin": None, "output_encoding_override": None},
    )
    ended = datetime.datetime.now(datetime.timezone.utc)
    elapsed = ended - started
    result = {
        "changed": True,
        "cmd": command,
        "stdout": response.get("stdout", ""),
        "stderr": response.get("stderr", ""),
        "rc": response["rc"],
        "start": started.strftime("%Y-%m-%d %I:%M:%S.%f"),
        "end": ended.strftime("%Y-%m-%d %I:%M:%S.%f"),
        "delta": "{0}:{1:02d}:{2:02d}.{3:06d}".format(
            elapsed.seconds // 3600,
            elapsed.seconds // 60 % 60,
            elapsed.seconds % 60,
            elapsed.microseconds,
        ),
    }
    # The released module reports the utility's status without treating a
    # nonzero exit code as an Ansible failure, including analysis-only mode.
    if response.get("failed") and "stdout" not in response:
        result.update(failed=True, msg=response.get("msg", "Could not run defrag.exe"))
    return result


def main():
    """Read the upstream volume-selection interface and report native execution."""
    run_module(
        lambda: _optimize(
            read_arguments(
                (
                    "include_volumes",
                    "exclude_volumes",
                    "freespace_consolidation",
                    "priority",
                    "parallel",
                ),
                "sustainablelobster.legacy_community_windows.win_defrag",
                allow_unknown=True,
            )
        )
    )


if __name__ == "__main__":
    main()
