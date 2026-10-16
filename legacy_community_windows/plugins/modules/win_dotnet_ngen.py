#!/usr/bin/python
# -*- coding: utf-8 -*-
# Copyright: (c) 2015, Peter Mounce <public@neverrunwithscissors.com>
# Copyright 2026 sustainablelobster
# SPDX-License-Identifier: GPL-3.0-or-later

"""Run installed NGen executables through Python rather than a PowerShell host."""

# WANT_JSON

import os
import subprocess

# The action stages the shared argument and native process helpers.
from legacy_windows_module import (  # pylint: disable=import-error
    as_bool,
    read_arguments,
    run_module,
)
from legacy_windows_process import run_command  # pylint: disable=import-error

DOCUMENTATION = r"""
---
module: win_dotnet_ngen
short_description: Runs ngen to recompile DLLs after .NET  updates
description:
    - After .NET framework is installed/updated, Windows will probably want to recompile things to optimise for the host.
    - This happens via scheduled task, usually at some inopportune time.
    - This module allows you to run this task on your own schedule, so you incur the CPU hit at some more convenient and controlled time.
    - U(https://docs.microsoft.com/en-us/dotnet/framework/tools/ngen-exe-native-image-generator#native-image-service)
    - U(http://blogs.msdn.com/b/dotnet/archive/2013/08/06/wondering-why-mscorsvw-exe-has-high-cpu-usage-you-can-speed-it-up.aspx)
options: {}
notes:
    - There are in fact two scheduled tasks for ngen but they have no triggers so aren't a problem.
    - There's no way to test if they've been completed.
    - The stdout is quite likely to be several megabytes.
author:
- Peter Mounce (@petemounce)
"""

EXAMPLES = r"""
- name: Run ngen tasks
  sustainablelobster.legacy_community_windows.win_dotnet_ngen:
"""

RETURN = r"""
dotnet_ngen_update_exit_code:
  description: The exit code after running the 32-bit ngen.exe update /force
    command.
  returned: 32-bit ngen executable exists
  type: int
  sample: 0
dotnet_ngen_update_output:
  description: The stdout after running the 32-bit ngen.exe update /force
    command.
  returned: 32-bit ngen executable exists
  type: str
  sample: sample output
dotnet_ngen_eqi_exit_code:
  description: The exit code after running the 32-bit ngen.exe
    executeQueuedItems command.
  returned: 32-bit ngen executable exists
  type: int
  sample: 0
dotnet_ngen_eqi_output:
  description: The stdout after running the 32-bit ngen.exe executeQueuedItems
    command.
  returned: 32-bit ngen executable exists
  type: str
  sample: sample output
dotnet_ngen64_update_exit_code:
  description: The exit code after running the 64-bit ngen.exe update /force
    command.
  returned: 64-bit ngen executable exists
  type: int
  sample: 0
dotnet_ngen64_update_output:
  description: The stdout after running the 64-bit ngen.exe update /force
    command.
  returned: 64-bit ngen executable exists
  type: str
  sample: sample output
dotnet_ngen64_eqi_exit_code:
  description: The exit code after running the 64-bit ngen.exe
    executeQueuedItems command.
  returned: 64-bit ngen executable exists
  type: int
  sample: 0
dotnet_ngen64_eqi_output:
  description: The stdout after running the 64-bit ngen.exe executeQueuedItems
    command.
  returned: 64-bit ngen executable exists
  type: str
  sample: sample output
"""


def _execute(arguments):
    check_mode = as_bool(
        arguments.get("_ansible_check_mode", False), "_ansible_check_mode"
    )
    result = {"changed": False}
    for architecture in ("", "64"):
        executable = os.path.join(
            os.environ.get("windir", os.environ.get("SystemRoot", r"C:\Windows")),
            "Microsoft.NET",
            "Framework" + architecture,
            "v4.0.30319",
            "ngen.exe",
        )
        if not os.path.isfile(executable):
            continue
        for operation, options in (
            ("update", "update /force"),
            ("eqi", "executeQueuedItems"),
        ):
            if check_mode:
                response = {
                    "rc": 0,
                    "stdout": "check mode output for " + executable + " " + options,
                }
            else:
                response = run_command(
                    executable,
                    subprocess.list2cmdline([executable]) + " " + options,
                    {"chdir": None, "stdin": None, "output_encoding_override": None},
                )
                if "stdout" not in response:
                    raise OSError(response.get("msg", "Failed to execute NGen."))
            prefix = "dotnet_ngen" + architecture + "_" + operation
            result[prefix + "_exit_code"] = response["rc"]
            result[prefix + "_output"] = response["stdout"]
        result["changed"] = True
    return result


def main():
    """Read module arguments and return the installed NGen operations."""
    run_module(
        lambda: _execute(
            read_arguments(
                (),
                "sustainablelobster.legacy_community_windows.win_dotnet_ngen",
                allow_unknown=True,
            )
        )
    )


if __name__ == "__main__":
    main()
