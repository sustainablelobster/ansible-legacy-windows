#!/usr/bin/python
# -*- coding: utf-8 -*-
# Copyright: 2017, Dag Wieers (@dagwieers) <dag@wieers.com>
# Copyright 2026 sustainablelobster
# SPDX-License-Identifier: GPL-3.0-or-later

"""Run an installed Microsoft PsExec executable with the released option contract."""

# WANT_JSON

import datetime
import os
import shutil
import subprocess

# The action stages the shared argument and native process helpers.
from legacy_windows_module import (  # pylint: disable=import-error
    as_bool,
    as_path,
    as_string,
    as_string_list,
    read_arguments,
    run_module,
)
from legacy_windows_process import run_command  # pylint: disable=import-error

DOCUMENTATION = r"""
---
module: win_psexec
short_description: Runs commands (remotely) as another (privileged) user
description:
- Run commands (remotely) through the PsExec service.
- Run commands as another (domain) user (with elevated privileges).
requirements:
- Microsoft PsExec
options:
  command:
    description:
    - The command line to run through PsExec (limited to 260 characters).
    type: str
    required: yes
  executable:
    description:
    - The location of the PsExec utility (in case it is not located in your PATH).
    type: path
    default: psexec.exe
  hostnames:
    description:
    - The hostnames to run the command.
    - If not provided, the command is run locally.
    type: list
    elements: str
  username:
    description:
    - The (remote) user to run the command as.
    - If not provided, the current user is used.
    type: str
  password:
    description:
    - The password for the (remote) user to run the command as.
    - This is mandatory in order authenticate yourself.
    type: str
  chdir:
    description:
    - Run the command from this (remote) directory.
    type: path
  nobanner:
    description:
    - Do not display the startup banner and copyright message.
    - This only works for specific versions of the PsExec binary.
    type: bool
    default: no
  noprofile:
    description:
    - Run the command without loading the account's profile.
    type: bool
    default: no
  elevated:
    description:
    - Run the command with elevated privileges.
    type: bool
    default: no
  interactive:
    description:
    - Run the program so that it interacts with the desktop on the remote system.
    type: bool
    default: no
  session:
    description:
    - Specifies the session ID to use.
    - This parameter works in conjunction with I(interactive).
    - It has no effect when I(interactive) is set to C(no).
    type: int
  limited:
    description:
    - Run the command as limited user (strips the Administrators group and allows only privileges assigned to the Users group).
    type: bool
    default: no
  system:
    description:
    - Run the remote command in the System account.
    type: bool
    default: no
  priority:
    description:
    - Used to run the command at a different priority.
    choices: [ abovenormal, background, belownormal, high, low, realtime ]
    type: str
  timeout:
    description:
    - The connection timeout in seconds
    type: int
  wait:
    description:
    - Wait for the application to terminate.
    - Only use for non-interactive applications.
    type: bool
    default: yes
notes:
- The module does not supply keyboard input. Commands that require interactive input must be run non-interactively.
- The installed PsExec tool controls output forwarding. PsExec 2.43 can omit stdout from immediate-exit children;
  this was also observed with the recorded upstream launcher.
- More information related to Microsoft PsExec is available from
  U(https://technet.microsoft.com/en-us/sysinternals/bb897553.aspx)
seealso:
- module: sustainablelobster.legacy_community_windows.psexec
- module: ansible.builtin.raw
- module: sustainablelobster.legacy_windows.win_command
- module: sustainablelobster.legacy_windows.win_shell
author:
- Dag Wieers (@dagwieers)
"""

EXAMPLES = r"""
- name: Run PsExec on the target node as the current user
  sustainablelobster.legacy_community_windows.win_psexec:
    command: whoami.exe

- name: Run regedit.exe locally (on target node) as SYSTEM and interactively
  sustainablelobster.legacy_community_windows.win_psexec:
    command: regedit.exe
    interactive: true
    system: true

- name: Run setup.exe on multiple servers as the domain administrator
  sustainablelobster.legacy_community_windows.win_psexec:
    command: E:\setup.exe /i /IACCEPTEULA
    hostnames:
      - remote_server1
      - remote_server2
    username: DOMAIN\Administrator
    password: some_password
    priority: high

- name: Run PsExec from custom location C:\Program Files\sysinternals\
  sustainablelobster.legacy_community_windows.win_psexec:
    command: netsh advfirewall set allprofiles state off
    executable: C:\Program Files\sysinternals\psexec.exe
    hostnames: [remote_server]
    password: some_password
    priority: low
"""

RETURN = r"""
cmd:
    description: The complete command line used by the module, including PsExec call and additional options.
    returned: always
    type: str
    sample: psexec.exe -nobanner \\remote_server -u "DOMAIN\Administrator" -p "some_password" -accepteula E:\setup.exe
pid:
    description: The PID of the async process created by PsExec.
    returned: when C(wait=False)
    type: int
    sample: 1532
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
    sample: Error 15 running E:\setup.exe
"""

_BOOLEANS = {
    "nobanner": (False, "-nobanner"),
    "noprofile": (False, "-e"),
    "elevated": (False, "-h"),
    "system": (False, "-s"),
    "interactive": (False, "-i"),
    "limited": (False, "-l"),
}
_PARAMETERS = (
    "command",
    "executable",
    "hostnames",
    "username",
    "password",
    "chdir",
    "nobanner",
    "noprofile",
    "elevated",
    "interactive",
    "session",
    "limited",
    "system",
    "priority",
    "timeout",
    "wait",
)


def _integer(arguments, name):
    value = arguments.get(name)
    if value is None:
        return None
    if isinstance(value, bool):
        return int(value)
    try:
        number = int(value)
    except (TypeError, ValueError) as error:
        raise ValueError(name + " must be a 32-bit integer.") from error
    if number < -2147483648 or number > 2147483647:
        raise ValueError(name + " must be a 32-bit integer.")
    return number


def _scheduling_options(arguments):
    options = []
    priority = as_string(arguments.get("priority"), "priority")
    if priority is not None:
        priority = priority.lower()
        if priority not in (
            "abovenormal",
            "background",
            "belownormal",
            "high",
            "low",
            "realtime",
        ):
            raise ValueError("Unsupported priority: " + priority)
        options.append("-" + priority)
    timeout = _integer(arguments, "timeout")
    if timeout is not None:
        options.extend(("-n", str(timeout)))
    return options


def _command(arguments):
    command = as_string(arguments.get("command"), "command")
    if command is None:
        raise ValueError("missing required arguments: command")
    executable = as_path(arguments.get("executable", "psexec.exe"), "executable")
    if not executable or not (shutil.which(executable) or os.path.isfile(executable)):
        raise ValueError("Executable '{0}' was not found.".format(executable))
    options = [executable]
    booleans = {
        name: as_bool(arguments.get(name, default), name)
        for name, (default, _flag) in _BOOLEANS.items()
    }
    if booleans["nobanner"]:
        options.append("-nobanner")
    hosts = as_string_list(arguments.get("hostnames"), "hostnames")
    if hosts:
        unique = {}
        for host in hosts:
            unique.setdefault(host.casefold(), host)
        options.append("\\\\" + ",".join(sorted(unique.values(), key=str.casefold)))
    for name, flag in (("username", "-u"), ("password", "-p"), ("chdir", "-w")):
        value = as_string(arguments.get(name), name)
        if value is not None:
            options.extend((flag, value))
    if not as_bool(arguments.get("wait", True), "wait"):
        options.append("-d")
    for name in ("noprofile", "elevated", "system", "interactive", "limited"):
        if booleans[name]:
            options.append(_BOOLEANS[name][1])
            if name == "interactive" and arguments.get("session") is not None:
                options.append(str(_integer(arguments, "session")))
    options.extend(_scheduling_options(arguments))
    options.append("-accepteula")
    # PsExec parses the remaining process command itself; it is not one argv item.
    return executable, subprocess.list2cmdline(options) + " " + command


def _execute(arguments):
    if as_bool(arguments.get("_ansible_check_mode", False), "_ansible_check_mode"):
        return {
            "changed": False,
            "skipped": True,
            "msg": "remote module does not support check mode",
        }
    executable, command = _command(arguments)
    password = as_string(arguments.get("password"), "password")
    displayed = command
    if password:
        displayed = displayed.replace(
            subprocess.list2cmdline([password]), "*PASSWORD_REPLACED*"
        )
    response = run_command(
        executable,
        command,
        {
            "chdir": None,
            "stdin": None,
            "output_encoding_override": None,
            "keep_stdin_open": True,
        },
    )
    if "stdout" not in response:
        raise OSError("Failed to run PsExec executable.")
    result = {
        "changed": True,
        "psexec_command": displayed,
        "stdout": response["stdout"],
        "stderr": response["stderr"],
        "rc": response["rc"] if as_bool(arguments.get("wait", True), "wait") else 0,
        "delta": response["delta"],
    }
    for name in ("start", "end"):
        result[name] = datetime.datetime.strptime(
            response[name], "%Y-%m-%d %H:%M:%S.%f"
        ).strftime("%Y-%m-%d %I:%M:%S.%f")
    if not as_bool(arguments.get("wait", True), "wait"):
        result["pid"] = response["rc"]
    return result


def main():
    """Read public options and return the installed PsExec process result."""
    run_module(
        lambda: _execute(
            read_arguments(
                _PARAMETERS, "sustainablelobster.legacy_community_windows.win_psexec"
            )
        )
    )


if __name__ == "__main__":
    main()
