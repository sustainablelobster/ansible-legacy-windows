#!/usr/bin/python
# -*- coding: utf-8 -*-
# Copyright 2026 sustainablelobster
# SPDX-License-Identifier: GPL-3.0-or-later

"""Execute a Windows program without interpreting its arguments as shell input."""

# WANT_JSON

# The action plugin stages these Python 3.4-compatible helpers beside the payload.
from legacy_windows_module import (  # pylint: disable=import-error
    DOTNET_WHITESPACE,
    as_bool,
    as_path,
    as_string,
    read_arguments,
    run_module,
)
from legacy_windows_process import (  # pylint: disable=import-error
    resolve_executable,
    run_command,
    skip_message,
)

DOCUMENTATION = r"""
---
module: win_command
short_description: Run a Windows executable without a shell
version_added: '1.0.0'
description:
  - Starts an executable directly on the Windows target.
  - Shell operators and shell variable expressions are passed as ordinary text.
  - The target requires Python 3.4.4 or newer.
options:
  _raw_params:
    description:
      - A free-form command line, with any quoting supplied by the caller.
      - Specify exactly one of free-form input, O(cmd), or O(argv).
    type: str
  cmd:
    description:
      - The executable and arguments as a Windows command line.
      - Specify exactly one of free-form input, O(cmd), or O(argv).
    type: str
  argv:
    description:
      - The executable followed by its individual arguments.
      - Arguments are quoted using Windows C runtime conventions.
      - As in the pinned upstream implementation, backslashes immediately before
        a final newline are doubled and reach the child doubled.
      - Programs with other argument conventions may require O(cmd) instead.
      - Specify exactly one of free-form input, O(cmd), or O(argv).
    type: list
    elements: str
  chdir:
    description:
      - The working directory for the child process.
    type: path
  creates:
    description:
      - Skip execution when this literal filesystem path exists.
      - This check takes precedence over O(removes).
    type: path
  removes:
    description:
      - Skip execution when this literal filesystem path does not exist.
    type: path
  stdin:
    description:
      - Text sent to standard input as UTF-8, without an added newline.
    type: str
  output_encoding_override:
    description:
      - The encoding used to decode both output streams instead of UTF-8.
      - A Unicode byte-order mark in an output stream takes precedence.
      - Encoding names use the target Python's text codecs, with C(unicode) selecting UTF-16LE.
      - C(shift_jis) uses Windows code page 932, including its Windows extensions.
      - Python-specific IDNA, Punycode, and Unicode escape transforms are rejected.
      - Available encoding names and replacement behavior can differ from .NET.
    type: str
attributes:
  check_mode:
    support: none
    description: Skips the module without evaluating filesystem guards.
  diff_mode:
    support: none
notes:
  - Path arguments expand Windows percent-delimited environment variables.
  - Output preserves line endings and trailing whitespace.
  - Nonzero child exit codes report failure after reporting a change.
  - With C(async) and C(poll=0), retrieve results using M(sustainablelobster.legacy_windows.async_status).
  - Automatic polling with C(poll>0) requires the installed collection's
    C(plugins/action/_native_async_polling) directory on the controller action plugin path.
    Set C(action_plugins) in the project's C(ansible.cfg); installation alone does not activate the adapter.
author:
  - sustainablelobster
"""

EXAMPLES = r"""
- name: Query the current identity
  sustainablelobster.legacy_windows.win_command: whoami.exe

- name: Pass arguments containing spaces without manual quoting
  sustainablelobster.legacy_windows.win_command:
    argv:
      - C:\Program Files\Example\tool.exe
      - an argument
    chdir: C:\Windows\Temp

- name: Run an installer only before its output exists
  sustainablelobster.legacy_windows.win_command:
    cmd: C:\Tools\setup.exe /quiet
    creates: C:\Tools\installed.txt
"""

RETURN = r"""
cmd:
  description: The command line selected for execution.
  returned: after command validation
  type: str
rc:
  description: Child exit code, launch error code, or zero for a filesystem skip.
  returned: after command validation
  type: int
stdout:
  description: Decoded standard output, including its original line endings.
  returned: after execution
  type: str
stderr:
  description: Decoded standard error, including its original line endings.
  returned: after execution
  type: str
stdout_lines:
  description: Standard output divided into lines by the Ansible controller.
  returned: after execution
  type: list
  elements: str
stderr_lines:
  description: Standard error divided into lines by the Ansible controller.
  returned: after execution
  type: list
  elements: str
start:
  description: UTC time when process execution began.
  returned: after execution
  type: str
end:
  description: UTC time when process execution completed.
  returned: after execution
  type: str
delta:
  description: Elapsed execution time, formatted as hours, minutes, and seconds.
  returned: after execution
  type: str
msg:
  description: The reason for skipping or failing the command.
  returned: skipped or failed
  type: str
"""

_MODULE_NAME = "sustainablelobster.legacy_windows.win_command"
_COMMAND_PARAMETERS = ("_raw_params", "argv", "cmd")
_PARAMETERS = _COMMAND_PARAMETERS + (
    "chdir",
    "creates",
    "removes",
    "stdin",
    "output_encoding_override",
)


def _argv(value):
    if value is None:
        return None
    if isinstance(value, str):
        value = [item.strip(DOTNET_WHITESPACE) for item in value.split(",")]
    elif isinstance(value, int) and not isinstance(value, bool):
        value = [value]
    if not isinstance(value, list):
        raise ValueError("argv must be a list of strings.")
    if any(item is None for item in value):
        # The released argument converter fails before selecting a command.
        raise ValueError(
            'Unhandled exception while executing module: Exception calling "Create" '
            'with "2" argument(s): "Object reference not set to an instance of an object."'
        )
    return [as_string(item, "argv") for item in value]


def _parameters(arguments):
    provided = [name for name in _COMMAND_PARAMETERS if name in arguments]
    if len(provided) > 1:
        raise ValueError(
            "parameters are mutually exclusive: " + ", ".join(_COMMAND_PARAMETERS)
        )
    parameters = {}
    for name in _PARAMETERS:
        value = arguments.get(name)
        if name == "argv":
            parameters[name] = _argv(value)
        elif name in ("chdir", "creates", "removes"):
            parameters[name] = as_path(value, name)
        else:
            parameters[name] = as_string(value, name)
    if not provided:
        raise ValueError(
            "one of the following is required: " + ", ".join(_COMMAND_PARAMETERS)
        )
    return parameters


def _quote_argument(value):
    if not value:
        return '""'
    if not any(
        character in DOTNET_WHITESPACE or character == '"' for character in value
    ):
        return value
    quoted = ['"']
    backslashes = 0
    for index, character in enumerate(value):
        if character == "\\":
            backslashes += 1
            continue
        if character == '"':
            quoted.append("\\" * (2 * backslashes + 1))
        elif character == "\n" and index == len(value) - 1:
            # Upstream's end anchor also matches before a final LF.
            quoted.append("\\" * (2 * backslashes))
        else:
            quoted.append("\\" * backslashes)
        quoted.append(character)
        backslashes = 0
    quoted.extend(["\\" * (2 * backslashes), '"'])
    return "".join(quoted)


def _command(parameters):
    if parameters["cmd"]:
        return None, parameters["cmd"]
    if parameters["_raw_params"]:
        return None, parameters["_raw_params"].strip(DOTNET_WHITESPACE)
    arguments = parameters["argv"]
    # Null argv and an empty list fail at different released selection steps.
    if arguments is None:
        raise ValueError(
            "Unhandled exception while executing module: Cannot index into a null array."
        )
    if not arguments:
        raise ValueError(
            "Unhandled exception while executing module: Cannot bind argument "
            "to parameter 'FilePath' because it is null."
        )
    executable = resolve_executable(arguments[0], parameters["chdir"])
    command_line = " ".join(
        _quote_argument(item) for item in [executable] + arguments[1:]
    )
    return executable, command_line


def _execute():
    arguments = read_arguments(_PARAMETERS, _MODULE_NAME)
    if as_bool(arguments.get("_ansible_check_mode", False), "_ansible_check_mode"):
        return {
            "changed": False,
            "skipped": True,
            "msg": "remote module ({0}) does not support check mode".format(
                _MODULE_NAME
            ),
        }
    parameters = _parameters(arguments)
    executable, command_line = _command(parameters)
    skip = skip_message(parameters)
    if skip:
        result = {
            "changed": False,
            "skipped": True,
            "cmd": command_line,
            "rc": 0,
            "msg": skip,
        }
    elif not command_line:
        # A whitespace-only free-form command reaches guards before binding fails.
        result = {
            "changed": False,
            "failed": True,
            "cmd": command_line,
            "rc": 2,
            "msg": "Failed to run: '': Cannot bind argument to parameter "
            "'CommandLine' because it is an empty string.",
        }
    else:
        result = run_command(executable, command_line, parameters)
    if as_bool(
        arguments.get("_ansible_inject_invocation", False), "_ansible_inject_invocation"
    ):
        invocation = {
            name: value
            for name, value in arguments.items()
            if not name.startswith("_ansible_")
        }
        invocation.update(parameters)
        result["invocation"] = {"module_args": invocation}
    return result


def main():
    """Read the argument file and emit one Ansible JSON result.

    :raises SystemExit: After emitting the module result.
    """
    run_module(_execute)


if __name__ == "__main__":
    main()
