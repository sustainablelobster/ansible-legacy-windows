#!/usr/bin/python
# -*- coding: utf-8 -*-
# Copyright: (c) 2017, Ansible Project
# Copyright 2026 sustainablelobster
# SPDX-License-Identifier: GPL-3.0-or-later

"""Manage plugins using the installed RabbitMQ command-line tool."""

# WANT_JSON

import ntpath
import os
import subprocess

try:
    import winreg
except ImportError:
    winreg = None

# The action stages these Python 3.4-compatible helpers beside the payload.
from legacy_windows_module import (  # pylint: disable=import-error
    as_bool,
    as_string,
    read_arguments,
    run_module,
)
from legacy_windows_process import run_command  # pylint: disable=import-error
from legacy_windows_text import decode_bytes  # pylint: disable=import-error

DOCUMENTATION = r"""
---
module: win_rabbitmq_plugin
short_description: Manage RabbitMQ plugins
description:
  - Manage plugins through the installed RabbitMQ command-line tool.
options:
  names:
    description: Comma-separated list of plugin names.
    type: str
    required: true
    aliases: [name]
  new_only:
    description:
      - Only enable missing plugins.
      - Does not disable plugins that are not in the names list.
    type: bool
    default: false
  state:
    description: Specify if plugins are to be enabled or disabled.
    type: str
    choices: [disabled, enabled]
    default: enabled
  prefix:
    description: Custom RabbitMQ installation prefix containing a bin or sbin directory.
    type: str
notes:
  - Requires an installed RabbitMQ CLI and its Erlang runtime, with access to the configured RabbitMQ node.
  - Without I(prefix), discovery checks the RabbitMQ uninstall registry entry before PATH.
  - Plugin names are literal CLI arguments, not shell commands. Batch entrypoints reject shell metacharacters in plugin names.
  - Check mode reads the enabled plugin list and predicts changes without enabling or disabling plugins.
author:
  - Artem Zinenko (@ar7z1)
  - sustainablelobster
"""

EXAMPLES = r"""
- name: Enable the management plugin while preserving other enabled plugins
  sustainablelobster.legacy_community_windows.win_rabbitmq_plugin:
    names: rabbitmq_management
    new_only: true
    state: enabled
"""

RETURN = r"""
enabled:
  description: List of plugins enabled during task run.
  returned: always
  type: list
  sample: [rabbitmq_management]
disabled:
  description: List of plugins disabled during task run.
  returned: always
  type: list
  sample: [rabbitmq_management]
"""


def _registry_prefix():
    if winreg is None:
        return None
    uninstall = r"Microsoft\Windows\CurrentVersion\Uninstall\RabbitMQ"
    for path in ("SOFTWARE\\Wow6432Node\\" + uninstall, "SOFTWARE\\" + uninstall):
        try:
            key = winreg.OpenKey(
                winreg.HKEY_LOCAL_MACHINE,
                path,
                0,
                winreg.KEY_READ | winreg.KEY_WOW64_64KEY,
            )
        except FileNotFoundError:
            continue
        with key:
            command = winreg.QueryValueEx(key, "UninstallString")[0]
            version = winreg.QueryValueEx(key, "DisplayVersion")[0]
        return ntpath.join(
            ntpath.dirname(command.strip('"')), "rabbitmq_server-" + version
        )
    return None


def _binary_directory(prefix):
    for name in ("bin", "sbin"):
        path = os.path.join(prefix, name)
        if os.path.isdir(path):
            return path
    return None


def _executable(prefix):
    directory = _binary_directory(prefix) if prefix else None
    if prefix and directory is None:
        raise ValueError('No binary folder in prefix "{0}"'.format(prefix))
    if not prefix:
        registered = _registry_prefix()
        directory = _binary_directory(registered) if registered else None
    directories = [directory] if directory else os.get_exec_path()
    extensions = [""] + os.environ.get("PATHEXT", ".COM;.EXE;.BAT;.CMD").split(";")
    for folder in directories:
        for extension in extensions:
            candidate = os.path.join(folder, "rabbitmq-plugins" + extension.lower())
            if os.path.isfile(candidate):
                return os.path.abspath(candidate)
    raise ValueError(
        "Can't execute rabbitmq-plugins: executable not found in the selected binary folder or PATH"
    )


def _batch_command(executable, arguments):
    # CMD does not recursively expand percent signs supplied by this environment
    # variable. Quoting also preserves literal spaces and metacharacters in paths.
    if any(character in executable for character in ('"', "\r", "\n", "\0")):
        raise ValueError("Invalid RabbitMQ batch executable path")
    if any(
        character in argument
        for argument in arguments
        for character in '"\r\n\0%&|<>^!()'
    ):
        raise ValueError(
            "Plugin names must not contain shell metacharacters "
            "when using a RabbitMQ batch entrypoint"
        )
    environment = os.environ.copy()
    environment["LEGACY_RABBITMQ_COMMAND"] = executable
    shell = os.path.join(
        os.environ.get("SystemRoot", r"C:\Windows"), "System32", "cmd.exe"
    )
    command_line = '"{0}" /d /v:off /s /c ""%LEGACY_RABBITMQ_COMMAND%" {1}"'.format(
        shell, " ".join('"' + argument + '"' for argument in arguments)
    )
    with subprocess.Popen(
        command_line,
        executable=shell,
        env=environment,
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    ) as process:
        stdout, stderr = process.communicate()
    return {
        "rc": process.returncode,
        "stdout": decode_bytes(stdout, "utf-8"),
        "stderr": decode_bytes(stderr, "utf-8"),
    }


def _command(executable, arguments):
    if ntpath.splitext(executable)[1].lower() in (".bat", ".cmd"):
        return _batch_command(executable, arguments)
    return run_command(
        executable,
        subprocess.list2cmdline([executable] + arguments),
        {"chdir": None, "stdin": None, "output_encoding_override": None},
    )


def _failure(result, command, operation):
    result.update(failed=True, msg="Can't execute rabbitmq-plugins " + operation)
    result.update({key: command.get(key, "") for key in ("rc", "stdout", "stderr")})
    if command.get("msg"):
        result["msg"] += ": " + command["msg"]
    return result


def _apply(executable, selected, check_mode, result):
    for operation, plugins, field, sign in selected:
        for plugin in plugins:
            if not check_mode:
                try:
                    command = _command(executable, [operation, plugin])
                except (OSError, ValueError) as error:
                    command = {
                        "rc": getattr(error, "winerror", None) or 2,
                        "msg": str(error),
                    }
                if command.get("failed") or command["rc"]:
                    return _failure(result, command, operation + " " + plugin)
            result[field].append(plugin)
            result["changed"] = True
            if "diff" in result:
                result["diff"]["prepared"] += sign + "[" + plugin + "]\n"
    return result


def _manage(arguments):
    names = as_string(arguments.get("names", arguments.get("name")), "names")
    if not names:
        raise ValueError("Missing required argument: names")
    new_only = as_bool(arguments.get("new_only", False), "new_only")
    state = as_string(arguments.get("state", "enabled"), "state")
    if state not in ("enabled", "disabled"):
        raise ValueError("state must be enabled or disabled")
    check_mode = as_bool(
        arguments.get("_ansible_check_mode", False), "_ansible_check_mode"
    )
    diff = as_bool(arguments.get("_ansible_diff", False), "_ansible_diff")
    plugins = names.split(",")
    executable = _executable(as_string(arguments.get("prefix"), "prefix"))
    if ntpath.splitext(executable)[1].lower() in (".bat", ".cmd"):
        # RabbitMQ's batch scripts forward arguments through CMD again. Reject
        # control syntax rather than allow a plugin name to become a command.
        if any(character in names for character in '"\r\n\0%&|<>^!()'):
            raise ValueError(
                "Plugin names must not contain shell metacharacters "
                "when using a RabbitMQ batch entrypoint"
            )
    result = {"changed": False, "enabled": [], "disabled": []}
    if diff:
        result["diff"] = {"prepared": ""}
    listed = _command(executable, ["list", "-E", "-m"])
    if listed.get("failed") or listed["rc"]:
        return _failure(result, listed, "list -E -m")
    enabled = [line for line in listed["stdout"].splitlines() if line]
    requested = {plugin.lower() for plugin in plugins}
    existing = {plugin.lower() for plugin in enabled}
    to_enable = (
        [plugin for plugin in plugins if plugin.lower() not in existing]
        if state == "enabled"
        else []
    )
    to_disable = (
        [plugin for plugin in enabled if plugin.lower() in requested]
        if state == "disabled"
        else [
            plugin
            for plugin in enabled
            if not new_only and plugin.lower() not in requested
        ]
    )
    return _apply(
        executable,
        (
            ("enable", to_enable, "enabled", "+"),
            ("disable", to_disable, "disabled", "-"),
        ),
        check_mode,
        result,
    )


def main():
    """Read the released module arguments and manage installed RabbitMQ plugins."""
    run_module(
        lambda: _manage(
            read_arguments(
                ("names", "name", "new_only", "state", "prefix"),
                "sustainablelobster.legacy_community_windows.win_rabbitmq_plugin",
                allow_unknown=True,
            )
        )
    )


if __name__ == "__main__":
    main()
