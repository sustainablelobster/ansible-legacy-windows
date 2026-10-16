#!/usr/bin/python
# -*- coding: utf-8 -*-
# Copyright 2026 sustainablelobster
# Copyright: (c) 2016, Dag Wieers (@dagwieers) <dag@wieers.com>
# SPDX-License-Identifier: GPL-3.0-or-later

"""Manage native application and URL shortcuts on Windows."""

# WANT_JSON

import os
import shutil

from legacy_community_windows_shortcut import Shortcut  # pylint: disable=import-error
from legacy_windows_module import (  # pylint: disable=import-error
    as_bool,
    as_path,
    as_string,
    expand_environment,
    read_arguments,
    run_module,
)

DOCUMENTATION = r"""
---
module: win_shortcut
short_description: Manage shortcuts on Windows
description:
  - Create, modify and delete native application and URL shortcuts.
options:
  src:
    description: Executable, absolute target path, or URL for the shortcut.
    type: str
  description:
    description: Description displayed for an application shortcut.
    type: str
  dest:
    description: Destination shortcut file ending with .lnk or .url.
    type: path
    required: true
  arguments:
    description: Additional executable arguments.
    type: str
    aliases: [args]
  directory:
    description: Working directory for an application shortcut.
    type: path
  icon:
    description: Icon path followed optionally by a comma and icon index.
    type: path
  hotkey:
    description: Letter, digit or F1-F24 key combined with Ctrl, Alt, Shift or Ext modifiers.
    type: str
  windowstyle:
    description: Initial application window presentation.
    type: str
    choices: [maximized, minimized, normal]
  state:
    description: Whether the shortcut should exist.
    type: str
    choices: [absent, present]
    default: present
  run_as_admin:
    description: Set or clear the application shortcut's administrator flag.
    type: bool
    default: false
notes:
  - Environment variables are expanded in target, arguments, description, destination, directory and icon values.
  - URL shortcuts use only src and dest; application-only properties are ignored for them.
  - Uses native Shell Link and Internet Shortcut interfaces without requiring Windows Script Host or PowerShell.
  - Check mode does not save shortcuts or change administrator flags, correcting upstream's administrator-flag mutation in check mode.
  - The administrator flag records launch intent; whether elevation is available depends on the installed Windows shell.
author:
  - sustainablelobster
  - Dag Wieers (@dagwieers)
seealso:
  - module: sustainablelobster.legacy_windows.win_file
"""

EXAMPLES = r"""
- name: Create an application shortcut
  sustainablelobster.legacy_community_windows.win_shortcut:
    src: cmd.exe
    dest: '%TEMP%\Command Prompt.lnk'
    arguments: /k echo ready
    windowstyle: normal

- name: Create a URL shortcut
  sustainablelobster.legacy_community_windows.win_shortcut:
    src: https://ansible.com/
    dest: '%TEMP%\Ansible.url'
"""

RETURN = r"""
{}
"""

_PARAMETERS = (
    "src",
    "description",
    "dest",
    "arguments",
    "args",
    "directory",
    "icon",
    "hotkey",
    "windowstyle",
    "state",
    "run_as_admin",
)


def _parameters(arguments):
    result = {}
    for name in ("src", "description", "hotkey", "windowstyle"):
        result[name] = as_string(arguments.get(name), name)
    result["args"] = as_string(
        arguments.get("arguments", arguments.get("args")), "arguments"
    )
    for name in ("src", "description", "args"):
        result[name] = expand_environment(result[name])
    for name in ("dest", "directory", "icon"):
        result[name] = as_path(arguments.get(name), name)
    if not result["dest"]:
        raise ValueError("Missing required argument: dest")
    result["state"] = as_string(arguments.get("state", "present"), "state")
    if result["state"] not in ("present", "absent"):
        raise ValueError("state must be present or absent")
    if result["windowstyle"] not in (None, "normal", "minimized", "maximized"):
        raise ValueError("windowstyle must be normal, minimized or maximized")
    result["run_as_admin"] = as_bool(
        arguments.get("run_as_admin", False), "run_as_admin"
    )
    if result["src"]:
        result["src"] = shutil.which(result["src"]) or result["src"]
    return result


def _manage(options, check_mode=False):
    path = options["dest"]
    result = {"changed": False, "dest": path, "state": options["state"]}
    if options["state"] == "absent":
        if os.path.exists(path):
            if not check_mode:
                os.unlink(path)
            result["changed"] = True
        return result
    if os.path.splitext(path)[1].lower() not in (".lnk", ".url"):
        raise ValueError("Shortcut destination must end with .lnk or .url")
    with Shortcut(path) as shortcut:
        current = shortcut.read()
        for name in (
            ("src",)
            if shortcut.url
            else (
                "src",
                "args",
                "directory",
                "hotkey",
                "icon",
                "description",
                "windowstyle",
                "run_as_admin",
            )
        ):
            requested = options[name]
            existing = current[name]
            if (
                name == "src"
                and not shortcut.url
                and requested
                and requested.lower().startswith("shell:")
            ):
                if not shortcut.matches_source(requested):
                    shortcut.set(name, requested)
                    result["changed"] = True
                continue
            if requested is not None and (
                requested.lower() != existing.lower()
                if isinstance(requested, str) and isinstance(existing, str)
                else requested != existing
            ):
                shortcut.set(name, requested)
                result["changed"] = True
        current = shortcut.read()
        current.pop("run_as_admin", None)
        if options["src"] and options["src"].lower().startswith("shell:"):
            current["src"] = options["src"]
        result.update(current)
        if result["changed"] and not check_mode:
            shortcut.save()
    return result


def main():
    """Read a WANT_JSON request and manage the native shortcut."""

    def _execute():
        arguments = read_arguments(
            _PARAMETERS, "sustainablelobster.legacy_community_windows.win_shortcut"
        )
        return _manage(
            _parameters(arguments),
            as_bool(arguments.get("_ansible_check_mode", False), "_ansible_check_mode"),
        )

    run_module(_execute)


if __name__ == "__main__":
    main()
