#!/usr/bin/python
# -*- coding: utf-8 -*-
# Copyright: (c) 2020, Jamie Magee <jamie.magee@gmail.com>
# Copyright 2026 sustainablelobster
# SPDX-License-Identifier: GPL-3.0-or-later

"""Manage packages through the installed Scoop command-line interface."""

# WANT_JSON

import re

import legacy_community_windows_scoop as scoop  # pylint: disable=import-error
from legacy_windows_module import (  # pylint: disable=import-error
    as_bool,
    as_string,
    as_string_list,
    read_arguments,
    run_module,
)

DOCUMENTATION = r"""
---
module: win_scoop
short_description: Manage packages using Scoop
description:
  - Manage packages using Scoop.
  - If Scoop is missing, a normal task runs its official installer.
options:
  architecture:
    description: Force the package's process architecture.
    type: str
    choices: [32bit, 64bit]
    aliases: [arch]
  global:
    description: Install the app globally.
    type: bool
    default: false
  independent:
    description: Do not install dependencies automatically.
    type: bool
    default: false
  name:
    description: Names of packages to install or remove.
    type: list
    elements: str
    required: true
  no_cache:
    description: Do not use the download cache.
    type: bool
    default: false
  purge:
    description: Remove persistent data when uninstalling.
    type: bool
    default: false
  skip_checksum:
    description: Skip downloaded package hash validation.
    type: bool
    default: false
  state:
    description: Desired package state.
    type: str
    choices: [absent, present]
    default: present
notes:
  - Scoop and its installer determine their own PowerShell and runtime requirements.
  - Check mode skips when Scoop is missing, without downloading or installing it.
author:
  - Jamie Magee (@JamieMagee)
  - sustainablelobster
"""

EXAMPLES = r"""
- name: Install jq
  sustainablelobster.legacy_community_windows.win_scoop:
    name: jq
"""


def _failure(result, command, message):
    result.update(failed=True, msg=message)
    result.update(
        {name: command.get(name, "") for name in ("rc", "stdout", "stderr", "command")}
    )
    return result


def _options(arguments):
    names = as_string_list(arguments.get("name"), "name")
    if not names or any(not name for name in names):
        raise ValueError("name is required and must contain nonempty package names.")
    state = as_string(arguments.get("state", "present"), "state").lower()
    if state not in ("absent", "present"):
        raise ValueError("state must be absent or present.")
    architecture = as_string(
        arguments.get("architecture", arguments.get("arch")), "architecture"
    )
    if architecture is not None:
        architecture = architecture.lower()
        if architecture not in ("32bit", "64bit"):
            raise ValueError("architecture must be 32bit or 64bit.")
    flags = {
        name: as_bool(arguments.get(name, False), name)
        for name in ("global", "independent", "no_cache", "purge", "skip_checksum")
    }
    return names, state, architecture, flags


def _installed_scoop(check, result):
    path = scoop.locate()
    if not path:
        if check:
            result.update(
                skipped=True,
                msg="Skipped check mode run on win_scoop as "
                "scoop.ps1 cannot be found on the system",
            )
            return None
        installed = scoop.bootstrap()
        path = scoop.locate()
        if not path:
            _failure(result, installed, "Failed to bootstrap scoop.ps1")
            return None
        result.update(
            changed=True,
            warnings=[
                "Scoop was missing from this system, so it was installed during this task run."
            ],
        )
    return path


def _operation(names, state, architecture, flags, installed):
    if state == "absent":
        # Scoop can remove broken installs omitted from export; always ask it.
        selected = names
        operation = ["uninstall"] + names
        operation += ["--" + name for name in ("global", "purge") if flags[name]]
    else:
        selected = [
            name
            for name in names
            if not any(
                item["name"].lower() == name.lower()
                and item["global"] == flags["global"]
                for item in installed
            )
        ]
        operation = ["install"] + selected
        if architecture:
            operation += ["--arch", architecture]
        operation += [
            option
            for name, option in (
                ("global", "--global"),
                ("independent", "--independent"),
                ("no_cache", "--no-cache"),
                ("skip_checksum", "--skip"),
            )
            if flags[name]
        ]
    return selected, operation


def _execute(arguments):
    names, state, architecture, flags = _options(arguments)
    check = as_bool(arguments.get("_ansible_check_mode", False), "_ansible_check_mode")
    result = {"changed": False, "rc": 0}
    path = _installed_scoop(check, result)
    if not path:
        return result
    exported = scoop.command(path, ["export"])
    if exported.get("failed") or exported["rc"]:
        return _failure(result, exported, "Error checking installed packages")
    selected, operation = _operation(
        names, state, architecture, flags, scoop.packages(exported["stdout"])
    )
    if not selected:
        return result
    if check:
        result["changed"] = True
        return result
    command = scoop.command(path, operation)
    if command.get("failed") or command["rc"]:
        return _failure(
            result,
            command,
            "Error {0} {1}".format(
                "uninstalling" if state == "absent" else "installing",
                ", ".join(selected),
            ),
        )
    if state == "present" or not re.search(
        r"ERROR '(.*?)' isn't installed\.", command["stdout"], re.IGNORECASE
    ):
        result["changed"] = True
    if arguments.get("_ansible_verbosity", 0) > 1:
        result["stdout"] = command["stdout"]
    return result


def main():
    """Run the released Scoop package interface."""
    run_module(
        lambda: _execute(
            read_arguments(
                (
                    "architecture",
                    "arch",
                    "global",
                    "independent",
                    "name",
                    "no_cache",
                    "purge",
                    "skip_checksum",
                    "state",
                ),
                "sustainablelobster.legacy_community_windows.win_scoop",
            )
        )
    )


if __name__ == "__main__":
    main()
