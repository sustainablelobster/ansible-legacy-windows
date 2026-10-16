#!/usr/bin/python
# -*- coding: utf-8 -*-
# Copyright: (c) 2015, Peter Mounce <public@neverrunwithscissors.com>
# Copyright 2026 sustainablelobster
# SPDX-License-Identifier: GPL-3.0-or-later

"""Install products through an existing Web Platform Installer CLI."""

# WANT_JSON

import os
import re
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
module: win_webpicmd
short_description: Install packages using Web Platform Installer command-line
description:
  - Installs packages through an existing C(webpicmd.exe) installation.
  - The configured vendor feeds must still provide the requested product and its installers.
options:
  name:
    description: Name of the package to install.
    type: str
    required: true
notes:
  - Accepts vendor EULAs and suppresses reboot; manage any required restart separately.
  - Microsoft retired Web Platform Installer and its public feed. This module does not restore retired vendor services.
  - Requires the installed WebPI CLI, its runtime prerequisites and a working configured product feed.
  - Check mode is not supported, matching the recorded released interface.
seealso:
  - module: sustainablelobster.legacy_windows.win_package
author:
  - Peter Mounce (@petemounce)
  - sustainablelobster
"""

EXAMPLES = r"""
- name: Install URLRewrite2 from the configured WebPI feed
  sustainablelobster.legacy_community_windows.win_webpicmd:
    name: URLRewrite2
"""


def _executable():
    directories = os.get_exec_path() + [r"C:\ProgramData\chocolatey\bin"]
    for folder in directories:
        candidate = os.path.join(folder, "webpicmd.exe")
        if os.path.isfile(candidate):
            return os.path.abspath(candidate)
    raise OSError(
        "webpicmd.exe is not installed. It must be installed and available on PATH."
    )


def _command(executable, arguments):
    return run_command(
        executable,
        subprocess.list2cmdline([executable] + arguments),
        {"chdir": None, "stdin": None, "output_encoding_override": None},
    )


def _execute(arguments):
    if as_bool(arguments.get("_ansible_check_mode", False), "_ansible_check_mode"):
        return {
            "changed": False,
            "skipped": True,
            "msg": "remote module does not support check mode",
        }
    name = as_string(arguments.get("name"), "name")
    if not name:
        raise ValueError("name is required.")
    executable = _executable()
    listed = _command(executable, ["/list", "/listoption:installed"])
    result = {"changed": False}
    if listed.get("failed") or listed["rc"]:
        result.update(
            failed=True,
            msg="Error checking installation status for " + name,
            webpicmd_error_cmd=None,
            webpicmd_error_log=listed.get("stdout", ""),
        )
        return result
    # The released provider applies the package as an unescaped regex to each
    # vendor output line. Retain that interface rather than treating it literally.
    if any(
        re.search("^" + name + r"\s+", line, re.IGNORECASE)
        for line in listed["stdout"].splitlines()
    ):
        return result
    installed = _command(
        executable, ["/install", "/products:" + name, "/accepteula", "/suppressreboot"]
    )
    if installed.get("failed") or installed["rc"]:
        result.update(
            failed=True,
            msg="Error installing " + name,
            webpicmd_error_cmd=None,
            webpicmd_error_log=installed.get("stdout", ""),
        )
    else:
        result["changed"] = (
            "install of products: success" in installed["stdout"].lower()
        )
    return result


def main():
    """Run the released WebPI product-install interface."""
    run_module(
        lambda: _execute(
            read_arguments(
                ("name",), "sustainablelobster.legacy_community_windows.win_webpicmd"
            )
        )
    )


if __name__ == "__main__":
    main()
