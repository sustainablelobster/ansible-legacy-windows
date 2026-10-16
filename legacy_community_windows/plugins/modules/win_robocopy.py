#!/usr/bin/python
# -*- coding: utf-8 -*-
# Copyright: (c) 2015, Corwin Brown <blakfeld@gmail.com>
# Copyright 2026 sustainablelobster
# SPDX-License-Identifier: GPL-3.0-or-later

"""Synchronize target directories through the installed Robocopy executable."""

# WANT_JSON

import glob
import re
import subprocess

# The action stages the shared argument and native process helpers.
from legacy_windows_module import (  # pylint: disable=import-error
    as_bool,
    as_path,
    as_string,
    expand_environment,
    read_arguments,
    run_module,
)
from legacy_windows_process import run_command  # pylint: disable=import-error

DOCUMENTATION = r"""
---
module: win_robocopy
short_description: Synchronizes the contents of two directories using Robocopy
description:
- Synchronizes the contents of files/directories from a source to destination.
- Under the hood this just calls out to RoboCopy, since that should be available
  on most modern Windows systems.
options:
  src:
    description:
    - Source file/directory to sync.
    type: path
    required: yes
  dest:
    description:
    - Destination file/directory to sync (Will receive contents of src).
    type: path
    required: yes
  recurse:
    description:
    - Includes all subdirectories (Toggles the C(/e) flag to RoboCopy).
    - If C(flags) is set, this will be ignored.
    type: bool
    default: no
  purge:
    description:
    - Deletes any files/directories found in the destination that do not exist in the source.
    - Toggles the C(/purge) flag to RoboCopy.
    - If C(flags) is set, this will be ignored.
    type: bool
    default: no
  flags:
    description:
      - Directly supply Robocopy flags.
      - If set, C(purge) and C(recurse) will be ignored.
    type: str
notes:
- This is not a complete port of the M(ansible.posix.synchronize) module. Unlike the M(ansible.posix.synchronize)
  module this only performs the sync/copy on the remote machine, not from the Ansible controller to the remote machine.
- This module does not currently support all Robocopy flags.
- Unlike community.windows 3.3.0, successful deletion-only operations report a
  change, including in check mode. Effective C(/PURGE) or C(/MIR) flags enable
  this reporting; C(/XX) excludes destination-only entries from deletion.
- Custom file masks, selection filters such as C(/XF) or C(/XD), and job files
  retain upstream's status-based reporting. Their deletion-only operations can
  still report unchanged because Robocopy's extra-entry status also counts
  retained entries.
seealso:
- module: ansible.posix.synchronize
- module: sustainablelobster.legacy_windows.win_copy
author:
- Corwin Brown (@blakfeld)
"""

EXAMPLES = r"""
- name: Sync the contents of one directory to another
  sustainablelobster.legacy_community_windows.win_robocopy:
    src: C:\DirectoryOne
    dest: C:\DirectoryTwo

- name: Sync the contents of one directory to another, including subdirectories
  sustainablelobster.legacy_community_windows.win_robocopy:
    src: C:\DirectoryOne
    dest: C:\DirectoryTwo
    recurse: true

- name: Synchronize a directory and remove destination-only entries
  sustainablelobster.legacy_community_windows.win_robocopy:
    src: C:\DirectoryOne
    dest: C:\DirectoryTwo
    purge: true

- name: Recursively synchronize and remove destination-only entries
  sustainablelobster.legacy_community_windows.win_robocopy:
    src: C:\DirectoryOne
    dest: C:\DirectoryTwo
    recurse: true
    purge: true

- name: Synchronize directories recursively with custom flags
  sustainablelobster.legacy_community_windows.win_robocopy:
    src: C:\DirectoryOne
    dest: C:\DirectoryTwo
    flags: /E /PURGE /XD SOME_DIR /XF SOME_FILE /MT:32

- name: Synchronize a file from a UNC path with custom flags
  sustainablelobster.legacy_community_windows.win_robocopy:
    src: \\Server1\Directory One
    dest: C:\DirectoryTwo
    flags: file.zip /E /PURGE /XD SOME_DIR /XF SOME_FILE /MT:32
"""

RETURN = r"""
cmd:
    description: The used command line.
    returned: always
    type: str
    sample: robocopy C:\DirectoryOne C:\DirectoryTwo /e /purge
src:
    description: The Source file/directory of the sync.
    returned: always
    type: str
    sample: C:\Some\Path
dest:
    description: The Destination file/directory of the sync.
    returned: always
    type: str
    sample: C:\Some\Path
recurse:
    description: Whether or not the recurse flag was toggled.
    returned: always
    type: bool
    sample: false
purge:
    description: Whether or not the purge flag was toggled.
    returned: always
    type: bool
    sample: false
flags:
    description: Any flags passed in by the user.
    returned: always
    type: str
    sample: /e /purge
rc:
    description: The return code returned by robocopy.
    returned: success
    type: int
    sample: 1
output:
    description: The output of running the robocopy command.
    returned: success
    type: str
    sample: "------------------------------------\\n   ROBOCOPY     ::     Robust File Copy for Windows         \\n------------------------------------\\n "
msg:
    description: Output interpreted into a concise message.
    returned: always
    type: str
    sample: No files copied!
"""

_STATUSES = {
    0: ("No files copied.", False, False),
    1: ("Files copied successfully!", True, False),
    2: (
        "Some Extra files or directories were detected. No files were copied.",
        False,
        True,
    ),
    3: ("(2+1) Some files were copied. Additional files were present.", True, True),
    4: (
        "Some mismatched files or directories were detected. Housekeeping might be required!",
        True,
        True,
    ),
    5: ("(4+1) Some files were copied. Some files were mismatched.", True, True),
    6: (
        "(4+2) Additional files and mismatched files exist. No files were copied.",
        False,
        False,
    ),
    7: (
        "(4+1+2) Files were copied, a file mismatch was present, "
        "and additional files were present.",
        True,
        True,
    ),
}


def _error_message(lines, default):
    separators = 0
    for line in lines:
        if separators < 3:
            if re.match(r"^\s*-+\s*$", line):
                separators += 1
        elif re.search("error", line, re.I):
            return line
    return default


def _unfiltered_purge(options):
    # Filtered extras can remain without clearing Robocopy's extra-entry status.
    if any(option and not option.startswith("/") for option in options):
        return False
    switches = set(option.split(":", 1)[0].upper() for option in options)
    selection = (
        "/XX",
        "/XF",
        "/XD",
        "/JOB",
        "/MAX",
        "/MIN",
        "/MAXAGE",
        "/MINAGE",
        "/MAXLAD",
        "/MINLAD",
        "/XA",
        "/IA",
        "/XJ",
        "/XJD",
        "/XJF",
        "/LEV",
    )
    return not switches.intersection(selection) and bool(
        switches.intersection(("/PURGE", "/MIR"))
    )


def _execute(arguments):
    source = as_string(arguments.get("src"), "src")
    if source is not None:
        source = expand_environment(source)
    destination = as_path(arguments.get("dest"), "dest")
    if not source or not destination:
        raise ValueError("src and dest are required.")
    purge = as_bool(arguments.get("purge", False), "purge")
    recurse = as_bool(arguments.get("recurse", False), "recurse")
    flags = as_string(arguments.get("flags"), "flags")
    result = {
        "changed": False,
        "src": source,
        "dest": destination,
        "purge": purge,
        "recurse": recurse,
        "flags": flags,
    }
    if not glob.glob(source):
        raise ValueError(source + " does not exist!")
    options = [source, destination]
    if as_bool(arguments.get("_ansible_check_mode", False), "_ansible_check_mode"):
        options.append("/l")
    if flags is None:
        if purge:
            options.append("/purge")
        if recurse:
            options.append("/e")
    else:
        options.extend(flags.split(" "))
    result["cmd"] = "robocopy " + " ".join(options)
    response = run_command(
        "robocopy.exe",
        subprocess.list2cmdline(["robocopy.exe"] + options),
        {"chdir": None, "stdin": None, "output_encoding_override": None},
    )
    if "stdout" not in response:
        raise OSError(response.get("msg", "Failed to execute Robocopy."))
    lines = response["stdout"].splitlines()
    result["output"] = lines if len(lines) > 1 else (lines[0] if lines else None)
    result["rc"] = result["return_code"] = response["rc"]
    status = response["rc"]
    message, changed, warning = _STATUSES.get(status, ("Success", False, False))
    changed = changed or (status in (2, 6) and _unfiltered_purge(options[2:]))
    result.update(msg=message, changed=changed)
    if status in range(1, 8):
        result["failed"] = False
    if warning:
        result["warnings"] = [message]
    if 8 <= status <= 16:
        defaults = {
            8: "Some files or directories could not be copied!",
            16: "Serious Error! No files were copied! Do you have permissions to access "
            + source
            + " and "
            + destination
            + "?",
        }
        result.update(
            failed=True,
            msg=_error_message(
                lines, defaults.get(status, "Fatal error. Check log message!")
            ),
        )
    return result


def main():
    """Read the public arguments and return Robocopy's interpreted status."""
    run_module(
        lambda: _execute(
            read_arguments(
                ("src", "dest", "purge", "recurse", "flags"),
                "sustainablelobster.legacy_community_windows.win_robocopy",
                allow_unknown=True,
            )
        )
    )


if __name__ == "__main__":
    main()
