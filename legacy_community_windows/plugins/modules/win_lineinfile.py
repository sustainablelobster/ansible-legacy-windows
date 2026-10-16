#!/usr/bin/python
# -*- coding: utf-8 -*-
# Copyright 2026 sustainablelobster
# SPDX-License-Identifier: GPL-3.0-or-later

"""Ensure individual lines exist or are absent in Windows text files."""

# WANT_JSON

from legacy_community_windows_lineinfile import manage  # pylint: disable=import-error
from legacy_windows_module import (  # pylint: disable=import-error
    as_bool,
    as_path,
    as_string,
    read_arguments,
    run_module,
)

DOCUMENTATION = r"""
---
module: win_lineinfile
short_description: Ensure a particular line is in a file, or replace an existing line using a back-referenced regular expression
description:
  - Search a file for a line and ensure that it is present or absent.
  - Replaces only the last matching line with state=present, and removes all matching lines with state=absent.
options:
  path:
    description: Path of the file to modify.
    type: path
    required: true
    aliases: [dest, destfile, name]
  backup:
    description: Save a timestamped copy of the original file when changing it.
    type: bool
    default: false
  regex:
    description: Regular expression used to find lines to replace or remove.
    aliases: [regexp]
  state:
    description: Whether the requested line should be present or absent.
    type: str
    choices: [absent, present]
    default: present
  line:
    description: Line to insert, replace, or remove. Required for state=present.
    type: str
  backrefs:
    description:
      - Expand replacement references such as C($1) and C(${name}) from the regex matches.
      - With no regex match the file remains unchanged, ignoring insertion selectors.
    type: bool
    default: false
  insertafter:
    description: Insert after the last matching line, or at EOF when no match exists.
    type: str
    choices: [EOF, '*regex*']
    default: EOF
  insertbefore:
    description: Insert before the last matching line, at BOF, or at EOF when no match exists.
    type: str
    choices: [BOF, '*regex*']
  create:
    description: Create a missing destination with state=present; its parent directory must exist.
    type: bool
    default: false
  validate:
    description:
      - Command to validate the proposed contents before changing the destination.
      - Include C(%s) for the temporary file path. The command does not run through a shell.
    type: str
  encoding:
    description:
      - Encoding used to write the file. With auto, preserve a detected Unicode BOM or use UTF-8 without a BOM.
      - Explicit UTF-8, UTF-16 and UTF-32 encodings write their byte-order mark.
      - Other encoding names use Python's standard-library codecs, including Windows code pages.
    type: str
    default: auto
  newline:
    description: Line separator written when changing the file; the presence or absence of a final newline is retained.
    type: str
    choices: [unix, windows]
    default: windows
notes:
  - When both insertion selectors are supplied, C(insertbefore) takes precedence, correcting the released upstream defect.
  - Patterns use Python 3.4 regular expressions with common .NET named-group spellings translated. Advanced .NET-specific syntax is not supported.
  - Check mode never creates a missing destination, unlike the recorded upstream implementation.
  - Validation runs in check mode against a temporary file. Temporary files are removed even when validation fails.
  - A missing file is created without a final newline. Existing unchanged files retain their original bytes.
seealso:
  - module: ansible.builtin.lineinfile
author:
  - sustainablelobster
  - Brian Lloyd (@brianlloyd)
"""

EXAMPLES = r"""
- name: Replace an application setting
  sustainablelobster.legacy_community_windows.win_lineinfile:
    path: C:\Temp\example.conf
    regex: '^name='
    line: name=JohnDoe

- name: Replace a captured setting and retain its prefix
  sustainablelobster.legacy_community_windows.win_lineinfile:
    path: C:\Temp\example.conf
    regex: '(^name=).*'
    line: '$1JohnDoe'
    backrefs: true
"""

RETURN = r"""
backup_file:
  description: Path of the original file's timestamped backup.
  returned: when backup=true and an existing file is changed outside check mode
  type: str
  sample: C:\Path\To\File.txt.11540.20150212-220915.bak
"""

_PARAMETERS = (
    "path",
    "dest",
    "destfile",
    "name",
    "backup",
    "regex",
    "regexp",
    "state",
    "line",
    "backrefs",
    "insertafter",
    "insertbefore",
    "create",
    "validate",
    "encoding",
    "newline",
)


def _parameters(arguments):
    result = {}
    for name, default in (
        ("state", "present"),
        ("line", None),
        ("insertafter", None),
        ("insertbefore", None),
        ("validate", None),
        ("encoding", "auto"),
        ("newline", "windows"),
    ):
        result[name] = as_string(arguments.get(name, default), name)
    result["path"] = as_path(
        next(
            (
                arguments[name]
                for name in ("path", "dest", "destfile", "name")
                if name in arguments
            ),
            None,
        ),
        "path",
    )
    result["regex"] = as_string(
        arguments.get("regex", arguments.get("regexp")), "regex"
    )
    for name in ("backup", "backrefs", "create"):
        result[name] = as_bool(arguments.get(name, False), name)
    if not result["path"]:
        raise ValueError("Missing required argument: path")
    for name, choices in (
        ("state", ("present", "absent")),
        ("newline", ("unix", "windows")),
    ):
        if result[name] not in choices:
            raise ValueError("{0} must be one of: {1}".format(name, ", ".join(choices)))
    if not result["encoding"]:
        raise ValueError("encoding must not be empty")
    if result["state"] == "present":
        if result["backrefs"] and not result["regex"]:
            raise ValueError("regexp= is required with backrefs=true")
        if not result["line"]:
            raise ValueError("line= is required with state=present")
        if not result["insertbefore"] and not result["insertafter"]:
            result["insertafter"] = "EOF"
    elif not result["regex"] and not result["line"]:
        raise ValueError("one of line= or regexp= is required with state=absent")
    return result


def main():
    """Read a WANT_JSON request and return the line-editing result."""

    def _execute():
        arguments = read_arguments(
            _PARAMETERS,
            "sustainablelobster.legacy_community_windows.win_lineinfile",
            allow_unknown=True,
        )
        return manage(
            _parameters(arguments),
            as_bool(arguments.get("_ansible_check_mode", False), "_ansible_check_mode"),
            as_bool(arguments.get("_ansible_diff", False), "_ansible_diff"),
        )

    run_module(_execute)


if __name__ == "__main__":
    main()
