#!/usr/bin/python
# -*- coding: utf-8 -*-
# Copyright 2026 sustainablelobster
# Copyright: (c) 2021, Kento Yagisawa <thel.vadam2485@gmail.com>
# SPDX-License-Identifier: GPL-3.0-or-later

"""Create ZIP files using the Python standard library."""

# WANT_JSON

import os
import zipfile

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
module: win_zip
short_description: Compress file or directory as zip archive on the Windows node
description:
  - Compress a file or directory as a ZIP archive on the Windows target.
  - Existing destination archives are left unchanged.
options:
  src:
    description:
      - Absolute path of the file or directory to archive.
      - A directory is included as the root entry unless the path ends with C(\*).
    type: str
    required: true
  dest:
    description: Absolute path of the destination ZIP file.
    type: path
    required: true
notes:
  - ZIP names use UTF-8 for non-ASCII characters and forward-slash separators.
  - Uses the Python standard library rather than requiring an installed compression engine.
  - Check mode predicts archive creation without creating the destination.
seealso:
  - module: community.general.archive
author:
  - sustainablelobster
  - Kento Yagisawa (@hiyoko_taisa)
"""

EXAMPLES = r"""
- name: Include a directory as the archive root
  sustainablelobster.legacy_community_windows.win_zip:
    src: C:\Logs
    dest: C:\Logs.zip

- name: Include only the directory contents
  sustainablelobster.legacy_community_windows.win_zip:
    src: C:\Logs\*
    dest: C:\Logs-content.zip
"""


def _entries(source, contents_only):
    if os.path.isfile(source):
        return [(source, os.path.basename(source))]
    base = source if contents_only else os.path.dirname(source)
    entries = []
    for directory, directories, filenames in os.walk(source):
        directories.sort()
        filenames.sort()
        if not directories and not filenames:
            relative = os.path.relpath(directory, base).replace(os.sep, "/")
            if relative != ".":
                entries.append((directory, relative + "/"))
        entries.extend(
            (
                os.path.join(directory, name),
                os.path.relpath(os.path.join(directory, name), base).replace(
                    os.sep, "/"
                ),
            )
            for name in filenames
        )
    return entries


def _compress(arguments):
    source = expand_environment(as_string(arguments.get("src"), "src"))
    destination = as_path(arguments.get("dest"), "dest")
    if not source or not destination:
        raise ValueError("src and dest are required")
    contents_only = source.endswith(("\\*", "/*"))
    if contents_only:
        source = source[:-2]
    source = os.path.normpath(source)
    if not os.path.exists(source):
        raise ValueError(
            "The source file or directory '{0}' does not exist.".format(source)
        )
    if not destination.lower().endswith(".zip"):
        raise ValueError(
            "The destination zip file path '{0}' need to be zip file path.".format(
                destination
            )
        )
    if os.path.exists(destination):
        return {
            "changed": False,
            "msg": "The destination zip file '{0}' already exists.".format(destination),
        }
    entries = _entries(source, contents_only)
    if not as_bool(arguments.get("_ansible_check_mode", False), "_ansible_check_mode"):
        # Discover inputs before opening the output, so a destination placed in
        # the source tree cannot recursively include its own growing archive.
        created = False
        try:
            with open(destination, "xb") as output:
                created = True
                with zipfile.ZipFile(
                    output, "w", compression=zipfile.ZIP_DEFLATED, allowZip64=True
                ) as archive:
                    for path, name in entries:
                        archive.write(path, name)
        except (OSError, ValueError, RuntimeError, zipfile.BadZipFile):
            if created:
                os.unlink(destination)
            raise
    return {"changed": True}


def main():
    """Read a WANT_JSON request and create the requested ZIP archive."""
    run_module(
        lambda: _compress(
            read_arguments(
                ("src", "dest"),
                "sustainablelobster.legacy_community_windows.win_zip",
            )
        )
    )


if __name__ == "__main__":
    main()
