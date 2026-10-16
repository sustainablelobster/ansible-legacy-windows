#!/usr/bin/python
# -*- coding: utf-8 -*-
# Copyright 2026 sustainablelobster
# Copyright: (c) 2015, Phil Schwartz <schwartzmx@gmail.com>
# SPDX-License-Identifier: GPL-3.0-or-later

"""Extract archives on the configured Windows Python interpreter."""

# WANT_JSON

from legacy_community_windows_unzip import extract  # pylint: disable=import-error
from legacy_windows_module import (  # pylint: disable=import-error
    as_bool,
    as_path,
    as_string,
    read_arguments,
    run_module,
)

DOCUMENTATION = r"""
---
module: win_unzip
short_description: Unzips compressed files and archives on the Windows node
description:
  - Extract archives into a destination directory on the Windows target.
  - Standard ZIP, TAR, TAR.GZ, TAR.BZ2, TAR.XZ, GZ and BZ2 formats use Python's standard library.
  - CAB/MSU archives use the installed Windows cabinet extractor; additional formats use an installed PSCX engine.
options:
  src:
    description: Absolute source archive path.
    type: path
    required: true
  dest:
    description: Absolute destination directory; it is created when necessary.
    type: path
    required: true
  delete_archive:
    description: Delete the source and extracted nested archives after successful extraction.
    type: bool
    default: false
    aliases: [rm]
  recurse:
    description: Expand ZIP, GZ, BZ2, TAR and MSU archives found beneath the extracted destination.
    type: bool
    default: false
  creates:
    description: Skip extraction if this file or directory exists.
    type: path
  password:
    description: Password for an encrypted archive; standard ZipCrypto is supported natively.
notes:
  - Without creates, archives are extracted again on each run and normally report a change.
  - Standard-library extraction rejects traversal outside the destination, existing links/reparse points, and TAR links or special files.
  - Additional formats and AES-encrypted ZIP archives require installed PowerShell and PSCX, as upstream does; the selected vendor engine controls its format support.
  - Common recursive extraction and ZipCrypto passwords do not require PSCX. ZIP passwords are encoded as UTF-8.
  - Cabinet extraction prefers C(extrac32.exe), which preserves member names on legacy Windows;
    C(expand.exe) is used when the cabinet extractor is absent.
  - Serialization of archive timestamps and permissions can differ from upstream engines. Extraction preserves file contents and paths, not archive ownership or access-control lists.
  - Check mode does not create directories, extract files or delete archives; removed reports the predicted deletion.
author:
  - sustainablelobster
  - Phil Schwartz (@schwartzmx)
seealso:
  - module: ansible.builtin.unarchive
"""

EXAMPLES = r"""
- name: Extract once using a destination guard
  sustainablelobster.legacy_community_windows.win_unzip:
    src: C:\Downloads\package.zip
    dest: C:\Applications\package
    creates: C:\Applications\package

- name: Recursively extract and remove compressed inputs
  sustainablelobster.legacy_community_windows.win_unzip:
    src: C:\Downloads\logs.zip
    dest: C:\Logs
    recurse: true
    delete_archive: true
"""

RETURN = r"""
dest:
  description: Destination directory path.
  returned: always
  type: str
removed:
  description: Whether archives were removed or would be removed in check mode.
  returned: always
  type: bool
src:
  description: Source archive path.
  returned: always
  type: str
"""

_PARAMETERS = ("src", "dest", "creates", "recurse", "delete_archive", "rm", "password")


def _parameters(arguments):
    result = {
        name: as_path(arguments.get(name), name) for name in ("src", "dest", "creates")
    }
    for name in ("src", "dest"):
        if not result[name]:
            raise ValueError("Missing required argument: " + name)
    result["recurse"] = as_bool(arguments.get("recurse", False), "recurse")
    result["delete_archive"] = as_bool(
        arguments.get("delete_archive", arguments.get("rm", False)), "delete_archive"
    )
    result["password"] = as_string(arguments.get("password"), "password")
    return result


# Each standalone payload keeps its own small WANT_JSON entry point so the
# target does not need a separate module-dispatch layer.
# pylint: disable=duplicate-code
def main():
    """Read a WANT_JSON extraction request and return its result."""

    def _execute():
        arguments = read_arguments(
            _PARAMETERS,
            "sustainablelobster.legacy_community_windows.win_unzip",
            allow_unknown=True,
        )
        return extract(
            _parameters(arguments),
            as_bool(arguments.get("_ansible_check_mode", False), "_ansible_check_mode"),
        )

    run_module(_execute)


if __name__ == "__main__":
    main()
