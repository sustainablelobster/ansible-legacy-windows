#!/usr/bin/python
# -*- coding: utf-8 -*-
# Copyright 2026 sustainablelobster
# Copyright: (c) 2015, Jon Hawkesworth (@jhawkesworth) <jhawkesworth@protonmail.com>
# SPDX-License-Identifier: GPL-3.0-or-later

"""Import registry files using the installed native registry command."""

# WANT_JSON

import codecs
import os
import re
import subprocess
import tempfile
from collections import Counter

try:
    import winreg
except ImportError:
    winreg = None

from legacy_windows_module import (  # pylint: disable=import-error
    as_bool,
    as_path,
    as_string,
    read_arguments,
    run_module,
)
from legacy_windows_text import decode_bytes  # pylint: disable=import-error

DOCUMENTATION = r"""
---
module: win_regmerge
short_description: Merges the contents of a registry file into the Windows registry
description:
  - Import a registry file with Windows reg.exe.
  - Optionally export a comparison key and compare its lines with the input file before importing.
options:
  path:
    description: Absolute target path of the registry file; mutually exclusive with content.
    type: path
  content:
    description: Registry file contents without a byte-order mark; mutually exclusive with path.
    type: str
  compare_to:
    description:
      - Parent key to export and compare, in HKLM or HKCU PowerShell-drive notation such as HKCU:\Software\Application.
      - When omitted or missing, the file is imported and reports changed on each run.
    type: str
notes:
  - Comparison is based on registry export text, not a desired-state interpretation of registry values. Use one root key per registry file.
  - Extra registry values are not removed by an import and can cause repeated comparison differences.
  - Comparison is case-insensitive and order-independent. Differences in export formatting can still cause repeated changes.
  - Content is staged as UTF-16 with a byte-order mark to preserve Unicode on legacy Windows; upstream Windows PowerShell's default ANSI staging can lose non-ASCII characters.
  - Check mode is unsupported and skips the operation without changing the registry.
seealso:
  - module: sustainablelobster.legacy_windows.win_reg_stat
  - module: sustainablelobster.legacy_windows.win_regedit
author:
  - sustainablelobster
  - Jon Hawkesworth (@jhawkesworth)
"""

EXAMPLES = r"""
- name: Merge registry settings and compare with the current key
  sustainablelobster.legacy_community_windows.win_regmerge:
    path: C:\Deploy\application.reg
    compare_to: HKLM:\Software\Application

- name: Import registry text
  sustainablelobster.legacy_community_windows.win_regmerge:
    content: |
      Windows Registry Editor Version 5.00

      [HKEY_CURRENT_USER\Software\Application]
      "Enabled"=dword:00000001
"""

RETURN = r"""
compare_to_key_found:
  description: Whether the comparison key was found.
  returned: when a comparison key was supplied but not found
  type: bool
difference_count:
  description: Number of unmatched lines between the input and registry export.
  returned: after a comparison
  type: int
compared:
  description: Whether an existing comparison key was exported and compared.
  returned: success
  type: bool
"""


def _comparison_key(path):
    match = re.match(r"^(HKLM|HKCU):\\(.*)$", path, re.IGNORECASE)
    if not match:
        return None
    return match.group(1).upper(), match.group(2)


def _key_exists(path):
    selected = _comparison_key(path)
    if selected is None:
        return False
    hive, subkey = selected
    root = winreg.HKEY_LOCAL_MACHINE if hive == "HKLM" else winreg.HKEY_CURRENT_USER
    try:
        with winreg.OpenKey(root, subkey):
            return True
    except FileNotFoundError:
        return False


def _run_reg(executable, arguments):
    with subprocess.Popen(
        [executable] + arguments, stdout=subprocess.PIPE, stderr=subprocess.PIPE
    ) as process:
        output, errors = process.communicate()
    return {
        "rc": process.returncode,
        "stdout": output.decode("utf-8", "replace"),
        "stderr": errors.decode("utf-8", "replace"),
    }


def _lines(path):
    with open(path, "rb") as source:
        text = decode_bytes(source.read(), "mbcs" if os.name == "nt" else "cp1252")
    # Get-Content strips each CR/LF terminator without dropping empty lines.
    lines = re.split(r"\r\n|\r|\n", text) if text else []
    if text.endswith(("\r", "\n")):
        lines.pop()
    return Counter(line.lower() for line in lines)


def _merge(arguments):
    path = as_path(arguments.get("path"), "path")
    content = as_string(arguments.get("content"), "content")
    comparison = as_string(arguments.get("compare_to"), "compare_to")
    if not path and not content:
        raise ValueError(
            "Missing required arguments: path or content. At lease one must be provided."
        )
    if path and content:
        raise ValueError("Extra arguments: path or content. Only one must be provided.")
    if as_bool(arguments.get("_ansible_check_mode", False), "_ansible_check_mode"):
        return {
            "changed": False,
            "skipped": True,
            "msg": "win_regmerge does not support check mode",
        }
    executable = os.path.join(
        os.environ.get("SystemRoot", r"C:\Windows"), "System32", "reg.exe"
    )
    if not os.path.isfile(executable):
        raise ValueError(
            "reg.exe not found at expected location '{0}'".format(executable)
        )
    result = {"changed": False, "compared": False}
    with tempfile.TemporaryDirectory(prefix="legacy-regmerge-") as temporary:
        if content:
            path = os.path.join(temporary, "content.reg")
            normalized = re.sub(r"\r\n|\r|\n", "\r\n", content)
            with open(path, "wb") as staged:
                staged.write(
                    codecs.BOM_UTF16_LE + (normalized + "\r\n").encode("utf-16-le")
                )
        if comparison and _key_exists(comparison):
            exported = os.path.join(temporary, "export.reg")
            expanded = "\\".join(_comparison_key(comparison))
            command = _run_reg(executable, ["EXPORT", expanded, exported])
            if command["rc"]:
                result.update(command)
                result.update(
                    failed=True, msg="error exporting registry '{0}'".format(expanded)
                )
                return result
            reference, actual = _lines(path), _lines(exported)
            differences = sum((reference - actual).values()) + sum(
                (actual - reference).values()
            )
            result["difference_count"] = differences
            result["compared"] = True
            if not result["difference_count"]:
                return result
        elif comparison:
            result["compare_to_key_found"] = False
        command = _run_reg(executable, ["IMPORT", path])
        if command["rc"]:
            result.update(command)
            result.update(
                failed=True,
                msg="error importing registry values from '{0}'".format(path),
            )
            return result
        result["changed"] = True
    return result


def main():
    """Read a WANT_JSON request and import native registry contents."""
    run_module(
        lambda: _merge(
            read_arguments(
                ("path", "content", "compare_to"),
                "sustainablelobster.legacy_community_windows.win_regmerge",
                allow_unknown=True,
            )
        )
    )


if __name__ == "__main__":
    main()
