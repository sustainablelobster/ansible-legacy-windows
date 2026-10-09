#!/usr/bin/python
# -*- coding: utf-8 -*-
# Copyright 2026 Joe Lustri
# SPDX-License-Identifier: GPL-3.0-or-later

"""Read a Windows file and return its bytes as an unchanged base64 response."""

# WANT_JSON

import base64
import ctypes
import os

# The action plugin stages this Python 3.4-compatible helper beside the payload.
from legacy_windows_module import (  # pylint: disable=import-error
    as_path,
    read_arguments,
    run_module,
)

DOCUMENTATION = r"""
---
module: slurp
short_description: Read a Windows file as base64
version_added: '1.0.0'
description:
  - Reads a file on the Windows target and returns its complete contents as base64.
  - Reads bytes without interpreting text encodings or changing line endings.
  - The target requires Python 3.4.4 or newer.
options:
  src:
    description:
      - Path of the file to read on the target.
      - Directories and wildcard patterns are not accepted.
      - Windows percent-delimited environment variables are expanded.
      - When both O(src) and its alias are supplied, O(src) takes precedence.
      - A path containing only ASCII spaces resolves to the current directory
        and is rejected as a directory; Unicode spaces remain literal.
    type: path
    required: true
    aliases: [path]
attributes:
  check_mode:
    support: full
    description: Reads and returns the same file contents without reporting a change.
  diff_mode:
    support: none
notes:
  - The whole file and encoded response are held in memory during execution.
  - Allow additional memory for base64 encoding and the JSON response.
  - The read handle allows other readers but excludes concurrent writers.
author:
  - Joe Lustri
"""

EXAMPLES = r"""
- name: Read a Windows configuration file
  sustainablelobster.legacy_windows.slurp:
    src: C:\Program Files\Example\settings.ini
  register: configuration

- name: Read a file using the path alias
  sustainablelobster.legacy_windows.slurp:
    path: C:\Windows\win.ini
  register: configuration
"""

RETURN = r"""
content:
  description: File bytes encoded as one base64 string without added line breaks.
  returned: success
  type: str
encoding:
  description: Identifies the encoding of C(content); always C(base64).
  returned: success
  type: str
  sample: base64
"""


def _source(arguments):
    if "src" in arguments:
        name = "src"
    elif "path" in arguments:
        name = "path"
    else:
        raise ValueError("Missing required argument: src.")
    source = as_path(arguments[name], name)
    if source is None or not source:
        raise ValueError("Specify a nonempty file path for " + name + ".")
    return source


def _read_bytes(source):
    if os.name != "nt":
        raise ValueError("slurp execution requires a Windows target.")
    # The CRT module is only available from a Windows Python installation.
    import msvcrt  # pylint: disable=import-outside-toplevel,import-error

    # Windows-only O_BINARY keeps the CRT from interpreting control bytes.
    read_flags = os.O_RDONLY | os.O_BINARY  # pylint: disable=no-member
    kernel = ctypes.WinDLL("kernel32", use_last_error=True)
    kernel.CreateFileW.argtypes = [
        ctypes.c_wchar_p,
        ctypes.c_ulong,
        ctypes.c_ulong,
        ctypes.c_void_p,
        ctypes.c_ulong,
        ctypes.c_ulong,
        ctypes.c_void_p,
    ]
    kernel.CreateFileW.restype = ctypes.c_void_p
    kernel.CloseHandle.argtypes = [ctypes.c_void_p]
    kernel.CloseHandle.restype = ctypes.c_int
    # Match ReadAllBytes: GENERIC_READ, FILE_SHARE_READ, OPEN_EXISTING.
    handle = kernel.CreateFileW(source, 0x80000000, 1, None, 3, 0x80, None)
    if handle == ctypes.c_void_p(-1).value:
        raise ctypes.WinError(ctypes.get_last_error())
    try:
        descriptor = msvcrt.open_osfhandle(handle, read_flags)
    except Exception:
        kernel.CloseHandle(handle)
        raise
    try:
        source_file = os.fdopen(descriptor, "rb")
    except Exception:
        # CRT adoption transferred handle ownership to this descriptor.
        os.close(descriptor)
        raise
    with source_file:
        return source_file.read()


def _execute():
    arguments = read_arguments(
        ("src", "path"), "sustainablelobster.legacy_windows.slurp", allow_unknown=True
    )
    source = _source(arguments)
    # The released filesystem provider resolves ASCII-space-only input to the
    # current directory. Do not strip Unicode whitespace or ordinary paths.
    if not source.strip(" ") or os.path.isdir(source):
        raise ValueError("Path " + source + " is a directory")
    if not os.path.isfile(source):
        raise ValueError("Path " + source + " is not found")
    content = _read_bytes(source)
    return {
        "changed": False,
        "content": base64.b64encode(content).decode("ascii"),
        "encoding": "base64",
    }


def main():
    """Read the argument file and emit one Ansible JSON result.

    :raises SystemExit: After emitting the module result.
    """
    run_module(_execute)


if __name__ == "__main__":
    main()
