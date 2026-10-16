#!/usr/bin/python
# -*- coding: utf-8 -*-
# Copyright 2026 sustainablelobster
# Copyright: (c) 2015, Sam Liu <sam.liu@activenetwork.com>
# SPDX-License-Identifier: GPL-3.0-or-later

"""Read executable version resources through the native Windows version API."""

# WANT_JSON

import ctypes
import os

from legacy_windows_module import (  # pylint: disable=import-error
    as_path,
    read_arguments,
    run_module,
)

DOCUMENTATION = r"""
---
module: win_file_version
short_description: Get DLL or EXE file build version
description:
  - Get DLL or EXE file build version.
notes:
  - This module always returns no change, including in check mode.
  - Uses native version resources and does not require loading the executable.
options:
  path:
    description:
      - File to get version.
      - Always provide an absolute path.
    type: path
    required: true
seealso:
  - module: sustainablelobster.legacy_windows.win_file
author:
  - sustainablelobster
  - Sam Liu (@SamLiu79)
  - Mikhail Samodurov (@EasyMoney322)
"""

EXAMPLES = r"""
- name: Read the command interpreter's version
  sustainablelobster.legacy_community_windows.win_file_version:
    path: C:\Windows\System32\cmd.exe
  register: executable_version
"""

RETURN = r"""
win_file_version:
  description: Version resource information; all component values are strings.
  returned: success
  type: complex
  contains:
    file_build_part:
      description: File build number.
      type: str
    file_major_part:
      description: Major version number.
      type: str
    file_minor_part:
      description: Minor version number.
      type: str
    file_private_part:
      description: File private part number.
      type: str
    file_version:
      description: File version string from the version resource.
      type: str
    file_version_raw:
      description: Dot-separated numeric file version, which may differ from file_version.
      type: str
    path:
      description: Requested file path.
      type: str
    product_version:
      description: Product version string from the version resource.
      type: str
"""


def _library():
    library = ctypes.WinDLL("version", use_last_error=True)
    library.GetFileVersionInfoSizeW.argtypes = [ctypes.c_wchar_p, ctypes.c_void_p]
    library.GetFileVersionInfoSizeW.restype = ctypes.c_uint32
    library.GetFileVersionInfoW.argtypes = [
        ctypes.c_wchar_p,
        ctypes.c_uint32,
        ctypes.c_uint32,
        ctypes.c_void_p,
    ]
    library.GetFileVersionInfoW.restype = ctypes.c_int32
    library.VerQueryValueW.argtypes = [
        ctypes.c_void_p,
        ctypes.c_wchar_p,
        ctypes.POINTER(ctypes.c_void_p),
        ctypes.POINTER(ctypes.c_uint32),
    ]
    library.VerQueryValueW.restype = ctypes.c_int32
    return library


def _query(library, resource, name):
    pointer, size = ctypes.c_void_p(), ctypes.c_uint32()
    if not library.VerQueryValueW(
        resource, name, ctypes.byref(pointer), ctypes.byref(size)
    ):
        return None, 0
    return pointer, size.value


def _fields(library, resource):
    result = {
        "file_version": "",
        "product_version": "",
        "file_major_part": "0",
        "file_minor_part": "0",
        "file_build_part": "0",
        "file_private_part": "0",
        "file_version_raw": "0.0.0.0",
    }
    pointer, size = _query(library, resource, "\\")
    if pointer and size >= 52:
        values = ctypes.cast(pointer, ctypes.POINTER(ctypes.c_uint32))
        if values[0] != 0xFEEF04BD:
            raise OSError("The file version record has an invalid signature.")
        parts = (values[2] >> 16, values[2] & 65535, values[3] >> 16, values[3] & 65535)
        for name, value in zip(
            (
                "file_major_part",
                "file_minor_part",
                "file_build_part",
                "file_private_part",
            ),
            parts,
        ):
            result[name] = str(value)
        result["file_version_raw"] = ".".join(str(value) for value in parts)
    elif pointer:
        raise OSError("The file version record is truncated.")
    translations = []
    pointer, size = _query(library, resource, "\\VarFileInfo\\Translation")
    if pointer:
        values = ctypes.cast(pointer, ctypes.POINTER(ctypes.c_uint16))
        translations = [
            (values[index], values[index + 1]) for index in range(0, size // 2 - 1, 2)
        ]
    translations.extend(((0x0409, 0x04B0), (0x0409, 0x04E4), (0x0409, 0)))
    for language, codepage in translations:
        strings = {}
        for field, name in (
            ("file_version", "FileVersion"),
            ("product_version", "ProductVersion"),
        ):
            pointer, size = _query(
                library,
                resource,
                "\\StringFileInfo\\{0:04X}{1:04X}\\{2}".format(
                    language, codepage, name
                ),
            )
            strings[field] = (
                ctypes.wstring_at(pointer, size - 1) if pointer and size else ""
            )
        if strings["file_version"]:
            result.update(strings)
            break
    return result


def _inspect(arguments):
    path = as_path(arguments.get("path"), "path")
    if not path:
        raise ValueError("Missing required argument: path")
    if not os.path.isfile(path):
        raise ValueError(
            "Specified path {0} does not exist or is not a file.".format(path)
        )
    if os.path.splitext(path)[1].lower() not in (".exe", ".dll"):
        raise ValueError(
            "Specified path {0} is not a valid file type; must be DLL or EXE.".format(
                path
            )
        )
    library = _library()
    size = library.GetFileVersionInfoSizeW(path, None)
    resource = ctypes.create_string_buffer(size)
    if size and not library.GetFileVersionInfoW(path, 0, size, resource):
        raise ctypes.WinError(ctypes.get_last_error())
    result = (
        _fields(library, resource)
        if size
        else {
            "file_version": "",
            "product_version": "",
            "file_major_part": "0",
            "file_minor_part": "0",
            "file_build_part": "0",
            "file_private_part": "0",
            "file_version_raw": "0.0.0.0",
        }
    )
    result["path"] = path
    return {"changed": False, "win_file_version": result}


def main():
    """Read a WANT_JSON request and return the native version resource."""
    run_module(
        lambda: _inspect(
            read_arguments(
                ("path",),
                "sustainablelobster.legacy_community_windows.win_file_version",
                allow_unknown=True,
            )
        )
    )


if __name__ == "__main__":
    main()
