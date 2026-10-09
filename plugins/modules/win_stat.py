#!/usr/bin/python
# -*- coding: utf-8 -*-
# Copyright 2026 Joe Lustri
# SPDX-License-Identifier: GPL-3.0-or-later

"""Inspect Windows filesystem entries through native APIs."""

# WANT_JSON

import ntpath

# The action stages these Python 3.4-compatible helpers beside the payload.
import legacy_windows_link as links  # pylint: disable=import-error
import legacy_windows_stat as filesystem  # pylint: disable=import-error
from legacy_windows_module import (  # pylint: disable=import-error
    DOTNET_WHITESPACE,
    as_bool,
    as_path,
    as_string,
    read_arguments,
    run_module,
)

DOCUMENTATION = r"""
---
module: win_stat
short_description: Inspect Windows files, directories, and links
version_added: '1.0.0'
description:
  - Returns filesystem metadata and optionally computes file checksums and directory sizes.
  - Uses Python 3.4.4 and native Windows APIs.
options:
  path:
    description: Literal Windows path to inspect. Both slash styles are accepted.
    type: path
    required: true
    aliases: [dest, name]
  get_checksum:
    description: Compute a checksum when the entry is a file.
    type: bool
    default: true
  get_size:
    description: Return file length or the sum of files beneath a directory.
    type: bool
    default: true
  checksum_algorithm:
    description:
      - Hash algorithm to use for O(get_checksum).
      - Fails if the native Windows crypto provider cannot use the requested algorithm.
    type: str
    default: sha1
    choices: [md5, sha1, sha256, sha384, sha512]
  follow:
    description: Follow symbolic links and junctions until reaching the final entry.
    type: bool
    default: false
attributes:
  check_mode:
    support: full
    description: Reads the same metadata as a normal invocation and reports no changes.
  diff_mode:
    support: none
notes:
  - A missing or inaccessible initial entry returns RV(stat.exists=false).
  - Directory sizes include hidden files and files reached through directory links.
  - A directory traversal failure returns a size of zero, following the upstream contract.
  - Checksum read failures fail the task; O(get_checksum=false) permits metadata-only inspection.
  - Hard-link name enumeration requires Windows Vista or Windows Server 2008 or newer.
  - On older systems, file link inspection warns and retains RV(stat.nlink=1) and an empty RV(stat.hlnk_targets).
author:
  - Joe Lustri
"""

EXAMPLES = r"""
- name: Inspect a configuration file
  sustainablelobster.legacy_windows.win_stat:
    path: C:\Application\settings.ini
  register: configuration

- name: Compute a SHA-256 checksum
  sustainablelobster.legacy_windows.win_stat:
    path: C:\Application\archive.zip
    checksum_algorithm: sha256

- name: Inspect a directory without traversing its contents
  sustainablelobster.legacy_windows.win_stat:
    path: C:\Application\logs
    get_size: false
"""

RETURN = r"""
stat:
  description: Metadata for the inspected entry. An absent entry contains only C(exists).
  returned: success
  type: complex
  contains:
    exists:
      description: Whether the initial entry could be found and inspected.
      type: bool
      returned: always
    attributes:
      description: Comma-separated Windows attribute names, or a numeric value for unknown bits.
      type: str
      returned: entry exists
    creationtime:
      description: Creation timestamp in seconds since 1970-01-01 UTC.
      type: float
      returned: entry exists
    lastaccesstime:
      description: Last-access timestamp in seconds since 1970-01-01 UTC.
      type: float
      returned: entry exists
    lastwritetime:
      description: Last-write timestamp in seconds since 1970-01-01 UTC.
      type: float
      returned: entry exists
    path:
      description: Absolute path of the entry, after resolving links when requested.
      type: str
      returned: entry exists
    filename:
      description: Final file or directory name. A drive root retains its root path.
      type: str
      returned: entry exists
    extension:
      description: File extension with its leading dot, or an empty string when absent.
      type: str
      returned: entry exists and is not a directory
    owner:
      description: Windows account name, owner-only SDDL for an unmapped account, or null on lookup failure.
      type: str
      returned: entry exists
    isarchive:
      description: Whether the attribute names include Archive.
      type: bool
      returned: entry exists
    isdir:
      description: Whether the entry has the Directory attribute.
      type: bool
      returned: entry exists
    ishidden:
      description: Whether the attribute names include Hidden.
      type: bool
      returned: entry exists
    isjunction:
      description: Whether link inspection identified a directory junction.
      type: bool
      returned: entry exists
    islnk:
      description: Whether link inspection identified a symbolic link.
      type: bool
      returned: entry exists
    isreadonly:
      description: Whether the attribute names include ReadOnly.
      type: bool
      returned: entry exists
    isreg:
      description: Whether the entry is a file and was not classified as a symbolic link or junction.
      type: bool
      returned: entry exists
    isshared:
      description: Whether one or more local shares name this directory.
      type: bool
      returned: entry exists
    sharename:
      description: Matching share name, or a list of names when more than one share matches.
      type: raw
      returned: shared directory
    nlink:
      description: Number of enumerated hard-link names. Defaults to one when enumeration is unavailable.
      type: int
      returned: entry exists
    hlnk_targets:
      description: Other enumerated hard-link paths, excluding this entry's path.
      type: list
      elements: str
      returned: entry exists
    lnk_type:
      description: The value C(hard) when multiple hard-link names were enumerated.
      type: str
      returned: hard link
    lnk_target:
      description: Link target spelling, retaining a relative target when present.
      type: str
      returned: symbolic link or junction
    lnk_source:
      description: Link target with a relative spelling resolved against the link's parent.
      type: str
      returned: symbolic link or junction
    size:
      description: File length or recursively calculated directory size, in bytes.
      type: int
      returned: entry exists and get_size is true
    checksum:
      description: Lowercase hexadecimal digest computed using the requested algorithm.
      type: str
      returned: file exists and get_checksum is true
"""

_MODULE_NAME = "sustainablelobster.legacy_windows.win_stat"
_PARAMETERS = (
    "path",
    "dest",
    "name",
    "get_checksum",
    "get_size",
    "checksum_algorithm",
    "follow",
)
_ALGORITHMS = ("md5", "sha1", "sha256", "sha384", "sha512")


def _parameters(arguments):
    supplied = [
        arguments[alias] for alias in ("path", "dest", "name") if alias in arguments
    ]
    if not supplied:
        raise ValueError("missing required arguments: path")
    path = as_path(supplied[-1], "path")
    if path is not None and not path.strip(DOTNET_WHITESPACE):
        raise ValueError("path must not be empty or contain only whitespace.")
    algorithm = as_string(
        arguments.get("checksum_algorithm", "sha1"), "checksum_algorithm"
    )
    if algorithm is not None:
        algorithm = algorithm.lower()
        if algorithm not in _ALGORITHMS:
            raise ValueError(
                "checksum_algorithm must be one of: " + ", ".join(_ALGORITHMS) + "."
            )
    parameters = {"path": path, "checksum_algorithm": algorithm}
    for name, default in (
        ("get_checksum", True),
        ("get_size", True),
        ("follow", False),
    ):
        value = arguments.get(name, default)
        parameters[name] = as_bool(value, name) if value is not None else None
    return parameters


def _link_source(path, link):
    target = link["target"]
    if not link["relative"]:
        return target
    # A rooted second operand replaces the first in the upstream path combine.
    combined = (
        target
        if ntpath.splitdrive(target)[0] or target.startswith(("/", "\\"))
        else ntpath.join(ntpath.dirname(path), target)
    )
    return filesystem.full_path(combined)


def _entry(path, follow, warnings):
    info = filesystem.file_info(path)
    if info is None:
        return None, None, path
    path = filesystem.full_path(path)
    link = None
    try:
        link = links.get_link_info(path)
    except (OSError, ValueError, NotImplementedError) as error:
        warnings.append("Failed to check/get link info for file: " + str(error))
    if follow and link is not None and link["type"] in ("symbolic", "junction"):
        return _entry(_link_source(path, link), True, warnings)
    return info, link, path


def _metadata(path, info):
    attributes = filesystem.attribute_names(info["attributes"])
    names = attributes.split(", ")
    is_directory = bool(info["attributes"] & 16)
    filename = ntpath.basename(path.rstrip("\\/"))
    if not filename or filename == ntpath.splitdrive(path)[0]:
        filename = path
    stat = {
        "exists": True,
        "attributes": attributes,
        "path": path,
        "filename": filename,
        "isarchive": "Archive" in names,
        "ishidden": "Hidden" in names,
        "isreadonly": "ReadOnly" in names,
        "isdir": is_directory,
        "isreg": not is_directory,
        "islnk": False,
        "isjunction": False,
        "isshared": False,
        "nlink": 1,
        "hlnk_targets": [],
        "owner": None,
    }
    for field, native_field in (
        ("creationtime", "creation_time"),
        ("lastaccesstime", "access_time"),
        ("lastwritetime", "modification_time"),
    ):
        stat[field] = float(info[native_field] - 116444736000000000) * 1e-7
    try:
        stat["owner"] = filesystem.owner(path)
    except (OSError, ValueError):
        pass
    return stat


def _directory(stat, get_size, warnings):
    try:
        names = filesystem.shares(stat["path"])
        if names:
            stat["isshared"] = True
            stat["sharename"] = names[0] if len(names) == 1 else names
    except (OSError, ValueError) as error:
        warnings.append(
            "Failed to check share info for '{0}': {1}".format(stat["path"], error)
        )
    if get_size:
        try:
            stat["size"] = filesystem.directory_size(stat["path"])
        except (OSError, ValueError):
            stat["size"] = 0


def _classify_link(stat, link):
    if link["type"] == "hard":
        stat["lnk_type"] = "hard"
        stat["nlink"] = len(link["target"])
        stat["hlnk_targets"] = [
            target
            for target in link["target"]
            if target.lower() != stat["path"].lower()
        ]
    else:
        stat["islnk"] = link["type"] == "symbolic"
        stat["isjunction"] = link["type"] == "junction"
        stat["isreg"] = False
        stat["lnk_target"] = link["target"]
        stat["lnk_source"] = _link_source(stat["path"], link)


def _inspect(parameters):
    result = {"changed": False, "stat": {"exists": False}}
    warnings = []
    try:
        path = parameters["path"]
        if path is None:
            raise ValueError("path must not be null.")
        links.enable_backup_privilege()
        info, link, resolved = _entry(path, parameters["follow"], warnings)
        if info is not None:
            stat = _metadata(resolved, info)
            if stat["isdir"]:
                _directory(stat, parameters["get_size"], warnings)
            else:
                filename = stat["filename"]
                dot = filename.rfind(".")
                stat["extension"] = (
                    filename[dot:] if 0 <= dot < len(filename) - 1 else ""
                )
                if parameters["get_checksum"]:
                    try:
                        stat["checksum"] = filesystem.checksum(
                            path, parameters["checksum_algorithm"]
                        )
                    except (OSError, ValueError) as error:
                        raise ValueError(
                            "Failed to get hash of file, set get_checksum to False "
                            "to ignore this error: " + str(error)
                        ) from error
                if parameters["get_size"]:
                    stat["size"] = info["size"]
            if link is not None:
                _classify_link(stat, link)
            result["stat"] = stat
    except (OSError, ValueError, NotImplementedError) as error:
        result.update({"failed": True, "msg": str(error)})
    if warnings:
        result["warnings"] = warnings
    return result


def _execute():
    arguments = read_arguments(_PARAMETERS, _MODULE_NAME)
    return _inspect(_parameters(arguments))


def main():
    """Read Ansible arguments and emit a filesystem inspection result.

    :raises SystemExit: After reporting success or failure as JSON.
    """
    run_module(_execute)


if __name__ == "__main__":
    main()
