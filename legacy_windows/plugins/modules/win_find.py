#!/usr/bin/python
# -*- coding: utf-8 -*-
# Copyright 2026 sustainablelobster
# SPDX-License-Identifier: GPL-3.0-or-later

"""Search Windows directories with Python 3.4.4 and native filesystem APIs."""

# WANT_JSON

import ntpath
import re
from functools import cmp_to_key

# The action stages these Python 3.4-compatible helpers beside the payload.
import legacy_windows_find_match as matching  # pylint: disable=import-error
import legacy_windows_link as links  # pylint: disable=import-error
import legacy_windows_stat as filesystem  # pylint: disable=import-error
import legacy_windows_time as timestamps  # pylint: disable=import-error
from legacy_windows_module import (  # pylint: disable=import-error
    DOTNET_WHITESPACE,
    as_bool,
    as_string,
    read_arguments,
    run_module,
)

# Each module's help must repeat the shared regex engine's limitations.
# Keeping that warning here is clearer than making readers chase another module.
# pylint: disable=duplicate-code
DOCUMENTATION = r"""
---
module: win_find
short_description: Find Windows filesystem entries
version_added: '1.0.0'
description:
  - Searches directories and returns metadata for entries satisfying all filters.
  - Uses Python 3.4.4 or newer and native Windows APIs.
options:
  paths:
    description:
      - Directories to search. Use literal absolute Windows filesystem paths.
      - Use O(patterns) for filename matching, not wildcard characters in a search root.
    type: list
    elements: str
    required: true
  age:
    description:
      - Minimum age, in seconds or with a suffix C(s), C(m), C(h), C(d), or C(w).
      - Negative values select entries no older than the absolute age.
    type: str
  age_stamp:
    description: Timestamp used for the age filter.
    type: str
    default: mtime
    choices: [mtime, ctime, atime]
  file_type:
    description: Kind of entry to return.
    type: str
    default: file
    choices: [file, directory, any]
  follow:
    description: Recurse through directory symbolic links and junctions.
    type: bool
    default: false
  hidden:
    description: Include hidden entries in results. Hidden directories are still traversed without this option.
    type: bool
    default: false
  patterns:
    description:
      - Match the basename against any of these patterns.
      - Defaults to no name filter. An empty list matches no entries.
    type: list
    elements: str
    aliases: [regex, regexp]
  recurse:
    description: Search child directories as well as immediate children.
    type: bool
    default: false
  depth:
    description:
      - Maximum directory depth when recursing. One searches immediate children only.
      - Zero, negative values, and an omitted value do not impose a depth limit.
    type: int
  size:
    description:
      - Minimum file size in bytes, optionally suffixed with C(b), C(k), C(m), C(g), or C(t).
      - Negative values select sizes at most the absolute value. Multipliers are powers of 1024.
      - The pinned upstream release compares directories using a scalar length of one.
    type: str
  use_regex:
    description: Use Python regular-expression searches instead of PowerShell-style wildcards.
    type: bool
    default: false
  case_sensitive:
    description: Make regular-expression matching case-sensitive. Wildcards remain case-insensitive.
    type: bool
    default: false
  get_checksum:
    description: Compute a checksum for each matching file. Read failures leave the checksum null.
    type: bool
    default: true
  checksum_algorithm:
    description: Algorithm used for file checksums.
    type: str
    default: sha1
    choices: [md5, sha1, sha256, sha384, sha512]
attributes:
  check_mode:
    support: full
    description: Performs the same read-only search and reports no changes.
  diff_mode:
    support: none
notes:
  - Regex matching uses Python's C(re) engine with limited .NET syntax translations.
  - Matching operates on UTF-16 code units; C(.) consumes one surrogate of a supplementary character such as an emoji.
  - Unicode general-category escapes, word/digit/space classes and word boundaries use fixed Unicode 8 data.
  - Case-insensitive matching uses Python's rules and can differ from .NET culture-dependent matching.
  - Atomic or balancing groups, class subtraction, scoped inline options and variable-width lookbehind are unsupported.
  - Inline options must appear at the pattern prefix; later options fail instead of changing the scope of earlier matches.
  - Numeric references combined with .NET named groups and Unicode block escapes are unsupported; general-category escapes are supported.
  - C(\Z) matches at strict end or before a final LF; C(\z) matches only at strict end.
  - Wildcard bracket ranges use the reference framework's fixed casing table,
    implemented in Python.
  - Native Windows casing and sorting tables vary by Windows version.
  - Timestamps are seconds since a local-wall-clock 1970 epoch, matching the pinned upstream release.
  - Overlapping roots are deduplicated by path spelling, not filesystem identity.
  - Use a finite O(depth) when following directory links that may form cycles.
  - PowerShell provider paths and relative-path resolution are not verified.
  - With C(async) and C(poll=0), retrieve results using M(sustainablelobster.legacy_windows.async_status).
  - Automatic polling with C(poll>0) requires the installed collection's
    C(plugins/action/_native_async_polling) directory on the controller action plugin path.
    Set C(action_plugins) in the project's C(ansible.cfg); installation alone does not activate the adapter.
author:
  - sustainablelobster
"""

# pylint: enable=duplicate-code
EXAMPLES = r"""
- name: Find configuration files recursively
  sustainablelobster.legacy_windows.win_find:
    paths: [C:\Application]
    patterns: ['*.ini', '*.conf']
    recurse: true

- name: Find large, old log files without reading their contents
  sustainablelobster.legacy_windows.win_find:
    paths: [C:\Logs]
    age: 7d
    size: 10m
    get_checksum: false
"""

RETURN = r"""
examined:
  description: Number of unique child paths examined before applying filters.
  type: int
  returned: success
matched:
  description: Number of matching entries.
  type: int
  returned: success
files:
  description: Matching entries sorted by full path using native case-insensitive comparison.
  type: list
  elements: dict
  returned: success
  contains:
    path:
      description: Absolute entry path.
      type: str
    filename:
      description: Entry basename.
      type: str
    exists:
      description: Always true for a returned entry.
      type: bool
    attributes:
      description: Windows attribute names, or a numeric value for unknown bits.
      type: str
    creationtime:
      description: Creation time in seconds since the local-wall-clock 1970 epoch.
      type: float
    lastaccesstime:
      description: Access time in seconds since the local-wall-clock 1970 epoch.
      type: float
    lastwritetime:
      description: Write time in seconds since the local-wall-clock 1970 epoch.
      type: float
    owner:
      description: Account name or owner-only SDDL; null when lookup fails.
      type: str
    extension:
      description: File extension including its dot, empty if absent, or null for directories.
      type: str
    size:
      description: File length in bytes, or null for directories.
      type: int
    checksum:
      description: Hexadecimal file digest, or null when disabled, unavailable, or a directory.
      type: str
    isarchive:
      description: Whether the Archive attribute is set.
      type: bool
    isdir:
      description: Whether the Directory attribute is set.
      type: bool
    ishidden:
      description: Whether the Hidden attribute is set.
      type: bool
    isreadonly:
      description: Whether the ReadOnly attribute is set.
      type: bool
    isreg:
      description: Whether the entry is a file not classified as a symbolic link or junction.
      type: bool
    isshared:
      description: Whether a local share names this directory.
      type: bool
    sharename:
      description: Matching share name, list of names, or null if not shared.
      type: raw
    islnk:
      description: Whether the entry is a symbolic link.
      type: bool
    isjunction:
      description: Whether the entry is a junction.
      type: bool
    nlink:
      description: Number of hard links, or one for other entries.
      type: int
    hlnk_targets:
      description: Empty for ordinary entries; a single null for hard links, preserving the pinned upstream result.
      type: list
      elements: raw
    lnk_source:
      description: Resolved symbolic-link or junction target, otherwise null.
      type: str
    lnk_target:
      description: Symbolic-link or junction target spelling, otherwise null.
      type: str
"""

_MODULE_NAME = "sustainablelobster.legacy_windows.win_find"
_PARAMETERS = (
    "paths",
    "age",
    "age_stamp",
    "file_type",
    "follow",
    "hidden",
    "patterns",
    "regex",
    "regexp",
    "recurse",
    "size",
    "use_regex",
    "get_checksum",
    "checksum_algorithm",
    "depth",
    "case_sensitive",
)
_TIME_FIELDS = {
    "ctime": "creation_time",
    "atime": "access_time",
    "mtime": "modification_time",
}


def _string_list(value, name):
    if value is None:
        return None
    if isinstance(value, str):
        value = [part.strip(DOTNET_WHITESPACE) for part in value.split(",")]
    elif (
        isinstance(value, int)
        and not isinstance(value, bool)
        and -(2**63) <= value < 2**63
    ):
        value = [value]
    if not isinstance(value, list):
        raise ValueError("Expected a list for " + name + ".")
    if any(item is None for item in value):
        raise ValueError(name + " must not contain null entries.")
    return [as_string(item, name) for item in value]


def _integer(value, name, bits):
    text = as_string(value, name).strip(DOTNET_WHITESPACE)
    if not re.match(r"^[+-]?[0-9]+$", text):
        raise ValueError("Expected an integer for " + name + ".")
    number = int(text)
    if not -(2 ** (bits - 1)) <= number < 2 ** (bits - 1):
        raise ValueError(name + " is outside the signed " + str(bits) + "-bit range.")
    return number


def _parameters(arguments):
    if "paths" not in arguments:
        raise ValueError("missing required arguments: paths")
    values = {"paths": _string_list(arguments["paths"], "paths") or []}
    patterns = None
    for name in ("patterns", "regex", "regexp"):
        if name in arguments:
            patterns = arguments[name]
    values["patterns"] = _string_list(patterns, "patterns")
    for name, default, choices in (
        ("age_stamp", "mtime", ("mtime", "ctime", "atime")),
        ("file_type", "file", ("file", "directory", "any")),
        ("checksum_algorithm", "sha1", ("md5", "sha1", "sha256", "sha384", "sha512")),
    ):
        value = as_string(arguments.get(name, default), name)
        if value is not None:
            value = value.lower()
            if value not in choices:
                raise ValueError(name + " must be one of: " + ", ".join(choices) + ".")
        values[name] = value
    for name in (
        "follow",
        "hidden",
        "recurse",
        "use_regex",
        "case_sensitive",
        "get_checksum",
    ):
        value = arguments.get(name, name == "get_checksum")
        values[name] = as_bool(value, name) if value is not None else False
    for name in ("age", "size"):
        values[name] = as_string(arguments.get(name), name)
    depth = arguments.get("depth")
    values["depth"] = _integer(depth, "depth", 32) if depth is not None else 0
    return values


def _quantity(value, name, units):
    if value is None:
        return None
    match = re.match(r"^(-?\d+)([" + "".join(units) + r"])?$", value, re.IGNORECASE)
    if match is None:
        return {"failed": True, "msg": "Invalid " + name + " pattern specified"}
    amount = _integer(match.group(1), name, 64)
    amount *= units.get((match.group(2) or "").lower(), 1)
    if not -(2**63) <= amount < 2**63:
        raise ValueError(name + " is outside the signed 64-bit range.")
    return amount


def _accepts(info, options):
    directory = bool(info["attributes"] & 16)
    type_match = options["file_type"] == "any" or options["file_type"] == (
        "directory" if directory else "file"
    )
    hidden_match = options["hidden"] or not info["attributes"] & 2
    pattern_match = options["patterns"] is None or matching.matches(
        info["name"],
        options["patterns"],
        options["use_regex"],
        options["case_sensitive"],
    )
    length = 1 if directory else info["size"]
    size = options["size"]
    size_match = size is None or (length >= size if size >= 0 else length <= -size)
    age = options["age"]
    age_match = True
    if age is not None:
        field = _TIME_FIELDS.get(options["age_stamp"])
        actual = timestamps.file_time_to_local_ticks(info[field]) if field else 0
        age_match = actual <= age if age >= 0 else actual >= -age
    return type_match and hidden_match and pattern_match and size_match and age_match


def _link_metadata(path, metadata):
    try:
        link = links.get_link_info(path)
    except NotImplementedError:
        # XP and Server 2003 can count hard links but cannot enumerate their names.
        count = filesystem.hardlink_count(path)
        metadata["nlink"] = count
        metadata["hlnk_targets"] = [None] if count > 1 else []
        return
    if link is None:
        return
    if link["type"] == "hard":
        metadata["nlink"] = len(link["target"])
        # ansible.windows 3.8.0 reads the wrong object for targets, yielding [null].
        metadata["hlnk_targets"] = [None]
        return
    metadata["islnk"] = link["type"] == "symbolic"
    metadata["isjunction"] = link["type"] == "junction"
    metadata["isreg"] = False
    target = link["target"]
    metadata["lnk_target"] = target
    if link["relative"]:
        if not ntpath.splitdrive(target)[0] and not target.startswith(("/", "\\")):
            target = ntpath.join(ntpath.dirname(path), target)
        target = filesystem.full_path(target)
    metadata["lnk_source"] = target


def _metadata(path, info, options, warnings):
    attributes = info["attributes"]
    directory = bool(attributes & 16)
    result = {
        "path": path,
        "filename": info["name"],
        "exists": True,
        "attributes": filesystem.attribute_names(attributes),
        "owner": None,
        "isarchive": bool(attributes & 32),
        "isdir": directory,
        "ishidden": bool(attributes & 2),
        "isreadonly": bool(attributes & 1),
        "isreg": not directory,
        "islnk": False,
        "isjunction": False,
        "isshared": False,
        "sharename": None,
        "extension": None,
        "size": None,
        "checksum": None,
        "nlink": 1,
        "hlnk_targets": [],
        "lnk_source": None,
        "lnk_target": None,
    }
    for field, native in (
        ("creationtime", "creation_time"),
        ("lastaccesstime", "access_time"),
        ("lastwritetime", "modification_time"),
    ):
        value = (
            float(
                timestamps.file_time_to_local_ticks(info[native]) - 621355968000000000
            )
            * 1e-7
        )
        # Released JSON serializes an integral TotalSeconds as an integer;
        # fractional values keep the existing conversion and precision.
        result[field] = int(value) if value.is_integer() else value
    try:
        result["owner"] = filesystem.owner(path)
    except (OSError, ValueError) as error:
        warnings.append("Failed to get the owner for '{0}': {1}".format(path, error))
    if directory:
        try:
            names = filesystem.shares(path)
            if names:
                result["isshared"] = True
                result["sharename"] = names[0] if len(names) == 1 else names
        except (OSError, ValueError) as error:
            warnings.append(
                "Failed to check share info for '{0}': {1}".format(path, error)
            )
    else:
        dot = info["name"].rfind(".")
        result["extension"] = (
            info["name"][dot:] if 0 <= dot < len(info["name"]) - 1 else ""
        )
        result["size"] = info["size"]
        if options["get_checksum"]:
            try:
                result["checksum"] = filesystem.checksum(
                    path, options["checksum_algorithm"]
                )
            except (OSError, ValueError):
                pass
    _link_metadata(path, result)
    return result


def _search(path, depth, options, checked, result):
    info = filesystem.file_info(path)
    if info is None:
        result["warnings"].append(
            "Argument path '{0}' does not exist or is not accessible, skipping".format(
                path
            )
        )
        return
    if not info["attributes"] & 16:
        result["warnings"].append(
            "Argument path '{0}' is a file not a directory, skipping".format(path)
        )
        return
    try:
        children = filesystem.directory_entries(path)
    except OSError as error:
        if getattr(error, "winerror", None) in (2, 3, 5):
            return
        raise
    for child in children:
        child_path = ntpath.join(path, child["name"])
        if child["attributes"] & 16 and options["recurse"] and depth != 1:
            if options["follow"] or not child["attributes"] & 1024:
                if depth == -(2**31):
                    raise ValueError(
                        "Recursion depth is outside the signed 32-bit range."
                    )
                _search(child_path, depth - 1, options, checked, result)
        key = matching.path_key(child_path)
        if key in checked:
            continue
        checked.add(key)
        result["examined"] += 1
        if _accepts(child, options):
            result["files"].append(
                _metadata(child_path, child, options, result["warnings"])
            )


def _find(options):
    options = dict(options)
    result = {
        "changed": False,
        "examined": 0,
        "matched": 0,
        "files": [],
        "warnings": [],
    }
    for name, units in (
        ("age", {"s": 1, "m": 60, "h": 3600, "d": 86400, "w": 604800}),
        ("size", {"b": 1, "k": 1024, "m": 1024**2, "g": 1024**3, "t": 1024**4}),
    ):
        quantity = _quantity(options[name], name, units)
        if isinstance(quantity, dict):
            result.update(quantity)
            del result["warnings"]
            return result
        options[name] = quantity
    if options["age"] is not None:
        threshold = timestamps.current_local_ticks() - abs(options["age"]) * 10000000
        if not 0 <= threshold <= 3155378975999999999:
            raise ValueError("age produces a date outside the supported range.")
        options["age"] = threshold if options["age"] >= 0 else -threshold
    links.enable_backup_privilege()
    checked = set()
    for path in options["paths"]:
        if not path:
            raise ValueError("paths must not contain an empty path.")
        # Roots are strings, not path-typed arguments: validate them without
        # expanding environment variables. The extended-length prefix retains
        # the measured native behavior of the upstream DirectoryInfo constructor.
        if not path.startswith("\\\\?\\") and any(
            ord(character) < 32 or character in '<>"|?*' for character in path
        ):
            raise ValueError("Invalid Windows path characters in paths.")
        _search(filesystem.full_path(path), options["depth"], options, checked, result)
    result["files"].sort(
        key=cmp_to_key(
            lambda left, right: matching.compare_paths(left["path"], right["path"])
        )
    )
    result["matched"] = len(result["files"])
    if not result["warnings"]:
        del result["warnings"]
    return result


def _execute():
    return _find(_parameters(read_arguments(_PARAMETERS, _MODULE_NAME)))


def main():
    """Read Ansible arguments and emit the read-only directory search result.

    :raises SystemExit: After reporting success or failure as JSON.
    """
    run_module(_execute)


if __name__ == "__main__":
    main()
