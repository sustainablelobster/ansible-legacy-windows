#!/usr/bin/python
# -*- coding: utf-8 -*-

# Copyright: (c) 2017, Liran Nisanov <lirannis@gmail.com>
# Copyright 2026 sustainablelobster
# SPDX-License-Identifier: GPL-3.0-or-later

"""Manage pagefile configuration through the installed native provider."""

# WANT_JSON

import os
import re

from legacy_community_windows_pagefile_native import (  # pylint: disable=import-error
    Pagefiles,
    registry_sizes,
)
from legacy_windows_module import (  # pylint: disable=import-error
    as_bool,
    as_string,
    read_arguments,
    run_module,
)

DOCUMENTATION = r"""
---
module: win_pagefile
short_description: Query or change pagefile configuration
description:
    - Query current pagefile configuration.
    - Enable/Disable AutomaticManagedPagefile.
    - Create new or override pagefile configuration.
options:
  drive:
    description:
      - The drive of the pagefile.
    type: str
  initial_size:
    description:
      - The initial size of the pagefile in megabytes.
    type: int
  maximum_size:
    description:
      - The maximum size of the pagefile in megabytes.
    type: int
  override:
    description:
      - Override the current pagefile on the drive.
    type: bool
    default: yes
  system_managed:
    description:
      - Configures current pagefile to be managed by the system.
    type: bool
    default: no
  automatic:
    description:
      - Configures AutomaticManagedPagefile for the entire system.
    type: bool
  remove_all:
    description:
      - Remove all pagefiles in the system, not including automatic managed.
    type: bool
    default: no
  test_path:
    description:
      - Use Test-Path on the drive to make sure the drive is accessible before creating the pagefile.
    type: bool
    default: yes
  state:
    description:
      - State of the pagefile.
    type: str
    choices: [ absent, present, query ]
    default: query
notes:
- Uses the installed Win32 pagefile provider; administrative permission to change pagefile settings is required.
- A provider without C(AutomaticManagedPagefile) returns null and a warning for that query field. Explicit changes to that unavailable setting fail before mutations.
- As in the released module, C(override=true) replaces an existing pagefile and reports changed each time. Use C(override=false) for idempotent fixed-size updates.
- C(override=false) preserves an existing system-managed pagefile rather than converting it to fixed sizes. Check mode predicts fixed-size updates without writing them.
- Pagefile configuration changes may require a restart before Windows changes the active paging files. The module does not restart Windows.
- There is difference between automatic managed pagefiles that configured once for the entire system and system managed pagefile that configured per pagefile.
- InitialSize 0 and MaximumSize 0 means the pagefile is managed by the system.
- Value out of range exception may be caused by several different issues, two common problems - No such drive, Pagefile size is too small.
- Setting a pagefile when AutomaticManagedPagefile is on will disable the AutomaticManagedPagefile.
author:
- sustainablelobster
- Liran Nisanov (@LiranNis)
"""

EXAMPLES = r"""
- name: Query pagefiles configuration
  sustainablelobster.legacy_community_windows.win_pagefile:

- name: Query C pagefile
  sustainablelobster.legacy_community_windows.win_pagefile:
    drive: C

- name: Set C pagefile, don't override if exists
  sustainablelobster.legacy_community_windows.win_pagefile:
    drive: C
    initial_size: 1024
    maximum_size: 1024
    override: false
    state: present

- name: Set C pagefile, override if exists
  sustainablelobster.legacy_community_windows.win_pagefile:
    drive: C
    initial_size: 1024
    maximum_size: 1024
    state: present

- name: Remove C pagefile
  sustainablelobster.legacy_community_windows.win_pagefile:
    drive: C
    state: absent

- name: >-
    Remove all current pagefiles, enable AutomaticManagedPagefile
    and query at the end
  sustainablelobster.legacy_community_windows.win_pagefile:
    remove_all: true
    automatic: true

- name: Remove all pagefiles disable AutomaticManagedPagefile and set C pagefile
  sustainablelobster.legacy_community_windows.win_pagefile:
    drive: C
    initial_size: 2048
    maximum_size: 2048
    remove_all: true
    automatic: false
    state: present

- name: Set D pagefile, override if exists
  sustainablelobster.legacy_community_windows.win_pagefile:
    drive: d
    initial_size: 1024
    maximum_size: 1024
    state: present
"""

RETURN = r"""
automatic_managed_pagefiles:
    description: Whether the pagefiles is automatically managed.
    returned: When state is query.
    type: bool
    sample: true
pagefiles:
    description: Contains caption, description, initial_size, maximum_size and name for each pagefile in the system.
    returned: When state is query.
    type: list
    sample:
      [{"caption": "c:\\ 'pagefile.sys'", "description": "'pagefile.sys' @ c:\\", "initial_size": 2048, "maximum_size": 2048, "name": "c:\\pagefile.sys"},
       {"caption": "d:\\ 'pagefile.sys'", "description": "'pagefile.sys' @ d:\\", "initial_size": 1024, "maximum_size": 1024, "name": "d:\\pagefile.sys"}]

"""


_PARAMETERS = (
    "drive",
    "initial_size",
    "maximum_size",
    "override",
    "system_managed",
    "automatic",
    "remove_all",
    "test_path",
    "state",
)


def _size(value, name):
    if value is None:
        return 0
    try:
        number = int(value)
    except (ValueError, TypeError) as error:
        raise ValueError(name + " must be an integer") from error
    if not 0 <= number <= 0x7FFFFFFF:
        raise ValueError(name + " must be between 0 and 2147483647 megabytes")
    return number


def _parameters(arguments):
    options = {
        "drive": as_string(arguments.get("drive"), "drive"),
        "state": as_string(arguments.get("state", "query"), "state"),
        "initial_size": _size(arguments.get("initial_size"), "initial_size"),
        "maximum_size": _size(arguments.get("maximum_size"), "maximum_size"),
        "automatic": (
            None
            if arguments.get("automatic") is None
            else as_bool(arguments["automatic"], "automatic")
        ),
    }
    for name, default in (
        ("override", True),
        ("system_managed", False),
        ("remove_all", False),
        ("test_path", True),
    ):
        options[name] = as_bool(arguments.get(name, default), name)
    if options["state"] not in ("query", "absent", "present"):
        raise ValueError("state must be absent, present or query")
    if options["drive"] is not None and not re.match(
        r"^[a-z]$", options["drive"], re.IGNORECASE
    ):
        raise ValueError("drive must be a single drive letter without a colon")
    if options["state"] == "present":
        if options["drive"] is None:
            raise ValueError("drive is required when state=present")
        if options["test_path"] and not os.path.isdir(options["drive"] + ":\\"):
            raise ValueError("Unable to access '{0}:' drive".format(options["drive"]))
    return options


def _selected(records, name):
    return next(
        (record for record in records if record["Name"].lower() == name.lower()), None
    )


def _write_sizes(provider, record, options):
    try:
        provider.set_sizes(record, options["initial_size"], options["maximum_size"])
    except OSError:
        # The released module removes the provider setting and updates
        # PagingFiles when that provider cannot persist a size change.
        provider.delete(record)
        registry_sizes(record["Name"], options["initial_size"], options["maximum_size"])


def _present(provider, options, check_mode, result):
    name = options["drive"] + ":\\pagefile.sys"
    existing = _selected(provider.records(), name)
    if existing is not None and options["override"]:
        result["changed"] = True
        if not check_mode:
            provider.delete(existing)
        existing = None
    if existing is None:
        result["changed"] = True
        if not check_mode:
            created = provider.create(name)
            if not options["system_managed"]:
                _write_sizes(provider, created, options)
    elif (
        not options["system_managed"]
        and (existing["InitialSize"], existing["MaximumSize"]) != (0, 0)
        and (existing["InitialSize"], existing["MaximumSize"])
        != (options["initial_size"], options["maximum_size"])
    ):
        result["changed"] = True
        if not check_mode:
            _write_sizes(provider, existing, options)


def _query(provider, options, automatic, result):
    records = provider.records()
    if options["drive"] is not None:
        name = options["drive"] + ":\\pagefile.sys"
        records = [
            record for record in records if record["Name"].lower() == name.lower()
        ]
    result["pagefiles"] = [
        {
            "name": record["Name"],
            "caption": record["Caption"],
            "description": record["Description"],
            "initial_size": record["InitialSize"],
            "maximum_size": record["MaximumSize"],
        }
        for record in records
    ]
    result["automatic_managed_pagefiles"] = automatic
    if not provider.automatic_supported:
        result["warnings"] = [
            "The installed Win32_ComputerSystem provider does not expose "
            "AutomaticManagedPagefile; automatic_managed_pagefiles is null."
        ]


def _apply(provider, options, check_mode, result):
    automatic = provider.automatic()
    if options["automatic"] is not None and not provider.automatic_supported:
        raise ValueError(
            "The installed Win32_ComputerSystem provider cannot configure AutomaticManagedPagefile"
        )
    if options["remove_all"]:
        records = provider.records()
        result["changed"] = bool(records)
        if not check_mode:
            for record in records:
                provider.delete(record)
    if options["automatic"] is not None and automatic != options["automatic"]:
        result["changed"] = True
        if not check_mode:
            provider.set_automatic(options["automatic"])
            automatic = provider.automatic()
    if options["state"] == "present":
        _present(provider, options, check_mode, result)
    elif options["state"] == "absent" and options["drive"] is not None:
        name = options["drive"] + ":\\pagefile.sys"
        record = _selected(provider.records(), name)
        if record:
            result["changed"] = True
            if not check_mode:
                provider.delete(record)
    elif options["state"] == "query":
        _query(provider, options, automatic, result)


def _manage(arguments):
    options = _parameters(arguments)
    check_mode = as_bool(
        arguments.get("_ansible_check_mode", False), "_ansible_check_mode"
    )
    result = {"changed": False}
    try:
        with Pagefiles() as provider:
            _apply(provider, options, check_mode, result)
    except (OSError, ValueError) as error:
        result.update(failed=True, msg="Failed to configure pagefiles: " + str(error))
    return result


def main():
    """Read a WANT_JSON request and query or change native pagefile settings."""
    run_module(
        lambda: _manage(
            read_arguments(
                _PARAMETERS,
                "sustainablelobster.legacy_community_windows.win_pagefile",
                allow_unknown=True,
            )
        )
    )


if __name__ == "__main__":
    main()
