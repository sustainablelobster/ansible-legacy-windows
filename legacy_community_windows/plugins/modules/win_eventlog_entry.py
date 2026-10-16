#!/usr/bin/python
# -*- coding: utf-8 -*-
# Copyright 2026 sustainablelobster
# Copyright: (c) 2017, Andrew Saraceni <andrew.saraceni@gmail.com>
# SPDX-License-Identifier: GPL-3.0-or-later

"""Write classic event-log entries through the native Windows event API."""

# WANT_JSON

import ctypes

# The action stages these Python 3.4-compatible helpers beside the payload.
import legacy_windows_eventlog as eventlog  # pylint: disable=import-error
from legacy_windows_module import (  # pylint: disable=import-error
    as_bool,
    as_string,
    read_arguments,
    run_module,
)

DOCUMENTATION = r"""
---
module: win_eventlog_entry
short_description: Write entries to Windows event logs
description:
     - Write log entries to a given event log from a specified source.
options:
  log:
    description:
      - Name of the event log to write an entry to.
    type: str
    required: yes
  source:
    description:
      - Name of the log source to indicate where the entry is from.
    type: str
    required: yes
  event_id:
    description:
      - The numeric event identifier for the entry.
      - Value must be between 0 and 65535.
    type: int
    required: yes
  message:
    description:
      - The message for the given log entry.
    type: str
    required: yes
  entry_type:
    description:
      - Indicates the entry being written to the log is of a specific type.
    type: str
    choices: [ Error, FailureAudit, Information, SuccessAudit, Warning ]
  category:
    description:
      - A numeric task category associated with the category message file for the log source.
    type: int
  raw_data:
    description:
      - Binary data associated with the log entry.
      - Value must be a comma-separated array of 8-bit unsigned integers (0 to 255).
    type: str
notes:
    - This module will always report a change when writing an event entry.
seealso:
- module: sustainablelobster.legacy_community_windows.win_eventlog
author:
    - Andrew Saraceni (@andrewsaraceni)
"""

EXAMPLES = r"""
- name: Write an entry to a Windows event log
  sustainablelobster.legacy_community_windows.win_eventlog_entry:
    log: MyNewLog
    source: NewLogSource1
    event_id: 1234
    message: This is a test log entry.

- name: Write another entry to a different Windows event log
  sustainablelobster.legacy_community_windows.win_eventlog_entry:
    log: AnotherLog
    source: MyAppSource
    event_id: 5000
    message: An error has occurred.
    entry_type: Error
    category: 5
    raw_data: 10,20
"""

RETURN = r"""
# Default return values
"""


_ENTRY_TYPES = {
    "error": 1,
    "warning": 2,
    "information": 4,
    "successaudit": 8,
    "failureaudit": 16,
}


# Keep the event's independent native fields explicit rather than bundling
# unrelated values into positional tuples or an undocumented state dictionary.
# pylint: disable=too-many-arguments,too-many-positional-arguments
def _write(source, event_id, message, entry_type, category, raw_data):
    library = ctypes.WinDLL("advapi32", use_last_error=True)
    library.RegisterEventSourceW.argtypes = [ctypes.c_wchar_p, ctypes.c_wchar_p]
    library.RegisterEventSourceW.restype = ctypes.c_void_p
    library.DeregisterEventSource.argtypes = [ctypes.c_void_p]
    library.DeregisterEventSource.restype = ctypes.c_int
    library.ReportEventW.argtypes = [
        ctypes.c_void_p,
        ctypes.c_uint16,
        ctypes.c_uint16,
        ctypes.c_uint32,
        ctypes.c_void_p,
        ctypes.c_uint16,
        ctypes.c_uint32,
        ctypes.POINTER(ctypes.c_wchar_p),
        ctypes.c_void_p,
    ]
    library.ReportEventW.restype = ctypes.c_int
    handle = library.RegisterEventSourceW(None, source)
    if not handle:
        raise ctypes.WinError(ctypes.get_last_error())
    try:
        messages = (ctypes.c_wchar_p * 1)(message)
        data = ctypes.create_string_buffer(raw_data) if raw_data else None
        if not library.ReportEventW(
            handle,
            entry_type,
            category,
            event_id,
            None,
            1,
            len(raw_data),
            messages,
            data,
        ):
            raise ctypes.WinError(ctypes.get_last_error())
    finally:
        library.DeregisterEventSource(handle)


# pylint: enable=too-many-arguments,too-many-positional-arguments


def _entry(arguments):
    required = {}
    for name in ("log", "source", "message"):
        value = as_string(arguments.get(name), name)
        if not value:
            raise ValueError("Missing required argument: " + name)
        required[name] = value
    try:
        event_id = int(arguments["event_id"])
    except (KeyError, ValueError, TypeError, OverflowError) as error:
        raise ValueError("event_id must be an integer between 0 and 65535") from error
    if not 0 <= event_id <= 65535:
        raise ValueError("Event ID must be between 0 and 65535")
    entry_type = as_string(arguments.get("entry_type") or "Information", "entry_type")
    if entry_type.lower() not in _ENTRY_TYPES:
        raise ValueError(
            "entry_type must be Error, FailureAudit, Information, SuccessAudit or Warning"
        )
    try:
        category = int(arguments.get("category") or 0)
        if not -32768 <= category <= 32767:
            raise ValueError("category must fit in a signed 16-bit integer")
        raw = as_string(arguments.get("raw_data"), "raw_data")
        raw_data = bytes(int(value.strip()) for value in raw.split(",")) if raw else b""
    except (ValueError, TypeError, OverflowError) as error:
        raise ValueError("Invalid event category or raw_data: " + str(error)) from error
    name = required["log"]
    source = required["source"]
    if not eventlog.log_details(name)["exists"]:
        raise ValueError("Log " + name + " does not exist and cannot be written to")
    registered = eventlog.source_log(source)
    if registered is None:
        raise ValueError("Source " + source + " does not exist")
    if registered.casefold() != name.casefold():
        raise ValueError(
            "Source "
            + source
            + " does not belong to log "
            + name
            + " and cannot be written to"
        )
    if not as_bool(arguments.get("_ansible_check_mode", False), "_ansible_check_mode"):
        _write(
            source,
            event_id,
            required["message"],
            _ENTRY_TYPES[entry_type.lower()],
            category & 0xFFFF,
            raw_data,
        )
    return {
        "changed": True,
        "msg": "Entry added to log " + name + " from source " + source,
    }


def main():
    """Read arguments and report the native event-writing result."""
    run_module(
        lambda: _entry(
            read_arguments(
                (
                    "log",
                    "source",
                    "event_id",
                    "message",
                    "entry_type",
                    "category",
                    "raw_data",
                ),
                "sustainablelobster.legacy_community_windows.win_eventlog_entry",
                allow_unknown=True,
            )
        )
    )


if __name__ == "__main__":
    main()
