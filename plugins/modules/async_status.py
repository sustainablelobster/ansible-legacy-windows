#!/usr/bin/python
# -*- coding: utf-8 -*-
# SPDX-License-Identifier: GPL-3.0-or-later
"""Read or erase an existing Windows asynchronous job cache file."""

# WANT_JSON

import codecs
import ctypes
import json
import locale
import os

from legacy_windows_module import (  # pylint: disable=import-error
    as_path,
    as_string,
    read_arguments,
    run_module,
)

DOCUMENTATION = r"""
---
module: async_status
short_description: Obtain the status of an existing asynchronous Windows job
version_added: '1.0.0'
description:
  - Reads or removes an existing asynchronous job cache file using Python 3.4.4 or newer.
  - Uses the standard Ansible controller status action and its result handling.
  - The cache directory is selected by C(ansible_async_dir), defaulting to
    C(%USERPROFILE%\.ansible_async).
  - This module does not launch asynchronous jobs. Supported native module
    actions can launch jobs with C(async) and C(poll=0); poll this module with
    an C(until) loop to read their results.
  - Automatic polling requires selecting the installed collection's
    C(plugins/action/_native_async_polling) directory with C(action_plugins)
    under C([defaults]) in the project's C(ansible.cfg). Without that opt-in,
    native actions reject C(poll>0) before launching. See the collection Usage
    guide for the configuration example; installation alone does not activate it.
  - Cleanup removes the cache entry even in check mode, matching upstream.
  - Files without an encoding marker use the target's Windows ANSI encoding,
    matching the upstream Windows PowerShell reader.
options:
  jid:
    description: Job or task identifier.
    type: str
    required: true
  mode:
    description:
      - V(status) reads the job result.
      - V(cleanup) removes the cache entry without stopping the job.
    type: str
    choices: [cleanup, status]
    default: status
attributes:
  check_mode:
    support: full
    description: Status reads normally; cleanup still removes the cache entry.
  diff_mode:
    support: none
  async:
    support: none
author:
  - sustainablelobster
"""

EXAMPLES = r"""
- name: Read the result of an existing job
  sustainablelobster.legacy_windows.async_status:
    jid: '{{ existing_job_id }}'

- name: Remove a completed job cache entry
  sustainablelobster.legacy_windows.async_status:
    jid: '{{ existing_job_id }}'
    mode: cleanup
"""

RETURN = r"""
ansible_job_id:
  description: The requested identifier, unless supplied by the job record.
  returned: status or cleanup
  type: str
started:
  description: Whether the job has started; normalized by the controller action.
  returned: always
  type: bool
finished:
  description: Whether the job has finished; normalized by the controller action.
  returned: always
  type: bool
results_file:
  description: Path of the job cache entry.
  returned: status
  type: str
erased:
  description: Path of the removed cache entry.
  returned: cleanup
  type: str
stdout:
  description: Standard output stored in the job result, or an empty string.
  returned: always
  type: str
stderr:
  description: Standard error stored in the job result, or an empty string.
  returned: always
  type: str
"""


def _unhandled(message):
    return {
        "changed": False,
        "failed": True,
        "exception": "(traceback unavailable)",
        "msg": "Unhandled exception while executing module: " + message,
    }


def _object(pairs):
    result = {}
    spellings = {}
    for name, value in pairs:
        previous = spellings.setdefault(name.lower(), name)
        if previous != name:
            raise ValueError("Job output contains case-conflicting property names")
        result[name] = value
    return result


def _read_output(path):
    with open(path, "rb") as stream:
        contents = stream.read()
    for marker, encoding in (
        (codecs.BOM_UTF32_LE, "utf-32"),
        (codecs.BOM_UTF32_BE, "utf-32"),
        (codecs.BOM_UTF8, "utf-8-sig"),
        (codecs.BOM_UTF16_LE, "utf-16"),
        (codecs.BOM_UTF16_BE, "utf-16"),
    ):
        if contents.startswith(marker):
            return contents.decode(encoding, errors="replace")
    return contents.decode(locale.getpreferredencoding(False), errors="replace")


def _attributes(path):
    function = ctypes.WinDLL("kernel32", use_last_error=True).GetFileAttributesW
    function.argtypes, function.restype = [ctypes.c_wchar_p], ctypes.c_uint32
    value = function(path)
    if value == 0xFFFFFFFF:
        raise ctypes.WinError(ctypes.get_last_error())
    return value


def _erase(path):
    if os.path.isdir(path):
        # Python 3.4's rmtree can traverse a directory junction. Remove the
        # reparse entry itself, never the unrelated directory it points at.
        if not _attributes(path) & 0x400:
            for name in os.listdir(path):
                _erase(os.path.join(path, name))
        os.rmdir(path)
    else:
        os.remove(path)


def _set_field(record, name, value):
    spelling = next((key for key in record if key.lower() == name), name)
    record[spelling] = value


def _scalar_type(value):
    if isinstance(value, list):
        value = next((item for item in value if item is not None), None)
    if isinstance(value, bool):
        return "System.Boolean"
    if isinstance(value, int):
        return "System.Int32" if -(2**31) <= value < 2**31 else "System.Int64"
    if isinstance(value, float):
        return "System.Double"
    return "System.String"


def _response():  # pylint: disable=too-many-return-statements
    # Each return is a distinct upstream status/failure outcome; keeping these
    # beside their conditions is clearer than nesting the entire job reader.
    args = read_arguments(
        ("jid", "mode", "_async_dir"),
        "sustainablelobster.legacy_windows.async_status",
        allow_unknown=True,
    )
    jid = as_string(args.get("jid"), "jid") or ""
    directory = as_path(args.get("_async_dir"), "_async_dir")
    if "jid" not in args or not directory:
        raise ValueError("jid and _async_dir are required arguments")
    mode = as_string(args.get("mode", "status"), "mode")
    if mode is None or mode.lower() not in ("status", "cleanup"):
        raise ValueError("mode must be status or cleanup")
    # Path.Combine(directory, '') returns directory without adding a separator.
    # Explicit null/empty identifiers pass the upstream legacy presence check.
    path = os.path.join(directory, jid) if jid else directory
    if not os.path.exists(path):
        return {
            "changed": False,
            "failed": True,
            "ansible_job_id": jid,
            "started": 1,
            "finished": 1,
            "msg": "could not find job at '" + directory + "'",
        }
    if mode.lower() == "cleanup":
        _erase(path)
        return {"changed": False, "ansible_job_id": jid, "erased": path}
    try:
        text = _read_output(path)
    except OSError:
        return {
            "changed": False,
            "results_file": path,
            "ansible_job_id": jid,
            "started": 1,
            "finished": 0,
        }
    try:
        data = json.loads(text, object_pairs_hook=_object) if text.strip() else None
    except ValueError:
        return {
            "changed": False,
            "failed": True,
            "ansible_job_id": jid,
            "results_file": path,
            "started": 1,
            "finished": 1,
            "msg": "Could not parse job output: ",
        }
    if data is None or data == []:
        return _unhandled("You cannot call a method on a null-valued expression.")
    if isinstance(data, list) and all(isinstance(record, dict) for record in data):
        # PowerShell enumerates ContainsKey over these objects, then attempts
        # to use 'finished' as an integer array index instead of a record key.
        return _unhandled(
            'Cannot convert value "finished" to type "System.Int32". Error: '
            '"Input string was not in a correct format."'
        )
    if not isinstance(data, dict):
        return _unhandled(
            "Method invocation failed because ["
            + _scalar_type(data)
            + "] does not contain a method named 'ContainsKey'."
        )
    names = {name.lower() for name in data}
    if "started" not in names:
        _set_field(data, "finished", 1)
        _set_field(data, "ansible_job_id", jid)
    elif "finished" not in names:
        data["finished"] = 0
    if "changed" not in names:
        data["changed"] = False
    return data


def main():
    """Read Ansible arguments and write the job status as JSON.

    :raises SystemExit: After reporting success or failure to Ansible.
    """
    run_module(_response)


if __name__ == "__main__":
    main()
