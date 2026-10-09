#!/usr/bin/python
# -*- coding: utf-8 -*-
# Copyright 2026 Joe Lustri
# SPDX-License-Identifier: GPL-3.0-or-later

"""Poll a Windows file or TCP condition with Python 3.4.4."""

# WANT_JSON

import math
import re
import time

# The action stages these Python 3.4-compatible helpers beside the payload.
import legacy_windows_regex as matching  # pylint: disable=import-error
import legacy_windows_wait as native  # pylint: disable=import-error
from legacy_windows_module import (  # pylint: disable=import-error
    DOTNET_WHITESPACE,
    as_path,
    as_string,
    read_arguments,
    run_module,
)

# Repeat shared regex and polling limitations so this module's help is complete.
# pylint: disable=duplicate-code
DOCUMENTATION = r"""
---
module: win_wait_for
short_description: Wait for a file or TCP condition
version_added: '1.0.0'
description:
  - Waits for a file, file contents, a listening TCP port, or drained TCP connections.
  - With no O(path) or O(port), sleeps for O(timeout) seconds unless O(state=drained).
  - Uses Python 3.4.4 or newer and native Windows APIs.
options:
  connect_timeout:
    description: Maximum seconds allowed for an individual TCP connection attempt.
    type: int
    default: 5
  delay:
    description: Seconds to wait before polling or beginning the unconditional sleep.
    type: int
  exclude_hosts:
    description:
      - Hosts whose resolved addresses are ignored when O(state=drained).
      - Unresolvable entries warn on each attempt with matching active connections.
    type: list
    elements: str
  host:
    description:
      - Hostname or IPv4 address to test for a listening TCP port.
      - With O(state=drained), selects a local address. C(0.0.0.0) selects all local addresses.
    type: str
    default: 127.0.0.1
  path:
    description: Literal filesystem path to poll, with Windows environment variables expanded.
    type: path
  port:
    description: Local or remote TCP port to examine, according to O(state).
    type: int
  regex:
    description:
      - Case-insensitive regular expression to search for in the entire file contents.
      - With O(state=absent), waits until the file is absent or its contents do not match.
      - Use inline C((?m)) to enable multiline anchors.
      - An empty file satisfies neither regex condition, matching the pinned upstream behavior.
    type: str
    aliases: [search_regex, regexp]
  sleep:
    description: Seconds to sleep after an unsuccessful attempt, including the final attempt.
    type: int
    default: 1
  state:
    description:
      - C(present) and C(started) wait for the file, regex match, or listening TCP port.
      - C(absent) waits for the file or regex match to disappear, or the TCP port to close.
      - C(stopped) checks only for a closed TCP port; C(drained) checks active local connections.
    type: str
    choices: [present, started, stopped, absent, drained]
    default: started
  timeout:
    description:
      - Seconds allowed for polling, measured after O(delay).
      - Connection attempts and polling sleeps may extend the total duration beyond this limit.
      - With no O(path) or O(port), this is the unconditional sleep duration.
      - A zero timeout performs no file or TCP checks, even when the condition is already satisfied.
    type: int
    default: 300
attributes:
  check_mode:
    support: full
    description: Performs the same waiting and read-only checks as normal mode.
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
  - PowerShell provider paths and relative-path resolution are not verified.
  - With C(async) and C(poll=0), retrieve results using M(sustainablelobster.legacy_windows.async_status).
  - Automatic polling with C(poll>0) requires the installed collection's
    C(plugins/action/_native_async_polling) directory on the controller action plugin path.
    Set C(action_plugins) in the project's C(ansible.cfg); installation alone does not activate the adapter.
author:
  - Joe Lustri
"""
# pylint: enable=duplicate-code

EXAMPLES = r"""
- name: Wait for an application to accept TCP connections
  sustainablelobster.legacy_windows.win_wait_for:
    port: 8080
    delay: 5
    timeout: 60

- name: Wait for a case-insensitive completion message
  sustainablelobster.legacy_windows.win_wait_for:
    path: C:\Application\setup.log
    regex: installation complete

- name: Wait for local TCP connections to drain
  sustainablelobster.legacy_windows.win_wait_for:
    host: 0.0.0.0
    port: 8080
    state: drained
    exclude_hosts: [127.0.0.1]
"""

RETURN = r"""
wait_attempts:
  description: Number of file or TCP checks performed, including the successful check.
  returned: after waiting
  type: int
  sample: 1
elapsed:
  description: Elapsed seconds including the initial delay and any polling sleeps.
  returned: success, polling timeout, or option-combination validation failure
  type: float
  sample: 2.14
"""

_MODULE_NAME = "sustainablelobster.legacy_windows.win_wait_for"
_PARAMETERS = (
    "connect_timeout",
    "delay",
    "exclude_hosts",
    "host",
    "path",
    "port",
    "regex",
    "search_regex",
    "regexp",
    "sleep",
    "state",
    "timeout",
)
_STATES = ("present", "started", "stopped", "absent", "drained")


def _pipeline_string(value, name):
    if isinstance(value, list):
        return " ".join(_pipeline_string(entry, name) or "" for entry in value)
    return as_string(value, name)


def _integer(value):
    # Legacy's -as conversion returns null on failure rather than rejecting the
    # argument. Its string conversion also accepts invariant floating-point text.
    if isinstance(value, str):
        if value == "":
            return 0
        value = value.strip(DOTNET_WHITESPACE)
        if re.match(r"^[+-]?[0-9]+$", value):
            value = int(value)
        elif re.match(r"^0[xX][0-9a-fA-F]+$", value):
            value = int(value, 16)
            if 2**31 <= value < 2**32:
                value -= 2**32
        elif re.match(
            r"^[+-]?(?:[0-9][0-9,]*(?:\.[0-9]*)?|\.[0-9]+)(?:[eE][+-]?[0-9]+)?$",
            value,
        ):
            value = float(value.replace(",", ""))
        else:
            return None
    if isinstance(value, float):
        if not math.isfinite(value):
            return None
        value = int(round(value))
    if isinstance(value, int) and -(2**31) <= value < 2**31:
        return int(value)
    return None


def _excludes(value):
    if isinstance(value, str):
        value = [part.strip(DOTNET_WHITESPACE) for part in value.split(",")]
    elif isinstance(value, int) and not isinstance(value, bool):
        if -(2**31) <= value < 2**31:
            value = [value]
    if value is not None and not isinstance(value, list):
        raise ValueError(
            "Get-AnsibleParam: Parameter 'exclude_hosts' is not a YAML list."
        )
    return value


def _parameters(arguments):
    parameters = {
        "connect_timeout": _integer(arguments.get("connect_timeout", 5)),
        "delay": _integer(arguments.get("delay")),
        "exclude_hosts": _excludes(arguments.get("exclude_hosts")),
        "host": as_string(arguments.get("host", "127.0.0.1"), "host"),
        "path": as_path(arguments.get("path"), "path"),
        "port": _integer(arguments.get("port")),
    }
    if parameters["path"] == "":
        raise RuntimeError(
            "Cannot bind argument to parameter 'Path' because it is an empty string."
        )
    regex = None
    for alias in ("regex", "search_regex", "regexp"):
        if alias in arguments:
            regex = arguments[alias]
            break
    parameters["regex"] = as_string(regex, "regex")
    parameters["sleep"] = _integer(arguments.get("sleep", 1))
    state = arguments.get("state", "started")
    if (_pipeline_string(state, "state") or "").lower() not in _STATES:
        raise ValueError(
            "Get-AnsibleParam: Argument state needs to be one of "
            + ",".join(_STATES)
            + " but was "
            + (_pipeline_string(state, "state") or "")
            + "."
        )
    parameters["state"] = as_string(state, "state")
    parameters["timeout"] = _integer(arguments.get("timeout", 300))
    return parameters


def _validation_error(parameters):
    path = parameters["path"]
    port = parameters["port"]
    state = parameters["state"].lower()
    excludes = parameters["exclude_hosts"]
    if port is not None and path is not None:
        return "port and path parameter can not both be passed to win_wait_for"
    if excludes is not None and state != "drained":
        return "exclude_hosts should only be with state=drained"
    if path is not None and state in ("stopped", "drained"):
        return (
            "state=" + parameters["state"] + " should only be used for checking a port "
            "in the win_wait_for module"
        )
    if port is not None and parameters["regex"] is not None:
        return (
            "regex should by used when checking a string in a file "
            "in the win_wait_for module"
        )
    return None


def _drained(parameters, result):
    connections = [
        remote
        for address, port, remote in native.active_connections()
        if port == parameters["port"]
        and (
            parameters["host"] == "0.0.0.0"
            or native.address_matches(address, parameters["host"])
        )
    ]
    if connections and parameters["exclude_hosts"] is not None:
        for excluded in parameters["exclude_hosts"]:
            name = _pipeline_string(excluded, "exclude_hosts")
            try:
                addresses = native.resolve_addresses(name or "")
            except (OSError, ValueError, TypeError):
                result.setdefault("warnings", []).append(
                    "Invalid hostname specified " + (name or "")
                )
            else:
                connections = [
                    remote
                    for remote in connections
                    if not any(
                        native.address_matches(remote, address) for address in addresses
                    )
                ]
    return not connections


def _condition(parameters, result):
    state = parameters["state"].lower()
    if parameters["path"] is not None:
        exists = native.path_exists(parameters["path"])
        if exists and parameters["regex"] is not None:
            contents = native.read_text(parameters["path"])
            exists = matching.search(contents or "", parameters["regex"])
            # Get-Content -Raw produces no scalar for an empty file. Both
            # upstream match operators then produce a false condition, while
            # still validating the pattern before they inspect that input.
            if contents is None:
                return False
        return not exists if state == "absent" else exists
    if state == "drained":
        return _drained(parameters, result)
    opened = native.port_open(
        parameters["host"], parameters["port"], parameters["connect_timeout"] or 0
    )
    return not opened if state in ("stopped", "absent") else opened


def _timeout_message(parameters):
    state = parameters["state"].lower()
    if parameters["path"] is not None:
        if parameters["regex"] is None:
            return "timeout while waiting for file {0} to be {1}".format(
                parameters["path"],
                "absent" if state == "absent" else "present",
            )
        return "timeout while waiting for string regex {0} in file {1} to {2}".format(
            parameters["regex"],
            parameters["path"],
            "not match" if state == "absent" else "match",
        )
    action = {
        "present": "start listening",
        "started": "start listening",
        "absent": "stop listening",
        "stopped": "stop listening",
        "drained": "drain",
    }[state]
    return "timeout while waiting for {0}:{1} to {2}".format(
        parameters["host"] or "", parameters["port"], action
    )


def _sleep(seconds):
    if seconds is None:
        raise RuntimeError(
            "Cannot validate argument on parameter 'Seconds'. The argument is null, "
            "empty, or an element of the argument collection contains a null value. "
            "Supply a collection that does not contain any null values and then "
            "try the command again."
        )
    if seconds < 0:
        raise RuntimeError(
            "Cannot validate argument on parameter 'Seconds'. The {0} argument is "
            "less than the minimum allowed range of 0. Supply an argument that is "
            "greater than or equal to 0 and then try the command again.".format(seconds)
        )
    time.sleep(seconds)


def _wait(parameters):
    result = {"changed": False, "elapsed": 0}
    error = _validation_error(parameters)
    if error:
        result.update(failed=True, msg=error)
        return result
    module_start = time.time()
    if parameters["delay"] is not None:
        _sleep(parameters["delay"])
    attempts = 0
    state = parameters["state"].lower()
    if parameters["path"] is None and parameters["port"] is None:
        if state != "drained":
            _sleep(parameters["timeout"])
    elif state in _STATES:
        start = time.time()
        complete = False
        while time.time() - start < (parameters["timeout"] or 0):
            attempts += 1
            if _condition(parameters, result):
                complete = True
                break
            _sleep(parameters["sleep"])
        if not complete:
            result.update(failed=True, msg=_timeout_message(parameters))
    result["elapsed"] = time.time() - module_start
    result["wait_attempts"] = attempts
    return result


def _response():
    arguments = read_arguments(_PARAMETERS, _MODULE_NAME, allow_unknown=True)
    return _wait(_parameters(arguments))


def main():
    """Read Ansible arguments and emit the polling result.

    :raises SystemExit: After reporting success or failure to Ansible.
    """
    run_module(_response)


if __name__ == "__main__":
    main()
