#!/usr/bin/python
# -*- coding: utf-8 -*-
# Copyright 2026 sustainablelobster
# SPDX-License-Identifier: GPL-3.0-or-later

"""Read TCP and UDP endpoint facts with a Python 3.4.4 payload."""

# WANT_JSON

# The action stages these native readers and their dependencies beside the payload.
# pylint: disable=import-error
import legacy_windows_ports as ports
import legacy_windows_process_info as process_info
import legacy_windows_uformat as uformat
from legacy_windows_module import (
    DOTNET_WHITESPACE,
    as_bool,
    as_string,
    as_string_list,
    read_arguments,
    run_module,
)

# pylint: enable=import-error

# Ansible interfaces must be self-contained; repeated option/return text is
# interface documentation, not duplicated execution logic.
# pylint: disable=duplicate-code
DOCUMENTATION = r"""
---
module: win_listen_ports_facts
short_description: Read TCP and UDP endpoints and their owning processes
version_added: '1.0.0'
description:
  - Returns TCP endpoints in selected states and all UDP endpoints as Ansible facts.
  - Includes each owning process's name, identifier, start time, and account.
  - Uses Python 3.4.4 and native Windows APIs.
options:
  date_uformat:
    description:
      - PowerShell 5.1 UFormat pattern for the owning process's local start time.
      - An explicit null retains the upstream serialized date representation.
    type: str
    default: '%c'
  tcp_filter:
    description:
      - TCP states to include. Does not filter UDP endpoints.
      - States are C(Closed), C(Listen), C(SynSent), C(SynReceived), C(Established), C(FinWait1), C(FinWait2), C(CloseWait), C(Closing), C(LastAck), C(TimeWait), C(DeleteTCB), and C(Bound).
      - Names are case-insensitive. An empty list selects no TCP endpoints; null is invalid.
    type: list
    elements: str
    default: [Listen]
attributes:
  check_mode:
    support: full
    description: Reads the same information as a normal invocation and reports no changes.
  diff_mode:
    support: none
notes:
  - Facts retain the upstream names C(tcp_listen) and C(udp_listen), even when selecting non-listening TCP states.
  - The process snapshot is taken before endpoint enumeration. A missing process or failed query discards partial facts.
  - Uses the modern native WMI endpoint provider when available and IP Helper tables on older Windows versions.
  - Legacy IP Helper tables cannot report C(Bound) entries; selecting that state produces a warning while retaining other selected states.
  - Process start time and owner can be null when Windows does not provide them.
  - Custom composite date formats can require locale fields unavailable on older Windows. Such requests fail with the missing field's name rather than substituting a pattern or culture.
author:
  - sustainablelobster
"""

EXAMPLES = r"""
- name: Read listening TCP ports and UDP endpoints
  sustainablelobster.legacy_windows.win_listen_ports_facts:

- name: Include established TCP connections
  sustainablelobster.legacy_windows.win_listen_ports_facts:
    tcp_filter: [Listen, Established]
    date_uformat: '%Y-%m-%d %H:%M:%S'

- name: Read UDP endpoints only
  sustainablelobster.legacy_windows.win_listen_ports_facts:
    tcp_filter: []
"""

RETURN = r"""
ansible_facts:
  description: Endpoint and process facts.
  returned: success
  type: dict
  contains:
    tcp_listen:
      description: TCP endpoints matching O(tcp_filter), in provider enumeration order.
      type: list
      elements: dict
      contains:
        address:
          description: Local IP address, including an IPv6 scope identifier when present.
          type: str
        port:
          description: Local port number.
          type: int
        pid:
          description: Owning process identifier.
          type: int
        name:
          description: Process name reported by Windows.
          type: str
        protocol:
          description: The string C(tcp).
          type: str
        stime:
          description: Formatted process start time, or null if unavailable.
          type: str
        user:
          description: Process owner as C(DOMAIN\User), or null if unavailable.
          type: str
    udp_listen:
      description: UDP endpoints with the same fields as RV(ansible_facts.tcp_listen), and C(udp) as their protocol.
      type: list
      elements: dict
"""
# pylint: enable=duplicate-code

_MODULE_NAME = "sustainablelobster.legacy_windows.win_listen_ports_facts"
_STATES = (
    "Closed",
    "Listen",
    "SynSent",
    "SynReceived",
    "Established",
    "FinWait1",
    "FinWait2",
    "CloseWait",
    "Closing",
    "LastAck",
    "TimeWait",
    "DeleteTCB",
    "Bound",
)
_STATE_VALUES = dict(zip(_STATES, list(range(1, 13)) + [100]))
_STATE_TYPE = "Microsoft.PowerShell.Cmdletization.GeneratedTypes.NetTCPConnection.State"


def _invalid_state_value(text):
    return ValueError(
        'Cannot convert value "{0}" to type "{1}" due to enumeration '
        "values that are not valid. Specify one of the following "
        "enumeration values and try again. The possible enumeration "
        'values are "{2}".'.format(text, _STATE_TYPE, ",".join(_STATES))
    )


def _state_value(text):
    value = text.strip(DOTNET_WHITESPACE)
    digits = value[1:] if value.startswith(("+", "-")) else value
    numeric = bool(digits) and all("0" <= char <= "9" for char in digits)
    if numeric:
        number = int(value)
        if not 0 <= number <= 255:
            detail = "Value was either too large or too small for an unsigned byte."
        elif number in _STATE_VALUES.values():
            return number
        else:
            raise _invalid_state_value(text)
    else:
        number = 0
        for part in value.split(","):
            name = part.strip(DOTNET_WHITESPACE).lower()
            # PowerShell accepts unambiguous prefixes only for a single name;
            # comma-combined enum names go through the exact-name parser.
            matches = [
                state
                for state in _STATES
                if (
                    state.lower() == name
                    if "," in value
                    else state.lower().startswith(name)
                )
            ]
            if len(matches) == 1:
                number |= _STATE_VALUES[matches[0]]
                continue
            if matches:
                detail = (
                    "The identifier name {0} cannot be processed because it is "
                    "either too similar or identical to the following enumerator "
                    "names: {1}. Use a more specific identifier name."
                ).format(text, ", ".join(matches))
            else:
                detail = (
                    "Unable to match the identifier name {0} to a valid "
                    "enumerator name. Specify one of the following enumerator "
                    "names and try again:\r\n{1}"
                ).format(text, ", ".join(_STATES))
            break
        else:
            if number not in _STATE_VALUES.values():
                raise _invalid_state_value(text)
            return number
    raise ValueError(
        'Cannot convert value "{0}" to type "{1}". Error: "{2}"'.format(
            text, _STATE_TYPE, detail
        )
    )


def _selected_states(values):
    if values is None:
        raise ValueError(
            "Cannot validate argument on parameter 'State'. The argument is "
            "null. Provide a valid value for the argument, and then try running "
            "the command again."
        )
    try:
        return set(_state_value(value) for value in values)
    except ValueError as error:
        raise ValueError(
            "Cannot process argument transformation on parameter 'State'. "
            'Cannot convert value "System.Collections.Generic.List`1[System.Object]" '
            'to type "{0}[]". Error: "{1}"'.format(_STATE_TYPE, error)
        ) from error


def _listener(endpoint, protocol, processes, date_format):
    process = processes.get(endpoint["pid"])
    return {
        "address": endpoint["address"],
        "name": process["name"],
        "pid": endpoint["pid"],
        "port": endpoint["port"],
        "protocol": protocol,
        "stime": uformat.format_date(process["creation_time"], date_format),
        "user": process["user"],
    }


def _response():
    arguments = read_arguments(("date_uformat", "tcp_filter"), _MODULE_NAME)
    date_format = as_string(arguments.get("date_uformat", "%c"), "date_uformat")
    filters = as_string_list(arguments.get("tcp_filter", ["Listen"]), "tcp_filter")
    warnings = []
    with process_info.ProcessReader() as processes:
        try:
            states = _selected_states(filters)
            facts = {
                "tcp_listen": [
                    _listener(endpoint, "tcp", processes, date_format)
                    for endpoint in ports.tcp_endpoints(states, warnings)
                ],
                "udp_listen": [
                    _listener(endpoint, "udp", processes, date_format)
                    for endpoint in ports.udp_endpoints()
                ],
            }
        # Upstream wraps all endpoint, owner, and date retrieval exceptions.
        except Exception as error:  # pylint: disable=broad-exception-caught
            raise ValueError(
                "An error occurred while retrieving ports facts: " + str(error)
            ) from error
    # Fact readers share an unchanged/warning envelope, not native readers.
    # pylint: disable=duplicate-code
    result = {"changed": False, "ansible_facts": facts}
    if warnings:
        result["warnings"] = warnings
    # pylint: enable=duplicate-code
    if as_bool(
        arguments.get("_ansible_inject_invocation", False), "_ansible_inject_invocation"
    ):
        result["invocation"] = {
            "module_args": {"date_uformat": date_format, "tcp_filter": filters}
        }
    return result


def main():
    """Emit endpoint facts through Ansible's JSON protocol.

    :raises SystemExit: After reporting success or failure.
    """
    run_module(_response)


# Each independently staged payload needs its own executable entry guard.
# pylint: disable=duplicate-code
if __name__ == "__main__":
    main()
# pylint: enable=duplicate-code
