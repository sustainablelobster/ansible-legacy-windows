#!/usr/bin/python
# -*- coding: utf-8 -*-
# Copyright 2026 sustainablelobster
# SPDX-License-Identifier: GPL-3.0-or-later
"""Manage persistent Windows routes with Python and shipped native tools."""

# WANT_JSON

import re

import legacy_windows_route as route  # pylint: disable=import-error
from legacy_windows_module import (  # pylint: disable=import-error
    DOTNET_WHITESPACE,
    as_bool,
    as_string,
    read_arguments,
    run_module,
)

DOCUMENTATION = r"""
---
module: win_route
short_description: Add or remove a static route
version_added: '1.0.0'
description:
  - Manages persistent routes using Python 3.4.4 and native Windows interfaces.
  - Preserves the destination-only existence check of pinned ansible.windows 3.8.0.
options:
  destination:
    description: Destination address and decimal prefix length, not a dotted mask.
    type: str
    required: true
  gateway:
    description: Next-hop address used to select the outgoing interface for a new route.
    type: str
    default: '0.0.0.0'
  metric:
    description:
      - Integer metric accepted by the interface.
      - Like pinned 3.8.0, the supplied value is ignored and new routes use metric zero.
      - Legacy Windows stores zero but uses its automatic active-route cost.
    type: int
    default: 1
  state:
    description: Whether to create or remove the route.
    type: str
    choices: [present, absent]
    default: present
attributes:
  check_mode:
    support: full
    description: Validates and predicts changes without writing routes.
  diff_mode:
    support: none
notes:
  - Requires administrator permission to change routes.
  - Existing persistent IPv4 destinations are unchanged regardless of prefix, gateway or metric.
  - Removal selects all routes for the exact prefix, ignoring the supplied gateway.
  - The pinned IPv4-only existence check cannot recognize IPv6 persistent routes.
  - Repeating an identical IPv6 route fails.
  - IPv6 removal reports no route and leaves the route unchanged.
  - IPv6 creation requires an installed IPv6 stack with native persistent routing.
  - On tested Server 2003, an unscoped link-local IPv6 gateway cannot select an interface.
  - On tested XP and Server 2003, new IPv4 routes require a nonzero IPv4 gateway.
  - Those legacy systems reject actual on-link creation but check mode still predicts it.
  - Check mode accepts host bits in a valid prefix; actual creation rejects them.
author:
  - sustainablelobster
"""

EXAMPLES = r"""
- name: Add a documentation-network route
  sustainablelobster.legacy_windows.win_route:
    destination: 192.0.2.0/24
    gateway: 192.168.1.1

- name: Remove the exact route prefix
  sustainablelobster.legacy_windows.win_route:
    destination: 192.0.2.0/24
    state: absent
"""

RETURN = r"""
msg:
  description: Whether the route was added, removed or already in the requested state.
  returned: success
  type: str
  sample: Route added
"""

_MODULE = "sustainablelobster.legacy_windows.win_route"
_PARAMETERS = ("destination", "gateway", "metric", "state")


def _metric(value):
    if value is None:
        return None
    text = as_string(value, "metric").strip(DOTNET_WHITESPACE)
    if not re.match(r"^[+-]?[0-9]+$", text):
        raise ValueError("metric must be a signed 32-bit integer")
    number = int(text)
    if not -(2**31) <= number < 2**31:
        raise ValueError("metric must be a signed 32-bit integer")
    return number


def _parameters(arguments):
    if "destination" not in arguments or arguments["destination"] is None:
        raise ValueError("missing required arguments: destination")
    state = as_string(arguments.get("state", "present"), "state")
    state = state.lower() if state is not None else state
    if state is not None and state not in ("present", "absent"):
        raise ValueError("state must be one of: present, absent")
    return {
        "destination": as_string(arguments["destination"], "destination"),
        "gateway": as_string(arguments.get("gateway", "0.0.0.0"), "gateway"),
        "metric": _metric(arguments.get("metric", 1)),
        "state": state,
    }


def _manage(parameters, check_mode):
    destination = parameters["destination"]
    exists = bool(route.persistent_routes(destination.split("/")[0]))
    present = parameters["state"] == "present"
    if exists == present:
        return {
            "changed": False,
            "msg": "Static route already exists" if present else "No route to remove",
        }
    try:
        if present:
            prepared = route.prepare_add(destination, parameters["gateway"])
            if not check_mode:
                route.add_route(prepared)
        else:
            prepared = route.prepare_remove(destination)
            if not check_mode:
                route.remove_route(prepared)
    except (OSError, ValueError, TypeError) as error:
        prefix = (
            "Failed to create a new route: "
            if present
            else "Failed to remove the requested route: "
        )
        raise OSError(prefix + str(error)) from error
    return {"changed": True, "msg": "Route added" if present else "Route removed"}


def _response():
    arguments = read_arguments(_PARAMETERS, _MODULE)
    return _manage(
        _parameters(arguments),
        as_bool(arguments.get("_ansible_check_mode", False), "_ansible_check_mode"),
    )


def main():
    """Read one Ansible request and report the route operation.

    :raises SystemExit: After emitting one success or failure response.
    """
    run_module(_response)


if __name__ == "__main__":
    main()
