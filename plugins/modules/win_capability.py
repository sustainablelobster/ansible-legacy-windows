#!/usr/bin/python
# -*- coding: utf-8 -*-
# Copyright 2026 sustainablelobster
# SPDX-License-Identifier: GPL-3.0-or-later

"""Manage Windows capabilities through native Python 3.4.4 servicing calls."""

# WANT_JSON

import legacy_windows_capability_manage as capability  # pylint: disable=import-error
from legacy_windows_module import (  # pylint: disable=import-error
    as_bool,
    as_path,
    as_string,
    as_string_list,
    read_arguments,
    run_module,
)

# Ansible interfaces must be self-contained; repeated option/return text is
# interface documentation, not duplicated execution logic.
# pylint: disable=duplicate-code
DOCUMENTATION = r"""
---
module: win_capability
short_description: Manage Windows capabilities
version_added: '1.0.0'
description:
  - Adds or removes capabilities in the running Windows installation.
  - Uses native DISM and Task Scheduler with Python 3.4.4.
options:
  name:
    description:
      - Capability names or wildcard patterns, in supplied order.
      - All patterns are checked before any installation or removal.
      - Use full identifiers including version suffixes on modern Windows.
    type: list
    elements: str
    required: true
  state:
    description: Whether requested capabilities should be present or absent.
    type: str
    choices: [absent, present]
    default: present
  disable_windows_update:
    description: Prevent Windows Update from supplying installation payloads.
    type: bool
    default: false
  source:
    description: Source directories to search for installation payloads.
    type: list
    elements: str
  log_level:
    description:
      - DISM logging level; allowed values are provider-dependent.
      - Zero omits the explicit level and uses the native default.
      - Debug level three is available on Windows 11 and Server 2025 or newer.
    type: int
  log_path:
    description: Optional DISM logging filename; environment variables are expanded.
    type: path
attributes:
  check_mode:
    support: full
    description: Predicts servicing; needed additions still validate a same-user batch logon.
  diff_mode:
    support: none
requirements:
  - Windows with native capability servicing and an elevated connection account.
  - The account must have SeBatchLogonRight when adding capabilities, including check mode.
notes:
  - Never restarts Windows or grants account rights.
  - A failure can leave earlier capabilities changed; no automatic rollback is performed.
  - Removal ignores source and logging options after the preflight query, matching the pinned source.
  - Multi-match patterns select every matching capability, including already-desired states.
author:
  - sustainablelobster
"""

EXAMPLES = r"""
- name: Install the XPS viewer
  sustainablelobster.legacy_windows.win_capability:
    name: XPS.Viewer~~~~0.0.1.0
    state: present

- name: Remove the XPS viewer without restarting Windows
  sustainablelobster.legacy_windows.win_capability:
    name: XPS.Viewer~~~~0.0.1.0
    state: absent
"""

RETURN = r"""
capabilities:
  description: Full identifiers selected for successful servicing, preserving order and duplicates.
  returned: after preflight on success
  type: list
  elements: str
reboot_required:
  description: Whether completed servicing reports a required reboot; false in check mode.
  returned: after argument validation
  type: bool
"""
# pylint: enable=duplicate-code

_PARAMETERS = (
    "disable_windows_update",
    "log_level",
    "log_path",
    "name",
    "source",
    "state",
)


def _log_level(value):
    if value is None:
        return None
    # Each capability interface reports its own argument type labels.
    # pylint: disable=duplicate-code
    if isinstance(value, str):
        kind = "System.String"
    elif isinstance(value, bool):
        kind = "System.Boolean"
    elif isinstance(value, float):
        kind = "System.Decimal"
    elif isinstance(value, int):
        kind = "System.Int32" if -(2**31) <= value < 2**31 else "System.Int64"
    elif isinstance(value, list):
        kind = "System.Object[]"
    else:
        kind = "System.Collections.Generic.Dictionary`2[System.String,System.Object]"
    # pylint: enable=duplicate-code
    detail = "Input string was not in a correct format."
    try:
        # Retain the accepted capability-info CLR Int32 text binding without
        # importing that module's entry point or widening shared helper scope.
        # This local public-option parser does not perform servicing operations.
        # pylint: disable=duplicate-code
        text = as_string(value, "log_level").lstrip(" \t\r\n\v\f")
        text = text.rstrip("\x00").rstrip(" \t\r\n\v\f")
        digits = text[1:] if text.startswith(("+", "-")) else text
        if not digits or any(character not in "0123456789" for character in digits):
            raise ValueError(detail)
        converted = int(text)
        if not -(2**31) <= converted < 2**31:
            detail = "Value was either too large or too small for an Int32."
            raise ValueError(detail)
        # pylint: enable=duplicate-code
        return converted
    except (TypeError, ValueError, OverflowError) as error:
        # Preserve this interface's binding failure without coupling entry points.
        # pylint: disable=duplicate-code
        raise ValueError(
            "argument for log_level is of type "
            + kind
            + " and we were unable to convert to int: "
            + detail
        ) from error
        # pylint: enable=duplicate-code


def _parameters(arguments):
    # Servicing modules bind their own required name and public state options.
    # pylint: disable=duplicate-code
    if "name" not in arguments:
        raise ValueError("missing required arguments: name")
    state = as_string(arguments.get("state", "present"), "state")
    if state is not None and state.lower() not in ("absent", "present"):
        raise ValueError(
            "value of state must be one of: absent, present. Got no match for: " + state
        )
    # pylint: enable=duplicate-code
    update = arguments.get("disable_windows_update", False)
    sources = as_string_list(arguments.get("source"), "source")
    # A one-element array containing an empty string is false in PowerShell.
    if sources == [""]:
        sources = None
    return {
        "names": as_string_list(arguments["name"], "name"),
        "state": state.lower() if state is not None else None,
        "sources": sources,
        "disable_update": (
            as_bool(update, "disable_windows_update") if update is not None else False
        ),
        "log_level": _log_level(arguments.get("log_level")),
        "log_path": as_path(arguments.get("log_path"), "log_path"),
    }


def _manage(options, result, check_mode):
    if not options["names"]:
        return
    level = options["log_level"]
    if level is not None:
        levels = capability.logging_levels()
        if not 0 <= level < len(levels):
            raise ValueError(
                "Cannot bind parameter 'LogLevel'. Cannot convert value \"{0}\" to type "
                '"Microsoft.Dism.Commands.LogLevel" due to enumeration values that '
                "are not valid. Specify one of the following enumeration values "
                "and try again. The possible enumeration values are "
                '"{1}".'.format(level, ",".join(levels))
            )
    names = capability.select(
        options["names"], options["state"], level, options["log_path"]
    )
    if options["state"] == "present" and names:
        try:
            outcome = capability.add_batch(names, options, check_mode)
        except OSError as error:
            # Task startup errors bypass the source's servicing FailJson handler.
            raise ValueError(str(error)) from error
        result["reboot_required"] = outcome["reboot_required"]
        if "failure" in outcome:
            result.update(failed=True, msg=outcome["failure"])
            return
    elif names and not check_mode:
        # The source removes with Online only, not the query's logging options.
        with capability.CapabilitySession() as native:
            for name in names:
                try:
                    reboot = native.remove(name)
                except OSError as error:
                    result.update(
                        failed=True,
                        msg="Failed to remove capability '" + name + "': " + str(error),
                    )
                    return
                result["reboot_required"] = result["reboot_required"] or reboot
    result["changed"] = bool(names)
    result["capabilities"] = names


def execute():
    """Bind the public request and preserve sequential servicing results.

    :returns: Changed flag, selected capabilities, reboot flag or public failure.
    :rtype: dict
    :raises ValueError: Public argument binding fails before servicing.
    """
    arguments = read_arguments(
        _PARAMETERS, "sustainablelobster.legacy_windows.win_capability"
    )
    options = _parameters(arguments)
    result = {"changed": False, "capabilities": [], "reboot_required": False}
    try:
        _manage(
            options,
            result,
            as_bool(arguments.get("_ansible_check_mode", False), "_ansible_check_mode"),
        )
    except LookupError as error:
        result.update(failed=True, msg=str(error))
    except ValueError as error:
        # Provider binding/parsing failures bypass the source's initialized result.
        return {
            "changed": False,
            "failed": True,
            "msg": "Unhandled exception while executing module: " + str(error),
        }
    except OSError as error:
        result.update(failed=True, msg=str(error))
    return result


def main():
    """Run the staged native payload and emit one Ansible JSON result.

    :raises SystemExit: Zero on success or one on public failure.
    """
    run_module(execute)


# Each independently staged payload needs its own executable entry guard.
# pylint: disable=duplicate-code
if __name__ == "__main__":
    main()
# pylint: enable=duplicate-code
