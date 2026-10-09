#!/usr/bin/python
# -*- coding: utf-8 -*-
# Copyright 2026 Joe Lustri
# SPDX-License-Identifier: GPL-3.0-or-later

"""Collect Windows facts with Python 3.4.4 and native interfaces."""

# WANT_JSON

import legacy_windows_setup as setup  # pylint: disable=import-error
from legacy_windows_module import (  # pylint: disable=import-error
    as_bool,
    as_path,
    as_string,
    as_string_list,
    read_arguments,
    run_module,
)

# Ansible requires each module's own complete check/diff attribute declaration.
# Sharing YAML fragments would make its published interface less readable.
# pylint: disable=duplicate-code
DOCUMENTATION = r"""
---
module: setup
short_description: Gather facts about Windows hosts
version_added: '1.0.0'
description:
  - Gathers Windows facts through Python 3.4.4-compatible payloads and native Windows interfaces.
  - Preserves the released subset selection and accepts additional gather-facts arguments without interpreting them.
options:
  gather_subset:
    description:
      - Select or exclude fact subsets, including C(min), C(network), C(hardware), C(external), and C(all).
      - Prefix exclusions with C(!). Use C(!all,!min) to collect only explicitly included subsets.
    type: list
    elements: str
    default: all
  gather_timeout:
    description: Timeout in seconds for each independent fact collector.
    type: int
    default: 10
  fact_path:
    description:
      - Directory of custom C(.json) facts and explicitly supplied C(.ps1) fact scripts.
      - C(.ps1) fact scripts require PowerShell.
    type: path
  _measure_subset:
    description: Include individual collector durations for internal diagnostics.
    type: bool
    default: false
attributes:
  check_mode:
    support: full
    description: Gathers the same facts without reporting changes; custom scripts still execute.
  diff_mode:
    support: none
notes:
  - Individual collector failures or timeouts return warnings alongside available facts.
  - On systems without nested process jobs, collectors require native WMI process creation when the connection job forbids breakaway.
  - The accepted C(dns) subset has no separate collector in the selected upstream release.
  - The PowerShell version fact reads the installed Windows PowerShell engine version without starting it.
  - WinRM certificate facts read the local WSMan configuration and machine certificate store without configuring listeners.
author:
  - Joe Lustri
"""

# pylint: enable=duplicate-code

# Ansible interfaces must be self-contained; repeated option/return text is
# interface documentation, not duplicated execution logic.
# pylint: disable=duplicate-code
EXAMPLES = r"""
- name: Gather native Windows facts
  sustainablelobster.legacy_windows.setup:

- name: Gather only distribution and domain facts
  sustainablelobster.legacy_windows.setup:
    gather_subset: ['!all', '!min', distribution, windows_domain]
"""

RETURN = r"""
ansible_facts:
  description: Selected Windows facts, the original subset request, and module_setup=true.
  returned: success
  type: dict
"""
# pylint: enable=duplicate-code


def _timeout(value):
    # Keep this public Hashtable diagnostic and lexical overflow handling local;
    # the DSC and PowerShell binders have different null and dictionary rules.
    # pylint: disable=duplicate-code
    if value is None or isinstance(value, int) and not isinstance(value, bool):
        if value is None or -(2**31) <= value < 2**31:
            return value
    if isinstance(value, str):
        kind = "System.String"
    elif isinstance(value, bool):
        kind = "System.Boolean"
    elif isinstance(value, float):
        kind = "System.Double" if "e" in repr(value) else "System.Decimal"
    elif isinstance(value, int):
        if -(2**63) <= value < 2**63:
            kind = "System.Int64"
        else:
            kind = (
                "System.Decimal"
                if abs(value) <= 79228162514264337593543950335
                else "System.Double"
            )
    elif isinstance(value, list):
        kind = "System.Object[]"
    else:
        kind = "System.Collections.Hashtable"

    # Basic's Int32 parser permits only ASCII whitespace, followed by optional
    # trailing nulls. Unicode whitespace and nulls before whitespace are invalid.
    text = as_string(value, "gather_timeout").lstrip(" \t\r\n\v\f")
    text = text.rstrip("\x00").rstrip(" \t\r\n\v\f")
    digits = text[1:] if text.startswith(("+", "-")) else text
    detail = "Input string was not in a correct format."
    if digits and all(character in "0123456789" for character in digits):
        # Strip leading zeroes before conversion so very long overflowing text
        # has the same result on target Python 3.4 and modern test interpreters.
        magnitude = digits.lstrip("0") or "0"
        limit = "2147483648" if text.startswith("-") else "2147483647"
        if len(magnitude) < len(limit) or (
            len(magnitude) == len(limit) and magnitude <= limit
        ):
            return -int(magnitude) if text.startswith("-") else int(magnitude)
        detail = "Value was either too large or too small for an Int32."
    raise ValueError(
        "argument for gather_timeout is of type {0} and we were unable to "
        "convert to int: {1}".format(kind, detail)
    )


def _parameters(arguments):
    unsupported = sorted(
        name
        for name in arguments
        if name.startswith("_")
        and name != "_measure_subset"
        and not name.startswith("_ansible_")
    )
    if unsupported and not as_bool(
        arguments.get("_ansible_ignore_unknown_opts", False),
        "_ansible_ignore_unknown_opts",
    ):
        raise ValueError(
            "Unsupported parameters for (sustainablelobster.legacy_windows.setup) module: "
            + ", ".join(unsupported)
            + ". Supported parameters include: _measure_subset, fact_path, "
            "gather_subset, gather_timeout"
        )
    timeout = _timeout(arguments.get("gather_timeout", 10))
    measure = arguments.get("_measure_subset", False)
    return {
        "gather_subset": as_string_list(
            arguments.get("gather_subset", ["all"]), "gather_subset"
        ),
        "gather_timeout": timeout,
        "fact_path": as_path(arguments.get("fact_path"), "fact_path"),
        "_measure_subset": (
            None if measure is None else as_bool(measure, "_measure_subset")
        ),
    }


def _response():
    arguments = read_arguments(
        ("gather_subset", "gather_timeout", "fact_path", "_measure_subset"),
        "sustainablelobster.legacy_windows.setup",
        allow_unknown=True,
    )
    parameters = _parameters(arguments)
    warnings = []
    facts = setup.read_facts(parameters, warnings)
    result = {"changed": False, "ansible_facts": facts}
    if warnings:
        result["warnings"] = warnings
    if as_bool(
        arguments.get("_ansible_inject_invocation", False), "_ansible_inject_invocation"
    ):
        invocation = dict(arguments)
        invocation.update(parameters)
        result["invocation"] = {
            "module_args": {
                key: value
                for key, value in invocation.items()
                if not key.startswith("_ansible_")
            }
        }
    return result


def main():
    """Emit selected Windows facts as an Ansible JSON result.

    :raises SystemExit: After emitting success or failure.
    """
    run_module(_response)


if __name__ == "__main__":
    main()
