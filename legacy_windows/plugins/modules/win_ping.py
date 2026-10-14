#!/usr/bin/python
# -*- coding: utf-8 -*-
# Copyright 2026 sustainablelobster
# SPDX-License-Identifier: GPL-3.0-or-later

"""Return a connectivity response through Ansible's JSON argument-file protocol."""

# WANT_JSON

# The action plugin stages this helper beside the payload on Windows.
from legacy_windows_module import (  # pylint: disable=import-error
    as_bool,
    as_string,
    read_arguments,
    run_module,
)

DOCUMENTATION = r"""
---
module: win_ping
short_description: Verify that a Windows Python payload can run
version_added: '1.0.0'
description:
  - Runs a Python payload on the target and returns a small response.
  - This checks the configured Ansible connection and interpreter, not ICMP.
  - The target payload requires Python 3.4.4 or newer.
options:
  data:
    description:
      - Text to return in the C(ping) result.
      - An explicitly supplied null value is returned as null.
      - The value C(crash), matched without regard to case, triggers a failure.
    type: str
    default: pong
attributes:
  check_mode:
    support: full
    description: Returns the same response in check mode without changing the target.
  diff_mode:
    support: none
author:
  - sustainablelobster
"""

EXAMPLES = r"""
- name: Check the Windows connection and Python interpreter
  sustainablelobster.legacy_windows.win_ping:

- name: Return a custom response
  sustainablelobster.legacy_windows.win_ping:
    data: connected

- name: Exercise module failure handling
  sustainablelobster.legacy_windows.win_ping:
    data: crash
"""

RETURN = r"""
ping:
  description: The supplied data value, or C(pong) when data was omitted.
  returned: success
  type: str
  sample: pong
"""


def _response():
    arguments = read_arguments(("data",), "sustainablelobster.legacy_windows.win_ping")
    data = as_string(arguments.get("data", "pong"), "data")
    if data is not None and data.lower() == "crash":
        raise RuntimeError("boom")

    result = {"changed": False, "ping": data}
    if as_bool(
        arguments.get("_ansible_inject_invocation", False), "_ansible_inject_invocation"
    ):
        invocation = {
            name: value
            for name, value in arguments.items()
            if not name.startswith("_ansible_")
        }
        invocation["data"] = data
        result["invocation"] = {"module_args": invocation}
    return result


def main():
    """Read Ansible arguments and write a JSON result to standard output.

    :raises SystemExit: After reporting success or failure to Ansible.
    """
    run_module(_response)


if __name__ == "__main__":
    main()
