#!/usr/bin/python
# -*- coding: utf-8 -*-
# Copyright 2026 sustainablelobster
# SPDX-License-Identifier: GPL-3.0-or-later

"""Select the Windows timezone using Python 3.4.4 and native interfaces."""

# WANT_JSON

import re

# The action stages the native timezone helper beside this payload.
import legacy_windows_environment as environment  # pylint: disable=import-error
import legacy_windows_timezone as timezone  # pylint: disable=import-error
from legacy_windows_module import (  # pylint: disable=import-error
    as_bool,
    as_string,
    read_arguments,
    run_module,
)

# Ansible interfaces must be self-contained; repeated option/return text is
# interface documentation, not duplicated execution logic.
# pylint: disable=duplicate-code
DOCUMENTATION = r"""
---
module: win_timezone
short_description: Select the Windows machine timezone
version_added: '1.0.0'
description:
  - Selects a timezone installed on the Windows target and controls automatic daylight-saving adjustment.
  - Uses Python 3.4.4 and native Windows interfaces.
options:
  timezone:
    description:
      - Installed Windows timezone identifier, such as C(Pacific Standard Time).
      - Append C(_dstoff) to disable automatic daylight-saving adjustment.
    type: str
    required: true
attributes:
  check_mode:
    support: full
    description: Reads and validates the requested timezone without changing the machine setting.
  diff_mode:
    support: full
    description: Returns the previous and requested timezone followed by a newline, including unchanged requests.
notes:
  - Timezone identifiers are compared without case. The result preserves the spelling supplied by the caller.
  - RV(timezone) is the requested value even in check mode; it is not a second read of the machine setting.
  - An explicit null counts as a supplied argument and remains null in RV(timezone).
  - The native utility's full catalogue is used for validation where available. Some values accepted in check mode are rejected when setting the timezone.
author:
  - sustainablelobster
"""

EXAMPLES = r"""
- name: Select Pacific time with automatic daylight-saving adjustment
  sustainablelobster.legacy_windows.win_timezone:
    timezone: Pacific Standard Time

- name: Select Pacific time without automatic daylight-saving adjustment
  sustainablelobster.legacy_windows.win_timezone:
    timezone: Pacific Standard Time_dstoff
"""

RETURN = r"""
previous_timezone:
  description: Machine timezone read before applying or predicting the request.
  returned: success
  type: str
timezone:
  description: Requested timezone, preserving the caller's spelling in normal and check mode.
  returned: success
  type: str
"""
# pylint: enable=duplicate-code

_MODULE_NAME = "sustainablelobster.legacy_windows.win_timezone"
_PARAMETERS = ("timezone",)


def _parameters(arguments):
    if "timezone" not in arguments:
        raise ValueError("missing required arguments: timezone")
    return as_string(arguments["timezone"], "timezone")


def _failure(result, message):
    result.update(
        {"failed": True, "msg": message, "exception": "(traceback unavailable)"}
    )
    return result


def _manage(requested, check_mode=False, diff_mode=False):
    result = {"changed": False, "previous_timezone": None, "timezone": requested}
    requested_text = requested or ""
    try:
        previous = timezone.get_timezone()
        result["previous_timezone"] = previous
        if diff_mode:
            result["diff"] = {"before": previous + "\n", "after": requested_text + "\n"}
        if not environment.values_equal(previous, requested):
            # Upstream removes every case-insensitive occurrence, not just a suffix.
            listed = re.sub("_dstoff", "", requested_text, flags=re.IGNORECASE)
            if not any(
                environment.values_equal(listed, installed)
                for installed in timezone.available_timezones()
            ):
                return _failure(
                    result,
                    "The specified timezone: "
                    + requested_text
                    + " isn't supported on the machine.",
                )
            if not check_mode:
                timezone.set_timezone(requested_text)
            result["changed"] = True
    except timezone.TimeZoneCommandError as error:
        _failure(result, "An error occurred when " + error.action + ".")
        result.update({"stdout": error.stdout, "stderr": error.stderr, "rc": error.rc})
    return result


def _response():
    try:
        # Each module binds core's check/diff flags before its own operation.
        # pylint: disable=duplicate-code
        arguments = read_arguments(_PARAMETERS, _MODULE_NAME)
        requested = _parameters(arguments)
        check_mode = as_bool(
            arguments.get("_ansible_check_mode", False), "_ansible_check_mode"
        )
        diff_mode = as_bool(arguments.get("_ansible_diff", False), "_ansible_diff")
        # pylint: enable=duplicate-code
    except ValueError as error:
        # Validation failures use the common unchanged Ansible failure envelope.
        # pylint: disable=duplicate-code
        return _failure({"changed": False}, str(error))
        # pylint: enable=duplicate-code
    return _manage(requested, check_mode, diff_mode)


def main():
    """Read an Ansible request and emit the timezone module's JSON result.

    :raises SystemExit: After reporting success or failure to Ansible.
    """
    run_module(_response)


# Each independently staged payload needs its own executable entry guard.
# pylint: disable=duplicate-code
if __name__ == "__main__":
    main()
# pylint: enable=duplicate-code
