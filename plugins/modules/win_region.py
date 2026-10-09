#!/usr/bin/python
# -*- coding: utf-8 -*-
# Copyright 2026 Joe Lustri
# SPDX-License-Identifier: GPL-3.0-or-later

"""Set Windows regional settings using Python 3.4.4 and native interfaces."""

# WANT_JSON

# The action stages the native regional and collation helpers beside this file.
import legacy_windows_environment as environment  # pylint: disable=import-error
import legacy_windows_region as region  # pylint: disable=import-error
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
module: win_region
short_description: Set Windows location and regional formats
version_added: '1.0.0'
description:
  - Sets the current user's geographical location and regional format.
  - Sets the system locale used by non-Unicode applications.
  - Can copy the current user's regional and input settings to default profiles.
  - Uses Python 3.4.4 and native Windows interfaces.
options:
  location:
    description:
      - Geographical identifier for the current user.
      - Supply at least one of O(location), O(format), or O(unicode_language).
    type: str
  format:
    description:
      - Windows culture name for the current user's regional format.
    type: str
  unicode_language:
    description:
      - Windows culture name for the system locale.
      - A change requires a restart; this module never restarts Windows.
    type: str
  copy_settings:
    description:
      - Copies the current format, location, keyboard, and input settings to default profiles only when another setting changes.
    type: bool
    default: false
attributes:
  check_mode:
    support: full
    description: Validates regional settings and predicts changes without writing or loading the default profile hive.
  diff_mode:
    support: none
notes:
  - Names are compared without case; settings are applied in location, format, and system-locale order.
  - Copying settings requires access to the default profile and permission to load its registry hive.
  - Copying preserves the caller's current privilege state; it does not enable disabled privileges. A copy failure can occur after earlier settings were changed.
author:
  - Joe Lustri
"""

EXAMPLES = r"""
- name: Select Australian formats and geographical location
  sustainablelobster.legacy_windows.win_region:
    format: en-AU
    location: 12

- name: Select the non-Unicode system locale
  sustainablelobster.legacy_windows.win_region:
    unicode_language: en-GB
  register: regional_settings
"""

RETURN = r"""
restart_required:
  description: Whether this request applied or predicted a system-locale change requiring a restart.
  returned: success
  type: bool
"""
# pylint: enable=duplicate-code

_MODULE_NAME = "sustainablelobster.legacy_windows.win_region"
_PARAMETERS = ("location", "format", "unicode_language", "copy_settings")


def _failure(result, message):
    result.update({"failed": True, "msg": message})
    return result


def _parameters(arguments):
    return {
        name: as_string(arguments.get(name), name)
        for name in ("location", "format", "unicode_language")
    }


def _manage(parameters, copy_settings, check_mode):
    result = {"changed": False, "restart_required": False}
    if all(value is None for value in parameters.values()):
        return _failure(
            result,
            "An argument for 'format', 'location' or 'unicode_language' needs to be supplied",
        )
    cultures = region.cultures()
    location = parameters["location"]
    if location is not None and not region.valid_location(location, cultures):
        return _failure(
            result,
            "The argument location '" + location + "' does not contain a valid Geo ID",
        )
    for name in ("format", "unicode_language"):
        requested = parameters[name]
        if requested is not None and not any(
            environment.values_equal(requested, culture) for culture in cultures
        ):
            return _failure(
                result,
                "The argument "
                + name
                + " '"
                + requested
                + "' does not contain a valid Culture Name",
            )
    if location is not None and region.change_location(location, check_mode):
        result["changed"] = True
    requested = parameters["format"]
    if requested is not None and not environment.values_equal(
        region.user_locale(), requested
    ):
        region.change_format(requested, check_mode)
        result["changed"] = True
    requested = parameters["unicode_language"]
    if requested is not None and region.change_system_locale(requested, check_mode):
        result.update({"changed": True, "restart_required": True})
    if copy_settings and result["changed"] and not check_mode:
        warnings = region.copy_user_settings()
        if warnings:
            result["warnings"] = warnings
    return result


def _response():
    try:
        arguments = read_arguments(_PARAMETERS, _MODULE_NAME)
        parameters = _parameters(arguments)
        copy_settings = as_bool(arguments.get("copy_settings", False), "copy_settings")
        check_mode = as_bool(
            arguments.get("_ansible_check_mode", False), "_ansible_check_mode"
        )
    except ValueError as error:
        return _failure({"changed": False}, str(error))
    try:
        return _manage(parameters, copy_settings, check_mode)
    except region.HiveLoadError as error:
        return _failure({"changed": False}, str(error))


def main():
    """Read an Ansible request and emit the regional-setting result.

    :raises SystemExit: After reporting success or failure to Ansible.
    """
    run_module(_response)


if __name__ == "__main__":
    main()
