#!/usr/bin/python
# -*- coding: utf-8 -*-
# Copyright 2026 Joe Lustri
# SPDX-License-Identifier: GPL-3.0-or-later

"""Return installed Windows capability metadata using Python 3.4.4."""

# WANT_JSON

# The action stages these Python 3.4-compatible helpers beside the payload.
import legacy_windows_capability as capability  # pylint: disable=import-error
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
module: win_capability_info
short_description: Read information about Windows capabilities
version_added: '1.0.0'
description:
  - Returns capability names, installation states, descriptions, and sizes.
  - Reads the running Windows image through the installed native DISM library.
  - Uses Python 3.4.4 and the Windows API.
options:
  disable_windows_update:
    description:
      - Prevent contacting Windows Update for source files.
      - Metadata queries do not install or download capability payloads.
    type: bool
    default: false
  log_level:
    description:
      - Maximum DISM logging level, managed by the installed Windows provider.
      - Levels are errors (0), warnings (1), information (2), and debug (3).
      - The tested upstream provider rejects debug (3) despite its documentation.
      - As in the pinned source, zero omits the explicit level and uses the provider default.
    type: int
  log_path:
    description:
      - Optional full DISM log filename; environment variables are expanded.
      - Omit this to use the Windows DISM log location.
    type: path
  name:
    description:
      - Alternative capability-name patterns, matched case-insensitively.
      - Supports Windows wildcard characters, including C(*) and C(?).
      - Omitted, null, empty lists, and one empty string return all capabilities.
    type: list
    elements: str
  source:
    description:
      - Source locations accepted by the upstream capability interface.
      - Metadata is read from the online image without installing source payloads.
    type: list
    elements: str
requirements:
  - Windows with the native capability metadata API and an elevated process.
attributes:
  check_mode:
    support: full
    description: Reads the same information without capability changes.
  diff_mode:
    support: none
notes:
  - The upstream module does not support Windows Server 2016.
author:
  - Joe Lustri
"""

EXAMPLES = r"""
- name: Read capabilities related to OpenSSH
  sustainablelobster.legacy_windows.win_capability_info:
    name: OpenSSH.*

- name: Read all capability metadata without changing the image
  sustainablelobster.legacy_windows.win_capability_info:
"""

RETURN = r"""
capabilities:
  description: Matching capabilities, in native enumeration order.
  returned: success
  type: list
  elements: dict
  contains:
    name:
      description: Capability identifier.
      type: str
      returned: always
    state:
      description: Native capability installation state.
      type: str
      returned: always
    display_name:
      description: Human-readable capability name.
      type: str
      returned: always
    description:
      description: Capability description.
      type: str
      returned: always
    download_size:
      description: Download size in bytes.
      type: int
      returned: always
    install_size:
      description: Installation size in bytes.
      type: int
      returned: always
"""
# pylint: enable=duplicate-code

_MODULE_NAME = "sustainablelobster.legacy_windows.win_capability_info"
_PARAMETERS = ("disable_windows_update", "log_level", "log_path", "name", "source")


def _log_level(value):
    if value is None:
        return None
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
    detail = "Input string was not in a correct format."
    try:
        # CLR integer parsing accepts ASCII whitespace and trailing NULs, not
        # Python's broader Unicode whitespace class or embedded NULs.
        text = as_string(value, "log_level").lstrip(" \t\r\n\v\f")
        text = text.rstrip("\x00").rstrip(" \t\r\n\v\f")
        digits = text[1:] if text.startswith(("+", "-")) else text
        if not digits or any(character not in "0123456789" for character in digits):
            raise ValueError(detail)
        converted = int(text)
        if not -(2**31) <= converted < 2**31:
            detail = "Value was either too large or too small for an Int32."
            raise ValueError(detail)
        return converted
    except (TypeError, ValueError, OverflowError) as error:
        raise ValueError(
            "argument for log_level is of type "
            + kind
            + " and we were unable to convert to int: "
            + detail
        ) from error


def execute():
    """Validate the public arguments and return current capability metadata.

    :returns: Unchanged result with matching capability dictionaries.
    :rtype: dict
    :raises ValueError: An argument or reached wildcard is invalid.
    :raises OSError: Native capability metadata is unavailable or cannot be read.
    """
    arguments = read_arguments(_PARAMETERS, _MODULE_NAME)
    # These bindings are public even though native metadata never fetches payloads.
    disable_update = arguments.get("disable_windows_update", False)
    if disable_update is not None:
        as_bool(disable_update, "disable_windows_update")
    as_string_list(arguments.get("source"), "source")
    names = as_string_list(arguments.get("name"), "name")
    # PowerShell considers a one-element collection with an empty string false.
    if names == [""]:
        names = None
    level = _log_level(arguments.get("log_level"))
    path = as_path(arguments.get("log_path"), "log_path")
    if level is not None and level not in (0, 1, 2):
        return {
            "changed": False,
            "failed": True,
            "msg": (
                "Unhandled exception while executing module: Cannot bind parameter "
                "'LogLevel'. Cannot convert value \"{0}\" to type "
                '"Microsoft.Dism.Commands.LogLevel" due to enumeration values that '
                "are not valid. Specify one of the following enumeration values "
                "and try again. The possible enumeration values are "
                '"Errors,Warnings,WarningsInfo".'
            ).format(level),
        }
    try:
        return {
            "changed": False,
            "capabilities": capability.capabilities(names or None, level, path),
        }
    except ValueError as error:
        # This public failure envelope is shared, not the metadata operation.
        # pylint: disable=duplicate-code
        return {
            "changed": False,
            "failed": True,
            "msg": "Unhandled exception while executing module: " + str(error),
        }
        # pylint: enable=duplicate-code


def main():
    """Run the payload using the staged Ansible JSON interface.

    :raises SystemExit: With zero for success or one for failure.
    """
    run_module(execute)


# Each independently staged payload needs its own executable entry guard.
# pylint: disable=duplicate-code
if __name__ == "__main__":
    main()
# pylint: enable=duplicate-code
