#!/usr/bin/python
# -*- coding: utf-8 -*-
# SPDX-License-Identifier: GPL-3.0-or-later

"""Invoke Windows PowerShell DSC from Python 3.4.4."""

# WANT_JSON

from legacy_windows_dsc import configure_resource  # pylint: disable=import-error
from legacy_windows_module import (  # pylint: disable=import-error
    read_arguments,
    run_module,
)

# Ansible interfaces must be self-contained; repeated option/return text is
# interface documentation, not duplicated execution logic.
# pylint: disable=duplicate-code
DOCUMENTATION = r"""
---
module: win_dsc
short_description: Invoke a classic PowerShell DSC resource
version_added: '1.0.0'
description:
  - Discovers an installed DSC resource and its dynamic property schema.
  - Tests its desired state and invokes Set only when needed outside check mode.
  - The payload uses Python 3.4.4 to call Windows PowerShell DSC.
options:
  resource_name:
    description:
      - Installed non-composite DSC resource name, accessible through the engine's module paths.
      - Composite resources are rejected; this module invokes individual resources, not compiled configurations.
    type: str
    required: true
  module_version:
    description:
      - Select an installed resource version. Omission selects the highest version.
      - The released module fails when C(latest) is explicitly supplied; this behavior is retained.
    type: str
    default: latest
  free_form:
    description:
      - Dynamic resource properties are supplied as task arguments, not a literal free_form option.
      - Embedded instances accept dictionaries; arrays accept lists or comma-separated strings.
      - Credential properties use separate C(_username) and C(_password) arguments.
      - Resource schema validation and engine errors are returned to the caller.
    type: str
    required: true
notes:
  - Requires Windows PowerShell 5.0 or newer, not PowerShell 7, and the classic DSC engine.
  - The default WSMan HTTP listener must already be configured and online.
  - Resources normally run as SYSTEM; C(PsDscRunAsCredential) selects another account.
  - Credential passwords are redacted from this module's returned diagnostics.
  - Windows DSC can retain resource script text and diagnostics in its own history. Do not put secrets in scripts or emit them from resources.
  - This module does not install an engine, alter listeners, or change Local Configuration Manager settings.
author:
  - Joe Lustri
"""

EXAMPLES = r"""
- name: Create an idempotent DSC-managed directory
  sustainablelobster.legacy_windows.win_dsc:
    resource_name: File
    DestinationPath: C:\Example\Directory
    Ensure: Present
    Type: Directory

- name: Select a resource module version
  sustainablelobster.legacy_windows.win_dsc:
    resource_name: CustomResource
    module_version: '1.2.0'
    Name: Example
"""

RETURN = r"""
module_version:
  description: Selected resource module version, or null for a binary resource.
  returned: After successful dynamic argument validation.
  type: str
reboot_required:
  description: Reboot flag returned by Set, or false when Set was not invoked.
  returned: After successful dynamic argument validation.
  type: bool
verbose_test:
  description: Verbose messages produced by the engine Test operation.
  returned: At verbosity three or higher after Test is invoked.
  type: list
  elements: str
verbose_set:
  description: Verbose messages produced by the engine Set operation.
  returned: At verbosity three or higher after Set is invoked.
  type: list
  elements: str
"""
# pylint: enable=duplicate-code


def _response():
    arguments = read_arguments(
        ("resource_name", "module_version"), "win_dsc", allow_unknown=True
    )
    return configure_resource(arguments)


def main():
    """Read dynamic DSC arguments and emit the public resource result.

    :raises SystemExit: After the JSON result is written.
    """
    run_module(_response)


if __name__ == "__main__":
    main()
