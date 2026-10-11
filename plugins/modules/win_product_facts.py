#!/usr/bin/python
# -*- coding: utf-8 -*-
# Copyright 2026 sustainablelobster
# SPDX-License-Identifier: GPL-3.0-or-later

"""Read Windows product and license facts using Python 3.4.4."""

# WANT_JSON

import legacy_windows_product as product  # pylint: disable=import-error
from legacy_windows_module import (  # pylint: disable=import-error
    as_bool,
    read_arguments,
    run_module,
)

# Ansible interfaces must be self-contained; repeated option/return text is
# interface documentation, not duplicated execution logic.
# pylint: disable=duplicate-code
DOCUMENTATION = r"""
---
module: win_product_facts
short_description: Read Windows product and license information
version_added: '1.0.0'
description:
  - Returns Windows product identification, product key, and license information as Ansible facts.
  - Uses Python 3.4.4 and native Windows interfaces.
options: {}
attributes:
  check_mode:
    support: full
    description: Reads the same information as a normal invocation and reports no changes.
  diff_mode:
    support: none
notes:
  - Product keys are sensitive. Use C(no_log=true) on this task and any task that displays or processes its results.
  - Returned facts can also be stored by fact caching; protect or disable that storage when collecting product keys.
  - License fields retain the provider's enumeration order. They can be null, a string, or a list when more than one Windows license is returned.
  - On pre-Vista Windows without the modern licensing provider, license edition, channel, and status are null with named warnings; available product identification is still returned.
  - If the licensing provider lacks C(ProductKeyChannel), matching licenses retain their available edition and status, with null channel values and a named warning.
  - On Vista, licensing queries require the Software Licensing service (C(slsvc)) to be running. This read-only module does not start services.
  - Permission and service failures while enumerating licenses fail the task without returning partial facts; they are not treated as unsupported fields.
  - This implementation only reads product and license information; it does not activate Windows or change its license.
author:
  - sustainablelobster
"""

EXAMPLES = r"""
- name: Read Windows product and license facts without logging sensitive keys
  sustainablelobster.legacy_windows.win_product_facts:
  no_log: true
"""

RETURN = r"""
ansible_facts:
  description: Windows product and license information.
  returned: success
  type: dict
  contains:
    ansible_os_product_id:
      description: Product identifier reported by Windows, or null if unavailable.
      type: raw
    ansible_os_product_key:
      description: Sensitive product key from the licensing provider or registry, or null if unavailable.
      type: raw
    ansible_os_license_edition:
      description: Windows license names, retaining null, a string, or a list as returned by the provider.
      type: raw
    ansible_os_license_channel:
      description: License channels, retaining null, a string, or a list as returned by the provider.
      type: raw
    ansible_os_license_status:
      description: License status names, retaining null, a string, or a list when multiple status names are returned.
      type: raw
"""
# pylint: enable=duplicate-code

_MODULE_NAME = "sustainablelobster.legacy_windows.win_product_facts"


def _response():
    arguments = read_arguments((), _MODULE_NAME)
    warnings = []
    facts = product.read_facts(warnings)
    # Fact readers share the unchanged/warning/invocation envelope, not readers.
    # pylint: disable=duplicate-code
    result = {"changed": False, "ansible_facts": facts}
    if warnings:
        result["warnings"] = warnings
    if as_bool(
        arguments.get("_ansible_inject_invocation", False), "_ansible_inject_invocation"
    ):
        result["invocation"] = {"module_args": {}}
    # pylint: enable=duplicate-code
    return result


def main():
    """Emit Windows product and license facts as an Ansible JSON result.

    :raises SystemExit: After reporting success or failure.
    """
    run_module(_response)


# Each independently staged payload needs its own executable entry guard.
# pylint: disable=duplicate-code
if __name__ == "__main__":
    main()
# pylint: enable=duplicate-code
