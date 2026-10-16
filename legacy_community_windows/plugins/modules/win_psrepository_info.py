#!/usr/bin/python
# -*- coding: utf-8 -*-
# Copyright: (c) 2020, Brian Scholer <@briantist>
# Copyright 2026 sustainablelobster
# SPDX-License-Identifier: GPL-3.0-or-later

"""Query installed PowerShellGet data through its vendor engine."""

# WANT_JSON

# The action stages the fixed vendor engine boundary beside this Python payload.
from legacy_community_windows_psget_engine import invoke  # pylint: disable=import-error
from legacy_windows_module import (  # pylint: disable=import-error
    as_string,
    read_arguments,
    run_module,
)

# Released interfaces and fixed vendor serializers intentionally repeat their
# field definitions; introducing formatting templates would obscure the contracts.
# pylint: disable=duplicate-code
DOCUMENTATION = r"""
---
module: win_psrepository_info
short_description: Gather information about PSRepositories
description:
  - Gather information about all or a specific PSRepository.
options:
  name:
    description:
      - The name of the repository to retrieve.
      - Supports any wildcard pattern supported by C(Get-PSRepository).
      - If omitted then all repositories will returned.
    type: str
    default: '*'
requirements:
  - C(PowerShellGet) module
seealso:
  - module: sustainablelobster.legacy_community_windows.win_psrepository
author:
  - Brian Scholer (@briantist)
"""

EXAMPLES = r"""
- name: Get info for a single repository
  sustainablelobster.legacy_community_windows.win_psrepository_info:
    name: PSGallery
  register: repo_info

- name: Find all repositories that start with 'MyCompany'
  sustainablelobster.legacy_community_windows.win_psrepository_info:
    name: MyCompany*

- name: Get info for all repositories
  sustainablelobster.legacy_community_windows.win_psrepository_info:
  register: repo_info

- name: Remove all repositories that don't have a publish_location set
  sustainablelobster.legacy_community_windows.win_psrepository:
    name: "{{ item.name }}"
    state: absent
  loop: >-
    {{ repo_info.repositories |
       selectattr('publish_location', 'none') | list }}
"""

RETURN = r"""
repositories:
  description:
    - A list of repositories (or an empty list is there are none).
  returned: always
  type: list
  elements: dict
  contains:
    name:
      description:
        - The name of the repository.
      type: str
      sample: PSGallery
    installation_policy:
      description:
        - The installation policy of the repository. The sample values are the only possible values.
      type: str
      sample:
        - Trusted
        - Untrusted
    trusted:
      description:
        - A boolean flag reflecting the value of C(installation_policy) as to whether the repository is trusted.
      type: bool
    package_management_provider:
      description:
        - The name of the package management provider for this repository.
      type: str
      sample: NuGet
    provider_options:
      description:
        - Provider-specific options for this repository.
      type: dict
    source_location:
      description:
        - The location used to find and retrieve modules. This should always have a value.
      type: str
      sample: https://www.powershellgallery.com/api/v2
    publish_location:
      description:
        - The location used to publish modules.
      type: str
      sample: https://www.powershellgallery.com/api/v2/package/
    script_source_location:
      description:
        - The location used to find and retrieve scripts.
      type: str
      sample: https://www.powershellgallery.com/api/v2/items/psscript
    script_publish_location:
      description:
        - The location used to publish scripts.
      type: str
      sample: https://www.powershellgallery.com/api/v2/package/
    registered:
      description:
        - Whether the module is registered. Should always be C(True)
      type: bool
"""

_OPERATION = r"""
Import-Module PowerShellGet -ErrorAction Stop
Enable-TlsProtocol
@{ changed = $false; repositories = @(Get-PSRepository -Name $p.name | Convert-ObjectToSnakeCase) }
"""


# pylint: enable=duplicate-code


def _execute(arguments):
    parameters = {"name": as_string(arguments.get("name", "*"), "name")}
    return invoke(_OPERATION, parameters)


def main():
    """Read module options and return the installed vendor's information."""
    run_module(
        lambda: _execute(
            read_arguments(
                ("name",),
                "sustainablelobster.legacy_community_windows.win_psrepository_info",
            )
        )
    )


if __name__ == "__main__":
    main()
