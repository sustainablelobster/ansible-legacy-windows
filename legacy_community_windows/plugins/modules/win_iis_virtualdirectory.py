#!/usr/bin/python
# -*- coding: utf-8 -*-
# Copyright: (c) 2015, Henrik Wallström <henrik@wallstroms.nu>
# Copyright 2026 sustainablelobster
# SPDX-License-Identifier: GPL-3.0-or-later

"""Manage installed native IIS capabilities with the released module interface."""

# WANT_JSON

from legacy_community_windows_iis import manage  # pylint: disable=import-error
from legacy_windows_module import (  # pylint: disable=import-error
    read_arguments,
    run_module,
)

# Released Ansible interface documentation intentionally repeats shared option prose.
# pylint: disable=duplicate-code
DOCUMENTATION = r"""
---
module: win_iis_virtualdirectory
short_description: Configures a virtual directory in IIS
description:
     - Creates, Removes and configures a virtual directory in IIS.
deprecated:
  removed_in: 4.0.0
  why: >-
    This module has been deprecated and an alternative supported module is available in the C(microsoft.iis) collection.
  alternative: Use C(microsoft.iis.virtual_directory) instead.
options:
  name:
    description:
      - The name of the virtual directory to create or remove.
    type: str
    required: yes
  state:
    description:
      - Whether to add or remove the specified virtual directory.
      - Removing will remove the virtual directory and all under it (Recursively).
    type: str
    choices: [ absent, present ]
    default: present
  site:
    description:
      - The site name under which the virtual directory is created or exists.
    type: str
    required: yes
  application:
    description:
      - The application under which the virtual directory is created or exists.
    type: str
  physical_path:
    description:
      - The physical path to the folder in which the new virtual directory is created.
      - The specified folder must already exist.
    type: str
  connect_as:
    description:
    - The type of authentication to use for the virtual directory. Either C(pass_through) or C(specific_user)
    - If C(pass_through), IIS will use the identity of the user or application pool identity to access the physical path.
    - If C(specific_user), IIS will use the credentials provided in I(username) and I(password) to access the physical path.
    type: str
    choices: [pass_through, specific_user]
    version_added: 1.0.0
  username:
    description:
    - Specifies the user name of an account that can access configuration files and content for the virtual directory.
    - Required when I(connect_as) is set to C(specific_user).
    type: str
    version_added: 1.0.0
  password:
    description:
    - The password associated with I(username).
    - Required when I(connect_as) is set to C(specific_user).
    type: str
    version_added: 1.0.0
notes:
  - Requires an existing IIS site and parent application, native management access and an existing physical content directory.
  - Check mode is not supported, matching the released interface.
seealso:
- module: sustainablelobster.legacy_community_windows.win_iis_webapplication
- module: sustainablelobster.legacy_community_windows.win_iis_webapppool
- module: sustainablelobster.legacy_community_windows.win_iis_webbinding
- module: sustainablelobster.legacy_community_windows.win_iis_website
author:
- sustainablelobster
- Henrik Wallström (@henrikwallstrom)
"""

EXAMPLES = r"""
- name: Create a virtual directory if it does not exist
  sustainablelobster.legacy_community_windows.win_iis_virtualdirectory:
    name: somedirectory
    site: somesite
    state: present
    physical_path: C:\virtualdirectory\some

- name: Remove a virtual directory if it exists
  sustainablelobster.legacy_community_windows.win_iis_virtualdirectory:
    name: somedirectory
    site: somesite
    state: absent

- name: Create a virtual directory on an application if it does not exist
  sustainablelobster.legacy_community_windows.win_iis_virtualdirectory:
    name: somedirectory
    site: somesite
    application: someapp
    state: present
    physical_path: C:\virtualdirectory\some
"""

# pylint: enable=duplicate-code


# Released interfaces share these option names; keeping each explicit avoids a
# second contract registry for simple public argument normalization.
# pylint: disable=duplicate-code
_PARAMETERS = (
    "application",
    "connect_as",
    "name",
    "password",
    "physical_path",
    "site",
    "state",
    "username",
)


# pylint: enable=duplicate-code


def main():
    """Execute the native IIS management request and return JSON."""
    run_module(
        lambda: manage(
            "win_iis_virtualdirectory",
            read_arguments(
                _PARAMETERS,
                "sustainablelobster.legacy_community_windows.win_iis_virtualdirectory",
                allow_unknown=True,
            ),
        )
    )


if __name__ == "__main__":
    main()
