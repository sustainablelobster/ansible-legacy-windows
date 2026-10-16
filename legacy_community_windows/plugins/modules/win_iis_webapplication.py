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
module: win_iis_webapplication
short_description: Configures IIS web applications
description:
- Creates, removes, and configures IIS web applications.
deprecated:
  removed_in: 4.0.0
  why: >-
    This module has been deprecated and an alternative supported module is available in the C(microsoft.iis) collection.
  alternative: Use C(microsoft.iis.web_application) instead.
options:
  name:
    description:
    - Name of the web application.
    type: str
    required: yes
  site:
    description:
    - Name of the site on which the application is created.
    type: str
    required: yes
  state:
    description:
    - State of the web application.
    type: str
    choices: [ absent, present ]
    default: present
  physical_path:
    description:
    - The physical path on the remote host to use for the new application.
    - The specified folder must already exist.
    type: str
  application_pool:
    description:
    - The application pool in which the new site executes.
    - If not specified, the application pool of the current website will be used.
    type: str
  connect_as:
    description:
    - The type of authentication to use for this application. Either C(pass_through) or C(specific_user)
    - If C(pass_through), IIS will use the identity of the user or application pool identity to access the file system or network.
    - If C(specific_user), IIS will use the credentials provided in I(username) and I(password) to access the file system or network.
    type: str
    choices: [pass_through, specific_user]
  username:
    description:
    - Specifies the user name of an account that can access configuration files and content for this application.
    - Required when I(connect_as) is set to C(specific_user).
    type: str
  password:
    description:
    - The password associated with I(username).
    - Required when I(connect_as) is set to C(specific_user).
    type: str
notes:
  - Requires an existing IIS site, native management access and an existing physical content directory.
  - Connect-as credentials are applied to the application root virtual directory.
  - Check mode validates configuration without persisting it.
seealso:
- module: sustainablelobster.legacy_community_windows.win_iis_virtualdirectory
- module: sustainablelobster.legacy_community_windows.win_iis_webapppool
- module: sustainablelobster.legacy_community_windows.win_iis_webbinding
- module: sustainablelobster.legacy_community_windows.win_iis_website
author:
- sustainablelobster
- Henrik Wallström (@henrikwallstrom)
"""

EXAMPLES = r"""
- name: Add ACME webapplication on IIS.
  sustainablelobster.legacy_community_windows.win_iis_webapplication:
    name: api
    site: acme
    state: present
    physical_path: C:\apps\acme\api
"""

RETURN = r"""
application_pool:
    description: The used/implemented application_pool value.
    returned: success
    type: str
    sample: DefaultAppPool
physical_path:
    description: The used/implemented physical_path value.
    returned: success
    type: str
    sample: C:\apps\acme\api
connect_as:
    description: How IIS will try to authenticate to the physical_path.
    returned: when the application exists
    type: str
    sample: specific_user
"""

# pylint: enable=duplicate-code


# Released interfaces share these option names; keeping each explicit avoids a
# second contract registry for simple public argument normalization.
# pylint: disable=duplicate-code
_PARAMETERS = (
    "application_pool",
    "connect_as",
    "name",
    "password",
    "physical_path",
    "site",
    "state",
    "username",
    "path",
)


# pylint: enable=duplicate-code


def main():
    """Execute the native IIS management request and return JSON."""
    run_module(
        lambda: manage(
            "win_iis_webapplication",
            read_arguments(
                _PARAMETERS,
                "sustainablelobster.legacy_community_windows.win_iis_webapplication",
                allow_unknown=True,
            ),
        )
    )


if __name__ == "__main__":
    main()
