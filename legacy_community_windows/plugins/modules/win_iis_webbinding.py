#!/usr/bin/python
# -*- coding: utf-8 -*-
# Copyright: (c) 2017, Noah Sparks <nsparks@outlook.com>
# Copyright: (c) 2017, Henrik Wallström <henrik@wallstroms.nu>
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
module: win_iis_webbinding
short_description: Configures a IIS Web site binding
description:
     - Creates, removes and configures a binding to an existing IIS Web site.
deprecated:
    removed_in: 4.0.0
    why: >-
      This module has been deprecated and an alternative supported module is available in the C(microsoft.iis) collection.
    alternative: Use C(microsoft.iis.website) instead.
options:
  name:
    description:
      - Names of web site.
    type: str
    required: yes
    aliases: [ website ]
  state:
    description:
      - State of the binding.
    type: str
    choices: [ absent, present ]
    default: present
  port:
    description:
      - The port to bind to / use for the new site.
    type: int
    default: 80
  ip:
    description:
      - The IP address to bind to / use for the new site.
    type: str
    default: '*'
  host_header:
    description:
      - The host header to bind to / use for the new site.
      - If you are creating/removing a catch-all binding, omit this parameter rather than defining it as '*'.
    type: str
  protocol:
    description:
      - The protocol to be used for the Web binding (usually HTTP, HTTPS, or FTP).
    type: str
    default: http
  certificate_hash:
    description:
      - Certificate hash (thumbprint) for the SSL binding. The certificate hash is the unique identifier for the certificate.
    type: str
  certificate_store_name:
    description:
      - Name of the certificate store where the certificate for the binding is located.
    type: str
    default: my
  ssl_flags:
    description:
      - This parameter is only valid on Server 2012 and newer.
      - Primarily used for enabling and disabling server name indication (SNI).
      - Set to C(0) to disable SNI.
      - Set to C(1) to enable SNI.
    type: str
notes:
  - Requires installed IIS native binding management and administrative access.
  - SNI and central certificate store flags require those capabilities in the installed IIS binding schema.
  - Certificates are selected from LocalMachine stores; HTTPS endpoint assignment uses the native HTTP Server API.
  - Removing an IIS7-style binding retains its HTTP.sys certificate assignment, matching upstream behavior.
seealso:
- module: sustainablelobster.legacy_community_windows.win_iis_virtualdirectory
- module: sustainablelobster.legacy_community_windows.win_iis_webapplication
- module: sustainablelobster.legacy_community_windows.win_iis_webapppool
- module: sustainablelobster.legacy_community_windows.win_iis_website
author:
- sustainablelobster
  - Noah Sparks (@nwsparks)
  - Henrik Wallström (@henrikwallstrom)
"""

EXAMPLES = r"""
- name: Add a HTTP binding on port 9090
  sustainablelobster.legacy_community_windows.win_iis_webbinding:
    name: Default Web Site
    port: 9090
    state: present

- name: Remove the HTTP binding on port 9090
  sustainablelobster.legacy_community_windows.win_iis_webbinding:
    name: Default Web Site
    port: 9090
    state: absent

- name: Remove the default http binding
  sustainablelobster.legacy_community_windows.win_iis_webbinding:
    name: Default Web Site
    port: 80
    ip: '*'
    state: absent

- name: Add a HTTPS binding
  sustainablelobster.legacy_community_windows.win_iis_webbinding:
    name: Default Web Site
    protocol: https
    port: 443
    ip: 127.0.0.1
    certificate_hash: B0D0FA8408FC67B230338FCA584D03792DA73F4C
    state: present

- name: Add a HTTPS binding with host header and SNI enabled
  sustainablelobster.legacy_community_windows.win_iis_webbinding:
    name: Default Web Site
    protocol: https
    port: 443
    host_header: test.com
    ssl_flags: 1
    certificate_hash: D1A3AF8988FD32D1A3AF8988FD323792DA73F4C
    state: present
"""

RETURN = r"""
website_state:
  description:
    - The state of the website being targeted
    - Can be helpful in case you accidentally cause a binding collision
      which can result in the targeted site being stopped
  returned: always
  type: str
  sample: "Started"
operation_type:
  description:
    - The type of operation performed
    - Can be removed, updated, matched, or added
  returned: on success
  type: str
  sample: "removed"
binding_info:
  description:
    - Information on the binding being manipulated
  returned: on success
  type: dict
  sample: |-
    "binding_info": {
      "bindingInformation": "127.0.0.1:443:",
      "certificateHash": "FF3910CE089397F1B5A77EB7BAFDD8F44CDE77DD",
      "certificateStoreName": "MY",
      "hostheader": "",
      "ip": "127.0.0.1",
      "port": 443,
      "protocol": "https",
      "sslFlags": "not supported"
    }
"""

# pylint: enable=duplicate-code


# Released interfaces share these option names; keeping each explicit avoids a
# second contract registry for simple public argument normalization.
# pylint: disable=duplicate-code
_PARAMETERS = (
    "certificate_hash",
    "certificate_store_name",
    "host_header",
    "ip",
    "name",
    "port",
    "protocol",
    "ssl_flags",
    "state",
    "website",
)


# pylint: enable=duplicate-code


def main():
    """Execute the native IIS management request and return JSON."""
    run_module(
        lambda: manage(
            "win_iis_webbinding",
            read_arguments(
                _PARAMETERS,
                "sustainablelobster.legacy_community_windows.win_iis_webbinding",
                allow_unknown=True,
            ),
        )
    )


if __name__ == "__main__":
    main()
