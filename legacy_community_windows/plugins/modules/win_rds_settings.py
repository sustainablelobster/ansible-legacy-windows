#!/usr/bin/python
# -*- coding: utf-8 -*-
# Copyright: (c) 2018, Kevin Subileau (@ksubileau)
# Copyright 2026 sustainablelobster
# SPDX-License-Identifier: GPL-3.0-or-later

"""Manage native Remote Desktop Gateway configuration."""

# WANT_JSON

from legacy_community_windows_rds import manage  # pylint: disable=import-error
from legacy_windows_module import (  # pylint: disable=import-error
    read_arguments,
    run_module,
)

# The released gateway interfaces share their option prose and examples.
# pylint: disable=duplicate-code
DOCUMENTATION = r"""
---
module: win_rds_settings
short_description: Manage main settings of a Remote Desktop Gateway server
description:
  - Configure general settings of a Remote Desktop Gateway server.
author:
  - sustainablelobster
  - Kevin Subileau (@ksubileau)
options:
  certificate_hash:
    description:
      - Certificate hash (thumbprint) for the Remote Desktop Gateway server. The certificate hash is the unique identifier for the certificate.
    type: str
  max_connections:
    description:
      - The maximum number of connections allowed.
      - If set to C(0), no new connections are allowed.
      - If set to C(-1), the number of connections is unlimited.
      - A value equal to the gateway's installed SKU maximum is also treated as unlimited, matching the released gateway provider.
    type: int
  ssl_bridging:
    description:
      - Specifies whether to use SSL Bridging.
      - 'C(none): no SSL bridging.'
      - 'C(https_http): HTTPS-HTTP bridging.'
      - 'C(https_https): HTTPS-HTTPS bridging.'
    type: str
    choices: [ https_http, https_https, none ]
  enable_only_messaging_capable_clients:
    description:
      - If enabled, only clients that support logon messages and administrator messages can connect.
    type: bool
requirements:
  - The installed Remote Desktop Gateway WMI provider in C(root/CIMv2/TerminalServices).
  - Administrative permission to manage the local gateway.
  - Certificates must be suitable for gateway server authentication, include their private key, and be installed in C(LocalMachine/My).
notes:
  - Uses installed gateway capabilities rather than excluding whole Windows versions. An unavailable requested property or method fails before writes.
  - Check mode validates requests and predicts changes without modifying gateway policies or settings.
  - Certificate and SSL bridging changes can require restarting the gateway service; the module does not restart it.
  - An explicit C(certificate_hash) request always finalizes native gateway configuration, including when the hash already matches, to recover interrupted assignments.
  - Repeated certificate finalization is idempotent. Change reporting uses the certificate hash and the native gateway configured state; check mode never finalizes configuration.
seealso:
- module: community.windows.win_rds_cap
- module: community.windows.win_rds_rap
- module: community.windows.win_rds_settings
"""

EXAMPLES = r"""
- name: Configure the Remote Desktop Gateway
  sustainablelobster.legacy_community_windows.win_rds_settings:
    certificate_hash: B0D0FA8408FC67B230338FCA584D03792DA73F4C
    max_connections: 50
  notify:
    - Restart TSGateway service
"""

RETURN = r"""
"""


_PARAMETERS = (
    "certificate_hash",
    "enable_only_messaging_capable_clients",
    "max_connections",
    "ssl_bridging",
)


# pylint: enable=duplicate-code


def main():
    """Execute the native gateway request and return JSON."""
    run_module(
        lambda: manage(
            "win_rds_settings",
            read_arguments(
                _PARAMETERS,
                "sustainablelobster.legacy_community_windows.win_rds_settings",
                allow_unknown=True,
            ),
        )
    )


if __name__ == "__main__":
    main()
