#!/usr/bin/python
# -*- coding: utf-8 -*-
# Copyright 2026 sustainablelobster
# Copyright: (c) 2017, Dag Wieers <dag@wieers.com>
# SPDX-License-Identifier: GPL-3.0-or-later

"""Send Wake-on-LAN packets from the configured Windows Python interpreter."""

# WANT_JSON

import binascii
import ipaddress
import socket

# The action stages this target-compatible helper beside the payload.
from legacy_windows_module import (  # pylint: disable=import-error
    as_bool,
    as_string,
    read_arguments,
    run_module,
)

DOCUMENTATION = r"""
---
module: win_wakeonlan
short_description: Send a magic Wake-on-LAN (WoL) broadcast packet
description:
- The C(win_wakeonlan) module sends magic Wake-on-LAN (WoL) broadcast packets.
- For non-Windows targets, use the M(community.general.wakeonlan) module instead.
options:
  mac:
    description:
    - MAC address to send Wake-on-LAN broadcast packet for.
    type: str
    required: yes
  broadcast:
    description:
    - Network broadcast address to use for broadcasting magic Wake-on-LAN packet.
    type: str
    default: 255.255.255.255
  port:
    description:
    - UDP port to use for magic Wake-on-LAN packet.
    type: int
    default: 7
todo:
- Does not have SecureOn password support
notes:
- This module sends a magic packet, without knowing whether it worked. It always report a change.
- Only works if the target system was properly configured for Wake-on-LAN (in the BIOS and/or the OS).
- Some BIOSes have a different (configurable) Wake-on-LAN boot order (i.e. PXE first).
seealso:
- module: community.general.wakeonlan
author:
- Dag Wieers (@dagwieers)
"""

EXAMPLES = r"""
- name: Send a magic Wake-on-LAN packet to 00:00:5E:00:53:66
  sustainablelobster.legacy_community_windows.win_wakeonlan:
    mac: 00:00:5E:00:53:66
    broadcast: 192.0.2.23

- name: Send a magic Wake-On-LAN packet on port 9 to 00-00-5E-00-53-66
  sustainablelobster.legacy_community_windows.win_wakeonlan:
    mac: 00-00-5E-00-53-66
    port: 9
  delegate_to: remote_system
"""

RETURN = r"""
# Default return values
"""


def _packet(mac):
    original = mac
    if len(mac) == 17:
        mac = mac.replace(mac[2], "")
    if len(mac) != 12:
        raise ValueError("Incorrect MAC address: " + original)
    try:
        target = binascii.unhexlify(mac.encode("ascii"))
    except (ValueError, UnicodeError, binascii.Error) as error:
        raise ValueError("Incorrect MAC address: " + original) from error
    return b"\xff" * 6 + target * 16


def _send(arguments):
    mac = as_string(arguments.get("mac"), "mac")
    if mac is None:
        raise ValueError("Missing required argument: mac")
    data = _packet(mac)
    broadcast = as_string(arguments.get("broadcast", "255.255.255.255"), "broadcast")
    address = ipaddress.ip_address(broadcast)
    try:
        port = int(arguments.get("port", 7))
    except (ValueError, TypeError, OverflowError) as error:
        raise ValueError("port must be an integer") from error
    if not -(2**31) <= port < 2**31:
        raise ValueError("port must fit in a signed 32-bit integer")
    if not as_bool(arguments.get("_ansible_check_mode", False), "_ansible_check_mode"):
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sender:
            sender.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
            sender.sendto(data, (str(address), port))
    return {"changed": True}


def main():
    """Read the Ansible argument file and report the packet-send result."""
    run_module(
        lambda: _send(
            read_arguments(
                ("mac", "broadcast", "port"),
                "sustainablelobster.legacy_community_windows.win_wakeonlan",
            )
        )
    )


if __name__ == "__main__":
    main()
