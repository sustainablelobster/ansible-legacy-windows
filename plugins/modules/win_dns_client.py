#!/usr/bin/python
# -*- coding: utf-8 -*-
# Copyright 2026 sustainablelobster
# SPDX-License-Identifier: GPL-3.0-or-later

"""Configure adapter DNS servers and the global suffix search list."""

# WANT_JSON

import datetime
import ipaddress

import legacy_windows_dns_client as dns  # pylint: disable=import-error
from legacy_windows_module import (  # pylint: disable=import-error
    as_bool,
    as_string,
    read_arguments,
    run_module,
)

DOCUMENTATION = r"""
---
module: win_dns_client
short_description: Configure DNS lookup on Windows adapters
version_added: '1.0.0'
description:
  - Configures ordered DNS servers on IP-enabled adapters and the global suffix search list.
  - Uses Python 3.4.4 and native Windows interfaces.
options:
  adapter_names:
    description:
      - Adapter connection captions or wildcard patterns.
      - Omission selects all named IP-enabled adapters.
    type: list
    elements: str
    default: ['*']
  dns_servers:
    description:
      - Ordered IPv4 or IPv6 DNS addresses.
      - An empty list resets static DNS, using DHCP values when available.
      - A nonempty request preserves settings for omitted address families.
    type: list
    elements: str
    required: true
    aliases: [ipv4_addresses, ip_addresses, addresses]
  suffix_search_list:
    description:
      - Ordered global suffixes used to resolve unqualified host names.
      - Omission, null, or an empty list leaves the current list unchanged.
    type: list
    elements: str
  log_path:
    description:
      - Optional target file receiving diagnostic lines, including in check mode.
    type: path
attributes:
  check_mode:
    support: full
    description: Predicts setting changes without invoking native setters.
  diff_mode:
    support: none
notes:
  - Uses the native DNS interface when available; otherwise IPv4 uses WMI and IPv6 uses the installed netsh IPv6 DNS commands.
  - Requires permission to change network DNS configuration.
  - Changes to several adapters or families are sequential; a later failure can leave earlier changes applied.
  - Like pinned 3.8.0, omitting a previously static address family can report changed on repeated requests.
author:
  - sustainablelobster
"""

EXAMPLES = r"""
- name: Set ordered DNS servers for one connection
  sustainablelobster.legacy_windows.win_dns_client:
    adapter_names: Ethernet
    dns_servers: [192.0.2.53, 192.0.2.54]

- name: Return matching connections to their automatic DNS settings
  sustainablelobster.legacy_windows.win_dns_client:
    adapter_names: 'Ethernet*'
    dns_servers: []
"""

RETURN = r"""
{}
"""

_MODULE = "sustainablelobster.legacy_windows.win_dns_client"
_PARAMETERS = (
    "adapter_names",
    "dns_servers",
    "ipv4_addresses",
    "ip_addresses",
    "addresses",
    "suffix_search_list",
    "log_path",
)


def _list(value, name):
    if value is None:
        return None
    # Unlike modules using Basic's list binder, this legacy reader keeps a
    # scalar string as one entry and does not split comma-delimited strings.
    if isinstance(value, list):
        return [as_string(entry, name) or "" for entry in value]
    text = as_string(value, name)
    return [text] if text else []


def _parameters(arguments):
    supplied = next(
        (
            name
            for name in ("dns_servers", "ipv4_addresses", "ip_addresses", "addresses")
            if name in arguments
        ),
        None,
    )
    if supplied is None:
        raise ValueError("missing required arguments: dns_servers")
    return {
        "adapter_names": _list(arguments.get("adapter_names", ["*"]), "adapter_names")
        or [],
        "dns_servers": _list(arguments[supplied], "dns_servers"),
        "suffix_search_list": _list(
            arguments.get("suffix_search_list"), "suffix_search_list"
        ),
        "log_path": as_string(arguments.get("log_path"), "log_path"),
    }


def _matches(adapter, desired):
    requested_versions = {ipaddress.ip_address(value).version for value in desired}
    if not requested_versions.issubset(
        {family["version"] for family in adapter["families"]}
    ):
        return False
    for family in adapter["families"]:
        requested = [
            value
            for value in desired
            if ipaddress.ip_address(value).version == family["version"]
        ]
        if family["bad_format"]:
            return False
        if family["dhcp"] and not requested:
            continue
        if requested != family["servers"]:
            return False
    return True


def _log(path, message):
    if path:
        try:
            with open(path, "a", encoding="utf-8") as stream:
                stream.write(
                    datetime.datetime.now(datetime.timezone.utc).strftime(
                        "%Y-%m-%d %H:%M:%SZ "
                    )
                    + message
                    + "\n"
                )
        except OSError:
            # The pinned debug writer continues when its optional file is unavailable.
            pass


def _manage(parameters, check_mode):
    adapters = dns.read_adapters(parameters["adapter_names"])
    if parameters["dns_servers"] is None:
        raise ValueError("Invalid IP address(es): ()")
    desired, invalid = [], []
    for address in parameters["dns_servers"]:
        try:
            desired.append(str(ipaddress.ip_address(address)))
        except ValueError:
            invalid.append(address)
    if invalid:
        raise ValueError("Invalid IP address(es): ({0})".format(", ".join(invalid)))
    changed = False
    for adapter in adapters:
        _log(
            parameters["log_path"], "Getting DNS config for adapter " + adapter["name"]
        )
        if not _matches(adapter, desired):
            changed = True
            if not check_mode:
                dns.write_servers(adapter, desired)
    suffixes = parameters["suffix_search_list"]
    # Pinned 3.8.0 preserves existing suffixes for an empty list as well as null.
    if suffixes and [value.lower() for value in dns.read_suffixes()] != [
        value.lower() for value in suffixes
    ]:
        changed = True
        if not check_mode:
            dns.write_suffixes(suffixes)
    return {"changed": changed}


def _response():
    arguments = read_arguments(_PARAMETERS, _MODULE, allow_unknown=True)
    return _manage(
        _parameters(arguments),
        as_bool(arguments.get("_ansible_check_mode", False), "_ansible_check_mode"),
    )


def main():
    """Read one Ansible request and return whether DNS settings changed.

    :raises SystemExit: After emitting the success or failure response.
    """
    run_module(_response)


if __name__ == "__main__":
    main()
