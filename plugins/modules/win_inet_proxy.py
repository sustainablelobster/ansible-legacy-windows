#!/usr/bin/python
# -*- coding: utf-8 -*-
# Copyright 2026 Joe Lustri
# SPDX-License-Identifier: GPL-3.0-or-later

"""Manage WinINet proxy settings using Python 3.4.4 and native APIs."""

# WANT_JSON

# The action stages these target-compatible helpers beside this payload.
import legacy_windows_environment as environment  # pylint: disable=import-error
import legacy_windows_inet_proxy as inet_proxy  # pylint: disable=import-error
from legacy_windows_module import (  # pylint: disable=import-error
    DOTNET_WHITESPACE,
    as_bool,
    as_string,
    as_string_list,
    read_arguments,
    run_module,
)

DOCUMENTATION = r"""
---
module: win_inet_proxy
short_description: Configure WinINet and Internet Explorer proxy settings
version_added: '1.0.0'
description:
  - Configures automatic detection, an automatic configuration URL, and an explicit proxy and bypass list.
  - Selects the current user's LAN settings by default, or an existing named connection.
  - Uses Python 3.4.4 and native Windows APIs.
options:
  auto_detect:
    description:
      - Enables automatic proxy discovery through WPAD.
    type: bool
    default: true
  auto_config_url:
    description:
      - URL of the proxy configuration script, commonly a PAC file.
      - Omit, use null, or use an empty string to remove this URL.
    type: str
  proxy:
    description:
      - Proxy host, host and port, or protocol-specific proxy string.
      - A dictionary may select C(http), C(https), C(ftp), and C(socks) endpoints.
      - Omit, use null, or use an empty string to remove the explicit proxy.
    type: raw
  bypass:
    description:
      - Hosts excluded from proxy use. C(<local>) selects names without a domain component and should be the last entry.
      - C(<-loopback>) disables the usual automatic bypass for loopback addresses.
      - Omit, use null, or use an empty string or list to clear the bypass list.
      - Supplying this option requires O(proxy).
    type: list
    elements: str
  connection:
    description:
      - Existing dial-up or VPN connection name.
      - Omit or use null to select the default LAN connection.
    type: str
attributes:
  check_mode:
    support: full
    description: Validates the connection and predicts differences without writes or native setter normalization.
  diff_mode:
    support: full
    description: Reports configuration dictionaries; the previous proxy key is C(server), while the requested key is C(proxy).
notes:
  - Omitted options reset to their defaults rather than retaining individual settings.
  - Existing Windows policy determines whether proxy configuration applies per user or machine-wide. This module does not change that policy.
  - This does not modify the system WinHTTP proxy, create connections, or store authentication credentials.
  - Comparisons ignore case, while diffs retain previous and requested spelling.
  - Real writes are read back. A mismatch requests restoration of all previous settings before reporting failure.
author:
  - Joe Lustri
"""

EXAMPLES = r"""
- name: Configure automatic detection and a PAC URL
  sustainablelobster.legacy_windows.win_inet_proxy:
    auto_detect: true
    auto_config_url: http://proxy.example.test/configuration.pac

- name: Set an explicit proxy without automatic detection
  sustainablelobster.legacy_windows.win_inet_proxy:
    auto_detect: false
    proxy: gateway.example.test:8080
    bypass: [intranet, '<local>']

- name: Restore defaults for the LAN connection
  sustainablelobster.legacy_windows.win_inet_proxy:
"""

RETURN = r"""
{}
"""

_MODULE_NAME = "sustainablelobster.legacy_windows.win_inet_proxy"
_PARAMETERS = ("auto_detect", "auto_config_url", "bypass", "connection", "proxy")
_PROTOCOLS = ("http", "https", "ftp", "socks")
_CONFIGURATION = ("auto_config_url", "auto_detect", "proxy", "bypass")


def _proxy_text(value):
    if isinstance(value, list):
        return " ".join(as_string(entry, "proxy") or "" for entry in value)
    return as_string(value, "proxy") or ""


def _proxy_value(value):
    if not isinstance(value, dict):
        return as_string(value, "proxy")
    invalid = [
        key
        for key in value
        if not any(environment.values_equal(key, valid) for valid in _PROTOCOLS)
    ]
    if invalid:
        raise ValueError(
            "Invalid keys found in proxy: "
            + ", ".join(sorted(invalid, key=str.lower))
            + ". Valid keys are http, https, ftp, socks."
        )
    return ";".join(
        protocol + "=" + _proxy_text(value[key])
        for protocol in _PROTOCOLS
        for key in value
        if environment.values_equal(protocol, key)
    )


def _check_duplicate_keys(proxy):
    if not isinstance(proxy, dict):
        return
    seen = {}
    for key in proxy:
        normalized = environment.name_key(key)
        if normalized in seen:
            raise ValueError(
                "failure during exec_wrapper: Cannot convert the JSON string "
                "because a dictionary that was converted from the string "
                "contains the duplicated keys '"
                + seen[normalized]
                + "' and '"
                + key
                + "'."
            )
        seen[normalized] = key


def _bypass(value):
    if isinstance(value, bool):
        raise ValueError(
            "argument for bypass is of type System.Boolean and we were unable "
            "to convert to list: System.Boolean cannot be converted to a list"
        )
    if isinstance(value, list) and any(entry is None for entry in value):
        raise ValueError(
            'Unhandled exception while executing module: Exception calling "Create" '
            'with "2" argument(s): "Object reference not set to an instance of an object."'
        )
    return as_string_list(value, "bypass")


def _parameters(arguments):
    proxy = arguments.get("proxy")
    # The upstream JSON wrapper rejects case-duplicate keys before binding.
    _check_duplicate_keys(proxy)
    auto_detect = arguments.get("auto_detect", True)
    if auto_detect is not None:
        try:
            auto_detect = as_bool(auto_detect, "auto_detect")
        except ValueError as error:
            if not isinstance(auto_detect, str):
                raise
            raise ValueError(
                "argument for auto_detect is of type System.String and we were "
                "unable to convert to bool: The value '"
                + auto_detect.lower().strip(DOTNET_WHITESPACE)
                + "' is not a valid boolean. Valid booleans include: "
                "y, yes, on, 1, true, t, 1.0, n, no, off, 0, false, f, 0.0"
            ) from error
    auto_config_url = as_string(arguments.get("auto_config_url"), "auto_config_url")
    bypass = _bypass(arguments.get("bypass"))
    connection = as_string(arguments.get("connection"), "connection")
    if "bypass" in arguments and "proxy" not in arguments:
        raise ValueError("missing parameter(s) required by 'bypass': proxy")
    proxy = _proxy_value(proxy)
    if bypass and (len(bypass) > 1 or bypass[0]) and not proxy:
        raise ValueError("missing parameter(s) required by ''bypass'': proxy")
    return {
        "auto_detect": auto_detect,
        "auto_config_url": auto_config_url or None,
        "proxy": proxy or None,
        "bypass": ";".join(bypass or []) or None,
        "connection": connection,
    }


def _failure(result, message):
    result.update(
        {"failed": True, "msg": message, "exception": "(traceback unavailable)"}
    )
    return result


def _changed_fields(previous, requested):
    changes = {}
    for name in _CONFIGURATION:
        equal = (
            previous[name] == requested[name]
            if name == "auto_detect"
            else environment.values_equal(previous[name], requested[name])
        )
        if not equal:
            changes[name] = requested[name]
    return changes


def _manage(parameters, check_mode=False, diff_mode=False):
    result = {"changed": False}
    connection = parameters["connection"]
    if connection is not None and not inet_proxy.valid_connection(connection):
        return _failure(result, "The connection '" + connection + "' does not exist.")
    previous = inet_proxy.get_proxy(connection)
    if diff_mode:
        before = dict(previous)
        # The pinned interface uses different names in the two diff dictionaries.
        before["server"] = before.pop("proxy")
        result["diff"] = {"before": before}
    requested = {name: parameters[name] for name in _CONFIGURATION}
    changes = _changed_fields(previous, requested)
    if changes and not check_mode:
        # Preserve native spelling for equal fields when another field changes.
        updated = dict(previous)
        updated.update(changes)
        inet_proxy.set_proxy(updated, connection)
        if _changed_fields(inet_proxy.get_proxy(connection), requested):
            inet_proxy.set_proxy(previous, connection)
            return _failure(
                result,
                "Unknown error when trying to set auto_config_url '"
                + (requested["auto_config_url"] or "")
                + "', proxy '"
                + (requested["proxy"] or "")
                + "', or bypass '"
                + (requested["bypass"] or "")
                + "'",
            )
    result["changed"] = bool(changes)
    if diff_mode:
        result["diff"]["after"] = requested
    return result


def _response():
    try:
        arguments = read_arguments(_PARAMETERS, _MODULE_NAME)
        parameters = _parameters(arguments)
        check_mode = as_bool(
            arguments.get("_ansible_check_mode", False), "_ansible_check_mode"
        )
        diff_mode = as_bool(arguments.get("_ansible_diff", False), "_ansible_diff")
    except ValueError as error:
        return _failure({"changed": False}, str(error))
    return _manage(parameters, check_mode, diff_mode)


def main():
    """Read an Ansible request and emit the WinINet proxy module's JSON result.

    :raises SystemExit: After reporting success or failure to Ansible.
    """
    run_module(_response)


if __name__ == "__main__":
    main()
