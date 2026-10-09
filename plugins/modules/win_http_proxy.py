#!/usr/bin/python
# -*- coding: utf-8 -*-
# Copyright 2026 Joe Lustri
# SPDX-License-Identifier: GPL-3.0-or-later

"""Manage the system WinHTTP proxy using Python 3.4.4 and native APIs."""

# WANT_JSON

# The action stages these target-compatible helpers beside this payload.
import legacy_windows_environment as environment  # pylint: disable=import-error
import legacy_windows_http_proxy as http_proxy  # pylint: disable=import-error
from legacy_windows_module import (  # pylint: disable=import-error
    as_bool,
    as_string,
    as_string_list,
    read_arguments,
    run_module,
)

DOCUMENTATION = r"""
---
module: win_http_proxy
short_description: Configure the system WinHTTP proxy
version_added: '1.0.0'
description:
  - Sets, clears, or imports the machine-wide Windows HTTP Services proxy configuration.
  - Uses Python 3.4.4 and native Windows APIs.
options:
  proxy:
    description:
      - Proxy host, host and port, or protocol-specific proxy string.
      - A dictionary may select C(http), C(https), C(ftp), and C(socks) proxy endpoints.
      - Omit this option or use null or an empty string to select direct access.
    type: raw
  bypass:
    description:
      - Hosts excluded from proxy use; C(<local>) selects names without a domain component.
      - Omit this option or use null or an empty string or list to clear the bypass list.
      - Requires O(proxy) and cannot be combined with O(source).
    type: list
    elements: str
  source:
    description:
      - Imports the current user's static Internet Explorer proxy and bypass list for the active connection.
      - Automatic detection and PAC URLs are not imported.
      - Cannot be combined with O(proxy) or O(bypass).
    type: str
    choices: [ie]
attributes:
  check_mode:
    support: full
    description: Reads configuration and predicts differences without writing or testing native setter normalization.
  diff_mode:
    support: full
    description: Reports dictionaries containing the native previous and requested proxy and bypass strings.
notes:
  - Requires permission to change the system-wide WinHTTP configuration.
  - This does not change the current user's WinINet or Internet Explorer configuration.
  - Comparisons ignore case, but diffs retain native and requested spelling.
  - A real write is read back. If Windows stores different values, the previous configuration is requested again and the module fails.
  - Importing from Internet Explorer is a one-time copy, not ongoing synchronization.
author:
  - Joe Lustri
"""

EXAMPLES = r"""
- name: Configure a proxy with local host exclusions
  sustainablelobster.legacy_windows.win_http_proxy:
    proxy: gateway.example.test:8080
    bypass: [intranet, '<local>']

- name: Select separate HTTP and HTTPS proxies
  sustainablelobster.legacy_windows.win_http_proxy:
    proxy:
      http: gateway.example.test:8080
      https: gateway.example.test:8443

- name: Import the current user's static Internet Explorer settings
  sustainablelobster.legacy_windows.win_http_proxy:
    source: ie

- name: Clear the system WinHTTP proxy and bypass list
  sustainablelobster.legacy_windows.win_http_proxy:
"""

RETURN = r"""
{}
"""

_MODULE_NAME = "sustainablelobster.legacy_windows.win_http_proxy"
_PARAMETERS = ("bypass", "proxy", "source")
_PROTOCOLS = ("http", "https", "ftp", "socks")


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
    bypass = _bypass(arguments.get("bypass"))
    source = as_string(arguments.get("source"), "source")
    if source is not None and not environment.values_equal(source, "ie"):
        raise ValueError(
            "value of source must be one of: ie. Got no match for: " + source
        )
    if "source" in arguments:
        for name in ("proxy", "bypass"):
            if name in arguments:
                raise ValueError(
                    "parameters are mutually exclusive: " + name + ", source"
                )
    if "bypass" in arguments and "proxy" not in arguments:
        raise ValueError("missing parameter(s) required by 'bypass': proxy")
    proxy = _proxy_value(proxy)
    if bypass and (len(bypass) > 1 or bypass[0]) and not proxy:
        raise ValueError("missing parameter(s) required by ''bypass'': proxy")
    return {"proxy": proxy, "bypass": ";".join(bypass or []), "source": source}


def _failure(result, message):
    result.update(
        {"failed": True, "msg": message, "exception": "(traceback unavailable)"}
    )
    return result


def _different(previous, requested):
    return any(
        not environment.values_equal(previous[name], requested[name])
        for name in ("proxy", "bypass")
    )


def _manage(parameters, check_mode=False, diff_mode=False):
    previous = http_proxy.get_proxy()
    result = {"changed": False}
    if diff_mode:
        result["diff"] = {"before": dict(previous)}
    requested = (
        http_proxy.get_ie_proxy()
        if environment.values_equal(parameters["source"], "ie")
        else {name: parameters[name] for name in ("proxy", "bypass")}
    )
    requested = {name: value or None for name, value in requested.items()}
    if _different(previous, requested):
        if not check_mode:
            http_proxy.set_proxy(requested["proxy"], requested["bypass"])
            if _different(http_proxy.get_proxy(), requested):
                http_proxy.set_proxy(previous["proxy"], previous["bypass"])
                return _failure(
                    result,
                    "Unknown error when trying to set proxy '"
                    + (requested["proxy"] or "")
                    + "' or bypass '"
                    + (requested["bypass"] or "")
                    + "'",
                )
        result["changed"] = True
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
    """Read an Ansible request and emit the WinHTTP proxy module's JSON result.

    :raises SystemExit: After reporting success or failure to Ansible.
    """
    run_module(_response)


if __name__ == "__main__":
    main()
