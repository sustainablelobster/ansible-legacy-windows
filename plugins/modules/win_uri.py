#!/usr/bin/python
# -*- coding: utf-8 -*-
# Copyright 2026 sustainablelobster
# SPDX-License-Identifier: GPL-3.0-or-later

"""Interact with web resources using Python 3.4.4 and native Windows APIs."""

# WANT_JSON

import legacy_windows_uri as uri  # pylint: disable=import-error
from legacy_windows_module import (  # pylint: disable=import-error
    as_bool,
    as_dictionary,
    as_path,
    as_string,
    as_string_list,
    read_arguments,
    run_module,
)

# Standalone schemas, option binding and JSON entry points repeat common web
# options deliberately; extracting them would hide each payload's public interface.
# pylint: disable=duplicate-code
DOCUMENTATION = r"""
---
module: win_uri
short_description: Interact with Windows-accessible web services
version_added: '1.0.0'
description:
  - Sends requests from the Windows target and returns response properties and headers.
  - Uses Python 3.4.4 or newer, native WinHTTP and standard-library HTTP.
  - Check mode performs the request, including uploads, but predicts O(dest) writes.
options:
  url:
    description: Absolute resource URL reachable from the target.
    type: str
    required: true
  content_type:
    description: Request Content-Type, overriding the corresponding O(headers) entry.
    type: str
  body:
    description:
      - Request body. Dictionaries and lists use Python's standard JSON serialization.
      - Object key order is not guaranteed. Keys and array order are preserved.
      - JSON object keys remain case-sensitive, including keys differing only by case.
        Upstream's PowerShell argument parser can reject those keys.
      - Supply a string body when an endpoint requires a specific representation.
      - Other values are converted to text and encoded as UTF-8.
      - FTP bodies require C(STOR), C(STOU) or C(APPE). Empty strings still upload.
        With C(STOU), the URL names the directory for the server-generated file.
      - File URI requests with a body are rejected before opening or changing
        the file, including in check mode. Use M(sustainablelobster.legacy_windows.win_copy)
        to write files.
    type: raw
  dest:
    description:
      - Write response bytes to this file when the content differs.
      - Parent directories are not created. A status failure may occur after the write.
    type: path
  creates:
    description: Skip the request when this file or directory already exists.
    type: path
  removes:
    description: Skip the request when this file or directory does not exist.
    type: path
  return_content:
    description:
      - Return the response body as UTF-8 text, replacing invalid byte sequences.
      - JSON-like content types also return a truthy decoded JSON value as RV(json).
      - Empty objects are returned. Empty lists, false, null and zero are not.
    type: bool
    default: false
  status_code:
    description: Accepted status codes. Other responses retain their metadata and fail.
    type: list
    elements: int
    default: [200]
  url_method:
    description: Request verb. Lowercase letters are converted to uppercase.
    type: str
    default: GET
    aliases: [method]
  follow_redirects:
    description:
      - Redirect policy. Safe follows only GET and HEAD requests.
      - Redirected requests do not forward origin Authorization or credentials.
    type: str
    choices: [all, none, safe]
    default: safe
  headers:
    description: Additional request headers.
    type: dict
  http_agent:
    description: User-Agent value, taking precedence over a non-default header value.
    type: str
    default: ansible-httpget
  maximum_redirection:
    description: Maximum automatic redirects. Zero disables following.
    type: int
    default: 50
  url_timeout:
    description: Request timeout in seconds. HTTP and HTTPS require a positive value.
    type: int
    default: 30
    aliases: [timeout]
  validate_certs:
    description: Validate HTTPS server certificates.
    type: bool
    default: true
  client_cert:
    description: Client certificate file or certificate-store provider path.
    type: str
  client_cert_password:
    description: Password for the client certificate file.
    type: str
  force_basic_auth:
    description: Send Basic credentials initially instead of waiting for a challenge.
    type: bool
    default: false
  url_username:
    description: Resource authentication username.
    type: str
  url_password:
    description: Resource authentication password.
    type: str
  use_default_credential:
    description: Use the current Windows account for supported integrated authentication.
    type: bool
    default: false
  use_proxy:
    description: Use the user's default proxy when no explicit proxy is supplied.
    type: bool
    default: true
  proxy_url:
    description: Explicit proxy URL.
    type: str
  proxy_username:
    description: Proxy authentication username.
    type: str
  proxy_password:
    description: Proxy authentication password.
    type: str
  proxy_use_default_credential:
    description: Use the current Windows account for supported proxy authentication.
    type: bool
    default: false
notes:
  - FTP uploads retain the final server reply. Common successful uploads require
    O(status_code=[226]) rather than the default HTTP status.
  - FTP body streams use a 300-second timeout, separate from O(url_timeout)
    for the control connection. A failed upload may leave a complete or
    partial remote file.
  - Like upstream, file URI responses have no protocol status and fail the
    O(status_code) check, even with C([0]). Unlike upstream, requests with a body
    fail before writing the file in both normal and check mode.
  - Request uploads alone do not set C(changed). This flag describes O(dest) writes.
  - HTTPS enables available TLS 1.1/1.2 on older WinHTTP implementations without changing machine-wide settings.
    Modern and explicitly configured protocol defaults are preserved; Windows security policy and cipher support still apply.
  - O(validate_certs=false) skips certificate checks, not TLS protocol negotiation.
  - Proxy-only authentication rejects localhost and IP-address destinations before connecting, including redirected requests.
    WinHTTP cannot reliably prevent these destinations from using the current login as unsolicited origin credentials.
    Use a DNS machine name or fully qualified hostname, or explicitly provide the intended origin credentials.
  - PFX-file client certificates require Windows Vista or newer for temporary private-key inspection.
    An installed C(Cert:\CurrentUser\My\thumbprint) certificate is not a verified XP workaround.
    The tested TLS 1.0 endpoint accepted the client certificate, but collection and native synchronous WinHTTP
    requests both timed out receiving HTTP. This does not establish that every XP HTTPS endpoint fails.
  - HTTP and HTTPS reject nonpositive O(url_timeout) values before connecting.
  - Percent-encoded forward slashes remain encoded in HTTP request paths.
  - With C(async) and C(poll=0), retrieve results using M(sustainablelobster.legacy_windows.async_status).
  - Automatic polling with C(poll>0) requires the installed collection's
    C(plugins/action/_native_async_polling) directory on the controller action plugin path.
    Set C(action_plugins) in the project's C(ansible.cfg); installation alone does not activate the adapter.
author:
  - sustainablelobster
"""

EXAMPLES = r"""
- name: Read a JSON endpoint
  sustainablelobster.legacy_windows.win_uri:
    url: http://example.test/api
    return_content: true

- name: Accept an explicit success status
  sustainablelobster.legacy_windows.win_uri:
    url: http://example.test/api
    method: POST
    content_type: application/json
    body: {enabled: true}
    status_code: [200, 201]
"""

RETURN = r"""
elapsed:
  description: Request elapsed time; early skips and explicit status failures retain zero.
  returned: always
  type: float
url:
  description: Original requested URL.
  returned: always
  type: str
status_code:
  description: Response status code, or null when no response is available.
  returned: after a request attempt
  type: int
status_description:
  description: HTTP response reason phrase.
  returned: after an HTTP response
  type: str
content:
  description: Response bytes decoded as UTF-8 with replacement.
  returned: when return_content is true and a response is available
  type: str
content_length:
  description:
    - Response byte length, including the upstream header override behavior.
    - A Content-Length header is returned as text; an absent HTTP header yields -1.
  returned: after a response is available
  type: raw
json:
  description: Truthy parsed JSON from a matching content type; it need not be a dictionary.
  returned: when return_content is true and matching JSON parses to a truthy value
  type: raw
"""

_STRINGS = {
    "url": None,
    "content_type": None,
    "url_method": "GET",
    "follow_redirects": "safe",
    "http_agent": "ansible-httpget",
    "client_cert": None,
    "client_cert_password": None,
    "url_username": None,
    "url_password": None,
    "proxy_url": None,
    "proxy_username": None,
    "proxy_password": None,
}
_BOOLS = {
    "return_content": False,
    "validate_certs": True,
    "force_basic_auth": False,
    "use_default_credential": False,
    "use_proxy": True,
    "proxy_use_default_credential": False,
}
_INTS = {"maximum_redirection": 50, "url_timeout": 30}
_PATHS = ("dest", "creates", "removes")
_PARAMETERS = (
    tuple(_STRINGS)
    + tuple(_BOOLS)
    + tuple(_INTS)
    + _PATHS
    + ("body", "headers", "status_code", "method", "timeout")
)


def _parameters(arguments):
    if arguments.get("url") is None:
        raise ValueError("missing required arguments: url")
    options = {
        name: as_string(arguments.get(name, default), name)
        for name, default in _STRINGS.items()
    }
    options.update({name: as_path(arguments.get(name), name) for name in _PATHS})
    for name, default in _BOOLS.items():
        value = arguments.get(name, default)
        options[name] = as_bool(value, name) if value is not None else False
    for name, default in _INTS.items():
        value = (
            arguments.get(name, arguments.get("timeout", default))
            if name == "url_timeout"
            else arguments.get(name, default)
        )
        try:
            options[name] = int(value) if value is not None else 0
        except (TypeError, ValueError) as error:
            raise ValueError("Expected an integer for " + name + ".") from error
    if "url_method" not in arguments and "method" in arguments:
        options["url_method"] = as_string(arguments["method"], "method")
    choices = ("all", "none", "safe")
    if (
        options["follow_redirects"] not in choices
        and options["follow_redirects"] is not None
    ):
        raise ValueError(
            "value of follow_redirects must be one of: all, none, safe, got: "
            + options["follow_redirects"]
        )
    try:
        values = as_string_list(arguments.get("status_code", [200]), "status_code")
        options["status_code"] = (
            [int(value) for value in values] if values is not None else []
        )
    except (TypeError, ValueError) as error:
        raise ValueError("Expected integer elements for status_code.") from error
    options["headers"] = as_dictionary(arguments.get("headers"), "headers")
    options["body"] = arguments.get("body")
    return options


def execute():
    """Bind the public URI parameters and execute the target-native request.

    :returns: Complete module result, including retained failure properties.
    :rtype: dict
    :raises ValueError: If public arguments cannot be bound.
    """
    arguments = read_arguments(_PARAMETERS, "sustainablelobster.legacy_windows.win_uri")
    return uri.request(
        _parameters(arguments),
        as_bool(arguments.get("_ansible_check_mode", False), "_ansible_check_mode"),
    )


def main():
    """Execute the staged Ansible JSON entry point.

    :raises SystemExit: With zero for success or one for failure.
    """
    run_module(execute)


if __name__ == "__main__":
    main()
