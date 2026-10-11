#!/usr/bin/python
# -*- coding: utf-8 -*-
# Copyright 2026 sustainablelobster
# SPDX-License-Identifier: GPL-3.0-or-later

"""Download files with Python 3.4.4 and native Windows HTTP services."""

# WANT_JSON

import legacy_windows_get_url as get_url  # pylint: disable=import-error
from legacy_windows_module import (  # pylint: disable=import-error
    as_bool,
    as_dictionary,
    as_path,
    as_string,
    read_arguments,
    run_module,
)

# Standalone schemas, option binding and JSON entry points repeat common web
# options deliberately; extracting them would hide each payload's public interface.
# pylint: disable=duplicate-code
DOCUMENTATION = r"""
---
module: win_get_url
short_description: Download files from HTTP, HTTPS, FTP, or file URLs
version_added: '1.0.0'
description:
  - Downloads a resource directly from the Windows target to an existing destination folder.
  - Uses Python 3.4.4, WinHTTP, and CryptoAPI.
  - Existing files are replaced only when the downloaded content differs.
options:
  url:
    description: Absolute resource URL reachable from the target.
    type: str
    required: true
  dest:
    description:
      - Destination file or existing directory. Directory destinations use the URL basename.
      - Windows environment variables are expanded. Parent directories are not created.
    type: path
    required: true
  force:
    description:
      - Download on every call, but replace the destination only when content differs.
      - If false, use Last-Modified or FTP MDTM unless a supplied checksum decides the result.
    type: bool
    default: true
  checksum:
    description: Expected digest. Cannot be combined with O(checksum_url).
    type: str
  checksum_algorithm:
    description: Digest algorithm used for both remote and destination content.
    type: str
    choices: [md5, sha1, sha256, sha384, sha512]
    default: sha1
  checksum_url:
    description: URL of a checksum list containing a record for the resource basename.
    type: str
  url_method:
    description:
      - Protocol method. HTTP defaults to GET and FTP defaults to RETR.
      - Modification checks use HTTP HEAD or FTP MDTM.
    type: str
    aliases: [method]
  follow_redirects:
    description:
      - Redirect policy. Safe follows only GET and HEAD requests.
      - Redirected requests do not forward Authorization or origin credentials.
    type: str
    choices: [all, none, safe]
    default: safe
  headers:
    description: Additional HTTP headers.
    type: dict
  http_agent:
    description: User-Agent header, taking precedence over a non-default header value.
    type: str
    default: ansible-httpget
  maximum_redirection:
    description: Maximum redirects. Zero disables redirects.
    type: int
    default: 50
  url_timeout:
    description: Request timeout in seconds. HTTP and HTTPS require a positive value.
    type: int
    default: 30
    aliases: [timeout]
  validate_certs:
    description: Validate HTTPS server certificates. Disable only for controlled test services.
    type: bool
    default: true
  client_cert:
    description: Client certificate file or Cert:\CurrentUser\My\thumbprint provider path.
    type: str
  client_cert_password:
    description: Password for the client certificate file.
    type: str
  force_basic_auth:
    description: Send Basic credentials on the initial request instead of waiting for a challenge.
    type: bool
    default: false
  url_username:
    description: Username for resource authentication.
    type: str
  url_password:
    description: Password for resource authentication.
    type: str
  use_default_credential:
    description: Use the current Windows account for NTLM or Negotiate authentication.
    type: bool
    default: false
  use_proxy:
    description: Use the current user's IE proxy unless O(proxy_url) overrides it.
    type: bool
    default: true
  proxy_url:
    description: Explicit HTTP proxy URI; unqualified local hosts are bypassed.
    type: str
  proxy_username:
    description: Username for proxy authentication.
    type: str
  proxy_password:
    description: Password for proxy authentication.
    type: str
  proxy_use_default_credential:
    description: Use the current Windows account for NTLM or Negotiate proxy authentication.
    type: bool
    default: false
attributes:
  check_mode:
    support: full
    description: Performs network requests and checksums but does not replace the destination.
  diff_mode:
    support: none
notes:
  - HTTPS enables available TLS 1.1/1.2 on older WinHTTP implementations without changing machine-wide settings.
    Modern and explicitly configured protocol defaults are preserved; Windows security policy and cipher support still apply.
  - O(validate_certs=false) skips certificate checks, not TLS protocol negotiation.
  - Percent-encoded forward slashes remain encoded in HTTP request paths.
  - Unsupported FTP methods fail before connecting, without partial download metadata.
  - HTTP and HTTPS reject O(url_timeout=0) before connecting. File and FTP behavior is unchanged.
  - Proxy-only authentication rejects localhost and IP-address destinations before connecting, including redirected requests.
    WinHTTP cannot reliably prevent these destinations from using the current login as unsolicited origin credentials.
    Use a DNS machine name or fully qualified hostname, or explicitly provide the intended origin credentials.
  - PFX-file client certificates require Windows Vista or newer for temporary private-key inspection.
    An installed C(Cert:\CurrentUser\My\thumbprint) certificate is not a verified XP workaround.
    The tested TLS 1.0 endpoint accepted the client certificate, but both collection and native synchronous
    WinHTTP requests timed out receiving HTTP. This observation does not establish that every XP HTTPS endpoint fails.
author:
  - sustainablelobster
"""

EXAMPLES = r"""
- name: Download a file with a known checksum
  sustainablelobster.legacy_windows.win_get_url:
    url: https://example.test/releases/package.zip
    dest: C:\Downloads\package.zip
    checksum_algorithm: sha256
    checksum: '0000000000000000000000000000000000000000000000000000000000000000'

- name: Download only when the remote file is newer
  sustainablelobster.legacy_windows.win_get_url:
    url: http://example.test/config.txt
    dest: C:\Downloads\config.txt
    force: false
"""

RETURN = r"""
dest:
  description: Resolved destination file.
  returned: when partial download metadata is available
  type: str
url:
  description: Requested URL.
  returned: when partial download metadata is available
  type: str
checksum_dest:
  description: Destination digest, including the unchanged existing file in check mode.
  returned: success when the destination exists
  type: str
checksum_src:
  description: Downloaded resource digest.
  returned: when resource bytes were downloaded
  type: str
elapsed:
  description: Seconds for the last network request and response processing; zero if none.
  returned: when partial download metadata is available
  type: float
size:
  description: Existing destination size in bytes.
  returned: success when the destination exists
  type: int
msg:
  description: Response status description or failure text.
  returned: when a request is made or fails
  type: str
status_code:
  description: Resource protocol status code.
  returned: when a response is received
  type: int
"""

_STRING_DEFAULTS = {
    "url": None,
    "dest": None,
    "checksum": None,
    "checksum_url": None,
    "checksum_algorithm": "sha1",
    "url_method": None,
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
_BOOL_DEFAULTS = {
    "force": True,
    "validate_certs": True,
    "force_basic_auth": False,
    "use_default_credential": False,
    "use_proxy": True,
    "proxy_use_default_credential": False,
}
_INT_DEFAULTS = {"maximum_redirection": 50, "url_timeout": 30}
_PARAMETERS = (
    tuple(_STRING_DEFAULTS)
    + tuple(_BOOL_DEFAULTS)
    + tuple(_INT_DEFAULTS)
    + ("headers", "method", "timeout")
)


def _parameters(arguments):
    missing = [name for name in ("dest", "url") if arguments.get(name) is None]
    if missing:
        raise ValueError("missing required arguments: " + ", ".join(missing))
    options = {
        name: as_string(arguments.get(name, default), name)
        for name, default in _STRING_DEFAULTS.items()
    }
    options["dest"] = as_path(arguments["dest"], "dest")
    for name, default in _BOOL_DEFAULTS.items():
        value = arguments.get(name, default)
        options[name] = as_bool(value, name) if value is not None else False
    for name, default in _INT_DEFAULTS.items():
        value = (
            arguments.get(name, arguments.get("timeout", default))
            if name == "url_timeout"
            else arguments.get(name, default)
        )
        try:
            options[name] = int(value) if value is not None else 0
        except (ValueError, TypeError) as error:
            raise ValueError("Expected an integer for " + name + ".") from error
    if "url_method" not in arguments and "method" in arguments:
        options["url_method"] = as_string(arguments["method"], "method")
    options["headers"] = as_dictionary(arguments.get("headers"), "headers")
    for name, choices in (
        ("checksum_algorithm", ("md5", "sha1", "sha256", "sha384", "sha512")),
        ("follow_redirects", ("all", "none", "safe")),
    ):
        if options[name] is not None and options[name] not in choices:
            raise ValueError(
                "value of {0} must be one of: {1}, got: {2}".format(
                    name, ", ".join(choices), options[name]
                )
            )
    if options["checksum"] is not None and options["checksum_url"] is not None:
        raise ValueError("parameters are mutually exclusive: checksum, checksum_url")
    return options


def execute():
    """Bind public arguments and execute the native download decision tree.

    :returns: Complete module result, retaining partial download metadata.
    :rtype: dict
    :raises ValueError: If public arguments cannot be bound.
    """
    arguments = read_arguments(
        _PARAMETERS, "sustainablelobster.legacy_windows.win_get_url"
    )
    return get_url.download(
        _parameters(arguments),
        as_bool(arguments.get("_ansible_check_mode", False), "_ansible_check_mode"),
    )


def main():
    """Execute the staged Ansible JSON payload.

    :raises SystemExit: With zero for success or one for failure.
    """
    run_module(execute)


if __name__ == "__main__":
    main()
