#!/usr/bin/python
# -*- coding: utf-8 -*-
# Copyright 2026 Joe Lustri
# SPDX-License-Identifier: GPL-3.0-or-later

"""Install and remove Windows Installer products, patches and executables."""

# WANT_JSON

import legacy_windows_package as package  # pylint: disable=import-error
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
module: win_package
short_description: Install and uninstall Windows packages
version_added: '1.0.0'
description:
  - Manages local or HTTP-served MSI, MSP, MSIX and traditional executable packages with native Windows APIs.
  - Uses Python 3.4.4-compatible payloads.
options:
  arguments:
    description:
      - Raw installer arguments, or a list of individually escaped arguments.
      - Do not supply MSI C(/qn), C(/log) or C(/norestart); the module supplies them.
    type: raw
  chdir:
    description: Working directory for the installer process.
    type: path
  checksum:
    description: Expected installer digest, checked before a changing installation outside check mode.
    type: str
  checksum_algorithm:
    description: Installer hashing algorithm.
    type: str
    choices: [md5, sha1, sha256, sha384, sha512]
    default: sha1
  verify_signature:
    description: Require a valid Authenticode signature before package installation.
    type: bool
    default: false
  creates_path:
    description: Literal path whose existence overrides the product installation check.
    type: path
  creates_version:
    description: Exact four-part file version required at O(creates_path).
    type: str
  creates_service:
    description:
      - Service key name or case-insensitive wildcard pattern whose existence overrides the prior installation checks.
      - Patterns support C(*), C(?), bracket sets and ranges, and backtick escapes; they match ordinary services, not drivers or display names.
      - Backtick escapes apply only when an unescaped wildcard is present; otherwise the full value is looked up literally, including backticks.
      - Exact service or driver key names and exact display names use native literal lookup.
      - Native service access or enumeration failures stop before installer execution instead of treating the service as absent.
    type: str
  expected_return_code:
    description: Installer return codes treated as success, expressed as signed 32-bit integers.
    type: list
    elements: int
    default: [0, 3010]
  log_path:
    description: Persistent MSI log path; otherwise a temporary log is removed on exit.
    type: path
  path:
    description:
      - Package filename or HTTP/HTTPS URL; required for O(state=present).
      - Local MSI identity comes from the native ProductCode, not the filename or supplied product ID.
      - An installed O(product_id) avoids downloading a URL for O(state=present), including check mode.
    type: str
  product_id:
    description:
      - MSI ProductCode, MSP PatchCode or registry uninstall key name, required for removal without a path.
      - For MSIX removal, the package name or full name registered for the executing user.
    type: str
  provider:
    description:
      - Package provider; local MSI, MSP, MSIX and registry providers are implemented.
      - MSIX installs and queries registrations for the executing user, not all users on the computer.
    type: str
    choices: [auto, msi, msix, msp, registry]
    default: auto
  state:
    description: Desired installation state.
    type: str
    choices: [absent, present]
    default: present
  wait_for_children:
    description:
      - Wait for the installer and its descendant process tree before returning.
      - Requires Windows 8 or Windows Server 2012 or newer, as in the released upstream interface.
      - Waiting for a long-running descendant can prevent the module from returning until that process stops.
      - Ignored by the MSIX provider, which waits for the native deployment operation instead.
    type: bool
    default: false
  url_method:
    description: HTTP request method for URL acquisition.
    type: str
  follow_redirects:
    description: URL redirect policy.
    type: str
    choices: [all, none, safe]
    default: safe
  headers:
    description: Additional HTTP request headers.
    type: dict
  http_agent:
    description: HTTP User-Agent.
    type: str
    default: ansible-httpget
  maximum_redirection:
    description: Maximum redirects.
    type: int
    default: 50
  url_timeout:
    description: URL request timeout in seconds. HTTP and HTTPS require a positive value.
    type: int
    default: 30
  validate_certs:
    description: Validate HTTPS server certificates.
    type: bool
    default: true
  client_cert:
    description: Client certificate path.
    type: str
  client_cert_password:
    description: Client certificate password.
    type: str
  force_basic_auth:
    description: Send Basic credentials on the initial request.
    type: bool
    default: false
  url_username:
    description: URL username.
    type: str
  url_password:
    description: URL password.
    type: str
  use_default_credential:
    description: Use current Windows credentials for URL authentication.
    type: bool
    default: false
  use_proxy:
    description: Use the current user's configured proxy.
    type: bool
    default: true
  proxy_url:
    description: Explicit proxy URL.
    type: str
  proxy_username:
    description: Proxy username.
    type: str
  proxy_password:
    description: Proxy password.
    type: str
  proxy_use_default_credential:
    description: Use current Windows credentials for proxy authentication.
    type: bool
    default: false
attributes:
  check_mode:
    support: full
    description: Inspects local identity and installation guards without executing an installer.
  diff_mode:
    support: none
notes:
  - HTTPS downloads enable available TLS 1.1/1.2 on older WinHTTP implementations without changing machine-wide settings.
    Modern and explicitly configured protocol defaults are preserved; Windows security policy and cipher support still apply.
  - O(validate_certs=false) skips certificate checks, not TLS protocol negotiation.
  - Proxy-only authentication rejects localhost and IP-address destinations before connecting, including redirected requests.
    WinHTTP cannot reliably prevent these destinations from using the current login as unsolicited origin credentials.
    Use a DNS machine name or fully qualified hostname, or explicitly provide the intended origin credentials.
  - PFX-file client certificates require Windows Vista or newer for temporary private-key inspection.
    An installed C(Cert:\CurrentUser\My\thumbprint) certificate is not a verified XP workaround.
    The tested TLS 1.0 endpoint accepted the client certificate, but both collection and native synchronous
    WinHTTP requests timed out receiving HTTP. This observation does not establish that every XP HTTPS endpoint fails.
  - The source evaluates creates_path, creates_version and creates_service in order; later checks replace prior installation status.
  - Successful installer return code C(3010) sets C(reboot_required); the module does not reboot Windows.
  - Registry removal without O(path) prefers C(QuietUninstallString) over C(UninstallString).
    Leading environment variables are expanded. For unquoted commands containing spaces, the first existing literal
    file assembled from command-line arguments is quoted as the executable; remaining arguments are preserved.
    If no file is found, the registry command is used unchanged. An explicit O(path) bypasses registry command recovery.
  - MSI installation adds a best-effort SYSTEM read permission to the package file.
author:
  - Joe Lustri
"""

EXAMPLES = r"""
- name: Install a local MSI with a private application directory
  sustainablelobster.legacy_windows.win_package:
    path: C:\staging\example.msi
    arguments: INSTALLDIR="C:\Applications\Example"
    log_path: C:\staging\example-install.log

- name: Remove a Windows Installer product
  sustainablelobster.legacy_windows.win_package:
    product_id: '{223D9A13-653B-4231-A365-EDDC30B4F226}'
    state: absent
"""

RETURN = r"""
checksum:
  description: Uppercase installer digest computed before a changing installation.
  returned: when installation computes a checksum outside check mode
  type: str
log:
  description: MSI log contents retained on an unexpected process return code.
  returned: installer failure when a log exists
  type: str
rc:
  description: Signed installer return code, or zero when no execution is required.
  returned: after installation status is read
  type: int
reboot_required:
  description: Whether a successful installer returned C(3010).
  returned: after argument validation
  type: bool
stdout:
  description: Installer standard output.
  returned: unexpected installer return code
  type: str
stderr:
  description: Installer standard error.
  returned: unexpected installer return code
  type: str
"""

_STRINGS = {
    "path": None,
    "product_id": None,
    "checksum": None,
    "checksum_algorithm": "sha1",
    "creates_version": None,
    "creates_service": None,
    "provider": "auto",
    "state": "present",
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
_BOOLS = {
    "verify_signature": False,
    "wait_for_children": False,
    "validate_certs": True,
    "force_basic_auth": False,
    "use_default_credential": False,
    "use_proxy": True,
    "proxy_use_default_credential": False,
}
_PATHS = ("chdir", "creates_path", "log_path")
_PARAMETERS = (
    tuple(_STRINGS)
    + tuple(_BOOLS)
    + _PATHS
    + (
        "arguments",
        "expected_return_code",
        "headers",
        "maximum_redirection",
        "url_timeout",
    )
)


def _integer(value, name):
    if value is None:
        return 0
    if isinstance(value, str):
        kind = "System.String"
    elif isinstance(value, bool):
        kind = "System.Boolean"
    elif isinstance(value, float):
        kind = "System.Double" if "e" in repr(value) else "System.Decimal"
    elif isinstance(value, int):
        if -(2**31) <= value < 2**31:
            kind = "System.Int32"
        elif -(2**63) <= value < 2**63:
            kind = "System.Int64"
        else:
            kind = (
                "System.Decimal"
                if abs(value) <= 79228162514264337593543950335
                else "System.Double"
            )
    elif isinstance(value, list):
        kind = "System.Object[]"
    else:
        kind = "System.Collections.Generic.Dictionary`2[System.String,System.Object]"
    # Basic's Int32 parser consumes signed decimal text, not Python's Boolean
    # conversion or float truncation. Match the measured legacy CLR whitespace.
    text = as_string(value, name).lstrip(" \t\r\n\v\f")
    text = text.rstrip("\x00").rstrip(" \t\r\n\v\f")
    digits = text[1:] if text.startswith(("+", "-")) else text
    detail = "Input string was not in a correct format."
    if digits and all(character in "0123456789" for character in digits):
        converted = int(text)
        if -(2**31) <= converted < 2**31:
            return converted
        detail = "Value was either too large or too small for an Int32."
    raise ValueError(
        "argument for {0} is of type {1} and we were unable to convert to int: {2}".format(
            name, kind, detail
        )
    )


def _parameters(arguments):
    options = {
        name: as_string(arguments.get(name, default), name)
        for name, default in _STRINGS.items()
    }
    options.update({name: as_path(arguments.get(name), name) for name in _PATHS})
    for name, choices in (
        ("state", ("absent", "present")),
        ("provider", ("msi", "msix", "msp", "registry", "auto")),
        ("checksum_algorithm", ("md5", "sha1", "sha256", "sha384", "sha512")),
        ("follow_redirects", ("all", "none", "safe")),
    ):
        if options[name] is not None and options[name].lower() not in choices:
            raise ValueError(
                "value of {0} must be one of: {1}, got: {2}".format(
                    name, ", ".join(choices), options[name]
                )
            )
        if options[name] is not None:
            # Basic validates these choices without case sensitivity. Dispatch
            # uses their canonical spellings; public diagnostics retain raw input.
            options[name] = options[name].lower()
    if options["state"] == "present" and options["path"] is None:
        raise ValueError("state is present but all of the following are missing: path")
    if (
        options["state"] == "absent"
        and options["path"] is None
        and options["product_id"] is None
    ):
        raise ValueError(
            "state is absent but any of the following are missing: path, product_id"
        )
    if options["creates_version"] is not None and options["creates_path"] is None:
        raise ValueError(
            "missing parameter(s) required by 'creates_version': creates_path"
        )
    for name, default in _BOOLS.items():
        value = arguments.get(name, default)
        options[name] = as_bool(value, name) if value is not None else False
    value = arguments.get("arguments")
    # Convert values before any native inspection, but retain list boundaries
    # until the selected provider determines its command-line syntax.
    options["arguments"] = (
        [as_string(item, "arguments") or "" for item in value]
        if isinstance(value, list)
        else as_string(value, "arguments")
    )
    raw_codes = as_string_list(
        arguments.get("expected_return_code", [0, 3010]), "expected_return_code"
    )
    try:
        options["expected_return_code"] = [int(value) for value in raw_codes or []]
        if any(
            not -2147483648 <= value <= 2147483647
            for value in options["expected_return_code"]
        ):
            raise ValueError("outside signed 32-bit range")
    except ValueError as error:
        raise ValueError(
            "Expected signed integer elements for expected_return_code."
        ) from error
    options["headers"] = as_dictionary(arguments.get("headers"), "headers")
    for name, default in (("maximum_redirection", 50), ("url_timeout", 30)):
        options[name] = _integer(arguments.get(name, default), name)
    return options


def execute():
    """Bind public parameters and execute the native package operation.

    :returns: Complete public result.
    :rtype: dict
    :raises ValueError: Public argument validation fails.
    """
    arguments = read_arguments(
        _PARAMETERS, "sustainablelobster.legacy_windows.win_package"
    )
    return package.manage(
        _parameters(arguments),
        as_bool(arguments.get("_ansible_check_mode", False), "_ansible_check_mode"),
    )


def main():
    """Emit one Ansible JSON result.

    :raises SystemExit: Zero on success or one on failure.
    """
    run_module(execute)


if __name__ == "__main__":
    main()
