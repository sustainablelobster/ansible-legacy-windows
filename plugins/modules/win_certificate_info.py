#!/usr/bin/python
# -*- coding: utf-8 -*-
# Copyright 2026 Joe Lustri
# SPDX-License-Identifier: GPL-3.0-or-later

"""Read Windows certificate stores using a Python 3.4.4 payload."""

# WANT_JSON

import legacy_windows_certificate as certificate  # pylint: disable=import-error
from legacy_windows_module import (  # pylint: disable=import-error
    as_bool,
    as_string,
    read_arguments,
    run_module,
)

DOCUMENTATION = r"""
---
module: win_certificate_info
short_description: Read certificates from a Windows certificate store
version_added: '1.0.0'
description:
  - Returns certificate information from the selected Windows certificate store.
  - Uses Python 3.4.4 and native Windows APIs.
options:
  thumbprint:
    description:
      - Hexadecimal certificate thumbprint to select.
      - Omit this option to read every certificate exposed by the selected store.
      - Matching accepts uppercase or lowercase hexadecimal digits.
    type: str
  store_name:
    description:
      - Store name, such as C(My), C(Root), C(CA), or a custom store name.
    type: str
    default: My
  store_location:
    description:
      - Read the current account's store or the computer's store.
    type: str
    choices: [CurrentUser, LocalMachine]
    default: LocalMachine
attributes:
  check_mode:
    support: full
    description: Performs the same certificate reads and reports no changes.
  diff_mode:
    support: none
notes:
  - The module does not import, remove, or modify certificates or private keys.
  - Certificate names and formatted extension text use the target's Windows formatting and language.
  - Date values follow the target account's calendar and time separator, matching upstream. Numeric dates use C(01/01/1970) interpreted in that calendar; calendars that cannot parse it cause a failure.
  - RV(certificates.raw) contains the encoded certificate, matching the selected upstream implementation's actual return field.
author:
  - Joe Lustri
"""

EXAMPLES = r"""
- name: Read certificates from the computer's personal store
  sustainablelobster.legacy_windows.win_certificate_info:
  register: personal_certificates

- name: Read a certificate by thumbprint
  sustainablelobster.legacy_windows.win_certificate_info:
    thumbprint: BD7AF104CF1872BDB518D95C9534EA941665FD27

- name: Read the current account's trusted root certificates
  sustainablelobster.legacy_windows.win_certificate_info:
    store_name: Root
    store_location: CurrentUser
"""

RETURN = r"""
exists:
  description: Whether at least one certificate matches the selection.
  returned: success
  type: bool
certificates:
  description: Selected certificates sorted by uppercase thumbprint; an empty list when none match.
  returned: success
  type: list
  elements: dict
  contains:
    archived:
      description: Whether the certificate has the archived property.
      type: bool
    dns_names:
      description: Certificate simple subject name followed by DNS names from its subject alternative name extension.
      type: list
      elements: str
    extensions:
      description: Certificate extensions in their encoded order.
      type: list
      elements: dict
      contains:
        critical:
          description: Whether the extension is marked critical.
          type: bool
        field:
          description: Windows friendly name for the extension identifier, or null when unknown.
          type: str
        value:
          description: Extension data formatted by Windows as a single string.
          type: str
    friendly_name:
      description: Stored certificate alias, or an empty string when unset.
      type: str
    has_private_key:
      description: Whether the certificate has an associated private key.
      type: bool
    intended_purposes:
      description:
        - Windows friendly names of the enhanced key usage identifiers; unknown identifiers are empty strings.
        - The entire value is null when the enhanced key usage extension contains no identifiers.
      returned: when an enhanced key usage extension is present
      type: list
      elements: str
    is_ca:
      description: Whether the basic constraints extension identifies a certificate authority.
      returned: when a basic constraints extension is present
      type: bool
    issued_by:
      description: Simple display name of the issuer.
      type: str
    issued_to:
      description: Simple display name of the subject.
      type: str
    issuer:
      description: Formatted issuer distinguished name.
      type: str
    key_usages:
      description: Key usage flag names; C(None) when no key usage bits are set.
      returned: when a key usage extension is present
      type: list
      elements: str
    path_length_constraint:
      description: Basic constraints path length integer; zero is also returned when no path length restriction is encoded.
      returned: when a basic constraints extension is present
      type: int
    public_key:
      description: Base64-encoded certificate public key bytes.
      type: str
    raw:
      description: Base64-encoded DER certificate bytes.
      type: str
    serial_number:
      description: Certificate serial number in uppercase hexadecimal.
      type: str
    signature_algorithm:
      description: Windows friendly name for the signature algorithm, or null when unknown.
      type: str
    ski:
      description: Subject key identifier in uppercase hexadecimal.
      returned: when a subject key identifier extension is present
      type: str
    subject:
      description: Formatted subject distinguished name.
      type: str
    thumbprint:
      description: SHA-1 certificate thumbprint in uppercase hexadecimal.
      type: str
    valid_from:
      description: Seconds from C(01/01/1970) in the target account's calendar to the certificate validity start in UTC.
      type: float
    valid_from_iso8601:
      description: Certificate validity start in UTC, using C(yyyy-MM-ddTHH:mm:ssZ) with the target account's calendar and time separator.
      type: str
    valid_to:
      description: Seconds from C(01/01/1970) in the target account's calendar to the certificate validity end in UTC.
      type: float
    valid_to_iso8601:
      description: Certificate validity end in UTC, using C(yyyy-MM-ddTHH:mm:ssZ) with the target account's calendar and time separator.
      type: str
    version:
      description: X.509 certificate version number.
      type: int
"""

_MODULE_NAME = "sustainablelobster.legacy_windows.win_certificate_info"
_PARAMETERS = ("store_location", "store_name", "thumbprint")
_LOCATIONS = ("CurrentUser", "LocalMachine")


def _parameters(arguments):
    parameters = {
        "store_location": as_string(
            arguments.get("store_location", "LocalMachine"), "store_location"
        ),
        "store_name": as_string(arguments.get("store_name", "My"), "store_name"),
        "thumbprint": as_string(arguments.get("thumbprint"), "thumbprint"),
    }
    location = parameters["store_location"]
    if location is None:
        raise RuntimeError(
            'Cannot convert value "" to type '
            '"System.Security.Cryptography.X509Certificates.StoreLocation". '
            'Error: "The identifier name  cannot be processed because it is '
            "either too similar or identical to the following enumerator names: "
            'CurrentUser, LocalMachine. Use a more specific identifier name."'
        )
    if location.lower() not in ("currentuser", "localmachine"):
        raise ValueError(
            "value of store_location must be one of: {0}. Got no match for: {1}".format(
                ", ".join(_LOCATIONS), location
            )
        )
    return parameters


def _response():
    arguments = read_arguments(_PARAMETERS, _MODULE_NAME)
    parameters = _parameters(arguments)
    certificates = certificate.read_certificates(
        parameters["store_name"], parameters["store_location"], parameters["thumbprint"]
    )
    result = {
        "changed": False,
        "exists": bool(certificates),
        "certificates": certificates,
    }
    if as_bool(
        arguments.get("_ansible_inject_invocation", False), "_ansible_inject_invocation"
    ):
        result["invocation"] = {"module_args": parameters}
    return result


def main():
    """Emit selected certificate records as an Ansible JSON result.

    :raises SystemExit: After reporting success or failure.
    """
    run_module(_response)


if __name__ == "__main__":
    main()
