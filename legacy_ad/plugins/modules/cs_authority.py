#!/usr/bin/python
# -*- coding: utf-8 -*-
# Copyright 2026 sustainablelobster
# Interface documentation derived from microsoft.ad, Copyright 2026 Ansible Project.
# SPDX-License-Identifier: GPL-3.0-or-later

"""Manage Certificate Services authority configuration through native Windows APIs."""

# WANT_JSON

from legacy_ad_cs_authority import (  # pylint: disable=import-error
    authority_arguments,
    manage_authority,
)
from legacy_ad_result import sanitize_result  # pylint: disable=import-error
from legacy_windows_module import (  # pylint: disable=import-error
    read_arguments,
    run_module,
)

# Ansible requires self-contained per-module documentation and return metadata.
# pylint: disable=duplicate-code
DOCUMENTATION = r"""
---
module: cs_authority
short_description: Manage CA CRL Distribution Points and Authority Information Access
version_added: '1.0.0'
description:
  - Manage CRL Distribution Point (CDP) and Authority Information Access
    (AIA) extension entries on a Windows Certificate Authority.
  - Uses the local CA's native registry configuration and service control APIs.
  - When O(cdp) or O(aia) is specified, the module enforces the exact
    desired list. Entries not in the desired list are removed, missing
    entries are added, and entries with matching URI but different flags
    are replaced.
  - When O(cdp) or O(aia) is omitted, that extension type is not managed.
  - The CertSvc service is restarted after changes when O(restart_service)
    is V(true).
options:
  cdp:
    description:
      - Desired list of CRL Distribution Point entries.
      - Each entry specifies a URI and the boolean flags that control
        how the CDP is used.
      - When specified, the module enforces exactly this list of CDPs.
        Existing entries not in the list are removed.
      - An empty list V([]) removes all CDP entries.
      - When omitted, CDP configuration is not managed.
      - "URI strings may contain ADCS variable tokens in angle-bracket
        format: C(<ServerDNSName>), C(<ServerShortName>),
        C(<CAName>), C(<CertificateName>), C(<CATruncatedName>),
        C(<CRLNameSuffix>), C(<DeltaCRLAllowed>),
        C(<ConfigurationContainer>), C(<CDPObjectClass>),
        C(<CAObjectClass>)."
    type: list
    elements: dict
    suboptions:
      uri:
        description:
          - The CDP URI.
          - Supports HTTP, LDAP, UNC, and file path URIs.
        type: str
        required: true
      publish_to_server:
        description:
          - Publish CRLs to this location.
        type: bool
        default: false
      publish_delta_to_server:
        description:
          - Publish delta CRLs to this location.
        type: bool
        default: false
      add_to_certificate_cdp:
        description:
          - Include this URI in the CDP extension of issued certificates.
        type: bool
        default: false
      add_to_freshest_crl:
        description:
          - Include this URI in the freshest CRL extension for locating
            delta CRLs.
        type: bool
        default: false
      add_to_crl_cdp:
        description:
          - Include this URI in the CDP extension of issued CRLs.
        type: bool
        default: false
      add_to_crl_idp:
        description:
          - Include this URI in the IDP (Issuing Distribution Point)
            extension of issued CRLs.
        type: bool
        default: false
  aia:
    description:
      - Desired list of Authority Information Access entries.
      - Each entry specifies a URI and whether it is an AIA or OCSP
        endpoint.
      - When specified, the module enforces exactly this list of AIA
        entries. Existing entries not in the list are removed.
      - An empty list V([]) removes all AIA entries.
      - When omitted, AIA configuration is not managed.
    type: list
    elements: dict
    suboptions:
      uri:
        description:
          - The AIA or OCSP URI.
        type: str
        required: true
      add_to_certificate_aia:
        description:
          - Include this URI in the AIA extension of issued certificates.
        type: bool
        default: false
      add_to_certificate_ocsp:
        description:
          - Include this URI in the OCSP extension of issued certificates.
        type: bool
        default: false
  restart_service:
    description:
      - Whether to restart the CertSvc service after making changes.
      - CDP and AIA changes typically require a service restart to take
        effect on newly issued certificates.
    type: bool
    default: true

notes:
  - This module must be run on the CA server itself.
  - Certificate Services must be installed and have an active local CA configuration.
  - Changes only affect newly issued certificates and CRLs. Previously
    issued certificates retain their original CDP and AIA references.
  - Administrator permissions on the CA are required.
  - CDP and AIA writes are not transactional; an earlier completed write remains if a later write or restart fails.
seealso:
  - module: sustainablelobster.legacy_ad.cs_template
extends_documentation_fragment:
  - ansible.builtin.action_common_attributes
attributes:
  check_mode:
    support: full
  diff_mode:
    support: none
  platform:
    platforms:
      - windows
author:
  - sustainablelobster
  - Ron Gershburg (@rgershbu)
"""

EXAMPLES = r"""
- name: Configure CDP with HTTP and local file publishing
  sustainablelobster.legacy_ad.cs_authority:
    cdp:
      - uri: >-
          C:\CertEnroll\<CAName><CRLNameSuffix><DeltaCRLAllowed>.crl
        publish_to_server: true
        publish_delta_to_server: true
      - uri: >-
          http://pki.corp.com/crl/<CAName><CRLNameSuffix><DeltaCRLAllowed>.crl
        add_to_certificate_cdp: true
        add_to_freshest_crl: true

- name: Configure AIA with HTTP and OCSP
  sustainablelobster.legacy_ad.cs_authority:
    aia:
      - uri: >-
          http://pki.corp.com/crl/<ServerDNSName>_<CAName><CertificateName>.crt
        add_to_certificate_aia: true
      - uri: 'http://ocsp.corp.com/ocsp'
        add_to_certificate_ocsp: true

- name: Configure both CDP and AIA together
  sustainablelobster.legacy_ad.cs_authority:
    cdp:
      - uri: >-
          C:\CertEnroll\<CAName><CRLNameSuffix><DeltaCRLAllowed>.crl
        publish_to_server: true
        publish_delta_to_server: true
      - uri: >-
          http://pki.corp.com/crl/<CAName><CRLNameSuffix><DeltaCRLAllowed>.crl
        add_to_certificate_cdp: true
        add_to_freshest_crl: true
    aia:
      - uri: >-
          http://pki.corp.com/crl/<ServerDNSName>_<CAName><CertificateName>.crt
        add_to_certificate_aia: true
      - uri: 'http://ocsp.corp.com/ocsp'
        add_to_certificate_ocsp: true
    restart_service: true

- name: Remove all CDP entries
  sustainablelobster.legacy_ad.cs_authority:
    cdp: []

- name: Configure CDP without restarting the service
  sustainablelobster.legacy_ad.cs_authority:
    cdp:
      - uri: >-
          http://pki.corp.com/crl/<CAName><CRLNameSuffix><DeltaCRLAllowed>.crl
        add_to_certificate_cdp: true
    restart_service: false
"""

RETURN = r"""
{}
"""
# pylint: enable=duplicate-code


def execute():
    """Manage the requested authority configuration and retain partial results.

    :returns: Ansible module result, including completed changes on failures.
    :rtype: dict
    """
    result = {"changed": False}
    raw = read_arguments(
        (), "sustainablelobster.legacy_ad.cs_authority", allow_unknown=True
    )
    arguments = None
    try:
        arguments = authority_arguments()
        manage_authority(arguments, result)
    # Keep this payload's error envelope beside its authority operation.
    # pylint: disable=duplicate-code
    except (OSError, ValueError, UnicodeError) as error:
        result.update({"failed": True, "msg": str(error)})
    return sanitize_result(result, raw, arguments)
    # pylint: enable=duplicate-code


def main():
    """Run the Certificate Services authority JSON payload."""
    run_module(execute)


if __name__ == "__main__":
    main()
