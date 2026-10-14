#!/usr/bin/python
# -*- coding: utf-8 -*-
# Copyright 2026 sustainablelobster
# Interface documentation derived from microsoft.ad, Copyright 2023 Ansible Project.
# SPDX-License-Identifier: GPL-3.0-or-later

"""Generate a Windows offline domain join blob for an existing AD computer."""

# WANT_JSON

import base64
import os
import traceback

import legacy_ad_offline_join as native  # pylint: disable=import-error
from legacy_ad_result import sanitize_result  # pylint: disable=import-error
from legacy_windows_module import (  # pylint: disable=import-error
    as_bool,
    as_string,
    read_arguments,
    run_module,
)

# Ansible requires self-contained per-module support metadata in these strings.
# pylint: disable=duplicate-code
DOCUMENTATION = r"""
---
module: offline_join
short_description: Get the Offline Domain Join BLOB
version_added: '1.0.0'
description:
  - Resolve an existing AD computer account and generate a native offline domain join blob.
  - The blob can join a computer to the domain without contacting a domain controller during the join.
options:
  blob_path:
    description:
      - Store binary bytes at this target path instead of returning base64 text.
      - Parent directories are not created. If the path already exists, the blob is not regenerated.
      - RV(blob) is null when this option is specified.
    type: str
  domain_server:
    description: Domain controller to use; defaults to the execution host's domain.
    type: str
  identity:
    description:
      - Existing computer DN, GUID, SID, or sAMAccountName.
      - Mutually exclusive with O(name); either O(identity) or O(name) is required.
    type: str
  name:
    description: Computer common name combined with O(path), mutually exclusive with O(identity).
    type: str
  path:
    description: Container for O(name); defaults to the directory's advertised computer-account container.
    type: str
  provision_root_ca_certs:
    description: Include local root CA certificates; requires C(NetCreateProvisioningPackage).
    type: bool
    default: false
attributes:
  check_mode:
    support: full
  diff_mode:
    support: none
  platform:
    platforms: [windows]
notes:
  - Uses the current Windows logon for native LDAP and provisioning. Use become with network credentials when delegation is unavailable.
  - A returned blob contains computer-account credentials. Use C(no_log=true) on tasks that return it, and secure files written with O(blob_path).
  - Always reports changed unless O(blob_path) already exists, matching upstream.
  - Generating a blob resets the existing computer account's password. Do not generate one for a computer already joined using that account.
  - Basic provisioning requires C(NetProvisionComputerAccount), introduced with Windows 7 and Server 2008 R2.
  - On systems exposing C(NetCreateProvisioningPackage), that API is used instead, matching upstream's provisioning implementation.
  - O(provision_root_ca_certs=true) is rejected before password changes if the newer package API is unavailable, including in check mode.
  - The native provisioning format is opaque and Windows-versioned. Blob creation alone does not prove that another host can consume it.
seealso:
  - module: sustainablelobster.legacy_ad.membership
  - module: sustainablelobster.legacy_ad.computer
author:
  - sustainablelobster
  - Jordan Borean (@jborean93)
"""

EXAMPLES = r"""
- name: Generate an offline blob for an existing computer
  sustainablelobster.legacy_ad.offline_join:
    identity: CLIENT01$
    domain_server: dc01.example.test
  register: offline_blob
  no_log: true

- name: Join the isolated computer with the blob
  sustainablelobster.legacy_ad.membership:
    offline_join_blob: '{{ offline_blob.blob }}'
    state: domain
    reboot: true
  delegate_to: client01

- name: Write a binary provisioning blob on the target
  sustainablelobster.legacy_ad.offline_join:
    name: CLIENT02
    path: OU=Computers,DC=example,DC=test
    blob_path: C:\Windows\Temp\client02.odj
"""

RETURN = r"""
blob:
  description:
    - Sensitive base64 provisioning data.
    - Empty string in check mode, or null when O(blob_path) is specified.
  returned: always
  type: str
"""
# pylint: enable=duplicate-code

_PARAMETERS = (
    "blob_path",
    "domain_server",
    "identity",
    "name",
    "path",
    "provision_root_ca_certs",
)


def _parameters(arguments):
    values = {
        name: as_string(arguments.get(name), name)
        for name in _PARAMETERS
        if name != "provision_root_ca_certs"
    }
    for name, value in values.items():
        if value is not None and "\0" in value:
            raise ValueError(name + " must not contain NUL characters.")
    values["provision_root_ca_certs"] = as_bool(
        arguments.get("provision_root_ca_certs", False), "provision_root_ca_certs"
    )
    if (values["identity"] is None) == (values["name"] is None):
        raise ValueError("Exactly one of identity and name is required.")
    return values


def _manage(parameters, check_mode=False):
    result = {"changed": False, "blob": None}
    try:
        domain, machine = native.computer_account(
            parameters["identity"],
            parameters["name"],
            parameters["path"],
            parameters["domain_server"],
        )
        path = parameters["blob_path"]
        if path and os.path.exists(path):
            return result
        # Resolve missing/newer-only APIs before an account's password can change,
        # including check mode, which must not promise an unsupported operation.
        native.provisioning_api(parameters["provision_root_ca_certs"])
        blob = (
            b""
            if check_mode
            else native.provision(
                domain,
                machine,
                parameters["domain_server"],
                parameters["provision_root_ca_certs"],
            )
        )
        result["changed"] = True
        if path:
            if not check_mode:
                with open(path, "wb") as output:
                    output.write(blob)
        else:
            result["blob"] = base64.b64encode(blob).decode("ascii")
    except (OSError, ValueError) as error:
        result.update(failed=True, msg=str(error))
    return result


def _response():
    raw, values = {}, None
    result = {"changed": False, "blob": None}
    try:
        raw = read_arguments(
            _PARAMETERS,
            "sustainablelobster.legacy_ad.offline_join",
            allow_unknown=True,
        )
        arguments = read_arguments(
            _PARAMETERS, "sustainablelobster.legacy_ad.offline_join"
        )
        values = _parameters(arguments)
        check = as_bool(
            arguments.get("_ansible_check_mode", False), "_ansible_check_mode"
        )
        result = _manage(values, check)
    # Each payload keeps its own secret-safe error envelope before emitting JSON.
    # pylint: disable=duplicate-code
    except (OSError, ValueError, UnicodeError) as error:
        result.update(failed=True, msg=str(error))
    # Unexpected boundary errors must also pass through credential redaction.
    except Exception as error:  # pylint: disable=broad-exception-caught
        result.update(
            failed=True,
            msg="Unhandled exception while executing module: " + str(error),
            exception=traceback.format_exc(),
        )
    return sanitize_result(result, raw, values)
    # pylint: enable=duplicate-code


def main():
    """Read an offline-provisioning task and emit its result.

    :raises SystemExit: After reporting an Ansible JSON success or failure.
    """
    run_module(_response)


if __name__ == "__main__":
    main()
