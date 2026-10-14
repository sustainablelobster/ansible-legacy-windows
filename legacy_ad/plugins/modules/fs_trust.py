#!/usr/bin/python
# -*- coding: utf-8 -*-
# Copyright 2026 sustainablelobster
# SPDX-License-Identifier: GPL-3.0-or-later

"""Manage AD FS relying-party trusts using installed vendor commands."""

# WANT_JSON

import traceback

from legacy_ad_adfs import (  # pylint: disable=import-error
    manage_trust,
    trust_parameters,
)
from legacy_ad_result import sanitize_result  # pylint: disable=import-error
from legacy_windows_module import (  # pylint: disable=import-error
    read_arguments,
    run_module,
)

_PARAMETERS = (
    "access_control_policy_name",
    "auto_update_enabled",
    "enabled",
    "encrypt_claims",
    "identifier",
    "metadata_file",
    "metadata_url",
    "monitoring_enabled",
    "name",
    "notes",
    "saml_endpoint",
    "signature_algorithm",
    "state",
    "token_lifetime",
    "wsfed_endpoint",
)


def _handler():
    result = {
        "changed": False,
        "identifier": [],
        "enabled": None,
        "monitoring_enabled": None,
    }
    raw, arguments = {}, None
    try:
        raw = read_arguments(_PARAMETERS, "sustainablelobster.legacy_ad.fs_trust")
        arguments = trust_parameters(raw)
        manage_trust(arguments, result)
    # Each independently staged payload preserves its partial failure envelope.
    # pylint: disable=duplicate-code
    except (OSError, ValueError, UnicodeError) as error:
        result.update(failed=True, msg=str(error))
    # Unexpected vendor boundary failures must still use Ansible's JSON contract.
    except Exception as error:  # pylint: disable=broad-exception-caught
        result.update(failed=True, msg=str(error), exception=traceback.format_exc())
    return sanitize_result(result, raw, arguments)
    # pylint: enable=duplicate-code


def main():
    """Emit the relying-party trust result through the shared JSON protocol."""
    run_module(_handler)


if __name__ == "__main__":
    main()
