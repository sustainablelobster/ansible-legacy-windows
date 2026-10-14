#!/usr/bin/python
# -*- coding: utf-8 -*-
# Copyright 2026 sustainablelobster
# SPDX-License-Identifier: GPL-3.0-or-later

"""Manage group managed service accounts using native Windows LDAP."""

import traceback

from legacy_ad_object import COMMON_PARAMETERS  # pylint: disable=import-error
from legacy_ad_result import sanitize_result  # pylint: disable=import-error
from legacy_ad_service_account import (  # pylint: disable=import-error
    PARAMETERS,
    manage_service_account,
    service_account_arguments,
)
from legacy_windows_module import (  # pylint: disable=import-error
    read_arguments,
    run_module,
)

# WANT_JSON


def execute():
    """Apply service-account changes and preserve completed partial effects.

    :returns: The Ansible gMSA result, excluding managed-password material.
    :rtype: dict
    """
    # Each payload owns its partial-effect envelope and raw credential boundary.
    # pylint: disable=duplicate-code
    result = {
        "changed": False,
        "distinguished_name": None,
        "object_guid": None,
        "sid": None,
    }
    raw, arguments = {}, None
    try:
        raw = read_arguments(
            COMMON_PARAMETERS + PARAMETERS,
            "sustainablelobster.legacy_ad.service_account",
            allow_unknown=True,
        )
        # pylint: enable=duplicate-code
        arguments = service_account_arguments()
        manage_service_account(arguments, result)
    # Each payload owns its JSON boundary and completed-change reporting.
    # pylint: disable=duplicate-code
    except (OSError, ValueError, UnicodeError) as error:
        result.update({"failed": True, "msg": str(error)})
    except Exception as error:  # pylint: disable=broad-exception-caught
        result.update(
            {
                "failed": True,
                "msg": "Unhandled exception while executing module: " + str(error),
                "exception": traceback.format_exc(),
            }
        )
    return sanitize_result(result, raw, arguments)


def main():
    """Run the gMSA payload through the shared Ansible JSON contract."""
    run_module(execute)


if __name__ == "__main__":
    main()
# pylint: enable=duplicate-code
