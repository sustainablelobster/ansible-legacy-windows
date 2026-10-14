#!/usr/bin/python
# -*- coding: utf-8 -*-
# Copyright 2026 sustainablelobster
# SPDX-License-Identifier: GPL-3.0-or-later

"""Manage Active Directory users with native Windows LDAP and logon APIs."""

import traceback

from legacy_ad_object import COMMON_PARAMETERS  # pylint: disable=import-error
from legacy_ad_result import sanitize_result  # pylint: disable=import-error
from legacy_ad_user import (  # pylint: disable=import-error
    PARAMETERS,
    manage_user,
    user_arguments,
)
from legacy_windows_module import (  # pylint: disable=import-error
    read_arguments,
    run_module,
)

# WANT_JSON


# Each public payload owns its JSON entry point and partial-failure reporting.
# pylint: disable=duplicate-code
def execute():
    """Manage the requested user without returning password values.

    :returns: Ansible user-management result, retaining partial changes on failure.
    :rtype: dict
    """
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
            "sustainablelobster.legacy_ad.user",
            allow_unknown=True,
        )
        arguments = user_arguments()
        manage_user(arguments, result)
    except (OSError, ValueError, UnicodeError) as error:
        result.update({"failed": True, "msg": str(error)})
    # Sanitize unexpected boundary failures before the shared runner emits JSON.
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
    """Run the user payload through the shared Ansible JSON contract."""
    run_module(execute)


if __name__ == "__main__":
    main()
