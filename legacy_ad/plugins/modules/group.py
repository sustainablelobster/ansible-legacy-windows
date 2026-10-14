#!/usr/bin/python
# -*- coding: utf-8 -*-
# Copyright 2026 sustainablelobster
# SPDX-License-Identifier: GPL-3.0-or-later

"""Manage Active Directory group objects with native Windows LDAP."""

import traceback

from legacy_ad_group import PARAMETERS, manage_group  # pylint: disable=import-error
from legacy_ad_object import (  # pylint: disable=import-error
    COMMON_PARAMETERS,
    object_arguments,
)
from legacy_ad_result import sanitize_result  # pylint: disable=import-error
from legacy_windows_module import (  # pylint: disable=import-error
    read_arguments,
    run_module,
)

# WANT_JSON


# Each public payload owns its JSON entry point and partial-failure reporting.
# pylint: disable=duplicate-code
def execute():
    """Manage the requested group while preserving observed partial changes.

    :returns: Ansible group-management result, including identifiers and failures.
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
            "sustainablelobster.legacy_ad.group",
            allow_unknown=True,
        )
        arguments = object_arguments("sustainablelobster.legacy_ad.group", PARAMETERS)
        manage_group(arguments, result)
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
    """Run the group payload through the shared Ansible JSON contract."""
    run_module(execute)


if __name__ == "__main__":
    main()
