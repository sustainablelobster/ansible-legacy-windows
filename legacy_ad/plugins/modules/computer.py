#!/usr/bin/python
# -*- coding: utf-8 -*-
# Copyright 2026 sustainablelobster
# Interface documentation derived from microsoft.ad, Copyright 2023 Ansible Project.
# SPDX-License-Identifier: GPL-3.0-or-later

"""Manage Active Directory computer accounts using native Windows LDAP."""

import traceback

from legacy_ad_computer import (  # pylint: disable=import-error
    PARAMETERS,
    computer_arguments,
    manage_computer,
)
from legacy_ad_object import COMMON_PARAMETERS  # pylint: disable=import-error
from legacy_ad_result import sanitize_result  # pylint: disable=import-error
from legacy_windows_module import (  # pylint: disable=import-error
    read_arguments,
    run_module,
)

# WANT_JSON


def execute():
    """Apply computer changes and retain identifiers after partial failures.

    :returns: The Ansible computer-account result.
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
            "sustainablelobster.legacy_ad.computer",
            allow_unknown=True,
        )
        arguments = computer_arguments()
        manage_computer(arguments, result)
    # Each payload owns its JSON entry point and completed-change reporting.
    # pylint: disable=duplicate-code
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
    """Run the computer payload through the shared Ansible JSON contract."""
    run_module(execute)


if __name__ == "__main__":
    main()
# pylint: enable=duplicate-code
