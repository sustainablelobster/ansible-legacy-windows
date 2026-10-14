#!/usr/bin/python
# -*- coding: utf-8 -*-
# Copyright 2026 sustainablelobster
# SPDX-License-Identifier: GPL-3.0-or-later

"""Manage native Windows directory promotion with secret-safe partial results."""

import traceback

from legacy_ad_domain import (  # pylint: disable=import-error
    CONTROLLER_PARAMETERS,
    controller_arguments,
    manage_controller,
)
from legacy_ad_result import sanitize_result  # pylint: disable=import-error
from legacy_windows_module import (  # pylint: disable=import-error
    read_arguments,
    run_module,
)

# WANT_JSON


# Each public module retains its own released JSON entry point.
# pylint: disable=duplicate-code
def execute():
    """Manage the requested role while retaining partial changes on failure.

    :returns: Ansible role-management result and reboot requirement.
    :rtype: dict
    """
    result = {"changed": False, "reboot_required": False, "_do_action_reboot": False}
    raw, arguments = {}, None
    try:
        raw = read_arguments(
            CONTROLLER_PARAMETERS,
            "sustainablelobster.legacy_ad.domain_controller",
            allow_unknown=True,
        )
        arguments = controller_arguments()
        manage_controller(arguments, result)
    except (OSError, ValueError, UnicodeError) as error:
        result.update(failed=True, msg=str(error))
    # Unexpected native failures must also pass through password redaction.
    except Exception as error:  # pylint: disable=broad-exception-caught
        result.update(
            failed=True,
            msg="Unhandled exception while executing module: " + str(error),
            exception=traceback.format_exc(),
        )
    return sanitize_result(result, raw, arguments)


def main():
    """Run the payload through the shared Windows JSON contract."""
    run_module(execute)


if __name__ == "__main__":
    main()
