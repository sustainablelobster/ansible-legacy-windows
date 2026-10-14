#!/usr/bin/python
# -*- coding: utf-8 -*-
# Copyright 2026 sustainablelobster
# SPDX-License-Identifier: GPL-3.0-or-later

"""Manage native Active Directory password settings objects."""

# WANT_JSON

import traceback

from legacy_ad_object import (  # pylint: disable=import-error
    COMMON_PARAMETERS,
    object_arguments,
)
from legacy_ad_policy_pso import PARAMETERS, manage_pso  # pylint: disable=import-error
from legacy_ad_result import sanitize_result  # pylint: disable=import-error
from legacy_windows_module import (  # pylint: disable=import-error
    read_arguments,
    run_module,
)


def execute():
    """Apply a PSO request and preserve identifiers and partial changes on failure.

    :returns: Ansible PSO result, sanitized for supplied credentials.
    :rtype: dict
    """
    result = {"changed": False, "distinguished_name": None, "object_guid": None}
    raw, arguments = {}, None
    try:
        raw = read_arguments(
            COMMON_PARAMETERS + PARAMETERS,
            "sustainablelobster.legacy_ad.pso",
            allow_unknown=True,
        )
        arguments = object_arguments("sustainablelobster.legacy_ad.pso", PARAMETERS)
        manage_pso(arguments, result)
    # Each payload keeps its own secret-safe error envelope before emitting JSON.
    # pylint: disable=duplicate-code
    except (OSError, ValueError, UnicodeError) as error:
        result.update(failed=True, msg=str(error))
    # Sanitize unexpected boundary failures before the shared runner emits JSON.
    except Exception as error:  # pylint: disable=broad-exception-caught
        result.update(
            failed=True,
            msg="Unhandled exception while executing module: " + str(error),
            exception=traceback.format_exc(),
        )
    return sanitize_result(result, raw, arguments)
    # pylint: enable=duplicate-code


def main():
    """Emit the PSO module result through the shared Ansible JSON contract."""
    run_module(execute)


if __name__ == "__main__":
    main()
