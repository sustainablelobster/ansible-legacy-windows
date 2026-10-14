#!/usr/bin/python
# -*- coding: utf-8 -*-
# Copyright 2026 sustainablelobster
# SPDX-License-Identifier: GPL-3.0-or-later

"""Manage local-side Active Directory trusts using native Windows security APIs."""

import traceback

from legacy_ad_result import sanitize_result  # pylint: disable=import-error
from legacy_ad_trust import (  # pylint: disable=import-error
    PARAMETERS,
    manage_trust,
    trust_arguments,
)
from legacy_windows_module import (  # pylint: disable=import-error
    read_arguments,
    run_module,
)

# WANT_JSON


def execute():
    """Manage a trust while retaining partial results and redacting its secret.

    :returns: The released trust module's observable result contract.
    :rtype: dict
    """
    result = {"changed": False, "distinguished_name": None}
    raw, arguments = {}, None
    try:
        raw = read_arguments(
            PARAMETERS, "sustainablelobster.legacy_ad.domain_trust", allow_unknown=True
        )
        arguments = trust_arguments()
        manage_trust(arguments, result)
    # Each payload keeps its own secret-safe error envelope before emitting JSON.
    # pylint: disable=duplicate-code
    except (OSError, ValueError, UnicodeError) as error:
        result.update(failed=True, msg=str(error))
    # Native boundary failures must retain secret-safe JSON reporting too.
    except Exception as error:  # pylint: disable=broad-exception-caught
        result.update(
            failed=True,
            msg="Unhandled exception while executing module: " + str(error),
            exception=traceback.format_exc(),
        )
    return sanitize_result(result, raw, arguments)
    # pylint: enable=duplicate-code


def main():
    """Run trust management through the established Windows JSON contract."""
    run_module(execute)


if __name__ == "__main__":
    main()
