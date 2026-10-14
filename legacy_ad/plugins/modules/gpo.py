#!/usr/bin/python
# -*- coding: utf-8 -*-
# Copyright 2026 sustainablelobster
# SPDX-License-Identifier: GPL-3.0-or-later

"""Manage existing Group Policy Object links through native LDAP."""

# WANT_JSON

import traceback

from legacy_ad_policy_gpo import (  # pylint: disable=import-error
    PARAMETERS,
    manage_gpo,
    parameters,
)
from legacy_ad_result import sanitize_result  # pylint: disable=import-error
from legacy_windows_module import (  # pylint: disable=import-error
    read_arguments,
    run_module,
)


def execute():
    """Run the GPO-link request while retaining its result on failures.

    :returns: Ansible GPO link result and optional before/after diff.
    :rtype: dict
    """
    result = {"changed": False}
    raw, arguments = {}, None
    try:
        raw = read_arguments(PARAMETERS, "sustainablelobster.legacy_ad.gpo")
        arguments = parameters(raw)
        manage_gpo(arguments, result)
    # Each independently staged payload owns its JSON and failure boundary.
    # pylint: disable=duplicate-code
    except (OSError, ValueError, UnicodeError) as error:
        result.update(failed=True, msg=str(error))
    # Native/JSON boundaries must report unexpected failures in Ansible's format.
    except Exception as error:  # pylint: disable=broad-exception-caught
        result.update(
            failed=True,
            msg="Unhandled exception while executing module: " + str(error),
            exception=traceback.format_exc(),
        )
    return sanitize_result(result, raw, arguments)


# pylint: enable=duplicate-code


def main():
    """Emit a GPO-link module result through the shared Ansible JSON contract."""
    run_module(execute)


if __name__ == "__main__":
    main()
