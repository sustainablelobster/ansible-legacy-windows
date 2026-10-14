#!/usr/bin/python
# -*- coding: utf-8 -*-
# Copyright 2026 sustainablelobster
# SPDX-License-Identifier: GPL-3.0-or-later

"""Manage AD FS claim rules using the installed vendor's rule validation."""

# WANT_JSON

import traceback

from legacy_ad_adfs import (  # pylint: disable=import-error
    claim_parameters,
    manage_claim_rules,
)
from legacy_ad_result import sanitize_result  # pylint: disable=import-error
from legacy_windows_module import (  # pylint: disable=import-error
    read_arguments,
    run_module,
)

_PARAMETERS = (
    "authorization_rules",
    "name",
    "state",
    "transform_rules",
)


def _handler():
    result = {
        "changed": False,
        "transform_rules": None,
        "authorization_rules": None,
        "diff": {"before": {}, "after": {}},
    }
    raw, arguments = {}, None
    try:
        raw = read_arguments(_PARAMETERS, "sustainablelobster.legacy_ad.fs_claim_rule")
        arguments = claim_parameters(raw)
        manage_claim_rules(arguments, result)
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
    """Emit claim-rule results and diff through the shared JSON protocol."""
    run_module(_handler)


if __name__ == "__main__":
    main()
