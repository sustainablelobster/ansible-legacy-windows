#!/usr/bin/python
# -*- coding: utf-8 -*-
# Copyright 2026 sustainablelobster
# SPDX-License-Identifier: GPL-3.0-or-later

"""Manage KDS root keys using the current Windows domain security context."""

# WANT_JSON

from legacy_ad_kds import kds_arguments, manage_root_key  # pylint: disable=import-error
from legacy_windows_module import (  # pylint: disable=import-error
    read_arguments,
    run_module,
)

_PARAMETERS = (
    "effective_time_hours",
    "key_id",
    "match_by",
    "state",
)


# Keep each public KDS payload's failure envelope next to its own operation.
# pylint: disable=duplicate-code
def _handler():
    result = {"changed": False, "key_id": None}
    try:
        raw = read_arguments(_PARAMETERS, "sustainablelobster.legacy_ad.kds_root_key")
        manage_root_key(kds_arguments(raw), result)
    except (OSError, UnicodeError, ValueError) as error:
        result.update({"failed": True, "msg": str(error)})
    return result


def main():
    """Run the KDS root-key management JSON payload."""
    run_module(_handler)


if __name__ == "__main__":
    main()
# pylint: enable=duplicate-code
