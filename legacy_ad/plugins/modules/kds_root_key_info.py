#!/usr/bin/python
# -*- coding: utf-8 -*-
# Copyright 2026 sustainablelobster
# SPDX-License-Identifier: GPL-3.0-or-later

"""Read KDS root-key metadata through the current domain security context."""

# WANT_JSON

from legacy_ad_kds import kds_arguments, read_root_keys  # pylint: disable=import-error
from legacy_windows_module import (  # pylint: disable=import-error
    read_arguments,
    run_module,
)

_PARAMETERS = ("key_id",)


# Keep each public KDS payload's failure envelope next to its own operation.
# pylint: disable=duplicate-code
def _handler():
    result = {"changed": False, "kds_root_keys": []}
    try:
        raw = read_arguments(
            _PARAMETERS, "sustainablelobster.legacy_ad.kds_root_key_info"
        )
        read_root_keys(kds_arguments(raw, information=True), result)
    except (OSError, UnicodeError, ValueError) as error:
        result.update({"failed": True, "msg": str(error)})
    return result


def main():
    """Run the read-only KDS information JSON payload."""
    run_module(_handler)


if __name__ == "__main__":
    main()
# pylint: enable=duplicate-code
