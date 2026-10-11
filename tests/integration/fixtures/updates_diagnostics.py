# -*- coding: utf-8 -*-
# Copyright 2026 sustainablelobster
# SPDX-License-Identifier: GPL-3.0-or-later

"""Read real Windows message descriptions at the minimum target Python version."""

import json
import sys

# The integration task copies both native helpers beside this owned fixture.
import legacy_windows_updates_native as native  # pylint: disable=import-error


def observe():
    """Read known, signed and unavailable native message descriptions.

    :returns: Actual runtime version and native descriptions indexed by code.
    :rtype: dict
    :raises AssertionError: The interpreter is not the compatibility floor.
    """
    assert sys.version_info[:3] == (3, 4, 4)
    codes = (0x80070005, -2147024891, 0x80070422, 0x80240020, 0xDEADBEEF)
    return {
        "python": list(sys.version_info[:3]),
        "messages": {str(code): native.hresult_description(code) for code in codes},
    }


if __name__ == "__main__":
    print(json.dumps(observe()))
