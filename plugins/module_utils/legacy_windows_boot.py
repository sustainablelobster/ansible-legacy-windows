# -*- coding: utf-8 -*-
# Copyright 2026 Joe Lustri
# SPDX-License-Identifier: GPL-3.0-or-later

"""Read the operating system's boot timestamp through native local WMI."""

import datetime

# The action stages this shared native WMI helper beside the payload.
from legacy_windows_wmi import (  # pylint: disable=import-error
    WmiConnection,
    parse_datetime,
)


def last_boot_time():
    """Read Win32_OperatingSystem.LastBootUpTime from local native WMI.

    :returns: Naive UTC datetime, retaining the reported microseconds.
    :rtype: datetime.datetime
    :raises OSError: COM or WMI cannot retrieve the operating system property.
    :raises ValueError: WMI does not return a complete datetime value.
    :raises OverflowError: The UTC timestamp is outside datetime's year range.
    :raises MemoryError: Allocation of a WMI query string fails.
    """
    with WmiConnection() as connection:
        rows = connection.query(
            "SELECT LastBootUpTime FROM Win32_OperatingSystem", ["LastBootUpTime"]
        )
        if not rows:
            raise OSError("WMI returned no Win32_OperatingSystem instance.")
        timestamp = parse_datetime(rows[0]["LastBootUpTime"], "LastBootUpTime")
        return timestamp.astimezone(datetime.timezone.utc).replace(tzinfo=None)
