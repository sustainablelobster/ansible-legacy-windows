# -*- coding: utf-8 -*-
# Copyright 2026 sustainablelobster
# SPDX-License-Identifier: GPL-3.0-or-later

"""Snapshot process names and creation times, then resolve endpoint owners."""

import datetime
from contextlib import ExitStack

# The action stages these shared native helpers beside the payload.
import legacy_windows_time as native_time  # pylint: disable=import-error
from legacy_windows_wmi import (  # pylint: disable=import-error
    WmiConnection,
    parse_datetime,
)


def _creation_time(value):
    if value is None:
        return None
    utc = parse_datetime(value, "CreationDate").astimezone(datetime.timezone.utc)
    seconds = ((utc.toordinal() - 1) * 86400) + utc.hour * 3600
    seconds += utc.minute * 60 + utc.second
    # Python 3.4's implicit astimezone() reports UTC on the tested Windows
    # runtimes. Use Windows timezone rules, retaining WMI's microseconds.
    local_ticks = native_time.utc_ticks_to_local_ticks(
        seconds * 10000000 + utc.microsecond * 10
    )
    days, remainder = divmod(local_ticks, 864000000000)
    return datetime.datetime.fromordinal(days + 1) + datetime.timedelta(
        microseconds=remainder // 10
    )


class ProcessReader:
    """Snapshot Win32_Process once on entry and keep WMI open for owner calls."""

    def __init__(self):
        self._connection = None
        self._cleanup = None
        self._processes = {}

    def __enter__(self):
        with ExitStack() as cleanup:
            self._connection = cleanup.enter_context(WmiConnection())
            rows = self._connection.query(
                "SELECT ProcessId, Name, CreationDate FROM Win32_Process",
                ["ProcessId", "Name", "CreationDate", "__PATH"],
            )
            self._processes = {row["ProcessId"]: row for row in rows}
            self._cleanup = cleanup.pop_all()
        return self

    def __exit__(self, exc_type, exc_value, traceback):
        self._cleanup.close()

    def get(self, pid):
        """Read snapshot details and invoke GetOwner for an endpoint's process.

        :param int pid: Endpoint's owning process identifier.
        :returns: Dictionary with name, naive local creation_time, and user.
            Name retains its executable suffix. Unknown timestamps or owners
            are None; owners join non-null Domain and User with a backslash.
        :rtype: dict
        :raises OSError: The process is absent or its owner cannot be queried.
        :raises ValueError: A WMI field or creation timestamp cannot be decoded.
        :raises OverflowError: Timestamp conversion is outside datetime's range.
        :raises MemoryError: Allocation of a WMI method string fails.
        """
        if pid not in self._processes:
            raise OSError(
                "Process {0} was not present in the WMI snapshot.".format(pid)
            )
        process = self._processes[pid]
        owner = self._connection.call_method(
            process["__PATH"], "GetOwner", ["Domain", "User"]
        )
        user = None
        if owner["Domain"] is not None and owner["User"] is not None:
            user = owner["Domain"] + "\\" + owner["User"]
        return {
            "name": process["Name"],
            "creation_time": _creation_time(process["CreationDate"]),
            "user": user,
        }
