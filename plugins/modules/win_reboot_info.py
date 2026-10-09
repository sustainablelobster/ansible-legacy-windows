#!/usr/bin/python
# -*- coding: utf-8 -*-
# Copyright 2026 Joe Lustri
# SPDX-License-Identifier: GPL-3.0-or-later

"""Read boot history and pending-reboot reasons with Python 3.4.4."""

# WANT_JSON

import datetime

# The action stages the native readers and their dependencies beside the payload.
import legacy_windows_boot as boot  # pylint: disable=import-error
import legacy_windows_reboot as reboot  # pylint: disable=import-error
from legacy_windows_module import (  # pylint: disable=import-error
    as_bool,
    read_arguments,
    run_module,
)

# Ansible interfaces must be self-contained; repeated option/return text is
# interface documentation, not duplicated execution logic.
# pylint: disable=duplicate-code
DOCUMENTATION = r"""
---
module: win_reboot_info
short_description: Read boot history and pending-reboot reasons
version_added: '1.0.0'
description:
  - Reads the operating system's last boot time, its most recent qualifying reboot event, and pending-reboot indicators.
  - Uses Python 3.4.4, native WMI, event-log APIs, and registry reads.
options: {}
attributes:
  check_mode:
    support: full
    description: Performs the same read as normal execution and reports no change.
  diff_mode:
    support: none
notes:
  - Does not reboot the host, clear pending operations, or change registry values or event logs.
  - Pending reasons follow the pinned upstream order, and reflect the registry view of the target Python process.
  - Only the newest System event with ID 1074 is considered. An event more than five minutes before the boot time is excluded.
  - When no qualifying event exists, the pinned upstream implementation returns an empty dictionary for RV(last_reboot.details), despite its documentation describing null.
  - Missing event properties remain null, except that a missing reason code follows upstream conversion to zero.
  - Uses the classic event-log API on XP and Server 2003 and the Windows Event Log API on newer systems.
  - A terminating event-query or formatting failure retains the pinned upstream failure caused by its invalid two-argument warning call.
author:
  - Joe Lustri
"""

EXAMPLES = r"""
- name: Read reboot information without rebooting
  sustainablelobster.legacy_windows.win_reboot_info:
  register: reboot_info

- name: Show why a reboot is pending
  ansible.builtin.debug:
    var: reboot_info.reboot_required_reasons
  when: reboot_info.reboot_required

- name: Show available details about the latest reboot event
  ansible.builtin.debug:
    var: reboot_info.last_reboot.details
  when: reboot_info.last_reboot.details | length > 0
"""

RETURN = r"""
last_reboot:
  description: Last boot time and available details of the latest reboot event.
  returned: success
  type: dict
  contains:
    time:
      description: UTC boot time formatted as C(YYYY-MM-DDTHH:MM:SSZ).
      type: str
    time_epoch:
      description: Fractional Unix seconds, preserving upstream tick-to-float conversion.
      type: float
    details:
      description: Details of the newest qualifying System event 1074, or an empty dictionary.
      type: dict
      contains:
        process:
          description: Process recorded as requesting shutdown or restart, or null when absent.
          type: str
        reason:
          description: Recorded reason text, or null when absent.
          type: str
        reason_code:
          description: Reason converted to a signed 64-bit integer where possible, otherwise its original value.
          type: raw
        type:
          description: Recorded action such as restart or shutdown, or null when absent.
          type: str
        comment:
          description: Recorded comment, including an empty string, or null when absent.
          type: str
        initiated_by:
          description: Recorded account name, or null when the event has no such property.
          type: str
        event_time:
          description: UTC event time formatted as C(YYYY-MM-DDTHH:MM:SSZ).
          type: str
reboot_required:
  description: Whether any of the six upstream registry indicators reports a pending reboot.
  returned: success
  type: bool
reboot_required_reasons:
  description: Ordered pending-reboot reasons, empty when no indicator is present.
  returned: success
  type: list
  elements: dict
  contains:
    source:
      description: C(component_based_servicing), C(windows_update), C(pending_file_rename), C(pending_computer_rename), C(domain_join), or C(server_manager).
      type: str
    description:
      description: Human-readable explanation of the pending operation.
      type: str
"""
# pylint: enable=duplicate-code

_MODULE_NAME = "sustainablelobster.legacy_windows.win_reboot_info"


def _response():
    arguments = read_arguments((), _MODULE_NAME)
    try:
        boot_time = boot.last_boot_time()
    except (OSError, ValueError, OverflowError, MemoryError) as error:
        # Upstream converts acquisition and datetime errors into a module failure.
        raise ValueError(
            "Failed to get last boot time from CIM: " + str(error)
        ) from error
    delta = boot_time - datetime.datetime(1970, 1, 1)
    ticks = (delta.days * 86400 + delta.seconds) * 10000000 + delta.microseconds * 10
    history = {
        "time": boot_time.strftime("%Y-%m-%dT%H:%M:%SZ"),
        # TimeSpan.TotalSeconds multiplies integer ticks by a double constant;
        # datetime.total_seconds() can round to a different final float.
        "time_epoch": ticks * 1e-7,
        "details": reboot.recent_reboot(boot_time),
    }
    reasons = reboot.pending_reboot_reasons()
    result = {
        "changed": False,
        "last_reboot": history,
        "reboot_required": bool(reasons),
        "reboot_required_reasons": reasons,
    }
    if as_bool(
        arguments.get("_ansible_inject_invocation", False), "_ansible_inject_invocation"
    ):
        result["invocation"] = {"module_args": {}}
    return result


def main():
    """Read Ansible arguments and emit read-only reboot information.

    :raises SystemExit: After reporting success or failure as JSON.
    """
    run_module(_response)


# Each independently staged payload needs its own executable entry guard.
# pylint: disable=duplicate-code
if __name__ == "__main__":
    main()
# pylint: enable=duplicate-code
