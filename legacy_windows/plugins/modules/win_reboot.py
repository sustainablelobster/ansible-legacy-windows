#!/usr/bin/python
# -*- coding: utf-8 -*-
# Copyright 2026 sustainablelobster
# SPDX-License-Identifier: GPL-3.0-or-later

"""Provide the action's native boot, shutdown and readiness operations."""

# WANT_JSON

import legacy_windows_reboot_request as reboot  # pylint: disable=import-error
from legacy_windows_module import (  # pylint: disable=import-error
    as_bool,
    as_string,
    read_arguments,
    run_module,
)

DOCUMENTATION = r"""
---
module: win_reboot
short_description: Reboot Windows and wait for management readiness
version_added: '1.0.0'
description:
  - Unconditionally restarts Windows and waits for a changed boot timestamp and successful readiness test.
  - Default boot, shutdown and readiness operations use native Windows tools and Python 3.4.4.
options:
  pre_reboot_delay:
    description: Seconds until restart. The minimum effective value is two seconds.
    type: float
    default: 2
    aliases: [pre_reboot_delay_sec]
  post_reboot_delay:
    description: Additional seconds after requesting restart before boot validation.
    type: float
    default: 0
    aliases: [post_reboot_delay_sec]
  reboot_timeout:
    description: Seconds allowed separately for boot validation and the readiness test.
    type: float
    default: 600
    aliases: [reboot_timeout_sec]
  connect_timeout:
    description: Per-attempt connection timeout while verifying the changed boot time.
    type: float
    default: 5
    aliases: [connect_timeout_sec]
  msg:
    description: Message displayed to logged-on users during shutdown.
    type: str
    default: Reboot initiated by Ansible
  boot_time_command:
    description:
      - Explicit PowerShell command returning a boot identifier stable until the next boot.
      - The default expression is implemented by the native WMI reader without invoking PowerShell.
    type: str
    default: '(Get-CimInstance -ClassName Win32_OperatingSystem -Property LastBootUpTime).LastBootUpTime.ToFileTime()'
  test_command:
    description:
      - Explicit PowerShell command whose successful exit establishes management readiness.
      - On modern Windows, defaults to waiting for the Windows logon marker to be recreated after restart.
      - On XP and Server 2003, waits for the native Service Control Manager automatic-service and driver startup-completion event.
    type: str
attributes:
  check_mode:
    support: full
    description: Returns a reboot prediction without validation or target execution.
  diff_mode:
    support: none
notes:
  - An already scheduled shutdown is aborted and replaced by this restart request.
  - Custom command interfaces require PowerShell.
  - The effective account needs the Windows rights required by the native shutdown tool.
  - Native C(runas) applies the requested account to boot, shutdown, and readiness
    operations, including after reconnection. The upstream reboot action ignores
    become; honoring it is a capability of this collection.
  - The requested account needs the permissions and logon rights required by these
    operations. Other privilege-escalation methods are rejected before target staging.
  - Native C(runas) can fail to acquire a SYSTEM token on XP or Server 2003,
    even with administrative access and an enabled debug privilege. A named
    account with a password can be used when it has the required permissions.
  - Reboot and readiness do not imply that every background service has settled.
  - The legacy startup event establishes completed automatic startup attempts, not that every service succeeded or that the logon prompt is displayed.
author:
  - sustainablelobster
"""

EXAMPLES = r"""
- name: Restart Windows and wait for native startup readiness
  sustainablelobster.legacy_windows.win_reboot:

- name: Allow extra time for a slow restart
  sustainablelobster.legacy_windows.win_reboot:
    reboot_timeout: 900
    post_reboot_delay: 30
"""

RETURN = r"""
rebooted:
  description: Whether a restart was requested successfully or predicted.
  type: bool
  returned: always
elapsed:
  description: Whole seconds elapsed after requesting restart.
  type: float
  returned: always
"""


def _response():
    arguments = read_arguments(
        ("_operation", "command", "delay", "message", "default_readiness", "expected"),
        "sustainablelobster.legacy_windows.win_reboot",
    )
    operation = arguments.get("_operation")
    if operation == "boot":
        result = reboot.observe_boot(as_string(arguments.get("command"), "command"))
    elif operation == "ready":
        result = reboot.observe_readiness(
            as_string(arguments.get("command"), "command"),
            as_string(arguments.get("expected"), "expected"),
        )
    elif operation == "request":
        try:
            delay = float(arguments.get("delay"))
        except (TypeError, ValueError) as error:
            raise ValueError("The internal reboot delay must be a number.") from error
        message = as_string(arguments.get("message"), "message")
        if message is None:
            raise ValueError("The internal reboot message is required.")
        result = reboot.request_reboot(
            delay,
            message,
            as_bool(arguments.get("default_readiness"), "default_readiness"),
        )
    elif operation == "abort":
        result = reboot.abort_reboot()
    else:
        raise ValueError("win_reboot must be invoked through its controller action.")
    result["changed"] = False
    return result


def main():
    """Emit one internal reboot operation through Ansible's JSON protocol.

    :raises SystemExit: Zero for a reported result, one for a payload failure.
    """
    run_module(_response)


if __name__ == "__main__":
    main()
