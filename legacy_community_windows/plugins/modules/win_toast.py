#!/usr/bin/python
# -*- coding: utf-8 -*-
# Copyright: (c) 2017, Jon Hawkesworth (@jhawkesworth) <jhawkesworth@protonmail.com>
# Copyright: (c) 2017, Ansible Project
# Copyright 2026 sustainablelobster
# SPDX-License-Identifier: GPL-3.0-or-later

"""Send local desktop toast notifications through native Windows Runtime APIs."""

# WANT_JSON

import datetime
import time

import legacy_community_windows_toast as native  # pylint: disable=import-error
from legacy_windows_module import (  # pylint: disable=import-error
    as_bool,
    as_string,
    read_arguments,
    run_module,
)

DOCUMENTATION = r"""
---
module: win_toast
short_description: Send local Windows desktop toast notifications
description:
  - Sends alerts to the local Windows desktop notification area.
options:
  expire:
    description: Seconds until the notification expires.
    type: int
    default: 45
  group:
    description: Notification group.
    type: str
    default: Powershell
  msg:
    description: Message text; newlines are preserved.
    type: str
    default: Hello, World!
  popup:
    description: Whether the notification pops up instead of appearing only in notification history.
    type: bool
    default: true
  tag:
    description: Notification tag.
    type: str
    default: Ansible
  title:
    description: Notification title, defaulting to the local short time.
    type: str
    default: Notification HH:mm
notes:
  - Requires the native Windows Runtime toast notification interfaces, including tag, group and popup suppression.
  - The recorded upstream release requires Windows 10 or Server 2016; this implementation checks actual APIs.
  - Uses the released Explorer-process check and succeeds without sending when no Explorer process exists.
  - Sends only to the executing account's local notification context, not every interactive user's session.
  - A sent notification waits for I(expire) seconds. Use Ansible async when the controller should not wait.
  - Check mode validates the notifier and message without showing a toast or waiting.
author:
  - Jon Hawkesworth (@jhawkesworth)
  - sustainablelobster
"""

EXAMPLES = r"""
- name: Warn local desktop users about an upgrade
  sustainablelobster.legacy_community_windows.win_toast:
    expire: 60
    title: System Upgrade Notification
    msg: Save your work before the automated upgrade begins.
  async: 90
  poll: 0
"""

RETURN = r"""
expire_at_utc:
  description: UTC date and time when the notification expires.
  returned: always
  type: str
  sample: 07 July 2017 04:50:54
no_toast_sent_reason:
  description: Reason no notification was sent.
  returned: when no logged in users are detected
  type: str
  sample: No logged in users to notify
sent_localtime:
  description: Local date and time when the send operation completed.
  returned: always
  type: str
  sample: 07 July 2017 05:45:54
time_taken:
  description: Elapsed operation time in seconds.
  returned: always
  type: float
  sample: 0.3706631999999997
toast_sent:
  description: Whether the native Show operation accepted the notification.
  returned: always
  type: bool
  sample: false
"""


def _execute(arguments):
    native.available()
    started = time.monotonic()
    now = datetime.datetime.now()
    try:
        expire = int(arguments.get("expire", 45))
    except (ValueError, TypeError, OverflowError) as error:
        raise ValueError("expire must be an integer number of seconds.") from error
    if expire < 0:
        raise ValueError("expire must not be negative.")
    expires_local = now + datetime.timedelta(seconds=expire)
    expires = datetime.datetime.now(datetime.timezone.utc) + datetime.timedelta(
        seconds=expire
    )
    parameters = {
        name: as_string(arguments.get(name, default), name)
        for name, default in (
            ("group", "Powershell"),
            ("msg", "Hello world!"),
            ("tag", "Ansible"),
        )
    }
    parameters["title"] = as_string(
        arguments.get(
            "title", "Notification: " + native.format_time(now, short_time=True)
        ),
        "title",
    )
    parameters["popup"] = as_bool(arguments.get("popup", True), "popup")
    check = as_bool(arguments.get("_ansible_check_mode", False), "_ansible_check_mode")
    result = {
        "changed": False,
        "expire_at": native.format_time(expires_local),
        "expire_at_utc": native.format_time(expires, long_date=True),
        "toast_sent": False,
    }
    if native.has_explorer():
        native.send(parameters, expires, check)
        if not check:
            result["toast_sent"] = True
            time.sleep(expire)
    else:
        result["no_toast_sent_reason"] = "No logged in users to notify"
    result["time_taken"] = time.monotonic() - started
    result["sent_localtime"] = native.format_time(
        datetime.datetime.now(), long_date=True
    )
    return result


def main():
    """Run the released local-toast interface using native notification APIs."""
    run_module(
        lambda: _execute(
            read_arguments(
                ("expire", "group", "msg", "popup", "tag", "title"),
                "sustainablelobster.legacy_community_windows.win_toast",
            )
        )
    )


if __name__ == "__main__":
    main()
