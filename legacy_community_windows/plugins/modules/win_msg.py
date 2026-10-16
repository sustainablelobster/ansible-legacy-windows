#!/usr/bin/python
# -*- coding: utf-8 -*-
# Copyright: (c) 2017, Jon Hawkesworth (@jhawkesworth) <jhawkesworth@protonmail.com>
# Copyright 2026 sustainablelobster
# SPDX-License-Identifier: GPL-3.0-or-later

"""Send local session messages through the installed Windows messaging utility."""

# WANT_JSON

import datetime
import shutil
import subprocess
import time

from legacy_windows_module import (  # pylint: disable=import-error
    as_bool,
    as_string,
    read_arguments,
    run_module,
)
from legacy_windows_process import run_command  # pylint: disable=import-error

DOCUMENTATION = r"""
---
module: win_msg
short_description: Sends a message to logged in users on Windows hosts
description:
    - Wraps the msg.exe command in order to send messages to Windows hosts.
options:
  to:
    description:
      - Who to send the message to. Can be a username, sessionname or sessionid.
    type: str
    default: '*'
  display_seconds:
    description:
      - How long to wait for receiver to acknowledge message, in seconds.
    type: int
    default: 10
  wait:
    description:
      - Whether to wait for users to respond.  Module will only wait for the number of seconds specified in display_seconds or 10 seconds if not specified.
        However, if I(wait) is C(yes), the message is sent to each logged on user in turn, waiting for the user to either press 'ok' or for
        the timeout to elapse before moving on to the next user.
    type: bool
    default: 'no'
  msg:
    description:
      - The text of the message to be displayed.
      - The message must be less than 256 characters.
    type: str
    default: Hello world!
requirements:
  - The installed Windows msg.exe utility and permission to message the selected sessions.
notes:
   - Check mode validates the request and predicts a send without invoking the message utility.
   - This module must run on a windows host, so ensure your play targets windows
     hosts, or delegates to a windows host.
   - Messages are only sent to the local host where the module is run.
   - The module does not support sending to users listed in a file.
   - Setting wait to C(yes) can result in long run times on systems with many logged in users.
seealso:
- module: sustainablelobster.legacy_community_windows.win_say
- module: sustainablelobster.legacy_community_windows.win_toast
author:
- Jon Hawkesworth (@jhawkesworth)
"""

EXAMPLES = r"""
- name: Warn logged in users of impending upgrade
  sustainablelobster.legacy_community_windows.win_msg:
    display_seconds: 60
    msg: >-
      Automated upgrade about to start.  Please save your work and log off
      before {{ deployment_start_time }}
"""

RETURN = r"""
msg:
    description: Test of the message that was sent.
    returned: changed
    type: str
    sample: Automated upgrade about to start.  Please save your work and log off before 22 July 2016 18:00:00
display_seconds:
    description: Value of display_seconds module parameter.
    returned: success
    type: str
    sample: 10
rc:
    description: The return code of the API call.
    returned: always
    type: int
    sample: 0
runtime_seconds:
    description: How long the module took to run on the remote windows host.
    returned: success
    type: str
    sample: 22 July 2016 17:45:51
sent_localtime:
    description: local time from windows host when the message was sent.
    returned: success
    type: str
    sample: 22 July 2016 17:45:51
wait:
    description: Value of wait module parameter.
    returned: success
    type: bool
    sample: false
"""


def _send(arguments):
    started = time.monotonic()
    message = as_string(arguments.get("msg", "Hello world!"), "msg")
    destination = as_string(arguments.get("to", "*"), "to")
    if message is None or destination is None:
        raise ValueError("msg and to must not be null.")
    length = len(message.encode("utf-16-le", "surrogatepass")) // 2
    if length > 255:
        raise ValueError(
            "msg length must be less than 256 characters, current length: {0}".format(
                length
            )
        )
    try:
        seconds = int(arguments.get("display_seconds", 10))
    except (TypeError, ValueError, OverflowError) as error:
        raise ValueError("display_seconds must be a 32-bit integer.") from error
    if not -2147483648 <= seconds <= 2147483647:
        raise ValueError("display_seconds must be a 32-bit integer.")
    wait = as_bool(arguments.get("wait", False), "wait")
    check_mode = as_bool(
        arguments.get("_ansible_check_mode", False), "_ansible_check_mode"
    )
    result = {"changed": True, "display_seconds": seconds, "msg": message, "wait": wait}
    if check_mode:
        result["rc"] = 0
    else:
        executable = shutil.which("msg.exe")
        if executable is None:
            raise OSError("The installed Windows msg.exe utility was not found.")
        options = [executable, destination, "/TIME:" + str(seconds)]
        if wait:
            options.append("/W")
        options.append(message)
        response = run_command(
            executable,
            subprocess.list2cmdline(options),
            {"chdir": None, "stdin": None, "output_encoding_override": None},
        )
        result["rc"] = response["rc"]
        if response["rc"]:
            result.update(
                failed=True,
                msg=response.get("stderr", "")
                or response.get("stdout", "")
                or response.get("msg", "The Windows message utility failed."),
            )
    result["runtime_seconds"] = time.monotonic() - started
    result["sent_localtime"] = datetime.datetime.now().strftime(
        "%A, %B %d, %Y %H:%M:%S"
    )
    return result


def main():
    """Read the public request and report local session message delivery."""
    run_module(
        lambda: _send(
            read_arguments(
                ("msg", "to", "display_seconds", "wait"),
                "sustainablelobster.legacy_community_windows.win_msg",
                allow_unknown=True,
            )
        )
    )


if __name__ == "__main__":
    main()
