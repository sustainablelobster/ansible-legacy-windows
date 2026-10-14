#!/usr/bin/python
# -*- coding: utf-8 -*-
# Copyright 2026 sustainablelobster
# SPDX-License-Identifier: GPL-3.0-or-later

"""Run a native Windows Update Agent round with an owned background worker."""

# WANT_JSON

import legacy_windows_updates_worker as worker  # pylint: disable=import-error
from legacy_windows_module import (  # pylint: disable=import-error
    as_bool,
    as_path,
    as_string,
    as_string_list,
    read_arguments,
    run_module,
)

DOCUMENTATION = r"""
---
module: win_updates
short_description: Search, download and install Windows updates
version_added: '1.0.0'
description:
  - Uses the native Windows Update Agent with Python 3.4.4 or newer.
  - Preserves the configured update source and reports per-update results.
options:
  accept_list:
    description: Case-insensitive title or KB regular expressions selecting updates.
    type: list
    elements: str
  reject_list:
    description: Case-insensitive title or KB regular expressions excluding updates.
    type: list
    elements: str
  category_names:
    description:
      - Categories to select; accepts a list or comma-separated text.
      - An empty list or V(*) selects all categories.
    type: list
    elements: str
    default: [CriticalUpdates, SecurityUpdates, UpdateRollups]
  skip_optional:
    description: Exclude updates whose native BrowseOnly flag is set.
    type: bool
    default: false
  maximum_retries_on_failed_updates:
    description: Repeated installation rounds tolerated before reporting an update rollback loop.
    type: int
    default: 1
  reboot:
    description: Reboot when required and continue installation rounds.
    type: bool
    default: false
  reboot_timeout:
    description: Seconds allowed independently for boot change and post-reboot readiness.
    type: int
    default: 1200
  server_selection:
    description: Select the configured, managed-server or Windows Update catalog.
    type: str
    choices: [default, managed_server, windows_update]
    default: default
  state:
    description: Whether to list selected updates, download them or install them.
    type: str
    choices: [searched, downloaded, installed]
    default: installed
  log_path:
    description: Optional progress log to append; its directory must already exist.
    type: path
  _operation:
    description: Internal controller operation; V(test) checks WUA access without a search.
    type: str
    choices: [start, poll, cancel, test]
    default: start
  _operation_options:
    description: Internal owned-worker options supplied by the action.
    type: dict
attributes:
  check_mode:
    support: partial
    description: Searches and predicts changes; accepts selected-update EULAs like the released source.
  diff_mode:
    support: none
notes:
  - Requires a functioning Windows Update Agent and configured update source.
    Older installations may need signed servicing-stack, SHA-2 support and agent updates installed separately first.
    This module does not bootstrap or replace Windows Update infrastructure.
  - Update workers first use the task's effective Windows account and require administrative WUA access and native WMI process creation.
  - If a native WMI access denial proves that no worker was created, startup is
    tried once under SYSTEM. This requires an accessible SYSTEM token and permission to impersonate it.
  - Failed WUA operations and uncertain worker-start results are not retried under SYSTEM.
  - Selected-update EULAs are accepted even with V(searched) or check mode.
  - A servicing failure can leave downloaded files, EULA acceptance or partial installations applied.
  - Synchronous failure messages include localized Windows system descriptions
    when available, with an unsigned hexadecimal HRESULT. Many WUA-specific
    codes have no system message and retain the numeric diagnostic only.
  - Diagnostic prose and symbolic error names do not reproduce upstream's
    static error table. Native COM descriptions are preserved.
  - Async top-level failure messages also include an available native system
    description while retaining the signed C(hresult) field.
  - Async per-update failures expose C(failure_hresult_code), without the
    synchronous C(failure_msg) field, as in upstream.
  - A dedicated worker survives connection loss; cancellation does not forcibly terminate active servicing.
  - With C(async) and C(poll=0), retrieve results using M(sustainablelobster.legacy_windows.async_status).
  - Automatic polling with C(poll>0) requires the installed collection's
    C(plugins/action/_native_async_polling) directory on the controller action plugin path.
    Set C(action_plugins) in the project's C(ansible.cfg); installation alone does not activate the adapter.
  - Async cannot be combined with O(reboot=true).
  - Accept and reject regexes search the title immediately followed by KB numbers,
    with spaces only between multiple KB numbers.
  - Regex matching uses Python's C(re) engine with limited .NET syntax translations.
  - Matching operates on UTF-16 code units; C(.) consumes one surrogate of a supplementary character such as an emoji.
  - Unicode general-category escapes, word/digit/space classes and word boundaries use fixed Unicode 8 data.
  - Case-insensitive matching uses Python's rules and can differ from .NET culture-dependent matching.
  - Atomic or balancing groups, class subtraction, scoped inline options and variable-width lookbehind are unsupported.
  - Inline options must appear at the pattern prefix; later options fail instead of changing the scope of earlier matches.
  - Numeric references combined with .NET named groups and Unicode block escapes are unsupported; general-category escapes are supported.
  - C(\Z) matches at strict end or before a final LF; C(\z) matches only at strict end.
  - Modern reboot readiness uses AutoLogonChecked; XP and Server 2003 use SCM auto-start completion, not GINA readiness.
  - Updates reboot readiness additionally waits while CBS reports active servicing.
author:
  - sustainablelobster
"""

EXAMPLES = r"""
- name: List selected updates
  sustainablelobster.legacy_windows.win_updates:
    state: searched

- name: Install security updates and complete required reboots
  sustainablelobster.legacy_windows.win_updates:
    category_names: [SecurityUpdates]
    reboot: true
"""

RETURN = r"""
found_update_count:
  description: Count of updates selected over all rounds.
  returned: always after controller option validation
  type: int
failed_update_count:
  description: Count of selected updates with a failed transfer or installation result.
  returned: always after controller option validation
  type: int
installed_update_count:
  description: Count of successfully installed selected updates.
  returned: always after controller option validation
  type: int
updates:
  description: Selected update IDs mapped to title, KBs, categories and download/install result flags.
  returned: always after controller option validation
  type: dict
  contains:
    failure_hresult_code:
      description:
        - HRESULT for an update whose download or installation failed.
        - Synchronous native HRESULTs normalize to an unsigned 32-bit integer;
          async results retain the native value. Synchronous loop detection
          instead reports the upstream-compatible sentinel C(-1).
      returned: within a failed update's information
      type: int
    failure_msg:
      description:
        - Diagnostic retaining the hexadecimal HRESULT, with a localized
          system description when available; otherwise the numeric code only.
        - Many WUA-specific errors have no system description. Text and symbolic
          names differ from upstream's static error table.
      returned: within a failed update's information in synchronous results
      type: str
filtered_updates:
  description: Excluded update IDs mapped to update information and ordered filtered_reasons.
  returned: always after controller option validation
  type: dict
reboot_required:
  description: Whether a reboot remains required after the last update round.
  returned: after an update round
  type: bool
rebooted:
  description: Whether the controller attempted a required reboot, including check-mode prediction.
  returned: after an update round
  type: bool
"""

_MODULE = "sustainablelobster.legacy_windows.win_updates"
_PARAMETERS = (
    "accept_list",
    "reject_list",
    "category_names",
    "skip_optional",
    "maximum_retries_on_failed_updates",
    "reboot",
    "reboot_timeout",
    "server_selection",
    "state",
    "log_path",
    "_operation",
    "_operation_options",
)


def _integer(value, name):
    if value is None:
        return None
    if isinstance(value, bool):
        kind = "System.Boolean"
    elif isinstance(value, str):
        kind = "System.String"
    elif isinstance(value, float):
        kind = "System.Double" if "e" in repr(value) else "System.Decimal"
    elif isinstance(value, int):
        if -(2**31) <= value < 2**31:
            return value
        kind = (
            "System.Int64"
            if -(2**63) <= value < 2**63
            else (
                "System.Decimal"
                if abs(value) <= 79228162514264337593543950335
                else "System.Double"
            )
        )
    else:
        kind = (
            "System.Object[]"
            if isinstance(value, list)
            else "System.Collections.Hashtable"
        )
    text = (
        as_string(value, name)
        .lstrip(" \t\r\n\v\f")
        .rstrip("\x00")
        .rstrip(" \t\r\n\v\f")
    )
    digits = text[1:] if text.startswith(("+", "-")) else text
    detail = "Input string was not in a correct format."
    if digits and all(character in "0123456789" for character in digits):
        magnitude = digits.lstrip("0") or "0"
        limit = "2147483648" if text.startswith("-") else "2147483647"
        if (
            len(magnitude) < len(limit)
            or len(magnitude) == len(limit)
            and magnitude <= limit
        ):
            return -int(magnitude) if text.startswith("-") else int(magnitude)
        detail = "Value was either too large or too small for an Int32."
    raise ValueError(
        "argument for {0} is of type {1} and we were unable to convert to int: {2}".format(
            name, kind, detail
        )
    )


def _parameters(arguments):
    result = {}
    for name, default in (
        ("accept_list", []),
        ("reject_list", []),
        ("category_names", ["CriticalUpdates", "SecurityUpdates", "UpdateRollups"]),
    ):
        result[name] = as_string_list(arguments.get(name, default), name) or []
    for name, default in (("skip_optional", False), ("reboot", False)):
        value = arguments.get(name, default)
        result[name] = None if value is None else as_bool(value, name)
    for name, default in (
        ("reboot_timeout", 1200),
        ("maximum_retries_on_failed_updates", 1),
    ):
        result[name] = _integer(arguments.get(name, default), name)
    for name, default, choices in (
        (
            "server_selection",
            "default",
            ("default", "managed_server", "windows_update"),
        ),
        ("state", "installed", ("searched", "downloaded", "installed")),
        ("_operation", "start", ("start", "poll", "cancel", "test")),
    ):
        value = as_string(arguments.get(name, default), name)
        if value is not None and value.lower() not in choices:
            raise ValueError(
                "{0} must be one of: {1}, got: {2}".format(
                    name, ", ".join(choices), value
                )
            )
        result[name] = value.lower() if value is not None else None
    result["log_path"] = as_path(arguments.get("log_path"), "log_path")
    result["check_mode"] = as_bool(
        arguments.get("_ansible_check_mode", False), "_ansible_check_mode"
    )
    result["test"] = result["_operation"] == "test"
    options = arguments.get("_operation_options") or {}
    if not isinstance(options, dict):
        raise ValueError("_operation_options must be a dictionary.")
    return result, options


def _response():
    arguments = read_arguments(_PARAMETERS, _MODULE)
    parameters, options = _parameters(arguments)
    operation = parameters.pop("_operation")
    if operation == "poll":
        return worker.poll(options)
    if operation == "cancel":
        return worker.cancel(options)
    if options.get("wait"):
        # Only the async action stages this target-side single-round projector.
        import legacy_windows_updates_async as asynchronous  # pylint: disable=import-error,import-outside-toplevel

        return asynchronous.wait(parameters)
    return worker.start(parameters)


def main():
    """Report the owned update operation through Ansible's JSON protocol.

    :raises SystemExit: After emitting its result.
    """
    run_module(_response)


if __name__ == "__main__":
    main()
