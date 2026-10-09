#!/usr/bin/python
# -*- coding: utf-8 -*-
# Copyright 2026 Joe Lustri
# SPDX-License-Identifier: GPL-3.0-or-later

"""Manage Windows Server roles and features using the native provider."""

# WANT_JSON

import os

import legacy_windows_feature_manage as features  # pylint: disable=import-error
from legacy_windows_module import (  # pylint: disable=import-error
    as_bool,
    as_string,
    as_string_list,
    read_arguments,
    run_module,
)

# Ansible interfaces must be self-contained; repeated option/return text is
# interface documentation, not duplicated execution logic.
# pylint: disable=duplicate-code
DOCUMENTATION = r"""
---
module: win_feature
short_description: Manage roles and features on Windows Server
version_added: '1.0.0'
description:
  - Installs or removes Windows Server roles, role services, and features.
  - Uses the installed native Server Manager provider or older ServerManagerCmd facility with Python 3.4.4.
options:
  name:
    description:
      - Literal feature names, as a list or comma-separated string.
      - Names are case-insensitive and are validated before any feature changes.
      - Duplicate names are serviced once.
    type: list
    elements: str
    required: true
  state:
    description: Whether the requested server features should be present or absent.
    type: str
    choices: [absent, present]
    default: present
  include_sub_features:
    description: Install all subordinate features instead of only default subfeatures.
    type: bool
    default: false
  include_management_tools:
    description: Include the corresponding management tools when installing or removing features.
    type: bool
    default: false
  source:
    description:
      - Literal local or UNC path supplying installation files.
      - A nonempty source is checked even for removal, no-op, and check-mode requests.
    type: str
attributes:
  check_mode:
    support: full
    description: Validates the request and reports the complete affected feature list without servicing.
  diff_mode:
    support: none
requirements:
  - Windows Server with the native Server Manager deployment provider or the installed ServerManagerCmd tool.
  - An elevated connection account.
notes:
  - Windows is never restarted; use C(reboot_required) to decide whether to reboot.
  - Removal preserves feature payload files.
  - A servicing failure may leave partial changes; no automatic rollback is performed.
  - The older ServerManagerCmd facility uses its Windows-default management-tool behavior. It cannot override an installation source; a nonempty source for a required install fails before servicing.
  - Numeric feature IDs unavailable in installed Win32_ServerFeature metadata are null on the older facility. Check mode predicts requested features, parents and catalogue subfeatures, but other native dependencies appear only in actual servicing results.
author:
  - Joe Lustri
"""

EXAMPLES = r"""
- name: Install the Telnet client on a server
  sustainablelobster.legacy_windows.win_feature:
    name: Telnet-Client
    state: present
  register: server_feature

- name: Install IIS with all subordinate features and management tools
  sustainablelobster.legacy_windows.win_feature:
    name: Web-Server
    include_sub_features: true
    include_management_tools: true

- name: Remove two server features without restarting Windows
  sustainablelobster.legacy_windows.win_feature:
    name: [Telnet-Client, TFTP-Client]
    state: absent
"""

RETURN = r"""
exitcode:
  description: Stringified result of the feature operation, such as Success or NoChangeNeeded.
  returned: after argument validation on success
  type: str
feature_result:
  description: Affected features in provider selection order.
  returned: after argument validation on success
  type: list
  elements: dict
  contains:
    id:
      description: The feature's numeric Server Manager identifier, or null if the older facility cannot supply it.
      type: int
    display_name:
      description: The feature's localized display name.
      type: str
    message:
      description: Messages returned for this feature.
      type: list
      elements: dict
      contains:
        message_type:
          description: The message type.
          type: str
        error_code:
          description: The native error code associated with the message.
          type: int
        text:
          description: The message text.
          type: str
    reboot_required:
      description: Whether this feature reports that a restart is needed.
      type: bool
    skip_reason:
      description: Why the operation was skipped for this feature, or NotSkipped.
      type: str
    success:
      description: Whether the operation succeeded for this feature.
      type: bool
reboot_required:
  description: Whether the server reports that a restart is needed.
  returned: after argument validation on success
  type: bool
success:
  description: Whether the complete feature operation succeeded.
  returned: after argument validation on success
  type: bool
"""
# pylint: enable=duplicate-code

_PARAMETERS = (
    "include_management_tools",
    "include_sub_features",
    "name",
    "source",
    "state",
)


def _parameters(arguments):
    if "name" not in arguments:
        raise ValueError("missing required arguments: name")
    state = as_string(arguments.get("state", "present"), "state")
    if state is not None and state.lower() not in ("absent", "present"):
        raise ValueError(
            "value of state must be one of: absent, present. Got no match for: " + state
        )
    options = {
        "names": as_string_list(arguments["name"], "name"),
        "state": state.lower() if state is not None else None,
        "source": as_string(arguments.get("source"), "source"),
    }
    for option in ("include_sub_features", "include_management_tools"):
        value = arguments.get(option, False)
        options[option] = as_bool(value, option) if value is not None else False
    return options


def execute():
    """Bind the upstream interface and manage one complete server feature batch.

    :returns: Public feature results, restart status, or an actionable failure.
    :rtype: dict
    :raises ValueError: Public argument binding fails before provider execution.
    """
    arguments = read_arguments(
        _PARAMETERS, "sustainablelobster.legacy_windows.win_feature"
    )
    options = _parameters(arguments)
    if options["source"] and not os.path.exists(options["source"]):
        return {
            "changed": False,
            "exitcode": "NoChangeNeeded",
            "feature_result": [],
            "reboot_required": False,
            "success": True,
            "failed": True,
            "msg": "Failed to find source path "
            + options["source"]
            + " for feature install",
        }
    try:
        return features.manage(
            options,
            as_bool(arguments.get("_ansible_check_mode", False), "_ansible_check_mode"),
        )
    except (OSError, ValueError) as error:
        return {
            "changed": False,
            "failed": True,
            "msg": "Unhandled exception while executing module: " + str(error),
        }


def main():
    """Emit one Ansible JSON result for the staged Python payload.

    :raises SystemExit: Zero on success or one on public failure.
    """
    run_module(execute)


# Each independently staged payload needs its own executable entry guard.
# pylint: disable=duplicate-code
if __name__ == "__main__":
    main()
# pylint: enable=duplicate-code
