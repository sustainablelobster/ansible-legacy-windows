#!/usr/bin/python
# -*- coding: utf-8 -*-
# Copyright: (c) 2020, Jamie Magee <jamie.magee@gmail.com>
# Copyright 2026 sustainablelobster
# SPDX-License-Identifier: GPL-3.0-or-later

"""Manage bucket membership through installed Scoop."""

# WANT_JSON

import legacy_community_windows_scoop as scoop  # pylint: disable=import-error
from legacy_windows_module import (  # pylint: disable=import-error
    as_bool,
    as_string,
    read_arguments,
    run_module,
)

DOCUMENTATION = r"""
---
module: win_scoop_bucket
version_added: 1.0.0
short_description: Manage Scoop buckets
description:
  - Manage Scoop bucket membership.
requirements:
  - git
options:
  name:
    description: Name of the Scoop bucket.
    type: str
    required: true
  repo:
    description: Git repository containing the bucket.
    type: str
  state:
    description: Desired bucket state.
    type: str
    choices: [absent, present]
    default: present
notes:
  - Requires Scoop on PATH and the engine required by that installed Scoop release.
  - Check mode skips when Scoop is missing, without installing it.
author:
  - Jamie Magee (@JamieMagee)
  - sustainablelobster
"""

EXAMPLES = r"""
- name: Add the extras bucket
  sustainablelobster.legacy_community_windows.win_scoop_bucket:
    name: extras

- name: Remove the versions bucket
  sustainablelobster.legacy_community_windows.win_scoop_bucket:
    name: versions
    state: absent

- name: Add a custom bucket
  sustainablelobster.legacy_community_windows.win_scoop_bucket:
    name: my-bucket
    repo: https://github.com/example/my-bucket
"""

RETURN = r"""
rc:
  description: Result code of the Scoop action.
  returned: always
  type: int
  sample: 0
stdout:
  description: Raw output from the Scoop action.
  returned: on failure or when verbosity is greater than 1
  type: str
  sample: The test bucket was added successfully.
"""


def _execute(arguments):
    name = as_string(arguments.get("name"), "name")
    if not name:
        raise ValueError("name is required.")
    repo = as_string(arguments.get("repo"), "repo")
    state = as_string(arguments.get("state", "present"), "state").lower()
    if state not in ("absent", "present"):
        raise ValueError("state must be absent or present.")
    check = as_bool(arguments.get("_ansible_check_mode", False), "_ansible_check_mode")
    result = {"changed": False, "rc": 0}
    path = scoop.locate()
    if not path:
        if check:
            result.update(
                skipped=True,
                msg="Skipped check mode run on win_scoop_bucket as "
                "scoop.ps1 cannot be found on the system",
            )
            return result
        raise ValueError("Failed to find scoop.ps1, make sure it is added to the PATH")
    installed = any(item.lower() == name.lower() for item in scoop.buckets(path))
    if installed == (state == "present"):
        return result
    if not check:
        command = scoop.command(
            path,
            ["bucket", "add" if state == "present" else "rm", name]
            + ([repo] if repo else []),
        )
        if command.get("failed") or command["rc"]:
            result.update(
                failed=True,
                rc=1,
                stdout=command["stdout"],
                msg="Failed to {0} scoop bucket, see stdout for more details".format(
                    "add" if state == "present" else "remove"
                ),
            )
            return result
        if arguments.get("_ansible_verbosity", 0) > 1:
            result["stdout"] = command["stdout"]
    result["changed"] = True
    return result


def main():
    """Run the released Scoop bucket interface."""
    run_module(
        lambda: _execute(
            read_arguments(
                ("name", "repo", "state"),
                "sustainablelobster.legacy_community_windows.win_scoop_bucket",
            )
        )
    )


if __name__ == "__main__":
    main()
