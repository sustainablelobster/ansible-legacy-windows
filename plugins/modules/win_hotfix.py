#!/usr/bin/python
# -*- coding: utf-8 -*-
# Copyright 2026 sustainablelobster
# SPDX-License-Identifier: GPL-3.0-or-later

"""Manage Windows hotfix packages with native DISM."""

# WANT_JSON

import os

import legacy_windows_hotfix as hotfix  # pylint: disable=import-error
from legacy_windows_module import (  # pylint: disable=import-error
    as_bool,
    as_path,
    as_string,
    expand_environment,
    read_arguments,
    run_module,
)

# Ansible interfaces must be self-contained; repeated option/return text is
# interface documentation, not duplicated execution logic.
# pylint: disable=duplicate-code
DOCUMENTATION = r"""
---
module: win_hotfix
short_description: Install and uninstall Windows hotfixes
version_added: '1.0.0'
description:
  - Installs MSU hotfix packages or removes installed packages.
  - Uses native DISM, expand.exe and WMI with Python 3.4.4-compatible payloads.
options:
  hotfix_identifier:
    description:
      - DISM package identifier, preferred over a KB identifier for removal.
      - Required for C(state=absent) unless C(hotfix_kb) is supplied.
      - With C(state=present), validates the identifiers in the supplied MSU.
    type: str
  hotfix_kb:
    description:
      - KB identifier such as C(KB3027108).
      - Required for C(state=absent) unless C(hotfix_identifier) is supplied.
      - With C(state=present), validates the KB identifiers in the supplied MSU.
    type: str
  state:
    description: Whether the hotfix should be installed or removed.
    type: str
    choices: [absent, present]
    default: present
  source:
    description:
      - Literal target path to the downloaded MSU file.
      - Required when C(state=present), including in check mode.
    type: path
attributes:
  check_mode:
    support: full
    description: Inspects packages and predicts changes without installing or removing them.
  diff_mode:
    support: none
notes:
  - Requires native DISM online package servicing and expand.exe on the target. Where DismApi.dll is unavailable, the installed DISM command provides package inspection and servicing.
  - Windows is never restarted; inspect C(reboot_required) after servicing.
  - Retain C(reboot_required) from a changing request. A later no-op may not rediscover a removed package's pending restart.
  - Package installation can have partial effects if a later package fails.
author:
  - sustainablelobster
"""

EXAMPLES = r"""
- name: Install a staged MSU and validate its KB
  sustainablelobster.legacy_windows.win_hotfix:
    source: C:\staging\windows-update.msu
    hotfix_kb: KB3027108
  register: hotfix_install

- name: Remove a package by its DISM identifier
  sustainablelobster.legacy_windows.win_hotfix:
    hotfix_identifier: Package_for_KB3027108~31bf3856ad364e35~amd64~~6.3.2.0
    state: absent
"""

RETURN = r"""
identifier:
  description: The first MSU package identifier, or the selected removal package.
  returned: when present-source metadata is read or a removal is required
  type: str
identifiers:
  description: MSU package identifiers in metadata order.
  returned: when present-source metadata is read
  type: list
  elements: str
kb:
  description: The first MSU KB identifier, or the selected removal package KB.
  returned: when present-source metadata is read or a removal is required
  type: str
kbs:
  description: MSU KB identifiers in metadata order; UNKNOWN when not available.
  returned: when present-source metadata is read
  type: list
  elements: str
reboot_required:
  description: Whether successful servicing or a pending package requires a reboot.
  returned: after argument validation
  type: bool
"""
# pylint: enable=duplicate-code

_PARAMETERS = ("hotfix_identifier", "hotfix_kb", "state", "source")


def _parameters(arguments):
    state = as_string(arguments.get("state", "present"), "state")
    if state is None or state.lower() not in ("absent", "present"):
        raise ValueError(
            "Get-AnsibleParam: Argument state needs to be one of "
            "absent,present but was " + (state or "") + "."
        )
    source = as_string(arguments.get("source"), "source")
    try:
        source = as_path(source, "source")
    except ValueError as error:
        raise ValueError(
            "Get-AnsibleParam: Parameter 'source' has an invalid path '{0}' "
            "specified.".format(expand_environment(source))
        ) from error
    return {
        "state": state.lower() if state is not None else None,
        "identifier": as_string(
            arguments.get("hotfix_identifier"), "hotfix_identifier"
        ),
        "kb": as_string(arguments.get("hotfix_kb"), "hotfix_kb"),
        "source": source,
    }


def _remove(session, parameters, check_mode, result):
    if parameters["identifier"] is not None:
        metadata = hotfix.metadata_from_name(session, parameters["identifier"])
    elif parameters["kb"] is not None:
        metadata = (
            hotfix.metadata_from_kb(session, parameters["kb"])
            if hotfix.installed_kb(parameters["kb"])
            else {"state": "NotPresent"}
        )
    else:
        raise ValueError(
            "either hotfix_identifier or hotfix_kb needs to be set when state=absent"
        )
    if metadata["state"] == "UninstallPending":
        result.update(
            identifier=metadata["name"], kb=metadata["kb"], reboot_required=True
        )
    elif metadata["state"] == "Installed":
        result.update(identifier=metadata["name"], kb=metadata["kb"])
        if not check_mode:
            try:
                result["reboot_required"] = session.remove(metadata["name"])
            except OSError as error:
                raise OSError(
                    "failed to remove package {0}: {1}".format(metadata["name"], error)
                ) from error
        result["changed"] = True


def _validate_source_metadata(parameters, metadata):
    for option, field, label in (
        ("identifier", "name", "identifier"),
        ("kb", "kb", "KB"),
    ):
        supplied = parameters[option]
        if supplied is not None and any(
            value[field].lower() != supplied.lower() for value in metadata
        ):
            raise ValueError(
                "the hotfix {0} {1} does not match with the source msu {0} "
                "{2}, please omit or specify the correct {0} to continue".format(
                    label, supplied, " ".join(value[field] for value in metadata)
                )
            )


def _install(session, parameters, check_mode, result):
    source = parameters["source"]
    if source is None:
        raise ValueError("source must be set when state=present")
    if not os.path.isfile(source):
        raise ValueError(
            "the path set for source " + source + " does not exist or is not a file"
        )
    with hotfix.ExpandedMsu(source) as directory:
        metadata = hotfix.metadata_from_file(session, directory)
        _validate_source_metadata(parameters, metadata)
        result["identifiers"] = [value["name"] for value in metadata]
        result["kbs"] = [value["kb"] for value in metadata]
        result["identifier"] = result["identifiers"][0] if metadata else None
        result["kb"] = result["kbs"][0] if metadata else None
        pending = any(value["state"] == "InstallPending" for value in metadata)
        needed = any(
            value["state"] not in ("Installed", "InstallPending") for value in metadata
        )
        if not needed and result["kb"] != "UNKNOWN":
            needed = not hotfix.installed_kb(result["kb"])
        if needed:
            if not check_mode:
                paths = [value["path"] for value in metadata]
                try:
                    restarts = [session.add(path) for path in paths]
                except OSError as error:
                    raise OSError(
                        "failed to add windows package from path "
                        + " ".join(paths)
                        + ": "
                        + str(error)
                    ) from error
                result["reboot_required"] = any(restarts)
            result["changed"] = True
        elif pending:
            result["reboot_required"] = True


def _response():
    arguments = read_arguments(
        _PARAMETERS, "sustainablelobster.legacy_windows.win_hotfix", allow_unknown=True
    )
    parameters = _parameters(arguments)
    result = {"changed": False, "reboot_required": False}
    try:
        check_mode = as_bool(
            arguments.get("_ansible_check_mode", False), "_ansible_check_mode"
        )
        with hotfix.HotfixSession() as session:
            if parameters["state"] == "absent":
                _remove(session, parameters, check_mode, result)
            else:
                _install(session, parameters, check_mode, result)
    except (OSError, ValueError) as error:
        result.update(failed=True, msg=str(error))
    return result


def main():
    """Emit the public hotfix result.

    :raises SystemExit: Zero on success or one on failure.
    """
    run_module(_response)


# Each independently staged payload needs its own executable entry guard.
# pylint: disable=duplicate-code
if __name__ == "__main__":
    main()
# pylint: enable=duplicate-code
