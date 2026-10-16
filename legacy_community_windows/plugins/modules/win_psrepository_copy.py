#!/usr/bin/python
# -*- coding: utf-8 -*-
# Copyright: (c) 2020, Brian Scholer <@briantist>
# Copyright 2026 sustainablelobster
# SPDX-License-Identifier: GPL-3.0-or-later

"""Copy registered repository files using native profile and XML operations."""

# WANT_JSON

import os

import legacy_community_windows_clixml_dictionary as repository_file  # pylint: disable=import-error
import legacy_windows_find_match as wildcard  # pylint: disable=import-error
import legacy_windows_user_profile as profiles  # pylint: disable=import-error
from legacy_windows_module import (  # pylint: disable=import-error
    as_bool,
    as_path,
    as_string_list,
    read_arguments,
    run_module,
)

# The released module interface is self-contained instead of being generated
# from execution internals or a second option registry.
# pylint: disable=duplicate-code
DOCUMENTATION = r"""
---
module: win_psrepository_copy
short_description: Copies registered PSRepositories to other user profiles
version_added: '1.0.0'
description:
  - Copies specified registered PSRepositories to other user profiles on the system.
  - Can include the C(Default) profile so that new users start with the selected repositories.
  - Can include special service accounts like the local SYSTEM user, LocalService, NetworkService.
options:
  source:
    description:
      - The full path to the source repositories XML file.
      - Defaults to the repositories registered to the current user.
    type: path
    default: '%LOCALAPPDATA%\Microsoft\Windows\PowerShell\PowerShellGet\PSRepositories.xml'
  name:
    description:
      - The names of repositories to copy.
      - Names are interpreted as wildcards.
    type: list
    elements: str
    default: ['*']
  exclude:
    description:
      - The names of repositories to exclude.
      - Names are interpreted as wildcards.
      - If a name matches both an include (I(name)) and I(exclude), it will be excluded.
    type: list
    elements: str
  profiles:
    description:
      - The names of user profiles to populate with repositories.
      - Names are interpreted as wildcards.
      - The C(Default) profile can also be matched.
      - The C(Public) and C(All Users) profiles cannot be targeted, as PSRepositories are not loaded from them.
    type: list
    elements: str
    default: ['*']
  exclude_profiles:
    description:
      - The names of user profiles to exclude.
      - If a profile matches both an include (I(profiles)) and I(exclude_profiles), it will be excluded.
      - By default, the service account profiles are excluded.
      - To explicitly exclude nothing, set I(exclude_profiles=[]).
    type: list
    elements: str
    default:
      - systemprofile
      - LocalService
      - NetworkService
  force:
    description:
      - If C(True), this deletes repositories that are not present in the source.
    type: bool
    default: False
    version_added: '1.0.0'
notes:
  - Does not require the C(PowerShellGet) module or any other external dependencies.
  - User profiles are loaded from the registry. If a given path does not exist (like if the profile directory was deleted), it is silently skipped.
  - If setting service account profiles, you may need C(become=yes). See examples.
  - "When PowerShellGet first sets up a repositories file, it always adds C(PSGallery), however if this module creates a new repos file and your selected
    repositories don't include C(PSGallery), it won't be in your destination."
  - "The values searched in I(profiles) (and I(exclude_profiles)) are profile names, not necessarily user names. This can happen when the profile path is
    deliberately changed or when domain user names conflict with users from the local computer or another domain. In this case the second+ user may have the
    domain name or local computer name appended, like C(JoeUser.Contoso) vs. C(JoeUser).
    If you intend to filter user profiles, ensure your filters catch the right names."
  - "In the case of the service accounts, the specific profiles are C(systemprofile) (for the C(SYSTEM) user), and C(LocalService) or C(NetworkService)
    for those accounts respectively."
  - "Repositories with credentials (requiring authentication) or proxy information will copy, but the credentials and proxy details will not as that
    information is not stored with repository."
seealso:
  - module: sustainablelobster.legacy_community_windows.win_psrepository
  - module: sustainablelobster.legacy_community_windows.win_psrepository_info
author:
  - Brian Scholer (@briantist)
"""

EXAMPLES = r"""
- name: Copy repositories to non-service profiles and the Default profile
  sustainablelobster.legacy_community_windows.win_psrepository_copy:

- name: Copy repositories to all profiles, including Default
  sustainablelobster.legacy_community_windows.win_psrepository_copy:
    exclude_profiles: []

- name: Copy repositories to profiles beginning with A, B or C
  sustainablelobster.legacy_community_windows.win_psrepository_copy:
    profiles:
      - 'A*'
      - 'B*'
      - 'C*'

- name: Copy repositories to profiles beginning B with exceptions
  sustainablelobster.legacy_community_windows.win_psrepository_copy:
    profiles: 'B*'
    exclude_profiles:
      - Brian
      - Brianna

- name: Copy selected repositories to service profiles with exceptions
  sustainablelobster.legacy_community_windows.win_psrepository_copy:
    name:
      - CompanyRepo1
      - CompanyRepo2
      - PSGallery
    profiles: 'svc*'
    exclude_profiles: 'svc-restricted'

- name: Copy repos matching a pattern with exceptions
  sustainablelobster.legacy_community_windows.win_psrepository_copy:
    name: 'CompanyRepo*'
    exclude: 'CompanyRepo*-Beta'

- name: Copy repositories from a custom XML file on the target host
  sustainablelobster.legacy_community_windows.win_psrepository_copy:
    source: 'C:\data\CustomRepostories.xml'

### A sample workflow of seeding a system with a custom repository

# A playbook that does initial host setup or builds system images

- name: Register custom repository
  sustainablelobster.legacy_community_windows.win_psrepository:
    name: PrivateRepo
    source_location: https://example.com/nuget/feed/etc
    installation_policy: trusted

- name: Ensure all current and new users have this repository registered
  sustainablelobster.legacy_community_windows.win_psrepository_copy:
    name: PrivateRepo

# In another playbook, run by other users (who may have been created later)

- name: Install a module
  sustainablelobster.legacy_community_windows.win_psmodule:
    name: CompanyModule
    repository: PrivateRepo
    state: present
"""

RETURN = r"""
"""

# pylint: enable=duplicate-code

_DEFAULT_SOURCE = (
    r"%LOCALAPPDATA%\Microsoft\Windows\PowerShell\PowerShellGet\PSRepositories.xml"
)
_REPOSITORY_SUBDIRECTORY = os.path.join(
    "AppData", "Local", "Microsoft", "Windows", "PowerShell", "PowerShellGet"
)
_PARAMETERS = ("source", "name", "exclude", "profiles", "exclude_profiles", "force")


def _profile_paths():
    registry = profiles.winreg
    if registry is None:
        raise ValueError("Repository profile selection requires a Windows target.")
    with registry.OpenKey(registry.HKEY_LOCAL_MACHINE, profiles.PROFILE_LIST) as key:
        values = {}
        for index in range(registry.QueryInfoKey(key)[1]):
            name, value, _kind = registry.EnumValue(key, index)
            values[name.lower()] = value
    default = values.get("default")
    if default is None and values.get("defaultuserprofile"):
        default = os.path.join(
            values.get("profilesdirectory", ""), values["defaultuserprofile"]
        )
    paths = [registry.ExpandEnvironmentStrings(default)] if default else []
    for sid in profiles.profile_sids():
        try:
            paths.append(profiles.profile_path(sid))
        except OSError as error:
            # Registry keys with no ProfileImagePath are not user profiles.
            if getattr(error, "winerror", error.errno) != 2:
                raise
    return [path for path in paths if os.path.isdir(path)]


def _selected(name, included, excluded):
    return wildcard.matches(name, included or []) and not wildcard.matches(
        name, excluded or []
    )


def _merge(current, source, selected):
    merged = current.copy()
    for key in selected:
        source_key, source_value = source[key]
        # A PowerShell hashtable retains its original key casing on assignment.
        merged[key] = (current[key][0] if key in current else source_key, source_value)
    return merged


def _copy_profile(profile, source, selected, options, result):
    name = os.path.basename(profile)
    directory = os.path.join(profile, _REPOSITORY_SUBDIRECTORY)
    destination = os.path.join(directory, "PSRepositories.xml")
    current = repository_file.read(destination) if os.path.isfile(destination) else {}
    desired = source.copy() if options["force"] else _merge(current, source, selected)
    before, after = repository_file.values(current), repository_file.values(desired)
    result["diff"]["before"][name] = before
    result["diff"]["after"][name] = after
    if before != after:
        if not options["check_mode"]:
            os.makedirs(directory, exist_ok=True)
            repository_file.write(destination, desired)
        result["changed"] = True


def _execute(arguments):
    options = {
        name: as_string_list(arguments.get(name, default), name)
        for name, default in (
            ("name", ["*"]),
            ("exclude", None),
            ("profiles", ["*"]),
            ("exclude_profiles", ["systemprofile", "LocalService", "NetworkService"]),
        )
    }
    options["force"] = as_bool(arguments.get("force", False), "force")
    options["check_mode"] = as_bool(
        arguments.get("_ansible_check_mode", False), "_ansible_check_mode"
    )
    result = {"changed": False, "diff": {"before": {}, "after": {}}}
    try:
        source = repository_file.read(
            as_path(arguments.get("source", _DEFAULT_SOURCE), "source")
        )
        selected = [
            key
            for key, name in repository_file.names(source).items()
            if _selected(name, options["name"], options["exclude"])
        ]
        for profile in _profile_paths():
            if _selected(
                os.path.basename(profile),
                options["profiles"],
                options["exclude_profiles"],
            ):
                _copy_profile(profile, source, selected, options, result)
    except (OSError, ValueError) as error:
        result.update({"failed": True, "msg": str(error)})
    if not as_bool(arguments.get("_ansible_diff", False), "_ansible_diff"):
        result.pop("diff")
    return result


def main():
    """Read repository selection options and copy only the selected profile files."""
    run_module(
        lambda: _execute(
            read_arguments(
                _PARAMETERS,
                "sustainablelobster.legacy_community_windows.win_psrepository_copy",
            )
        )
    )


if __name__ == "__main__":
    main()
