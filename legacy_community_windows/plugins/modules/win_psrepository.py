#!/usr/bin/python
# -*- coding: utf-8 -*-
# Copyright: (c) 2020, Brian Scholer <@briantist>
# Copyright: (c) 2018, Wojciech Sciesinski <wojciech[at]sciesinski[dot]net>
# Copyright: (c) 2017, Daniele Lazzari <lazzari@mailup.com>
# Copyright 2026 sustainablelobster
# SPDX-License-Identifier: GPL-3.0-or-later

"""Manage repository registrations through the installed PowerShellGet engine."""

# WANT_JSON

# The action stages the fixed operation engine beside this Python payload.
from legacy_community_windows_psget_engine import invoke  # pylint: disable=import-error
from legacy_windows_module import (  # pylint: disable=import-error
    as_bool,
    as_string,
    read_arguments,
    run_module,
)

# Released interfaces and fixed vendor operations intentionally repeat their
# field definitions; templates would obscure the public contracts.
# pylint: disable=duplicate-code
DOCUMENTATION = r"""
---
module: win_psrepository
short_description: Adds, removes or updates a Windows PowerShell repository.
description:
  - This module helps to add, remove and update Windows PowerShell repository on Windows-based systems.
options:
  name:
    description:
      - Name of the repository to work with.
    type: str
    required: yes
  source_location:
    description:
      - Specifies the URI for discovering and installing modules from this repository.
      - A URI can be a NuGet server feed (most common situation), HTTP, HTTPS, FTP or file location.
      - Required when registering a new repository or using I(force=True).
    type: str
    aliases:
      - source
  script_source_location:
    description:
      - Specifies the URI for discovering and installing scripts from this repository.
    type: str
  publish_location:
    description:
      - Specifies the URI for publishing modules to this repository.
    type: str
  script_publish_location:
    description:
      - Specifies the URI for publishing scripts to this repository.
    type: str
  state:
    description:
      - If C(present) a new repository is added or updated.
      - If C(absent) a repository is removed.
    type: str
    choices: [ absent, present ]
    default: present
  installation_policy:
    description:
      - Sets the C(InstallationPolicy) of a repository.
      - Will default to C(trusted) when creating a new repository or used with I(force=True).
    type: str
    choices: [ trusted, untrusted ]
  force:
    description:
      - If C(True), any differences from the desired state will result in the repository being unregistered, and then re-registered.
      - I(force) has no effect when I(state=absent). See notes for additional context.
    type: bool
    default: False
  proxy:
    description:
      - Proxy to use for repository.
    type: str
    required: no
    version_added: '1.0.0'
  username:
    description:
      - Username to authenticate against private repository.
    type: str
    required: no
    version_added: '1.0.0'
  password:
    description:
      - Password to authenticate against private repository.
    type: str
    required: no
    version_added: '1.0.0'
requirements:
  - PowerShell Module L(PowerShellGet >= 1.6.0,https://www.powershellgallery.com/packages/PowerShellGet/)
  - PowerShell Module L(PackageManagement >= 1.1.7,https://www.powershellgallery.com/packages/PackageManagement/)
  - PowerShell Package Provider C(NuGet) >= 2.8.5.201
notes:
  - See the examples on how to update the NuGet package provider.
  - You can not use C(win_psrepository) to re-register (add) removed PSGallery, use the command C(Register-PSRepository -Default) instead.
  - When registering or setting I(source_location), PowerShellGet will transform the location according to internal rules, such as following HTTP/S redirects.
  - This can result in a C(CHANGED) status on each run as the values will never match and will be "reset" each time.
  - To work around that, find the true destination value with M(sustainablelobster.legacy_community_windows.win_psrepository_info) or C(Get-PSRepository) and update the playbook to
    match.
  - When updating an existing repository, all options except I(name) are optional. Only supplied options will be updated. Use I(force=True) to exactly match.
  - I(script_location), I(publish_location), and I(script_publish_location) are optional but once set can only be cleared with I(force=True).
  - Using I(force=True) will unregister and re-register the repository if there are any changes, so that it exactly matches the options specified.
seealso:
  - module: sustainablelobster.legacy_community_windows.win_psrepository_info
  - module: sustainablelobster.legacy_community_windows.win_psmodule
author:
  - Wojciech Sciesinski (@it-praktyk)
  - Brian Scholer (@briantist)
"""

EXAMPLES = r"""
---
- name: Ensure the required NuGet package provider version is installed
  sustainablelobster.legacy_windows.win_shell: >-
    Find-PackageProvider -Name Nuget -ForceBootstrap -IncludeDependencies -Force

- name: Register a PowerShell repository
  sustainablelobster.legacy_community_windows.win_psrepository:
    name: MyRepository
    source_location: https://myrepo.com
    state: present

- name: Remove a PowerShell repository
  sustainablelobster.legacy_community_windows.win_psrepository:
    name: MyRepository
    state: absent

- name: Add an untrusted repository
  sustainablelobster.legacy_community_windows.win_psrepository:
    name: MyRepository
    installation_policy: untrusted

- name: Add a repository with different locations
  sustainablelobster.legacy_community_windows.win_psrepository:
    name: NewRepo
    source_location: https://myrepo.example/module/feed
    script_source_location: https://myrepo.example/script/feed
    publish_location: https://myrepo.example/api/module/publish
    script_publish_location: https://myrepo.example/api/script/publish

- name: Update only two properties on the above repository
  sustainablelobster.legacy_community_windows.win_psrepository:
    name: NewRepo
    installation_policy: untrusted
    script_publish_location: https://scriptprocessor.example/publish

- name: Clear script locations from the above repository by re-registering it
  sustainablelobster.legacy_community_windows.win_psrepository:
    name: NewRepo
    installation_policy: untrusted
    source_location: https://myrepo.example/module/feed
    publish_location: https://myrepo.example/api/module/publish
    force: true

- name: Register a PowerShell repository with credentials
  sustainablelobster.legacy_community_windows.win_psrepository:
    name: MyRepository
    source_location: https://myrepo.com
    state: present
    username: repo_username
    password: repo_password
"""

RETURN = """
"""

_OPERATION = r"""

$name = $p.name
$source_location = $p.source_location
$script_source_location = $p.script_source_location
$publish_location = $p.publish_location
$script_publish_location = $p.script_publish_location
$state = $p.state
$installation_policy = $p.installation_policy
$force = $p.force
$proxy = $p.proxy
$repo_user = $p.username
$repo_pass = $p.password
$check_mode = $p.check_mode
$result = @{ changed = $false }
try {
Enable-TlsProtocol

if (-not (Import-Module -Name PowerShellGet -MinimumVersion 1.6.0 -PassThru -ErrorAction SilentlyContinue)) {
    throw "PowerShellGet version 1.6.0+ is required."
}

$repository_params = @{
    Name = $name
}

$Repo = Get-PSRepository @repository_params -ErrorAction SilentlyContinue

if ($installation_policy) {
    $repository_params.InstallationPolicy = $installation_policy
}

if ($proxy) {
    $repository_params.Proxy = $Proxy
}

if ($repo_user -and $repo_pass ) {
    $repository_params.Credential = New-Object -TypeName PSCredential ($repo_user, ($repo_pass | ConvertTo-SecureString -AsPlainText -Force))
}

function Resolve-LocationParameter {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string[]]
        $Name ,

        [Parameter(Mandatory = $true)]
        [hashtable]
        $Splatter
    )

    End {
        foreach ($param in $Name) {
            $val = Get-Variable -Name $param -ValueOnly -ErrorAction SilentlyContinue
            if ($val) {
                if ($val -as [uri]) {
                    $Splatter[$param.Replace('_', '')] = $val -as [uri]
                }
                else {
                    throw "'$param' must be a valid URI."
                }
            }
        }
    }
}

Resolve-LocationParameter -Name source_location, publish_location, script_source_location, script_publish_location -Splatter $repository_params

if (-not $repository_params.SourceLocation -and $state -eq 'present' -and ($force -or -not $Repo)) {
    throw "'source_location' is required when registering a new repository or using force with 'state' == 'present'."
}
Function Update-NuGetPackageProvider {
    $PackageProvider = Get-PackageProvider -ListAvailable | Where-Object { ($_.name -eq 'Nuget') -and ($_.version -ge "2.8.5.201") }
    if ($null -eq $PackageProvider) {
        Find-PackageProvider -Name Nuget -ForceBootstrap -IncludeDependencies -Force | Out-Null
    }
}

if ($Repo) {
    $changed_properties = @{}

    if ($force -and -not $repository_params.InstallationPolicy) {
        $repository_params.InstallationPolicy = 'trusted'
    }

    if ($repository_params.InstallationPolicy) {
        if ($Repo.InstallationPolicy -ne $repository_params.InstallationPolicy) {
            $changed_properties.InstallationPolicy = $repository_params.InstallationPolicy
        }
    }

    if ($repository_params.SourceLocation) {
        # force check not needed here because it's done earlier; source_location is required with force
        if ($repository_params.SourceLocation -ne $Repo.SourceLocation) {
            $changed_properties.SourceLocation = $repository_params.SourceLocation
        }
    }

    if ($force -or $repository_params.ScriptSourceLocation) {
        if ($repository_params.ScriptSourceLocation -ne $Repo.ScriptSourceLocation) {
            $changed_properties.ScriptSourceLocation = $repository_params.ScriptSourceLocation
        }
    }

    if ($force -or $repository_params.PublishLocation) {
        if ($repository_params.PublishLocation -ne $Repo.PublishLocation) {
            $changed_properties.PublishLocation = $repository_params.PublishLocation
        }
    }

    if ($force -or $repository_params.ScriptPublishLocation) {
        if ($repository_params.ScriptPublishLocation -ne $Repo.ScriptPublishLocation) {
            $changed_properties.ScriptPublishLocation = $repository_params.ScriptPublishLocation
        }
    }

    if ($changed_properties.Count -gt 0) {
        if ($repository_params.Credential) {
            $changed_properties.Credential = $repository_params.Credential
        }
    }
}

if ($Repo -and ($state -eq "absent" -or ($force -and $changed_properties.Count -gt 0))) {
    if (-not $check_mode) {
        Update-NuGetPackageProvider
        Unregister-PSRepository -Name $name
    }
    $result.changed = $true
}

if ($state -eq "present") {
    if (-not $Repo -or ($force -and $changed_properties.Count -gt 0)) {
        if (-not $repository_params.InstallationPolicy) {
            $repository_params.InstallationPolicy = "trusted"
        }
        if (-not $check_mode) {
            Update-NuGetPackageProvider
            Register-PSRepository @repository_params
        }
        $result.changed = $true
    }
    else {
        if ($changed_properties.Count -gt 0) {
            if (-not $check_mode) {
                Update-NuGetPackageProvider
                Set-PSRepository -Name $name @changed_properties
            }
            $result.changed = $true
        }
    }
}



}
catch {
    $message = [string]$_.Exception.Message
    if ($repo_pass) { $message = $message.Replace($repo_pass, '*PASSWORD_REPLACED*') }
    $result.failed = $true
    $result.msg = $message
}
$result
"""
# pylint: enable=duplicate-code

_PARAMETERS = (
    "name",
    "source_location",
    "source",
    "script_source_location",
    "publish_location",
    "script_publish_location",
    "state",
    "installation_policy",
    "force",
    "proxy",
    "username",
    "password",
)


def _execute(arguments):
    parameters = {
        name: as_string(arguments.get(name), name)
        for name in (
            "name",
            "script_source_location",
            "publish_location",
            "script_publish_location",
            "installation_policy",
            "proxy",
            "username",
            "password",
        )
    }
    if not parameters["name"]:
        raise ValueError("name is required.")
    parameters["source_location"] = as_string(
        arguments.get("source_location", arguments.get("source")), "source_location"
    )
    parameters["state"] = (
        as_string(arguments.get("state", "present"), "state") or ""
    ).lower()
    if parameters["state"] not in ("present", "absent"):
        raise ValueError("state must be present or absent.")
    if parameters["installation_policy"] is not None:
        parameters["installation_policy"] = parameters["installation_policy"].lower()
        if parameters["installation_policy"] not in ("trusted", "untrusted"):
            raise ValueError("installation_policy must be trusted or untrusted.")
    parameters["force"] = as_bool(arguments.get("force", False), "force")
    # Each public payload keeps its check-mode conversion and module entry point
    # explicit; a dispatcher would obscure these independent Ansible interfaces.
    # pylint: disable=duplicate-code
    parameters["check_mode"] = as_bool(
        arguments.get("_ansible_check_mode", False), "_ansible_check_mode"
    )
    return invoke(_OPERATION, parameters)


def main():
    """Read public options and return the installed repository operation."""
    run_module(
        lambda: _execute(
            read_arguments(
                _PARAMETERS,
                "sustainablelobster.legacy_community_windows.win_psrepository",
                allow_unknown=True,
            )
        )
    )


if __name__ == "__main__":
    main()
# pylint: enable=duplicate-code
