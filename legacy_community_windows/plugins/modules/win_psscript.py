#!/usr/bin/python
# -*- coding: utf-8 -*-
# Copyright: (c) 2020, Brian Scholer <@briantist>
# Copyright 2026 sustainablelobster
# SPDX-License-Identifier: GPL-3.0-or-later

"""Manage installed scripts through the native PowerShellGet engine."""

# WANT_JSON

from legacy_community_windows_psget_engine import invoke  # pylint: disable=import-error
from legacy_windows_module import (  # pylint: disable=import-error
    as_bool,
    as_string,
    read_arguments,
    run_module,
)

# Released interface text and fixed vendor operations retain their explicit
# fields; a template or a simulated module object would hide the real contract.
# pylint: disable=duplicate-code
DOCUMENTATION = r"""
---
module: win_psscript
short_description: Install and manage PowerShell scripts from a PSRepository
description:
  - Add or remove PowerShell scripts from registered PSRepositories.
options:
  name:
    description:
      - The name of the script you want to install or remove.
    type: str
    required: True
  repository:
    description:
      - The registered name of the repository you want to install from.
      - Cannot be used when I(state=absent).
      - If omitted, all repositories will be searched.
      - To register a repository, use M(sustainablelobster.legacy_community_windows.win_psrepository).
    type: str
  scope:
    description:
      - Determines whether the script is installed for only the C(current_user) or for C(all_users).
    type: str
    choices:
      - current_user
      - all_users
    default: all_users
  state:
    description:
      - The desired state of the script. C(absent) removes the script.
      - C(latest) will ensure the most recent version available is installed.
      - C(present) only installs if the script is missing.
    type: str
    choices:
      - present
      - absent
      - latest
    default: present
  required_version:
    description:
      - The exact version of the script to install.
      - Cannot be used with I(minimum_version) or I(maximum_version).
      - Cannot be used when I(state=latest).
    type: str
  minimum_version:
    description:
      - The minimum version of the script to install.
      - Cannot be used when I(state=latest).
    type: str
  maximum_version:
    description:
      - The maximum version of the script to install.
      - Cannot be used when I(state=latest).
    type: str
  allow_prerelease:
    description:
      - If C(yes) installs scripts flagged as prereleases.
    type: bool
    default: no
  source_username:
    description:
      - The username portion of the credential required to access the repository.
      - Must be used together with I(source_password).
    type: str
  source_password:
    description:
      - The password portion of the credential required to access the repository.
      - Must be used together with I(source_username).
    type: str
requirements:
  - C(PowerShellGet) module v1.6.0+
seealso:
  - module: sustainablelobster.legacy_community_windows.win_psrepository
  - module: sustainablelobster.legacy_community_windows.win_psrepository_info
  - module: sustainablelobster.legacy_community_windows.win_psmodule
notes:
  - Unlike PowerShell modules, scripts do not support side-by-side installations of multiple versions. Installing a new version will replace the existing one.
author:
  - Brian Scholer (@briantist)
"""

EXAMPLES = r"""
- name: Install a script from PSGallery
  sustainablelobster.legacy_community_windows.win_psscript:
    name: Test-RPC
    repository: PSGallery

- name: Find and install the latest version of a script from any repository
  sustainablelobster.legacy_community_windows.win_psscript:
    name: Get-WindowsAutoPilotInfo
    state: latest

- name: Remove a script that isn't needed
  sustainablelobster.legacy_community_windows.win_psscript:
    name: Defrag-Partition
    state: absent

- name: Install a specific version of a script for the current user
  sustainablelobster.legacy_community_windows.win_psscript:
    name: CleanOldFiles
    scope: current_user
    required_version: 3.10.2

- name: Install a script below a certain version
  sustainablelobster.legacy_community_windows.win_psscript:
    name: New-FeatureEnable
    maximum_version: 2.99.99

- name: Ensure a minimum version of a script is present
  sustainablelobster.legacy_community_windows.win_psscript:
    name: OldStandby
    minimum_version: 3.0.0

- name: Install any available version that fits a specific range
  sustainablelobster.legacy_community_windows.win_psscript:
    name: FinickyScript
    minimum_version: 2.5.1
    maximum_version: 2.6.19
"""

RETURN = r"""
"""


_OPERATION = r"""
$result = @{ changed = $false }
try {
    Import-Module PowerShellGet -MinimumVersion 1.6.0 -ErrorAction Stop
    Enable-TlsProtocol
    $parameters = @{}
    foreach ($property in $p.PSObject.Properties) {
        if ($property.Name -ne 'check_mode') {
            $parameters[$property.Name] = $property.Value
        }
    }
    $state = $p.state
function Get-SplattableParameter {
    [CmdletBinding(DefaultParameterSetName = 'All')]
    [OutputType([hashtable])]
    param(
        [Parameter(Mandatory = $true)]
        [hashtable]
        $Parameters ,

        [Parameter(ParameterSetName = 'ForCommand')]
        [Alias('For')]
        [String]
        $ForCommand ,

        [Parameter(ParameterSetName = 'WithCommand', ValueFromPipeline = $true)]
        [Alias('Command')]
        [System.Management.Automation.CommandInfo]
        $WithCommand
    )

    Process {
        $ret = @{}

        $cmd = switch ($PSCmdlet.ParameterSetName) {
            'WithCommand' { $WithCommand }
            'ForCommand' { Get-Command -Name $ForCommand }
        }

        if ($cmd) {
            $commons = [System.Management.Automation.Cmdlet]::CommonParameters + [System.Management.Automation.Cmdlet]::CommonOptionalParameters
            $validParams = $cmd.Parameters.GetEnumerator() | ForEach-Object -Process {
                if ($commons -notcontains $_.Key) {
                    $_.Key
                }
            }
        }

        switch -Wildcard ($Parameters.Keys) {
            '*' {
                $value = $Parameters[$_]
                if ($null -eq $value) {
                    continue
                }

                $key = $_.Replace('_', '')
                if ($validParams -and $validParams -notcontains $key) {
                    continue
                }
            }

            'scope' { $value = $value.Replace('_', '') }
            'source_username' { continue } # handled in password block
            'source_password' {
                $key = 'Credential'
                $secure = ConvertTo-SecureString -String $value -AsPlainText -Force
                $value = New-Object -TypeName System.Management.Automation.PSCredential -ArgumentList $Parameters.source_username, $secure
            }
            '*_version' {
                if ($Parameters.state -eq 'latest') {
                    throw "version options can't be used with 'state': 'latest'"
                }
            }
            'repository' {
                if ($Parameters.state -eq 'absent') {
                    throw "'repository' is not valid with 'state': 'absent'"
                }
            }

            '*' { $ret[$key] = $value }
        }

        $ret
    }
}

$pGet, $pUninstall, $pFind, $pInstall = Get-Command -Name @(
    'Get-InstalledScript'
    , 'Uninstall-Script'
    , 'Find-Script'
    , 'Install-Script'
) | Get-SplattableParameter -Parameters $parameters

$existing = Get-InstalledScript @pGet -ErrorAction SilentlyContinue
$existing = if ($existing) {
    $existing | Group-Object -Property Name -AsHashTable -AsString
}
else {
    @{}
}

if ($state -eq 'absent') {
    if ($existing.Count) {
        try {
            $result.changed = $true
            if (-not $p.check_mode) {
                $existing.Values | Uninstall-Script -Force -ErrorAction Stop
            }
        }
        catch {
            throw ("Error uninstalling scripts. " + $_.Exception.Message)
        }
    }
}
else {
    # state is 'present' or 'latest'
    try {
        $remote = Find-Script @pFind -ErrorAction Stop
    }
    catch {
        throw ("Error searching for scripts. " + $_.Exception.Message)
    }

    try {
        $toInstall = $remote | Where-Object -FilterScript {
            -not $existing.ContainsKey($_.Name) -or (
                $state -eq 'latest' -and
                ($_.Version -as [version]) -gt ($existing[$_.Name].Version -as [version])
            )
        }

        if (($toInstall | Group-Object -Property Name -NoElement | Where-Object -Property Count -gt 1)) {
            throw "Multiple scripts found. Please choose a specific repository."
        }

        $result.changed = $toInstall -as [bool]

        if ($toInstall -and -not $p.check_mode) {
            $toInstall | Install-Script -Scope:$pInstall.scope -Force -ErrorAction Stop
        }
    }
    catch {
        throw ("Error installing scripts. " + $_.Exception.Message)
    }
}


}
catch {
    $message = [string]$_.Exception.Message
    if ($p.source_password) {
        $message = $message.Replace($p.source_password, '*PASSWORD_REPLACED*')
    }
    $result.failed = $true
    $result.msg = $message
}
$result
"""
# pylint: enable=duplicate-code

_PARAMETERS = (
    "name",
    "repository",
    "scope",
    "state",
    "required_version",
    "minimum_version",
    "maximum_version",
    "source_username",
    "source_password",
    "allow_prerelease",
)


def _execute(arguments):
    parameters = {
        name: as_string(arguments.get(name), name)
        for name in _PARAMETERS
        if name != "allow_prerelease"
    }
    if not parameters["name"]:
        raise ValueError("name is required.")
    for name, default, choices in (
        ("scope", "all_users", ("all_users", "current_user")),
        ("state", "present", ("present", "absent", "latest")),
    ):
        parameters[name] = (parameters[name] or default).lower()
        if parameters[name] not in choices:
            raise ValueError(name + " must be one of " + ", ".join(choices) + ".")
    versions = (
        parameters["required_version"],
        parameters["minimum_version"],
        parameters["maximum_version"],
    )
    if versions[0] and any(versions[1:]):
        raise ValueError(
            "required_version cannot be used with minimum_version or maximum_version."
        )
    if parameters["state"] == "latest" and any(versions):
        raise ValueError("version options cannot be used with state latest.")
    if parameters["state"] == "absent" and parameters["repository"]:
        raise ValueError("repository cannot be used with state absent.")
    if bool(parameters["source_username"]) != bool(parameters["source_password"]):
        raise ValueError(
            "source_username and source_password must be supplied together."
        )
    parameters["allow_prerelease"] = as_bool(
        arguments.get("allow_prerelease", False), "allow_prerelease"
    )
    parameters["check_mode"] = as_bool(
        arguments.get("_ansible_check_mode", False), "_ansible_check_mode"
    )
    return invoke(_OPERATION, parameters)


def main():
    """Read public script options and return the installed engine's result."""
    run_module(
        lambda: _execute(
            read_arguments(
                _PARAMETERS,
                "sustainablelobster.legacy_community_windows.win_psscript",
            )
        )
    )


if __name__ == "__main__":
    main()
