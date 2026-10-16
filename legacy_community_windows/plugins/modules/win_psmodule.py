#!/usr/bin/python
# -*- coding: utf-8 -*-
# Copyright: (c) 2018, Wojciech Sciesinski <wojciech[at]sciesinski[dot]net>
# Copyright: (c) 2017, Daniele Lazzari <lazzari@mailup.com>
# Copyright 2026 sustainablelobster
# SPDX-License-Identifier: GPL-3.0-or-later

"""Manage vendor PowerShell modules through installed package commands."""

# WANT_JSON

from legacy_community_windows_psget_engine import invoke  # pylint: disable=import-error
from legacy_windows_module import (  # pylint: disable=import-error
    as_bool,
    as_string,
    read_arguments,
    run_module,
)

# Released interface text and fixed vendor operations are explicit so a reader
# can compare the supported contract without following a template registry.
# pylint: disable=duplicate-code
DOCUMENTATION = r"""
---
module: win_psmodule
short_description: Adds or removes a Windows PowerShell module
description:
  - This module helps to install Windows PowerShell modules and register custom modules repository on Windows-based systems.
options:
  name:
    description:
      - Name of the Windows PowerShell module that has to be installed.
    type: str
    required: yes
  state:
    description:
      - If C(present) a new module is installed.
      - If C(absent) a module is removed.
      - If C(latest) a module is updated to the newest version.
    type: str
    choices: [ absent, latest, present ]
    default: present
  required_version:
    description:
      - The exact version of the PowerShell module that has to be installed.
    type: str
  minimum_version:
    description:
      - The minimum version of the PowerShell module that has to be installed.
    type: str
  maximum_version:
    description:
      - The maximum version of the PowerShell module that has to be installed.
    type: str
  allow_clobber:
    description:
      - If C(yes) allows install modules that contains commands those have the same names as commands that already exists.
    type: bool
    default: no
  skip_publisher_check:
    description:
      - If C(yes), allows you to install a different version of a module that already exists on your computer in the case when a different one
        is not digitally signed by a trusted publisher and the newest existing module is digitally signed by a trusted publisher.
    type: bool
    default: no
  allow_prerelease:
    description:
      - If C(yes) installs modules marked as prereleases.
      - It doesn't work with the parameters C(minimum_version) and/or C(maximum_version).
      - It doesn't work with the C(state) set to absent.
    type: bool
    default: no
  repository:
    description:
      - Name of the custom repository to use.
    type: str
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
  accept_license:
    description:
      - Accepts the module's license.
      - Required for modules that require license acceptance, since interactively answering the prompt is not possible.
      - Corresponds to the C(-AcceptLicense) parameter of C(Install-Module).
      - >-
        Installation of a module or a dependency that requires license acceptance cannot be detected in check mode,
        but will cause a failure at runtime unless I(accept_license=true).
    type: bool
    required: no
    default: false
    version_added: '1.0.0'
  force:
    description:
      - Overrides warning messages about module installation conflicts
      - If there is an existing module with the same name and version, force overwrites that version
      - Corresponds to the C(-Force) parameter of C(Install-Module).
      - >-
        If module as dependency, it will also force reinstallation of dependency.
        Updating them to latest if version isn't specified in module manifest.
    type: bool
    required: no
    default: false
    version_added: '1.0.0'
notes:
  - PowerShell modules needed
      - PowerShellGet >= 1.6.0
      - PackageManagement >= 1.1.7
  - PowerShell package provider needed
      - NuGet >= 2.8.5.201
  - On PowerShell 5.x required modules and a package provider will be updated under the first run of the win_psmodule module.
  - On PowerShell 3.x and 4.x you have to install them before using the win_psmodule.
seealso:
- module: sustainablelobster.legacy_community_windows.win_psrepository
author:
- Wojciech Sciesinski (@it-praktyk)
- Daniele Lazzari (@dlazz)
"""

EXAMPLES = r"""
---
- name: Add a PowerShell module
  sustainablelobster.legacy_community_windows.win_psmodule:
    name: PowerShellModule
    state: present

- name: Add an exact version of PowerShell module
  sustainablelobster.legacy_community_windows.win_psmodule:
    name: PowerShellModule
    required_version: "4.0.2"
    state: present

- name: Install or update an existing PowerShell module to the newest version
  sustainablelobster.legacy_community_windows.win_psmodule:
    name: PowerShellModule
    state: latest

- name: Install newer version of built-in Windows module
  sustainablelobster.legacy_community_windows.win_psmodule:
    name: Pester
    skip_publisher_check: true
    state: present

- name: Add a PowerShell module and register a repository
  sustainablelobster.legacy_community_windows.win_psmodule:
    name: MyCustomModule
    repository: MyRepository
    state: present

- name: Add a PowerShell module from a specific repository
  sustainablelobster.legacy_community_windows.win_psmodule:
    name: PowerShellModule
    repository: MyRepository
    state: present

- name: Add a PowerShell module from a specific repository with credentials
  win_psmodule:
    name: PowerShellModule
    repository: MyRepository
    username: repo_username
    password: repo_password
    state: present

- name: Remove a PowerShell module
  sustainablelobster.legacy_community_windows.win_psmodule:
    name: PowerShellModule
    state: absent
"""

RETURN = r"""
---
output:
  description: A message describing the task result.
  returned: always
  sample: "Module PowerShellCookbook installed"
  type: str
nuget_changed:
  description: True when Nuget package provider is installed.
  returned: always
  type: bool
  sample: true
repository_changed:
  description: True when a custom repository is installed or removed.
  returned: always
  type: bool
  sample: true
"""

_OPERATION = r"""
$name = $p.name
$required_version = $p.required_version
$minimum_version = $p.minimum_version
$maximum_version = $p.maximum_version
$repo = $p.repository
$repo_user = $p.username
$repo_pass = $p.password
$state = $p.state
$allow_clobber = $p.allow_clobber
$skip_publisher_check = $p.skip_publisher_check
$allow_prerelease = $p.allow_prerelease
$accept_license = $p.accept_license
$force = $p.force
$check_mode = $p.check_mode
$result = @{ changed = $false; output = ''; nuget_changed = $false; repository_changed = $false }
try {
Enable-TlsProtocol

Function Install-NugetProvider {
    Param(
        [Bool]$CheckMode
    )
    $PackageProvider = Get-PackageProvider -ListAvailable | Where-Object { ($_.name -eq 'Nuget') -and ($_.version -ge "2.8.5.201") }
    if (-not($PackageProvider)) {
        try {
            Install-PackageProvider -Name NuGet -MinimumVersion 2.8.5.201 -Force -WhatIf:$CheckMode | Out-Null
            $result.changed = $true
            $result.nuget_changed = $true
        }
        catch [ System.Exception ] {
            $ErrorMessage = "Problems adding package provider: $($_.Exception.Message)"
            throw $ErrorMessage
        }
    }
}

Function Install-PrereqModule {
    Param(
        [Switch]$TestInstallationOnly,
        [bool]$AllowClobber,
        [Bool]$CheckMode,
        [bool]$AcceptLicense,
        [string]$Repository
    )

    # Those are minimum required versions of modules.
    $PrereqModules = @{
        PackageManagement = '1.1.7'
        PowerShellGet = '1.6.0'
    }

    $ExistingPrereqModule = Get-Module -Name @($PrereqModules.Keys) -ListAvailable |
        Where-Object { $_.Version -ge $PreReqModules[$_.Name] } |
        Select-Object -ExpandProperty Name -Unique
    $toInstall = $PrereqModules.Keys |
        Where-Object { $_ -notin $ExistingPrereqModule } |
        Select-Object @{N = 'Name'; E = { $_ } }, @{N = 'Version'; E = { $PrereqModules[$_] } }

    if ($TestInstallationOnly) {
        return (-not [bool]$toInstall)
    }
    elseif ($toInstall) {
        $result.changed = $true
        if ($CheckMode) {
            $result.output = "Skipped check mode run on win_psmodule as the pre-reqs need upgrading"
            return $false
        }

        # Need to run this in another process as importing PackageManagement at
        # the older version is irreversible (you cannot load the same dll at
        # different versions). Start-Job runs in a new process so it can safely
        # use the older version to install our pre-reqs.
        # https://github.com/ansible-collections/community.windows/issues/487
        $job = Start-Job -ScriptBlock {
            $ErrorActionPreference = 'Stop'

            if (-not (Get-PackageProvider -ListAvailable | Where-Object { ($_.name -eq 'Nuget') -and ($_.version -ge "2.8.5.201") }) ) {
                Install-PackageProvider -Name NuGet -MinimumVersion 2.8.5.201 -Force | Out-Null
            }

            $Repository = $using:Repository

            foreach ($info in $using:ToInstall) {
                $install_params = @{
                    Name = $info.Name
                    MinimumVersion = $info.Version
                    Force = $true
                }
                $installCmd = Get-Command -Name Install-Module
                if ($installCmd.Parameters.ContainsKey('SkipPublisherCheck')) {
                    $install_params.SkipPublisherCheck = $true
                }
                if ($installCmd.Parameters.ContainsKey('AllowClobber')) {
                    $install_params.AllowClobber = $using:AllowClobber
                }
                if ($installCmd.Parameters.ContainsKey('AcceptLicense')) {
                    $install_params.AcceptLicense = $using:AcceptLicense
                }
                if ($Repository) {
                    $install_params.Repository = $Repository
                }

                Install-Module @install_params > $null
            }
        }

        try {
            $null = $job | Receive-Job -AutoRemoveJob -Wait -ErrorAction Stop
        }
        catch {
            $ErrorMessage = "Problems adding a prerequisite module PackageManagement or PowerShellGet: $($_.Exception.Message)"
            $result.exception = ($_ | Out-String) + "`r`n" + $_.ScriptStackTrace
            throw $ErrorMessage
        }
    }
    $true
}

Function Get-PsModule {
    Param(
        [Parameter(Mandatory = $true)]
        [String]$Name,
        [String]$RequiredVersion,
        [String]$MinimumVersion,
        [String]$MaximumVersion
    )

    $ExistingModule = @{
        Exists = $false
        Version = ""
    }

    # Use Where-Object with '-eq' to handle wildcard names
    $ExistingModules = Get-Module -ListAvailable -Name $Name | Where-Object { $_.name -eq $Name }
    $ExistingModulesCount = $($ExistingModules | Measure-Object).Count

    if ( $ExistingModulesCount -gt 0 ) {

        $ExistingModules | Add-Member -MemberType ScriptProperty -Name FullVersion -Value {
            if ( $null -ne ( $this.PrivateData ) ) {
                [String]"$($this.Version)-$(($this | Select-Object -ExpandProperty PrivateData).PSData.Prerelease)".TrimEnd('-')
            }
            else {
                [String]"$($this.Version)"
            }
        }

        if ( -not ($RequiredVersion -or
                $MinimumVersion -or
                $MaximumVersion) ) {

            $ReturnedModule = $ExistingModules | Select-Object -First 1
        }
        elseif ( $RequiredVersion ) {
            $ReturnedModule = $ExistingModules | Where-Object -FilterScript { $_.FullVersion -eq $RequiredVersion }
        }
        elseif ( $MinimumVersion -and $MaximumVersion ) {
            $ReturnedModule = $ExistingModules |
                Where-Object -FilterScript { $MinimumVersion -le $_.Version -and $MaximumVersion -ge $_.Version } |
                Select-Object -First 1
        }
        elseif ( $MinimumVersion ) {
            $ReturnedModule = $ExistingModules | Where-Object -FilterScript { $MinimumVersion -le $_.Version } | Select-Object -First 1
        }
        elseif ( $MaximumVersion ) {
            $ReturnedModule = $ExistingModules | Where-Object -FilterScript { $MaximumVersion -ge $_.Version } | Select-Object -First 1
        }
    }

    $ReturnedModuleCount = ($ReturnedModule | Measure-Object).Count

    if ( $ReturnedModuleCount -eq 1 ) {
        $ExistingModule.Exists = $true
        $ExistingModule.Version = $ReturnedModule.FullVersion
    }

    $ExistingModule
}

Function Add-DefinedParameter {
    Param (
        [Parameter(Mandatory = $true)]
        [Hashtable]$Hashtable,
        [Parameter(Mandatory = $true)]
        [String[]]$ParametersNames
    )

    ForEach ($ParameterName in $ParametersNames) {
        $ParameterVariable = Get-Variable -Name $ParameterName -ErrorAction SilentlyContinue
        if ( $ParameterVariable.Value -and $Hashtable.Keys -notcontains $ParameterName ) {
            $Hashtable.Add($ParameterName, $ParameterVariable.Value)
        }
    }

    $Hashtable
}

Function Install-PsModule {
    Param(
        [Parameter(Mandatory = $true)]
        [String]$Name,
        [String]$RequiredVersion,
        [String]$MinimumVersion,
        [String]$MaximumVersion,
        [String]$Repository,
        [System.Management.Automation.PSCredential]$Credential = [System.Management.Automation.PSCredential]::Empty,
        [Bool]$AllowClobber,
        [Bool]$SkipPublisherCheck,
        [Bool]$AllowPrerelease,
        [Bool]$CheckMode,
        [Bool]$AcceptLicense,
        [Bool]$Force
    )

    $getParams = @{
        Name = $Name
        RequiredVersion = $RequiredVersion
        MinimumVersion = $MinimumVersion
        MaximumVersion = $MaximumVersion
    }
    $ExistingModuleBefore = Get-PsModule @getParams

    if ( -not $ExistingModuleBefore.Exists ) {
        try {
            # Install NuGet provider if needed.
            Install-NugetProvider -CheckMode $CheckMode

            $ht = @{
                Name = $Name
            }

            [String[]]$ParametersNames = @("RequiredVersion", "MinimumVersion", "MaximumVersion", "AllowPrerelease",
                "Repository", "Credential")
            $ht = Add-DefinedParameter -Hashtable $ht -ParametersNames $ParametersNames

            # When module require License Acceptance, or repository is Untrusted.
            # `-Force` is mandatory to skip interactive prompt
            $psgetModuleInfo = Find-Module @ht
            if (($psgetModuleInfo.AdditionalMetadata.requireLicenseAcceptance -eq "True") -or
                ((Get-PSRepository -Name $psgetModuleInfo.Repository).InstallationPolicy -eq "Untrusted")) {
                $ht["Force"] = $true
            }
            else {
                $ht["Force"] = $Force
            }

            $ht = $ht + @{
                WhatIf = $CheckMode
                AcceptLicense = $AcceptLicense
            }

            [String[]]$ParametersNames = @("AllowClobber", "SkipPublisherCheck")
            $ht = Add-DefinedParameter -Hashtable $ht -ParametersNames $ParametersNames

            Install-Module @ht -ErrorVariable ErrorDetails | Out-Null

            $result.changed = $true
            $result.output = "Module $($Name) installed"
        }
        catch [ System.Exception ] {
            $ErrorMessage = "Problems installing $($Name) module: $($_.Exception.Message)"
            throw $ErrorMessage
        }
    }
    else {
        $result.output = "Module $($Name) already present"
    }
}

Function Remove-PsModule {
    Param(
        [Parameter(Mandatory = $true)]
        [String]$Name,
        [String]$RequiredVersion,
        [String]$MinimumVersion,
        [String]$MaximumVersion,
        [Bool]$CheckMode
    )
    # If module is present, uninstalls it.
    # Use Where-Object with '-eq' to handle wildcard names
    if (Get-Module -ListAvailable -Name $Name | Where-Object { $_.name -eq $Name }) {
        try {
            $ht = @{
                Name = $Name
                Confirm = $false
                Force = $true
            }

            $ExistingModuleBefore = Get-PsModule -Name $Name -RequiredVersion $RequiredVersion -MinimumVersion $MinimumVersion -MaximumVersion $MaximumVersion

            [String[]]$ParametersNames = @("RequiredVersion", "MinimumVersion", "MaximumVersion")

            $ht = Add-DefinedParameter -Hashtable $ht -ParametersNames $ParametersNames

            if ( -not ( $RequiredVersion -or $MinimumVersion -or $MaximumVersion ) ) {
                $ht.Add("AllVersions", $true)
            }

            if ( $ExistingModuleBefore.Exists) {
                # The Force parameter overwrite the WhatIf parameter
                if ( -not $CheckMode ) {
                    Uninstall-Module @ht -ErrorVariable ErrorDetails | Out-Null
                }
                $result.changed = $true
                $result.output = "Module $($Name) removed"
            }
        }
        catch [ System.Exception ] {
            $ErrorMessage = "Problems uninstalling $($Name) module: $($_.Exception.Message)"
            throw $ErrorMessage
        }
    }
    else {
        $result.output = "Module $($Name) removed"
    }
}

Function Find-LatestPsModule {
    Param(
        [Parameter(Mandatory = $true)]
        [String]$Name,
        [String]$Repository,
        [System.Management.Automation.PSCredential]$Credential = [System.Management.Automation.PSCredential]::Empty,
        [Bool]$AllowPrerelease,
        [Bool]$CheckMode
    )

    try {
        $ht = @{
            Name = $Name
        }

        [String[]]$ParametersNames = @("AllowPrerelease", "Repository", "Credential")

        $ht = Add-DefinedParameter -Hashtable $ht -ParametersNames $ParametersNames

        $LatestModule = Find-Module @ht | Select-Object Version
    }
    catch [ System.Exception ] {
        $ErrorMessage = "Cannot find the module $($Name): $($_.Exception.Message)"
        throw $ErrorMessage
    }

    if ( $LatestModule.Version.GetType().FullName -eq 'System.Object[]' ) {
        $ErrorMessage = "The module $Name exists in multiple repositories. Define a repository."
        throw $ErrorMessage
    }

    $LatestModule
}

# Check PowerShell version, fail if < 5.0 and required modules are not installed
$PsVersion = $PSVersionTable.PSVersion
if ($PsVersion.Major -lt 5 ) {
    $PrereqModulesInstalled = Install-PrereqModule -TestInstallationOnly
    if ( -not $PrereqModulesInstalled ) {
        $ErrorMessage = -join @(
            "Modules PowerShellGet and PackageManagement in versions 1.6.0 and 1.1.7 respectively "
            "have to be installed before using the win_psmodule."
        )
        throw $ErrorMessage
    }
}

if ( $required_version -and ( $minimum_version -or $maximum_version ) ) {
    $ErrorMessage = "Parameters required_version and minimum/maximum_version are mutually exclusive."
    throw $ErrorMessage
}

if ( $allow_prerelease -and ( $minimum_version -or $maximum_version ) ) {
    $ErrorMessage = "Parameters minimum_version, maximum_version can't be used with the parameter allow_prerelease."
    throw $ErrorMessage
}

if ( $allow_prerelease -and $state -eq "absent" ) {
    $ErrorMessage = "The parameter allow_prerelease can't be used with state set to 'absent'."
    throw $ErrorMessage
}

if ( ($state -eq "latest") -and
    ( $required_version -or $minimum_version -or $maximum_version ) ) {
    $ErrorMessage = "When the parameter state is equal to 'latest' you can't use any of required_version, minimum_version, maximum_version."
    throw $ErrorMessage
}

if ( $repo ) {
    $RepositoryExists = Get-PSRepository -Name $repo -ErrorAction SilentlyContinue
    if ( $null -eq $RepositoryExists) {
        $ErrorMessage = "The repository $repo doesn't exist."
        throw $ErrorMessage
    }

}

if ($repo_user -and $repo_pass ) {
    $repo_credential = New-Object -TypeName PSCredential ($repo_user, ($repo_pass | ConvertTo-SecureString -AsPlainText -Force))
}

if ( ($allow_clobber -or $allow_prerelease -or $skip_publisher_check -or
        $required_version -or $minimum_version -or $maximum_version -or $accept_license) ) {
    # Update the PowerShellGet and PackageManagement modules.
    # It's required to support AllowClobber, AllowPrerelease parameters.
    # This must occur before PackageManagement or PowerShellGet is imported in
    # the current process.
    if (-not (Install-PrereqModule -AllowClobber $allow_clobber -CheckMode $check_mode -AcceptLicense $accept_license -Repository $repo)) {
        return $result
    }
}

Import-Module -Name PackageManagement, PowerShellGet -Force

if ($state -eq "present") {
    if ($name) {
        $ht = @{
            Name = $name
            RequiredVersion = $required_version
            MinimumVersion = $minimum_version
            MaximumVersion = $maximum_version
            Repository = $repo
            AllowClobber = $allow_clobber
            SkipPublisherCheck = $skip_publisher_check
            AllowPrerelease = $allow_prerelease
            CheckMode = $check_mode
            Credential = $repo_credential
            AcceptLicense = $accept_license
            Force = $force
        }
        Install-PsModule @ht
    }
}
elseif ($state -eq "absent") {
    if ($name) {
        $ht = @{
            Name = $Name
            CheckMode = $check_mode
            RequiredVersion = $required_version
            MinimumVersion = $minimum_version
            MaximumVersion = $maximum_version
        }
        Remove-PsModule @ht
    }
}
elseif ( $state -eq "latest") {

    $ht = @{
        Name = $Name
        AllowPrerelease = $allow_prerelease
        Repository = $repo
        CheckMode = $check_mode
        Credential = $repo_credential
    }

    $LatestModule = Find-LatestPsModule @ht

    $ExistingModule = Get-PsModule $Name

    if ( ($LatestModule.Version -ne $ExistingModule.Version) -or $force ) {

        $ht = @{
            Name = $Name
            RequiredVersion = $LatestModule.Version
            Repository = $repo
            AllowClobber = $allow_clobber
            SkipPublisherCheck = $skip_publisher_check
            AllowPrerelease = $allow_prerelease
            CheckMode = $check_mode
            Credential = $repo_credential
            AcceptLicense = $accept_license
            Force = $force
        }
        Install-PsModule @ht
    }
}


}
catch {
    $message = [string]$_.Exception.Message
    if ($repo_pass) {
        $message = $message.Replace($repo_pass, '*PASSWORD_REPLACED*')
        if ($result.exception) {
            $result.exception = $result.exception.Replace($repo_pass, '*PASSWORD_REPLACED*')
        }
    }
    $result.failed = $true
    $result.msg = $message
}
$result
"""
# pylint: enable=duplicate-code

_TEXT_PARAMETERS = (
    "name",
    "required_version",
    "minimum_version",
    "maximum_version",
    "repository",
    "username",
    "password",
)
_BOOL_PARAMETERS = (
    "allow_clobber",
    "skip_publisher_check",
    "allow_prerelease",
    "accept_license",
    "force",
)
_PARAMETERS = _TEXT_PARAMETERS + _BOOL_PARAMETERS + ("state",)


def _execute(arguments):
    parameters = {
        name: as_string(arguments.get(name), name) for name in _TEXT_PARAMETERS
    }
    if not parameters["name"]:
        raise ValueError("name is required.")
    parameters.update(
        (name, as_bool(arguments.get(name, False), name)) for name in _BOOL_PARAMETERS
    )
    parameters["state"] = (
        as_string(arguments.get("state", "present"), "state") or ""
    ).lower()
    if parameters["state"] not in ("present", "absent", "latest"):
        raise ValueError("state must be present, absent or latest.")
    # Keep the module's public check-mode and entry-point contract explicit,
    # independently of the script and repository frontends using this engine.
    # pylint: disable=duplicate-code
    parameters["check_mode"] = as_bool(
        arguments.get("_ansible_check_mode", False), "_ansible_check_mode"
    )
    return invoke(_OPERATION, parameters)


def main():
    """Read module-management options and return the installed engine's result."""
    run_module(
        lambda: _execute(
            read_arguments(
                _PARAMETERS,
                "sustainablelobster.legacy_community_windows.win_psmodule",
                allow_unknown=True,
            )
        )
    )


if __name__ == "__main__":
    main()
# pylint: enable=duplicate-code
