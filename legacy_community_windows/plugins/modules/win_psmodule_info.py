#!/usr/bin/python
# -*- coding: utf-8 -*-
# Copyright: (c) 2020, Brian Scholer <@briantist>
# Copyright 2026 sustainablelobster
# SPDX-License-Identifier: GPL-3.0-or-later

"""Query installed PowerShellGet data through its vendor engine."""

# WANT_JSON

# The action stages the fixed vendor engine boundary beside this Python payload.
from legacy_community_windows_psget_engine import invoke  # pylint: disable=import-error
from legacy_windows_module import (  # pylint: disable=import-error
    as_bool,
    as_string,
    as_string_list,
    read_arguments,
    run_module,
)

# Released interfaces and fixed vendor serializers intentionally repeat their
# field definitions; introducing formatting templates would obscure the contracts.
# pylint: disable=duplicate-code
DOCUMENTATION = r"""
---
module: win_psmodule_info
short_description: Gather information about PowerShell Modules
description:
  - Gather information about PowerShell Modules including information from PowerShellGet.
options:
  name:
    description:
      - The name of the module to retrieve.
      - Supports any wildcard pattern supported by C(Get-Module).
      - If omitted then all modules will returned.
    type: str
    default: '*'
  repository:
    description:
      - The name of the PSRepository the modules were installed from.
      - This acts as a filter against the modules that would be returned based on the I(name) option.
      - Modules that were not installed from a repository will not be returned if this option is set.
      - Only modules installed from a registered repository will be returned.
      - If the repository was re-registered after module installation with a new C(SourceLocation), this will not match.
    type: str
  include_properties:
    description:
      - List of property names to include in the output.
      - Property names should be in snake_case format (e.g., C(module_base), C(exported_functions)).
      - If omitted, all available properties are returned.
      - When specified, only the requested properties will be included in the output.
      - To get minimal output similar to the old C(simplified=true), use C([name, version, author, module_base]).
      - See the RETURN section for a complete list of available properties.
      - Repository-related properties (repository, repository_source_location, installed_date, published_date, etc.)
        require PowerShellGet lookups and may be slower.
    type: list
    elements: str
  skip_module_repository_info:
    description:
      - When C(true), skips querying PowerShellGet for repository-related metadata.
      - This significantly improves performance but repository properties will be C(null).
      - Repository properties include C(repository), C(repository_source_location), C(installed_date), C(published_date),
        C(updated_date), C(package_management_provider), C(installed_location), C(tags), C(compatible_ps_editions),
        C(license_uri), C(project_uri), C(icon_uri), C(release_notes), and C(dependencies).
      - When C(include_properties) is specified without any repository properties, this is automatically set to C(true) for optimization.
    type: bool
    default: false
requirements:
  - C(PowerShellGet) module
seealso:
  - module: sustainablelobster.legacy_community_windows.win_psrepository_info
  - module: sustainablelobster.legacy_community_windows.win_psscript_info
author:
  - Brian Scholer (@briantist)
"""

EXAMPLES = r"""
- name: Get info about all modules on the system
  sustainablelobster.legacy_community_windows.win_psmodule_info:

- name: Get info about the ScheduledTasks module
  sustainablelobster.legacy_community_windows.win_psmodule_info:
    name: ScheduledTasks

- name: Get info about networking modules
  sustainablelobster.legacy_community_windows.win_psmodule_info:
    name: Net*

- name: Get name, version, author and module path for all modules
  sustainablelobster.legacy_community_windows.win_psmodule_info:
    include_properties:
      - name
      - version
      - author
      - module_base
  register: simple_modules

- name: Get module info without the extra repository lookups
  sustainablelobster.legacy_community_windows.win_psmodule_info:
    skip_module_repository_info: true
  register: modules_fast

- name: Get info about all modules installed from the PSGallery repository
  sustainablelobster.legacy_community_windows.win_psmodule_info:
    repository: PSGallery
  register: gallery_modules

- name: Update all modules retrieved from above example
  sustainablelobster.legacy_community_windows.win_psmodule:
    name: "{{ item }}"
    state: latest
  loop: "{{ gallery_modules.modules | map(attribute='name') }}"

- name: Get info about all modules on the system
  sustainablelobster.legacy_community_windows.win_psmodule_info:
  register: all_modules

- name: Find modules installed from a repository that isn't registered now
  set_fact:
    missing_repository_modules: "{{
      all_modules
      | json_query('modules[?repository!=null && '
                   ~ 'repository==repository_source_location].'
                   ~ '{name: name, version: version, repository: repository}')
      | list
    }}"

- debug:
    var: missing_repository_modules
"""

RETURN = r"""
modules:
  description:
    - A list of modules (or an empty list is there are none).
    - When I(include_properties) is specified, only contains the requested properties.
    - When I(include_properties) is not specified (default), contains all available module properties listed below.
  returned: always
  type: list
  elements: dict
  contains:
    name:
      description:
        - The name of the module.
      type: str
      sample: PSReadLine
    version:
      description:
        - The module version.
      type: str
      sample: 1.2.3
    guid:
      description:
        - The GUID of the module.
      type: str
      sample: 74c9fd30-734b-4c89-a8ae-7727ad21d1d5
    path:
      description:
        - The path to the module.
      type: str
      sample: 'C:\WINDOWS\system32\WindowsPowerShell\v1.0\Modules\PKI\PKI.psd1'
    module_base:
      description:
        - The path that contains the module's files.
      type: str
      sample: 'C:\WINDOWS\system32\WindowsPowerShell\v1.0\Modules\PKI'
    installed_location:
      description:
        - The path where the module is installed.
        - This should have the same value as C(module_base) but only has a value when the module was installed via PowerShellGet.
      type: str
      sample: 'C:\Program Files\WindowsPowerShell\Modules\posh-git\0.7.1'
    exported_aliases:
      description:
        - The aliases exported from the module.
      type: list
      elements: str
      sample:
        - glu
        - slu
    exported_cmdlets:
      description:
        - The cmdlets exported from the module.
      type: list
      elements: str
      sample:
        - Get-Certificate
        - Get-PfxData
    exported_commands:
      description:
        - All of the commands exported from the module. Includes functions, cmdlets, and aliases.
      type: list
      elements: str
      sample:
        - glu
        - Get-LocalUser
    exported_dsc_resources:
      description:
        - The DSC resources exported from the module.
      type: list
      elements: str
      sample:
        - xWebAppPool
        - xWebSite
    exported_format_files:
      description:
        - The format files exported from the module.
      type: list
      elements: path
      sample:
        - 'C:\WINDOWS\system32\WindowsPowerShell\v1.0\Modules\DnsClient\DnsCmdlets.Format.ps1xml'
        - 'C:\WINDOWS\system32\WindowsPowerShell\v1.0\Modules\DnsClient\DnsConfig.Format.ps1xml'
        - 'C:\WINDOWS\system32\WindowsPowerShell\v1.0\Modules\DnsClient\DnsClientPSProvider.Format.ps1xml'
    exported_functions:
      description:
        - The functions exported from the module.
      type: list
      elements: str
      sample:
        - New-VirtualDisk
        - New-Volume
    exported_type_files:
      description:
        - The type files exported from the module.
      type: list
      elements: path
      sample:
        - 'C:\WINDOWS\system32\WindowsPowerShell\v1.0\Modules\DnsClient\DnsCmdlets.Types.ps1xml'
        - 'C:\WINDOWS\system32\WindowsPowerShell\v1.0\Modules\DnsClient\DnsConfig.Types.ps1xml'
        - 'C:\WINDOWS\system32\WindowsPowerShell\v1.0\Modules\DnsClient\DnsClientPSProvider.Types.ps1xml'
    exported_variables:
      description:
        - The variables exported from the module.
      type: list
      elements: str
      sample:
        - GitPromptScriptBlock
    exported_workflows:
      description:
        - The workflows exported from the module.
        - This will not be present if targeting a PowerShell 7 interpreter.
      type: list
      elements: str
    access_mode:
      description:
        - The module's access mode. See U(https://docs.microsoft.com/en-us/dotnet/api/system.management.automation.moduleaccessmode)
      type: str
      sample: ReadWrite
    module_type:
      description:
        - The module's type. See U(https://docs.microsoft.com/en-us/dotnet/api/system.management.automation.moduletype)
      type: str
      sample: Script
    processor_architecture:
      description:
        - The module's processor architecture. See U(https://docs.microsoft.com/en-us/dotnet/api/system.reflection.processorarchitecture)
      type: str
      sample: Amd64
    author:
      description:
        - The author of the module.
      type: str
      sample: Warren Frame
    copyright:
      description:
        - The copyright of the module.
      type: str
      sample: '(c) 2016 Warren F. All rights reserved.'
    company_name:
      description:
        - The company name of the module.
      type: str
      sample: Microsoft Corporation
    description:
      description:
        - The description of the module.
      type: str
      sample: Provides cmdlets to work with local users and local groups
    clr_version:
      description:
        - The CLR version of the module.
      type: str
      sample: '4.0'
    compatible_ps_editions:
      description:
        - The PS Editions the module is compatible with.
      type: list
      elements: str
      sample:
        - Desktop
    dependencies:
      description:
        - The modules required by this module.
      type: list
      elements: str
    dot_net_framework_version:
      description:
        - The .Net Framework version of the module.
      type: str
      sample: '4.6.1'
    file_list:
      description:
        - The files included in the module.
      type: list
      elements: path
      sample:
        - 'C:\Program Files\WindowsPowerShell\Modules\PowerShellGet\1.6.0\PSModule.psm1'
        - 'C:\Program Files\WindowsPowerShell\Modules\PowerShellGet\1.6.0\PSGet.Format.ps1xml'
        - 'C:\Program Files\WindowsPowerShell\Modules\PowerShellGet\1.6.0\PSGet.Resource.psd1'
    help_info_uri:
      description:
        - The help info address of the module.
      type: str
      sample: 'https://go.microsoft.com/fwlink/?linkid=390823'
    icon_uri:
      description:
        - The address of the icon of the module.
      type: str
      sample: 'https://raw.githubusercontent.com/powershell/psscriptanalyzer/master/logo.png'
    license_uri:
      description:
        - The address of the license for the module.
      type: str
      sample: 'https://github.com/PowerShell/xPendingReboot/blob/master/LICENSE'
    project_uri:
      description:
        - The address of the module's project.
      type: str
      sample: 'https://github.com/psake/psake'
    repository_source_location:
      description:
        - The source location of the repository where the module was installed from.
      type: str
      sample: 'https://www.powershellgallery.com/api/v2'
    repository:
      description:
        - The PSRepository where the module was installed from.
        - This value is not historical. It depends on the PSRepositories that are registered now for the current user.
        - The C(repository_source_location) must match the current source location of a registered repository to get a repository name.
        - If there is no match, then this value will match C(repository_source_location).
      type: str
      sample: PSGallery
    release_notes:
      description:
        - The module's release notes. This is a free text field and no specific format should be assumed.
      type: str
      sample: |
        ## 1.4.6
        - Update `HelpInfoUri` to point to the latest content

        ## 1.4.5
        - Bug fix for deadlock when getting parameters in an event

        ## 1.4.4
        - Bug fix when installing modules from private feeds
    installed_date:
      description:
        - The date the module was installed.
      type: str
      sample: '2018-02-14T17:55:34.9620740-05:00'
    published_date:
      description:
        - The date the module was published.
      type: str
      sample: '2017-03-15T04:18:09.0000000'
    updated_date:
      description:
        - The date the module was last updated.
      type: str
      sample: '2019-12-31T09:20:02.0000000'
    log_pipeline_execution_details:
      description:
        - Determines whether pipeline execution detail events should be logged.
      type: bool
    module_list:
      description:
        - A list of modules packaged with this module.
        - This value is not often returned and the modules are not automatically processed.
      type: list
      elements: dict
      contains:
        name:
          description:
            - The name of the module.
            - This may also be a path to the module file.
          type: str
          sample: '.\WindowsUpdateLog.psm1'
        guid:
          description:
            - The GUID of the module.
          type: str
          sample: 82fdb72c-ecc5-4dfd-b9d5-83cf6eb9067f
        version:
          description:
            - The minimum version of the module.
          type: str
          sample: '2.0'
        maximum_version:
          description:
            - The maximum version of the module.
          type: str
          sample: '2.9'
        required_version:
          description:
            - The exact version of the module required.
          type: str
          sample: '3.1.4'
    nested_modules:
      description:
        - A list of modules nested with and loaded into the scope of this module.
        - This list contains full module objects, so each item can have all of the properties listed here, including C(nested_modules).
      type: list
      elements: dict
    required_modules:
      description:
        - A list of modules required by this module.
        - This list contains full module objects, so each item can have all of the properties listed here, including C(required_modules).
        - These module objects may not contain full information however, so you may see different results than if you had directly queried the module.
      type: list
      elements: dict
    required_assemblies:
      description:
        - A list of assemblies that the module requires.
        - The values may be a simple name or a full path.
      type: str
      sample:
        - Microsoft.Management.Infrastructure.CimCmdlets.dll
        - Microsoft.Management.Infrastructure.Dll
    package_management_provider:
      description:
        - If the module was installed from PowerShellGet, this is the package management provider used.
      type: str
      sample: NuGet
    power_shell_host_name:
      description:
        - The name of the PowerShell host that the module requires.
      type: str
      sample: Windows PowerShell ISE Host
    power_shell_host_version:
      description:
        - The version of the PowerShell host that the module requires.
      type: str
      sample: '1.1'
    power_shell_version:
      description:
        - The minimum version of PowerShell that the module requires.
      type: str
      sample: '5.1'
    prefix:
      description:
        - The default prefix applied to C(Verb-Noun) commands exported from the module, resulting in C(Verb-PrefixNoun) names.
      type: str
    private_data:
      description:
        - Arbitrary private data used by the module. This is typically defined in the module manifest.
        - This module limits the depth of the data returned for module types other than C(Script) and C(Manifest).
        - The C(PSData) is commonly supplied and provides metadata for PowerShellGet but those fields are surfaced in top-level properties as well.
      type: dict
      sample:
        PSData:
          LicenseUri: https://example.com/module/LICENSE
          ProjectUri: https://example.com/module/
          ReleaseNotes: |
            v2 - Fixed some bugs
            v1 - First release
          Tags:
            - networking
            - serialization
    root_module:
      description:
        - The root module as defined in the manifest.
        - This may be a module name, filename, or full path.
      type: str
      sample: WindowsErrorReporting.psm1
    scripts:
      description:
        - A list of scripts (C(.ps1) files) that run in the caller's session state when the module is imported.
        - This value comes from the C(ScriptsToProcess) field in the module's manifest.
      type: list
      sample:
        - PrepareEnvironment.ps1
        - InitializeData.ps1
    tags:
      description:
        - The tags defined in the module's C(PSData) metadata.
      type: list
      elements: str
      sample:
        - networking
        - serialization
        - git
        - dsc
"""

_OPERATION = r"""
Import-Module PowerShellGet -ErrorAction Stop
# Define the list of properties that are managed by PowerShellGet repository lookups
# This is used both by Add-ModuleRepositoryInfo and for optimization checks
$RepositoryManagedProperties = @(
    'PublishedDate'
    'InstalledDate'
    'UpdatedDate'
    'Dependencies'
    'Repository'
    'PackageManagementProvider'
    'InstalledLocation'
    'RepositorySourceLocation'
    'Tags'
    'CompatiblePSEditions'
    'LicenseUri'
    'ProjectUri'
    'IconUri'
    'ReleaseNotes'
    'ExportedDscResources' # ExportedDscResources is not returned here, this is a hack for Windows 2012/R2 to ensure the field is present
    'Prefix'               # Prefix is not actually returned here, this is a hack for Windows 2012 just to ensure the field is present
)

# We need to remove this type data so that arrays don't get serialized weirdly.
# In some cases, an array gets serialized as an object with a Count and Value property where the value is the actual array.
# See: https://stackoverflow.com/a/48858780/3905079
if (-not $IsCoreCLR) {
    Remove-TypeData System.Array
}

function ConvertTo-SerializableModuleInfo {
    <#
        .SYNOPSIS
        Transforms some members of a ModuleInfo object to be more serialization-friendly and prevent infinite recursion.

        .DESCRIPTION
        Stringifies version properties so we don't get serialized [System.Version] objects which aren't very useful.

        ExportedCommands and some other Exported* members are problematic in a few ways.
        For one, they contain a reference to the full ModuleInfo object they are found in. This is probably useful
        for nested modules and such, but in most cases they are just a reference to the current module, and this will
        recurse infinitely.

        Further, the rest of the properties of the exported commands aren't needed for this module. A low depth on JSON
        conversion doesn't fully work because some other module fields need it deeper than 1, and since this is a
        dictionary we get a JSOn object whose property names and values are both just the name of the command.

        So instead we just make an array of the names, as that's good enough for what we want to return.

        NestedModules and RequiredModules are full ModuleInfo objects so that becomes a recursive call.
        Limiting depth or reference counting shouldn't be necessary because the entries aren't references; they
        have to actually exist.

        ModuleList gets recursed as well even though it's a tiny subset of fields, to transform versions and to
        convert to snake_case.

        PrivateData can contain any data but a module manifest is a static file that can't contain references or
        problematic types like [Type]. Unfortunately some module types like CIM (and presumably binary?) seem to be
        able to populate that with whatever they want.

        As a precaution then, for module type that is not Script or Manifest, we limit PrivateData to a shallow depth.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true, ValueFromPipeline = $true)]
        [Object]
        $InputObject ,

        [Parameter()]
        [string[]]
        $ExcludeProperty = @(
            <#
                Definition is the script that makes up the script module.
                Big to return from this module, but also it doesn't ever seem to be filled in
                in the data from Get-Module -ListAvailable.
            #>
            'Definition',
            <#
                OnRemove is a script that gets run before the module is removed.
                Not necessary for return.
            #>
            'OnRemove',
            <#
                For binary modules, ImplementingAssembly is a reference to the assembly.
                No use returning it.
            #>
            'ImplementingAssembly',
            <#
                The session state instance of a loaded module. It's a runtime property only returned
                without -ListAvailable and has no value serialized.
            #>
            'SessionState'
        )
    )

    Process {
        $properties = foreach ($p in $InputObject.PSObject.Properties) {
            $pName = $p.Name
            $pValue = $p.Value

            switch -Regex ($pName) {
                '^PrivateData$' {
                    if (
                        $InputObject.ModuleType -notin @(
                            [System.Management.Automation.ModuleType]::Script,
                            [System.Management.Automation.ModuleType]::Manifest
                        )
                    ) {
                        $safeVal = $pValue | ConvertTo-Json -Depth 1 | ConvertFrom-Json
                        @{
                            Name = $pName
                            Expression = { $safeVal }.GetNewClosure()
                        }
                    }
                    else {
                        $pName
                    }
                    break
                }
                '^(?:NestedModules|ModuleList|RequiredModules)$' {
                    # Nested and Required modules are full moduleinfo objects
                    # ModuleList isn't but its simplified fields need much of the same treatment
                    if ($pValue) {
                        @{
                            Name = $pName
                            Expression = {
                                @(, ($pValue | ConvertTo-SerializableModuleInfo | Convert-ObjectToSnakeCase -NoRecurse))
                            }.GetNewClosure()
                        }
                    }
                    else {
                        $pName
                    }
                    break
                }
                'Version$' {
                    @{
                        Name = $pName
                        Expression = { $pValue.ToString() }.GetNewClosure()
                    }
                    break
                }
                '^Exported' {
                    @{
                        Name = $pName
                        Expression = { @(, $pValue.Keys) }.GetNewClosure()
                    }
                    break
                }
                default {
                    if ($pValue -is [datetime]) {
                        @{
                            Name = $pName
                            Expression = { $pValue.ToString('o') }.GetNewClosure()
                        }
                    }
                    elseif ($pValue -is [enum] -or $pValue -is [type]) {
                        @{
                            Name = $pName
                            Expression = { $pValue.ToString() }.GetNewClosure()
                        }
                    }
                    else {
                        $pName
                    }
                }
            }
        }

        $InputObject | Select-Object -Property $properties -ExcludeProperty $ExcludeProperty
    }
}

function Select-ModuleProperty {
    <#
        .SYNOPSIS
        Filters a module dictionary to include only specified properties.

        .DESCRIPTION
        Takes a module information dictionary (already converted to snake_case) and returns
        only the properties specified in the PropertyList parameter.

        Properties that don't exist in the module dictionary are silently skipped.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true, ValueFromPipeline = $true)]
        [System.Collections.Specialized.OrderedDictionary]
        $InputObject,

        [Parameter(Mandatory = $true)]
        [string[]]
        $PropertyList
    )

    Process {
        $result = [Ordered]@{}
        foreach ($prop in $PropertyList) {
            if ($InputObject.Contains($prop)) {
                $result[$prop] = $InputObject[$prop]
            }
        }
        $result
    }
}

function Add-ModuleRepositoryInfo {
    <#
        .SYNOPSIS
        Takes a ModuleInfo object and adds some info that came from PowerShellGet

        .DESCRIPTION
        Checks if there's information from Get-InstalledModule about the current module,
        and if so adds to it to ModuleInfo object. The fields are always added, with null
        values if need be.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true, ValueFromPipeline = $true)]
        [System.Object]
        $InputObject ,

        [Parameter()]
        [String]
        $RepositoryName
    )

    Begin {
        # Use the variable defined at the script level
        $wantedProperties = $RepositoryManagedProperties

        # Get all the installed modules at once. This prevents us from having to make an expensive individual call for every
        # local module, the vast majority of which didn't come from PowerShellGet.
        # The results here won't contain every version, but that's ok because we'll still have a fast signal as to whether
        # it makes sense to make a version-specific call for the individual module.
        $installedModules = Get-InstalledModule -ErrorAction SilentlyContinue | Group-Object -Property Name -AsHashTable -AsString
    }

    Process {
        $moduleName = $InputObject.Name

        $installed = if ($installedModules -and $installedModules.Contains($moduleName)) {
            # we know at least one version of this module was installed from PowerShellGet
            # Check whether this local module version matches the initially installed version.
            # use it
            if ($installedModules[$moduleName].Version -eq $InputObject.Version) {
                $installedModules[$moduleName]
            }
            else {
                # make an individual call to see if this specific version of the local module was installed from PowerShellGet
                $im = Get-InstalledModule -Name $InputObject.Name -RequiredVersion $InputObject.Version -AllowPrerelease -ErrorAction SilentlyContinue
                if ($im) {
                    $im
                }
            }
        }

        if ($RepositoryName -and $installed.Repository -ne $RepositoryName) {
            return
        }

        $members = @{}
        $wantedProperties | ForEach-Object -Process {
            if (-not $InputObject.$_) {
                # if the fields are present in both places, let's prefer what's sent in
                $members[$_] = $installed.$_
            }
        }

        $InputObject | Add-Member -NotePropertyMembers $members -Force -PassThru
    }
}

$modules = Get-Module -ListAvailable -Name $p.name

# Optimization: Skip expensive PowerShellGet lookups if include_properties is specified
# and doesn't contain any repository-related properties (converted to snake_case)
$skipRepositoryLookup = $false
if ($p.include_properties) {
    $repositoryPropertiesSnakeCase = $RepositoryManagedProperties | ForEach-Object {
        Convert-StringToSnakeCase -string $_
    }

    # Check if any requested property requires repository info
    $hasRepositoryProperty = $false
    foreach ($prop in $p.include_properties) {
        if ($repositoryPropertiesSnakeCase -contains $prop) {
            $hasRepositoryProperty = $true
            break
        }
    }

    # Only skip if no repository properties were requested
    if (-not $hasRepositoryProperty) {
        $skipRepositoryLookup = $true
    }
}

if (-not $p.skip_module_repository_info -and -not $skipRepositoryLookup) {
    $modules = $modules | Add-ModuleRepositoryInfo -RepositoryName $p.repository
}

$result = @{ changed = $false; modules = @(
    $modules |
        ConvertTo-SerializableModuleInfo |
        Convert-ObjectToSnakeCase -NoRecurse |
        ForEach-Object {
            if ($p.include_properties) {
                Select-ModuleProperty -InputObject $_ -PropertyList $p.include_properties
            }
            else {
                # Default: return all properties
                $_
            }
        }
) }
$result
"""


# pylint: enable=duplicate-code


def _execute(arguments):
    parameters = {
        "name": as_string(arguments.get("name", "*"), "name"),
        "repository": as_string(arguments.get("repository"), "repository"),
        "include_properties": as_string_list(
            arguments.get("include_properties"), "include_properties"
        ),
        "skip_module_repository_info": as_bool(
            arguments.get("skip_module_repository_info", False),
            "skip_module_repository_info",
        ),
    }
    return invoke(_OPERATION, parameters)


def main():
    """Read module options and return the installed vendor's information."""
    run_module(
        lambda: _execute(
            read_arguments(
                (
                    "name",
                    "repository",
                    "include_properties",
                    "skip_module_repository_info",
                ),
                "sustainablelobster.legacy_community_windows.win_psmodule_info",
            )
        )
    )


if __name__ == "__main__":
    main()
