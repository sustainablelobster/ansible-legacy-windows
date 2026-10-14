"""Call Windows PowerShell DSC from Python 3.4.4."""

# SPDX-License-Identifier: GPL-3.0-or-later

import base64
import json
import os
import subprocess

# DSC requires Windows PowerShell 5 and its CIM/WSMan engine.
ENGINE_SCRIPT = r"""
$ErrorActionPreference = 'Stop'
$ProgressPreference = 'SilentlyContinue'
[Console]::InputEncoding = New-Object Text.UTF8Encoding($false)
[Console]::OutputEncoding = New-Object Text.UTF8Encoding($false)
$request = [Console]::In.ReadToEnd() | ConvertFrom-Json
$namespace = 'root\Microsoft\Windows\DesiredStateConfiguration'

function Read-Schema([string]$className) {
    $class = Get-CimClass -Namespace $namespace -ClassName $className
    $properties = @()
    foreach ($property in $class.CimClassProperties) {
        if ($property.Flags.ToString().Split(',').Trim() -contains 'ReadOnly') { continue }
        if ($class.CimSuperClassName -eq 'OMI_BaseResource' -and
            $property.Name -in @('ResourceId', 'SourceInfo', 'ModuleName', 'ModuleVersion', 'ConfigurationName')) {
            continue
        }
        $flags = $property.Flags.ToString().Split(',').Trim()
        $entry = [ordered]@{
            name = $property.Name
            type = $property.CimType.ToString()
            required = ('Key' -in $flags -or 'Required' -in $flags)
            reference = $property.ReferenceClassName
            choices = $null
            properties = $null
        }
        if ($null -ne $property.Qualifiers['Values']) {
            $entry.choices = @($property.Qualifiers['Values'].Value)
        }
        if ($property.ReferenceClassName -and
            $property.ReferenceClassName -notin @('MSFT_Credential', 'MSFT_KeyValuePair')) {
            $entry.properties = @(Read-Schema $property.ReferenceClassName)
        }
        $properties += $entry
    }
    return $properties
}

function Convert-Properties($schema, $raw) {
    $output = @{}
    foreach ($entry in $schema) {
        $name = $entry.name
        if ($entry.reference -eq 'MSFT_Credential') {
            $username = $raw.PSObject.Properties[$name + '_username']
            if ($null -eq $username -or $null -eq $username.Value) { continue }
            $password = $raw.PSObject.Properties[$name + '_password'].Value
            $secure = ConvertTo-SecureString -String $password -AsPlainText -Force
            $output[$name] = New-Object Management.Automation.PSCredential($username.Value, $secure)
            continue
        }
        $member = $raw.PSObject.Properties[$name]
        if ($null -eq $member -or $null -eq $member.Value) { continue }
        $value = $member.Value
        if ($entry.reference -eq 'MSFT_KeyValuePair') {
            $value = @($value.PSObject.Properties | ForEach-Object {
                New-CimInstance -ClassName MSFT_KeyValuePair -ClientOnly -Property @{
                    Key = $_.Name; Value = $_.Value.ToString()
                }
            })
        }
        elseif ($entry.reference) {
            $items = @($value)
            $converted = @()
            foreach ($item in $items) {
                try {
                    $properties = Convert-Properties $entry.properties $item
                    $converted += New-CimInstance -ClassName $entry.reference -ClientOnly -Property $properties
                }
                catch {
                    throw "Failed to cast dict value for option '$name' to a CimInstance: $($_.Exception.Message)"
                }
            }
            if ($entry.type.EndsWith('Array')) { $value = $converted }
            else { $value = $converted[0] }
        }
        elseif ($entry.type -notin @('String', 'StringArray', 'Boolean', 'BooleanArray', 'Unknown')) {
            $typeName = $entry.type -replace 'SInt', 'Int' -replace 'Real32', 'Single' -replace 'Real64', 'Double'
            if ($typeName -eq 'Int8') { $typeName = 'SByte' }
            if ($typeName -eq 'UInt8') { $typeName = 'Byte' }
            if ($typeName -eq 'Char16') { $typeName = 'Char' }
            if ($typeName.EndsWith('Array')) {
                $typeName = $typeName.Substring(0, $typeName.Length - 5) + '[]'
            }
            $value = [Management.Automation.LanguagePrimitives]::ConvertTo($value, [type]('System.' + $typeName))
        }
        $output[$name] = $value
    }
    return $output
}

$response = $null
try {
    if ($PSVersionTable.PSVersion.Major -lt 5) {
        throw 'win_dsc requires Windows PowerShell version 5.0 or newer.'
    }
    $portPath = 'WSMan:\localhost\Client\DefaultPorts\HTTP'
    $port = (Get-Item -LiteralPath $portPath).Value
    if (-not (Test-WSMan -Port $port -ErrorAction SilentlyContinue)) {
        $response = @{error = "The win_dsc module requires the WSMan HTTP listener to be configured and online. The port win_dsc is set to use is $port as configured by 'Get-Item -LiteralPath $portPath'."}
    }
    elseif ($request.operation -eq 'discover') {
        if (-not $request.arguments.PSObject.Properties['resource_name']) {
            $response = @{error = 'missing required argument: resource_name'}
        }
        else {
            $name = $request.arguments.resource_name
            $version = 'latest'
            $import = @{Name = $name; ErrorAction = 'SilentlyContinue'}
            if ($request.arguments.PSObject.Properties['module_version']) {
                $version = $request.arguments.module_version
                $import.RequiredVersion = $version
            }
            Import-Module @import
            $culture = [Threading.Thread]::CurrentThread.CurrentUICulture
            try {
                [Threading.Thread]::CurrentThread.CurrentUICulture = [cultureinfo]::InstalledUICulture
                Import-Module PSDesiredStateConfiguration -ErrorAction Continue
            }
            finally { [Threading.Thread]::CurrentThread.CurrentUICulture = $culture }
            $resources = @(Get-DscResource -Name $name -ErrorAction SilentlyContinue | Sort-Object Version)
            $resource = $null
            if ($version -eq 'latest' -and $resources.Count) { $resource = $resources[-1] }
            else { $resource = $resources | Where-Object { $_.Version -eq $version } }
            if (-not $resource) {
                if ($version -eq 'latest') { $response = @{error = "Resource '$name' not found."} }
                else {
                    $installed = $resources.Version -join "', '"
                    $response = @{error = "Resource '$name' with version '$version' not found. Versions installed: '$installed'."}
                }
            }
            elseif ($resource.ImplementedAs -eq 'Composite') {
                $response = @{error = "unsupported resource type: '$name' is a composite resource"}
            }
            else {
                $invocation = @{Name = $resource.Name; ModuleName = 'PSDesiredStateConfiguration'}
                $moduleVersion = $null
                if ($resource.Module) {
                    $moduleVersion = $resource.Module.Version.ToString()
                    $invocation.ModuleName = @{ModuleName = $resource.Module.Name; ModuleVersion = $moduleVersion}
                }
                try { $null = Invoke-DscResource @invocation -Method Get -Property @{Fake = 'Fake'} -ErrorAction Stop }
                catch { }
                $response = @{invocation = $invocation; module_version = $moduleVersion; properties = @(Read-Schema $resource.ResourceType)}
            }
        }
    }
    else {
        $properties = Convert-Properties $request.schema $request.properties
        $arguments = @{Name = $request.invocation.Name; ModuleName = $request.invocation.ModuleName}
        if ($arguments.ModuleName -is [pscustomobject]) {
            $arguments.ModuleName = @{
                ModuleName = $arguments.ModuleName.ModuleName
                ModuleVersion = $arguments.ModuleName.ModuleVersion
            }
        }
        $records = @(& { Invoke-DscResource @arguments -Property $properties -Method $request.method -Verbose -ErrorAction Continue } 2>&1 3>&1 4>&1)
        $output = @($records | Where-Object { $_ -isnot [Management.Automation.ErrorRecord] -and
            $_ -isnot [Management.Automation.WarningRecord] -and $_ -isnot [Management.Automation.VerboseRecord] })
        $errors = @($records | Where-Object { $_ -is [Management.Automation.ErrorRecord] })
        $response = @{
            result = $output
            warnings = @($records | Where-Object { $_ -is [Management.Automation.WarningRecord] } | ForEach-Object Message)
            verbose = @($records | Where-Object { $_ -is [Management.Automation.VerboseRecord] } | ForEach-Object Message)
        }
        if ($errors.Count) {
            $response.error = "Failed to invoke DSC $($request.method) method: $($errors[0].Exception.Message)"
        }
    }
}
catch {
    $response = @{error = $_.Exception.Message}
    if ($request.operation -eq 'discover') {
        $response.error = 'Unhandled exception while executing module: ' + $response.error
    }
}
[Console]::Out.Write(($response | ConvertTo-Json -Depth 100 -Compress))
"""


def engine_request(request):
    """Exchange one JSON request with the installed Windows DSC engine.

    :param dict request: Discovery or resource-operation request.
    :returns: JSON engine response, including its errors and diagnostic streams.
    :rtype: dict
    :raises OSError: The DSC engine is absent or cannot start.
    :raises ValueError: The engine did not produce a JSON object.
    """
    windows = os.environ.get("SystemRoot", r"C:\Windows")
    executable = None
    for directory in ("Sysnative", "System32"):
        candidate = os.path.join(
            windows, directory, "WindowsPowerShell", "v1.0", "powershell.exe"
        )
        if os.path.isfile(candidate):
            executable = candidate
            break
    if executable is None:
        raise OSError(
            "win_dsc requires the installed Windows PowerShell 5.0 or newer "
            "DSC engine; it is not available on this host"
        )
    command = base64.b64encode(ENGINE_SCRIPT.encode("utf-16-le")).decode("ascii")
    with subprocess.Popen(
        [
            executable,
            "-NoLogo",
            "-NoProfile",
            "-NonInteractive",
            "-EncodedCommand",
            command,
        ],
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    ) as process:
        stdout, stderr = process.communicate(
            json.dumps(request, ensure_ascii=True).encode("ascii")
        )
    try:
        response = json.loads(stdout.decode("utf-8-sig"))
    except (UnicodeError, ValueError) as error:
        raise ValueError(
            "Windows PowerShell DSC engine returned no valid JSON response: {0}".format(
                stderr.decode("utf-8", "replace").strip()
            )
        ) from error
    if not isinstance(response, dict):
        raise ValueError("Windows PowerShell DSC engine response must be a JSON object")
    return response
