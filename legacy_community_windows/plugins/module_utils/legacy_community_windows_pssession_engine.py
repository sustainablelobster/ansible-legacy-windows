# Copyright: (c) 2020, Brian Scholer <@briantist>
# Copyright 2026 sustainablelobster
# SPDX-License-Identifier: GPL-3.0-or-later

"""Apply fixed PSSession configuration operations through the installed engine."""

import ctypes
import json
import os
import subprocess
import tempfile

import legacy_community_windows_clixml_dictionary as clixml  # pylint: disable=import-error

_OPERATION = r"""
param([string]$Directory)
$ErrorActionPreference = 'Stop'
$ProgressPreference = 'SilentlyContinue'
$p = Import-Clixml -Path ([Management.Automation.WildcardPattern]::Escape((Join-Path $Directory 'request.xml')))
$parameters = $p
$result = @{ changed = $false }
$diff = @{ before = @{}; after = @{} }
try {
$pssc_options = @{
    guid = @{ type = 'raw' }
    schema_version = @{ type = 'raw' }
    author = @{ type = 'str' }
    description = @{ type = 'str' }
    company_name = @{ type = 'str' }
    copyright = @{ type = 'str' }
    session_type = @{ type = 'str' ; choices = @('default', 'empty', 'restricted_remote_server') }
    transcript_directory = @{ type = 'path' }
    run_as_virtual_account = @{ type = 'bool' }
    run_as_virtual_account_groups = @{ type = 'list' ; elements = 'str' }
    mount_user_drive = @{ type = 'bool' }
    user_drive_maximum_size = @{ type = 'raw' }
    group_managed_service_account = @{ type = 'str' }
    scripts_to_process = @{ type = 'list' ; elements = 'str' }
    role_definitions = @{ type = 'dict' }
    required_groups = @{ type = 'dict' }
    language_mode = @{ type = 'str' ; choices = @('no_language', 'restricted_language', 'constrained_language', 'full_language') }
    execution_policy = @{ type = 'str' ; choices = @('default', 'remote_signed', 'restricted', 'undefined', 'unrestricted') }
    powershell_version = @{ type = 'raw' }
    modules_to_import = @{ type = 'list' ; elements = 'raw' }
    visible_aliases = @{ type = 'list' ; elements = 'str' }
    visible_cmdlets = @{ type = 'list' ; elements = 'raw' }
    visible_functions = @{ type = 'list' ; elements = 'raw' }
    visible_external_commands = @{ type = 'list' ; elements = 'str' }
    alias_definitions = @{ type = 'dict' }
    function_definitions = @{ type = 'dict' }
    variable_definitions = @{ type = 'list' ; elements = 'dict' }
    environment_variables = @{ type = 'dict' }
    types_to_process = @{ type = 'list' ; elements = 'path' }
    formats_to_process = @{ type = 'list' ; elements = 'path' }
    assemblies_to_load = @{ type = 'list' ; elements = 'str' }
}

$session_configuration_options = @{
    name = @{ type = 'str' ; required = $true }
    processor_architecure = @{ type = 'str' ; choices = @('amd64', 'x86') }
    access_mode = @{ type = 'str' ; choices = @('disabled', 'local', 'remote') }
    use_shared_process = @{ type = 'bool' }
    thread_apartment_state = @{ type = 'str' ; choices = @('mta', 'sta') }
    thread_options = @{ type = 'str' ; choices = @('default', 'reuse_thread', 'use_current_thread', 'use_new_thread') }
    startup_script = @{ type = 'path' }
    maximum_received_data_size_per_command_mb = @{ type = 'raw' }
    maximum_received_object_size_mb = @{ type = 'raw' }
    security_descriptor_sddl = @{ type = 'str' }
    run_as_credential_username = @{ type = 'str' }
    run_as_credential_password = @{ type = 'str' ; no_log = $true }
}


function Import-PowerShellDataFileLegacy {
    <#
        .SYNOPSIS
        A pre-PowerShell 5.0 version of Import-PowerShellDataFile

        .DESCRIPTION
        Safely imports a PowerShell Data file in PowerShell versions before 5.0
        when the built-in command was introduced. Non-literal Path support is not included.
    #>
    [CmdletBinding()]
    [OutputType([hashtable])]
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSAvoidUsingInvokeExpression', '', Justification = 'Required to process PS data file')]
    param(
        [Parameter(Mandatory = $true)]
        [Alias('Path')]
        [String]
        $LiteralPath
    )

    End {
        $astloader = [System.Management.Automation.Language.Parser]::ParseFile($LiteralPath, [ref] $null , [ref] $null)
        $ht = $astloader.Find({ param($ast)
                $ast -is [System.Management.Automation.Language.HashtableAst]
            }, $false)

        if (-not $ht) {
            throw "Invalid PowerShell Data File."
        }

        # SafeGetValue() is not available before PowerShell 5 anyway, so we'll do the unsafe load and just execute it.
        # The only files we're loading are ones we generated from options, or ones that were already attached to existing
        # session configurations.
        # $ht.SafeGetValue()
        Invoke-Expression -Command $ht.Extent.Text
    }
}

if (-not (Get-Command -Name 'Microsoft.PowerShell.Utility\Import-PowerShellDataFile' -ErrorAction SilentlyContinue)) {
    New-Alias -Name 'Import-PowerShellDataFile' -Value 'Import-PowerShellDataFileLegacy'
}

function ConvertFrom-SnakeCase {
    [CmdletBinding()]
    [OutputType([String])]
    param(
        [Parameter(Mandatory = $true, ValueFromPipeline = $true)]
        [String]
        $SnakedString
    )

    Process {
        [regex]::Replace($SnakedString, '^_?.|_.', { param($m) $m.Value.TrimStart('_').ToUpperInvariant() })
    }
}

function ConvertFrom-AnsibleOption {
    [CmdletBinding()]
    [OutputType([System.Collections.IDictionary])]
    param(
        [Parameter(Mandatory = $true)]
        [System.Collections.IDictionary]
        $Params ,

        [Parameter(Mandatory = $true)]
        [hashtable]
        $OptionSet
    )

    End {
        $ret = @{}
        foreach ($option in $OptionSet.GetEnumerator()) {
            $raw_name = $option.Name
            switch -Wildcard ($raw_name) {
                'run_as_credential_*' {
                    $raw_name = $raw_name -replace '_[^_]+$'
                    $name = ConvertFrom-SnakeCase -SnakedString $raw_name
                    if (-not $ret.Contains($name)) {
                        $un = $Params["${raw_name}_username"]
                        if ($un) {
                            $secpw = ConvertTo-SecureString -String $Params["${raw_name}_password"] -AsPlainText -Force
                            $value = New-Object -TypeName PSCredential -ArgumentList $un, $secpw
                            $ret[$name] = $value
                        }
                    }
                    break
                }

                default {
                    $value = $Params[$raw_name]
                    if ($null -ne $value) {
                        if ($option.Value.choices) {
                            # the options that have choices have them listed in snake_case versions of their real values
                            $value = ConvertFrom-SnakeCase -SnakedString $value
                        }
                        $name = ConvertFrom-SnakeCase -SnakedString $raw_name
                        if ($raw_name -eq 'processor_architecure') {
                            $name = 'ProcessorArchitecture'
                        }
                        $ret[$name] = $value
                    }
                }
            }
        }

        $ret
    }
}

function ConvertTo-PsNative {
    <#
    .SYNOPSIS
    Normalize runtime objects to PowerShell-native types.

    .DESCRIPTION
    Semantics:
    - Unwraps PSObject to BaseObject
    - Converts IDictionary -> Hashtable (recursively) with string keys
    - Converts IEnumerable -> array of parsed elements (recursively), preserving strings
    - Converts any other types -> serialized string
    - Preserves int type

    .NOTES
    - This is used for Ansible argument spec entries declared as "type='raw'"
        so that module parameters arriving as CLR or PSObject-wrapped values
        are made PowerShell-native before being passed to PowerShell cmdlets.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        $Value
    )

    End {
        if ($null -eq $Value) { return $null }

        # Unwrap PSObject wrapper if present
        if ($Value -is [System.Management.Automation.PSObject] -and $null -ne $Value.BaseObject) {
            $Value = $Value.BaseObject
        }

        # IDictionary -> Hashtable
        if ($Value -is [System.Collections.IDictionary]) {
            $ht = @{}
            foreach ($k in $Value.Keys) {
                $v = $Value[$k]
                if ($k -is [string]) { $keyName = $k } else { $keyName = $k.ToString() }
                $ht[$keyName] = ConvertTo-PsNative -Value $v
            }
            return $ht
        }
        # IEnumerable -> array of parsed elements
        elseif ($Value -is [System.Collections.IList]) {
            return @(
                foreach ($e in $Value) { ConvertTo-PsNative -Value $e }
            )
        }
        # Int -> preserve int type
        elseif ($Value -is [int]) {
            return $Value
        }
        # Default -> serialize to string
        else {
            return [string]$Value
        }
    }
}

function Write-GeneratedSessionConfiguration {
    [CmdletBinding()]
    [OutputType([System.IO.FileInfo])]
    param(
        [Parameter(Mandatory = $true)]
        [System.Collections.IDictionary]
        $ParameterSet ,

        [Parameter()]
        [String]
        $OutFile
    )

    End {
        $file = if ($OutFile) {
            $OutFile
        }
        else {
            Join-Path $Directory ([Guid]::NewGuid().ToString('N') + '.pssc')
        }

        $file = $file -replace '(?<!\.pssc)$', '.pssc'

        # The vendor validates these raw option lists as native strings and hashtables.

        # Prepare a copy of the parameter set so we can substitute normalized lists
        $p = @{}
        foreach ($k in $ParameterSet.Keys) {
            if (@('ModulesToImport', 'VisibleCmdlets', 'VisibleFunctions') -contains $k) {
                $p[$k] = ConvertTo-PsNative $ParameterSet[$k]
            }
            else {
                $p[$k] = $ParameterSet[$k]
            }
        }

        New-PSSessionConfigurationFile -Path $file @p
        [System.IO.FileInfo]$file
    }
}

function Compare-ConfigFile {
    <#
        .SYNOPSIS
        This function compares the existing config file to the desired

        .DESCRIPTION
        We'll load the contents of both the desired and existing config, remove fields that shouldn't be
        compared, then generate a new config based on the existing and compare those files.

        This could be done as a direct file compare, without loading the contents as objects.
        The primary reasons to do it this slightly more complicated way are:

        - To ignore GUID as a value that matters: if you don't supply it a new one is generated for you,
          but PSSessionConfigurations don't use this for anything; it's just metadata. If you supply one,
          we want to compare it. If you don't, we shouldn't count the "mismatch" against you though.

        - To normalize the existing file based on the following stuff so we avoid unnecessary changes:

        - A file compare either has to be case insensitive (won't catch changes in values) or case sensitive
          (will may force changes on differences that don't matter, like case differences in key values)

        - A file compare will see changes on whitespace and line ending differences; although those could be
          accounted for in other ways, this method handles them.

        - A file compare will see changes on other non-impacting syntax style differences like indentation.
    #>
    [CmdletBinding()]
    [OutputType([bool])]
    param(
        [Parameter(Mandatory = $true, ValueFromPipelineByPropertyName = $true)]
        [System.IO.FileInfo]
        $ConfigFilePath ,

        [Parameter(Mandatory = $true)]
        [System.IO.FileInfo]
        $NewConfigFile ,

        [Parameter(Mandatory = $true)]
        [System.Collections.IDictionary]
        $Params ,

        [Parameter()]
        [String[]]
        $UseExistingIfMissing
    )

    Process {
        $desired_config = $NewConfigFile.FullName

        $existing_content = Import-PowerShellDataFile -LiteralPath $ConfigFilePath.FullName
        $desired_content = Import-PowerShellDataFile -LiteralPath $desired_config

        $diff.before.pscc = $existing_content
        $diff.after.pscc = $desired_content

        $regen = $false
        foreach ($ignorable_param in $UseExistingIfMissing) {
            # here we're checking for the parameters that shouldn't be compared if they are in the existing
            # config, but missing in the desired config. To account for this, we copy the value from the
            # existing into the desired so that when we regenerate it, it'll match the existing if there
            # aren't other changes.
            if (-not $Params.Contains($ignorable_param) -and $existing_content.Contains($ignorable_param)) {
                $desired_content[$ignorable_param] = $existing_content[$ignorable_param]
                $regen = $true
            }
        }

        # re-write and read the desired config file
        if ($regen) {
            $NewConfigFile.Delete()
            $desired_config = Write-GeneratedSessionConfiguration -ParameterSet $desired_content -OutFile $desired_config
        }

        $desired_content = Get-Content -Raw -LiteralPath $desired_config

        # re-write/import the existing one too to get a pristine version
        # this will account for unimporant case differences, comments, whitespace, etc.
        $pristine_config = Write-GeneratedSessionConfiguration -ParameterSet $existing_content
        $existing_content = Get-Content -Raw -LiteralPath $pristine_config

        # with all this de/serializing out of the way we can just do a simple case-sensitive string compare
        $desired_content -ceq $existing_content

        Remove-Item -LiteralPath $pristine_config -Force -ErrorAction SilentlyContinue
    }
}

function Compare-SessionOption {
    <#
        .DESCRIPTION
        This function is used for comparing the session options that don't get set in the config file.
        This _should_ have been straightforward for anything other than RunAsCredential, except that for
        some godforesaken reason a smattering of settings have names that differ from their parameter name.

        This list is defined internally in PowerShell here:
        https://git.io/JfUk7

    #>
    [CmdletBinding()]
    [OutputType([bool])]
    param(
        [Parameter(Mandatory = $true)]
        [System.Collections.IDictionary]
        $DesiredOptions ,

        [Parameter(Mandatory = $true)]
        [Object]
        $ExistingOptions
    )

    End {
        $optnamer = @{
            ProcessorArchitecture = 'Architecture'
            processor_architecure = 'Architecture'
            ThreadApartmentState = 'pssessionthreadapartmentstate'
            ThreadOptions = 'pssessionthreadoptions'
            MaximumReceivedDataSizePerCommandMb = 'PSMaximumReceivedDataSizePerCommandMB'
            MaximumReceivedObjectSizeMb = 'PSMaximumReceivedObjectSizeMB'
        } | Add-Member -MemberType ScriptMethod -Name GetValueOrKey -Value {
            param($key)

            $val = $this[$key]
            if ($null -eq $val) {
                return $key
            }
            else {
                return $val
            }
        } -Force -PassThru

        # Determine diffs in diff mode
        # AccessMode is not a property itself, it's a switch for the Register/Set command which changes some other config properties.
        # Remove it from Diff because it cannot be determined...
        $ignore_options_in_diff = @('AccessMode', 'RunAsCredential')

        $smatch = $true
        $after = @{}
        $before = @{}

        foreach ($opt in $session_configuration_options.GetEnumerator()) {
            if ($ignore_options_in_diff -contains $opt.Name) { continue }
            $key = ConvertFrom-SnakeCase -SnakedString $optnamer.GetValueOrKey($opt.Name)
            $before.Add($key, $ExistingOptions.($key))
        }
        $after = $before.Clone()

        foreach ($opt in $DesiredOptions.GetEnumerator()) {
            if ($ignore_options_in_diff -contains $opt.Name) { continue }
            $key = ConvertFrom-SnakeCase -SnakedString $optnamer.GetValueOrKey($opt.Name)
            $desired_value = $opt.Value
            if ($opt.Name -eq 'ProcessorArchitecture') {
                $desired_value = if ($opt.Value -eq 'amd64') { '64' } else { '32' }
            }
            $after[$key] = $desired_value

            $smatch = $smatch -and (
                $ExistingOptions.($optnamer.GetValueOrKey($opt.Name)) -ceq $desired_value
            )
            if (-not $smatch -and -not $p.diff_mode) {
                break
            }
        }

        $diff.before.session = $before
        $diff.after.session = $after

        if ($DesiredOptions.Contains('RunAsCredential')) {
            # since we can't retrieve/compare password, a change must always be made if a cred is specified
            return $false
        }

        return $smatch
    }
}


$opt_pssc = ConvertFrom-AnsibleOption -Params $parameters -OptionSet $pssc_options
$opt_session = ConvertFrom-AnsibleOption -Params $parameters -OptionSet $session_configuration_options

$existing = Get-PSSessionConfiguration -Name $opt_session.Name -ErrorAction SilentlyContinue

try {
    $diff.before = @{ session = $null; pscc = $null; }
    $diff.after = @{ session = $null; pscc = $null; }

    if ($opt_pssc.Count) {
        # config file options were passed to the module, so generate a config file from those
        $desired_config = Write-GeneratedSessionConfiguration -ParameterSet $opt_pssc
    }
    if ($existing) {
        # the endpoint is registered
        if ($existing.ConfigFilePath -and (Test-Path -LiteralPath $existing.ConfigFilePath)) {
            # the registered endpoint uses a config file
            if ($desired_config) {
                # a desired config file exists, so compare it to the existing one
                $content_match = $existing |
                    Compare-ConfigFile -NewConfigFile $desired_config -Params $opt_pssc -UseExistingIfMissing (
                        $parameters.lenient_config_fields | ConvertFrom-SnakeCase
                    )
            }
            else {
                # existing endpoint has a config file but no config file options were passed, so there is no match
                $content_match = $false
            }
        }
        else {
            # existing endpoint doesn't use a config file, so it's a match if there are also no config options passed
            $content_match = $opt_pssc.Count -eq 0
        }

        $session_match = Compare-SessionOption -DesiredOptions $opt_session -ExistingOptions $existing
    }

    $state = $parameters.state

    $create = $state -eq 'present' -and (-not $existing -or -not $content_match)
    $remove = $existing -and ($state -eq 'absent' -or -not $content_match)
    $session_change = -not $session_match -and $state -ne 'absent'

    $result.changed = $create -or $remove -or $session_change

    if (-not $p.check_mode) {
        if ($remove) {
            # Wait-WinRMConnection
            $null = Unregister-PSSessionConfiguration -Name $opt_session.Name -Force
        }

        if ($create) {
            if ($desired_config) {
                $opt_session.Path = $desired_config
            }
            # Wait-WinRMConnection
            $null = Register-PSSessionConfiguration @opt_session -Force
        }
        elseif ($session_change) {
            $psso = $opt_session
            # Wait-WinRMConnection
            $null = Set-PSSessionConfiguration @psso -Force
        }
    }
}
catch [System.Management.Automation.ParameterBindingException] {
    $e = $_
    if ($e.Exception.ErrorId -eq 'NamedParameterNotFound') {
        $psv = $PSVersionTable.PSVersion.ToString(2)
        $param = $e.Exception.ParameterName
        $cmd = $e.InvocationInfo.MyCommand.Name
        $message = "Parameter '$param' is not available for '$cmd' in PowerShell $psv."
    }
    else {
        $message = "Unknown parameter binding error: $($e.Exception.Message)"
    }

    throw $message
}
finally {
    if ($desired_config) {
        Remove-Item -LiteralPath $desired_config -Force -ErrorAction SilentlyContinue
    }
}


}
catch {
    $message = [string]$_.Exception.Message
    if ($p.run_as_credential_password) {
        $message = $message.Replace($p.run_as_credential_password, '*PASSWORD_REPLACED*')
    }
    $result.failed = $true
    $result.msg = $message
}
if ($p.diff_mode) { $result.diff = $diff }
if (Get-Command ConvertTo-Json -ErrorAction SilentlyContinue) {
    $json = ConvertTo-Json -InputObject $result -Depth 99 -Compress
    [IO.File]::WriteAllText((Join-Path $Directory 'result.json'), $json, (New-Object Text.UTF8Encoding($false)))
}
else {
    $result | Export-Clixml -Path (Join-Path $Directory 'result.xml') -Depth 99 -Encoding UTF8
}
"""


def _validate_credential(username, password):
    if not username:
        return
    domain = None
    if "\\" in username:
        domain, username = username.split("\\", 1)
    security = ctypes.WinDLL("advapi32", use_last_error=True)
    security.LogonUserW.argtypes = [
        ctypes.c_wchar_p,
        ctypes.c_wchar_p,
        ctypes.c_wchar_p,
        ctypes.c_uint32,
        ctypes.c_uint32,
        ctypes.POINTER(ctypes.c_void_p),
    ]
    security.LogonUserW.restype = ctypes.c_int
    kernel = ctypes.WinDLL("kernel32", use_last_error=True)
    kernel.CloseHandle.argtypes = [ctypes.c_void_p]
    kernel.CloseHandle.restype = ctypes.c_int
    token = ctypes.c_void_p()
    if not security.LogonUserW(username, domain, password, 3, 0, ctypes.byref(token)):
        raise OSError(
            "Could not validate RunAs Credential: "
            + str(ctypes.WinError(ctypes.get_last_error()))
        )
    if not kernel.CloseHandle(token):
        raise ctypes.WinError(ctypes.get_last_error())


def _engine():
    root = os.environ.get("SystemRoot", r"C:\Windows")
    for system in ("Sysnative", "System32"):
        path = os.path.join(root, system, "WindowsPowerShell", "v1.0", "powershell.exe")
        if os.path.isfile(path):
            return path
    raise OSError(
        "The installed Windows PowerShell session-configuration engine was not found."
    )


def invoke(parameters):
    """Apply one fixed session operation after checking any supplied RunAs credential.

    :param parameters: Validated public options and internal check/diff booleans.
    :type parameters: dict
    :returns: Plain result including change state, optional diff and vendor failure.
    :rtype: dict
    :raises OSError: Credential validation, engine launch or result capture fails.
    :raises ValueError: The installed engine returns malformed result data.
    :raises BaseException: Interruption propagates after stopping the owned engine.
    """
    _validate_credential(
        parameters.get("run_as_credential_username"),
        parameters.get("run_as_credential_password"),
    )
    # Session registration owns its credential redaction and result failures;
    # sharing the similar Pester launcher would hide those separate contracts.
    # pylint: disable=duplicate-code
    with tempfile.TemporaryDirectory(prefix="legacy-community-pssession-") as directory:
        script_path = os.path.join(directory, "operation.ps1")
        with open(script_path, "w", encoding="utf-8-sig") as script_file:
            script_file.write(_OPERATION)
        clixml.write(
            os.path.join(directory, "request.xml"), clixml.from_values(parameters)
        )
        command = [
            _engine(),
            "-NoLogo",
            "-NoProfile",
            "-NonInteractive",
            "-ExecutionPolicy",
            "Bypass",
            "-File",
            script_path,
            directory,
        ]
        with subprocess.Popen(
            command,
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        ) as process:
            try:
                _stdout, stderr = process.communicate()
            except BaseException:
                process.kill()
                process.communicate()
                raise
        json_path = os.path.join(directory, "result.json")
        xml_path = os.path.join(directory, "result.xml")
        if os.path.isfile(json_path):
            with open(json_path, "r", encoding="utf-8-sig") as result_file:
                result = json.load(result_file)
        elif os.path.isfile(xml_path):
            result = clixml.values(clixml.read(xml_path))
        # pylint: enable=duplicate-code
        else:
            message = stderr.decode("utf-8", "replace").strip()
            password = parameters.get("run_as_credential_password")
            if password:
                message = message.replace(password, "*PASSWORD_REPLACED*")
            raise OSError(
                "PSSession configuration did not return an operation result: " + message
            )
        if not isinstance(result, dict) or not isinstance(result.get("changed"), bool):
            raise ValueError(
                "PSSession configuration returned an invalid operation result."
            )
        if process.returncode and not result.get("failed"):
            result.update(
                {
                    "failed": True,
                    "msg": "The installed session-configuration engine failed.",
                }
            )
        return result
