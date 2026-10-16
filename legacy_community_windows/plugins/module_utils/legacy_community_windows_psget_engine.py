# Copyright: (c) 2020, Brian Scholer <@briantist>
# Copyright: (c) 2025, Ansible Project
# Copyright 2026 sustainablelobster
# SPDX-License-Identifier: GPL-3.0-or-later

"""Invoke fixed PowerShellGet operations with data-only arguments from Python3.4."""

import json
import os
import subprocess
import tempfile

_FORMATTERS = r"""
function Convert-ObjectToSnakeCase {
    <#
        .SYNOPSIS
        Converts an object with CamelCase properties to a dictionary with snake_case keys.
        Works in the spirit of and depends on the existing CamelConversion module util.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true, ValueFromPipeline = $true)]
        [OutputType([System.Collections.Specialized.OrderedDictionary])]
        [Object]
        $InputObject ,

        [Parameter()]
        [Switch]
        $NoRecurse ,

        [Parameter()]
        [Switch]
        $OmitNull
    )

    Process {
        $result = [Ordered]@{}
        foreach ($property in $InputObject.PSObject.Properties) {
            $value = $property.Value
            if (-not $NoRecurse -and $value -is [System.Collections.IDictionary]) {
                $value = Convert-DictToSnakeCase -dict $value
            }
            elseif (-not $NoRecurse -and ($value -is [Array] -or $value -is [System.Collections.ArrayList])) {
                $value = Convert-ListToSnakeCase -list $value
            }
            elseif ($null -eq $value) {
                if ($OmitNull) {
                    continue
                }
            }
            elseif (-not $NoRecurse -and $value -isnot [System.ValueType] -and $value -isnot [string]) {
                $value = Convert-ObjectToSnakeCase -InputObject $value
            }

            $name = Convert-StringToSnakeCase -string $property.Name
            $result[$name] = $value
        }
        $result
    }
}

function Enable-TlsProtocol {
    <#
    .SYNOPSIS
    Gets .NET to use the system configured TLS protocols for outbound connections.

    .DESCRIPTION
    This function ensures that the .NET runtime is configured to use the system
    configured TLS protocols for outbound connections. This is particularly
    important for PowerShell hosts running on older versions of .NET Framework
    where only TLS 1.0 is used.

    This also handles running in a PSRemoting WSMan host where the default is
    hardcoded to use 1.0, 1.1, and 1.2 only even if 1.3 is available.

    .NOTES
    https://github.com/ansible-collections/ansible.windows/pull/573#issuecomment-1865477707
    #>
    [CmdletBinding()]
    param ()

    $currentProtocol = [System.Net.ServicePointManager]::SecurityProtocol
    if ([System.Net.SecurityProtocolType].GetMember("Tls13")) {
        # If the Tls13 member is present we are on .NET Framework 4.8+ so using
        # the SystemDefault setting will use the OS policies. If it's not set
        # to SystemDefault already we are running in a PSRemoting WSMan host
        # and need some reflection to reconfigure the policies to get it to use
        # the OS policies.

        if ($currentProtocol -ne 'SystemDefault') {
            # https://learn.microsoft.com/en-us/dotnet/framework/network-programming/tls#switchsystemnetdontenablesystemdefaulttlsversions
            $disableSystemTlsField = [System.Net.ServicePointManager].GetField(
                's_disableSystemDefaultTlsVersions',
                [System.Reflection.BindingFlags]'NonPublic, Static')
            if ($disableSystemTlsField -and $disableSystemTlsField.GetValue($null)) {
                $disableSystemTlsField.SetValue($null, $false)
            }

            [System.Net.ServicePointManager]::SecurityProtocol = [System.Net.SecurityProtocolType]::SystemDefault
        }
    }
    else {
        # We are on .NET 4.7 or older, as TLS 1.2 is the max version we can
        # use here regardless of the OS, manually enable the protocols known to
        # the runtime.
        if ([System.Net.SecurityProtocolType].GetMember("Tls11")) {
            $currentProtocol = $currentProtocol -bor [System.Net.SecurityProtocolType]::Tls11
        }
        if ([System.Net.SecurityProtocolType].GetMember("Tls12")) {
            $currentProtocol = $currentProtocol -bor [System.Net.SecurityProtocolType]::Tls12
        }
        [System.Net.ServicePointManager]::SecurityProtocol = $currentProtocol
    }

}


function Convert-StringToSnakeCase {
    param([string]$string)
    $value = [regex]::Replace($string, '(.)([A-Z][a-z]+)', '$1_$2')
    ([regex]::Replace($value, '([a-z0-9])([A-Z])', '$1_$2')).ToLowerInvariant()
}
function Convert-DictToSnakeCase {
    param([System.Collections.IDictionary]$dict)
    $result = [ordered]@{}
    foreach ($key in $dict.Keys) {
        $value = $dict[$key]
        if ($value -is [System.Collections.IDictionary]) {
            $value = Convert-DictToSnakeCase -dict $value
        }
        elseif ($value -is [Array] -or $value -is [System.Collections.ArrayList]) {
            $value = Convert-ListToSnakeCase -list $value
        }
        $result[(Convert-StringToSnakeCase -string $key)] = $value
    }
    $result
}
function Convert-ListToSnakeCase {
    param([System.Collections.IList]$list)
    ,@(
        foreach ($value in $list) {
            if ($value -is [System.Collections.IDictionary]) {
                Convert-DictToSnakeCase -dict $value
            }
            elseif ($value -is [Array] -or $value -is [System.Collections.ArrayList]) {
                Convert-ListToSnakeCase -list $value
            }
            else { $value }
        }
    )
}
"""

_PREFIX = (
    _FORMATTERS
    + r"""
$ErrorActionPreference = 'Stop'
$ProgressPreference = 'SilentlyContinue'
$request = $null
try {
    $request = ConvertFrom-Json -InputObject ([Console]::In.ReadToEnd())
    $p = $request.parameters
    function Invoke-VendorOperation {
        [CmdletBinding()]
        param()
"""
)
_SUFFIX = r"""
    }
    $warnings = @()
    $result = Invoke-VendorOperation -WarningVariable warnings
    $response = @{ success = $true; result = $result; warnings = @(
        $warnings | ForEach-Object { [string]$_ }
    ) }
}
catch {
    $response = @{ success = $false; message = [string]$_.Exception.Message }
}
if ($request -and $request.result_path) {
    $json = ConvertTo-Json -InputObject $response -Depth 99 -Compress
    [IO.File]::WriteAllText($request.result_path, $json, (New-Object Text.UTF8Encoding($false)))
}
else {
    Write-Error 'Unable to read the PowerShellGet operation request.' -ErrorAction Continue
    exit 1
}
"""


def _engine():
    root = os.environ.get("SystemRoot", r"C:\Windows")
    for system in ("Sysnative", "System32"):
        executable = os.path.join(
            root, system, "WindowsPowerShell", "v1.0", "powershell.exe"
        )
        if os.path.isfile(executable):
            return executable
    raise OSError(
        "The installed Windows PowerShell/PowerShellGet engine was not found."
    )


def _redact(message, parameters):
    for name in ("password", "source_password"):
        secret = parameters.get(name)
        if secret:
            message = message.replace(secret, "*PASSWORD_REPLACED*")
    return message


def invoke(script, parameters):
    """Run one fixed operation using the installed PowerShellGet-capable engine.

    This boundary is for PowerShellGet workflows, whose engine supports the
    native JSON cmdlets. It is not a general script module or a connection
    transport, and does not impose its prerequisites on other vendor modules.

    :param script: Fixed trusted operation source from the calling payload.
    :type script: str
    :param parameters: Public options passed only as JSON on standard input.
    :type parameters: dict
    :returns: The operation's plain-data result and any vendor warnings.
    :rtype: dict
    :raises OSError: The installed engine or the requested vendor operation fails.
    :raises ValueError: The engine returns malformed operation results.
    :raises BaseException: Interruption propagates after terminating the owned process.
    """
    executable = _engine()
    with tempfile.TemporaryDirectory(prefix="legacy-community-psget-") as directory:
        script_path = os.path.join(directory, "operation.ps1")
        with open(script_path, "w", encoding="utf-8-sig") as script_file:
            script_file.write(_PREFIX + script + _SUFFIX)
        # Like the existing Windows PowerShell helper, use a fixed script file
        # rather than exceeding Windows' command-line limit with encoded source.
        # Keep this vendor's JSON request and cancellation boundary local; the
        # similar Pester/session runners use different native result contracts.
        # pylint: disable=duplicate-code
        command = [
            executable,
            "-NoLogo",
            "-NoProfile",
            "-NonInteractive",
            "-ExecutionPolicy",
            "Bypass",
            "-File",
            script_path,
        ]
        result_path = os.path.join(directory, "result.json")
        request = {"parameters": parameters, "result_path": result_path}
        with subprocess.Popen(
            command,
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        ) as process:
            try:
                _stdout, stderr = process.communicate(
                    json.dumps(request, ensure_ascii=True).encode("ascii")
                )
            except BaseException:
                # An interrupted owned vendor process must not outlive this operation.
                process.kill()
                process.communicate()
                raise
        # pylint: enable=duplicate-code
        if not os.path.isfile(result_path):
            raise OSError(
                _redact(
                    "PowerShellGet did not return an operation result: "
                    + stderr.decode("utf-8", "replace").strip(),
                    parameters,
                )
            )
        with open(result_path, "r", encoding="utf-8-sig") as result_file:
            response = json.load(result_file)
        if not isinstance(response, dict) or not isinstance(
            response.get("success"), bool
        ):
            raise ValueError("PowerShellGet returned an invalid operation response.")
        if not response["success"] or process.returncode:
            raise OSError(
                _redact(
                    response.get("message", "PowerShellGet operation failed."),
                    parameters,
                )
            )
        result = response.get("result")
        if not isinstance(result, dict):
            raise ValueError(
                "PowerShellGet operation did not return a result dictionary."
            )
        if response.get("warnings"):
            result.setdefault("warnings", []).extend(response["warnings"])
        return result
