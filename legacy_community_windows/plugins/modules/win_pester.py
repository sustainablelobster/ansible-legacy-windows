#!/usr/bin/python
# -*- coding: utf-8 -*-
# Copyright: (c) 2017, Erwan Quelin (@equelin) <erwan.quelin@gmail.com>
# Copyright: (c) 2018, Ansible Project
# Copyright 2026 sustainablelobster
# SPDX-License-Identifier: GPL-3.0-or-later

"""Run installed Pester with a fixed operation supporting its older engines."""

# WANT_JSON

import json
import os
import subprocess
import tempfile

import legacy_community_windows_clixml_dictionary as clixml  # pylint: disable=import-error
from legacy_windows_module import (  # pylint: disable=import-error
    as_bool,
    as_dictionary,
    as_string,
    as_string_list,
    read_arguments,
    run_module,
)

# Released interface and vendor operations remain literal and reviewable.
# pylint: disable=duplicate-code
DOCUMENTATION = r"""
---
module: win_pester
short_description: Run Pester tests on Windows hosts
description:
  - Run Pester tests on Windows hosts.
  - Test files have to be available on the remote host.
requirements:
  - Pester
options:
  path:
    description:
      - Path to a pester test file or a folder where tests can be found.
      - If the path is a folder, the module will consider all ps1 files as Pester tests.
    type: str
    required: true
  tags:
    description:
      - Runs only tests in Describe blocks with specified Tags values.
      - Accepts multiple comma separated tags.
    type: list
    elements: str
  output_file:
    description:
      - Generates an output test report.
    type: str
  output_format:
    description:
      - Format of the test report to be generated.
      - This parameter is to be used with output_file option.
    type: str
    default: NunitXML
  test_parameters:
    description:
      - Allows to specify parameters to the test script.
    type: dict
  version:
    description:
      - Minimum version of the pester module that has to be available on the remote host.
    type: str
    aliases:
    - minimum_version
author:
    - Erwan Quelin (@equelin)
    - Prasoon Karunan V (@prasoonkarunan)
"""

EXAMPLES = r"""
- name: Get facts
  sustainablelobster.legacy_windows.setup:

- name: Add Pester module
  action:
    module_name: >-
      {{ 'sustainablelobster.legacy_community_windows.win_psmodule'
         if ansible_powershell_version >= 5
         else 'chocolatey.chocolatey.win_chocolatey' }}
    name: Pester
    state: present

- name: Run the pester test provided in the path parameter.
  sustainablelobster.legacy_community_windows.win_pester:
    path: C:\Pester

- name: Run the pester tests only for the tags specified.
  sustainablelobster.legacy_community_windows.win_pester:
    path: C:\Pester\TestScript.tests
    tags: CI,UnitTests

# Run pesters tests files that are present in the specified folder
# Require the specified minimum Pester version.
- name: Run tests in a folder and check the Pester module version
  sustainablelobster.legacy_community_windows.win_pester:
    path: C:\Pester\test01.test.ps1
    version: 4.1.0

- name: Run the pester test present in a folder with given script parameters.
  sustainablelobster.legacy_community_windows.win_pester:
    path: C:\Pester\test04.test.ps1
    test_parameters:
      Process: lsass
      Service: bits

- name: Run a test file and generate an NUnitXML report
  sustainablelobster.legacy_community_windows.win_pester:
    path: C:\Pester\test04.test.ps1
    output_file: c:\Pester\result\testresult.xml
"""

RETURN = r"""
pester_version:
    description: Version of the pester module found on the remote host.
    returned: always
    type: str
    sample: 4.3.1
output:
    description: Results of the Pester tests.
    returned: success
    type: list
    sample: false
"""

_OPERATION = r"""
param([string]$Directory)
$ErrorActionPreference = 'Stop'
$ProgressPreference = 'SilentlyContinue'
$p = Import-Clixml -Path ([System.Management.Automation.WildcardPattern]::Escape((Join-Path $Directory 'request.xml')))
$result = @{ changed = $false }
try {
$output_file = $p.output_file
$output_format = $p.output_format
$path = $p.path
$tags = $p.tags
$test_parameters = $p.test_parameters
$version = $p.version

Try {
    $version = [version]$version
}
Catch {
    throw "Value '$version' for parameter 'minimum_version' is not a valid version format"
}

# Make sure path is a real path
Try {
    $path = $path.TrimEnd("\")
    $path = (Get-item -LiteralPath $path).FullName
}
Catch {
    throw "Cannot find file or directory: '$path' as it does not exist"
}

# Import Pester module if available
$Pester = 'Pester'

If (-not (Get-Module -Name $Pester -ErrorAction SilentlyContinue)) {
    If (Get-Module -Name $Pester -ListAvailable -ErrorAction SilentlyContinue) {
        Import-Module $Pester
    }
    else {
        $msg = -join @(
            "Cannot find module: $Pester. Check if pester is installed, and if it is not, "
            "install using win_psmodule or chocolatey.chocolatey.win_chocolatey."
        )
        throw $msg
    }
}

# Add actual pester's module version in the ansible's result variable
$Pester_version = (Get-Module -Name $Pester).Version.ToString()
$result.pester_version = $Pester_version

# Test if the Pester module is available with a version greater or equal than the one specified in the $version parameter
If ((-not (Get-Module -Name $Pester -ErrorAction SilentlyContinue | Where-Object { $_.Version -ge $version })) -and ($version)) {
    throw "$Pester version is not greater or equal to $version"
}

#Prepare Invoke-Pester parameters depending of the Pester's version.
#Invoke-Pester output deactivation behave differently depending on the Pester's version
If ($result.pester_version -ge "4.0.0") {
    $Parameters = @{
        "show" = "none"
        "PassThru" = $True
    }
}
else {
    $Parameters = @{
        "quiet" = $True
        "PassThru" = $True
    }
}

if ($tags.count) {
    $Parameters.Tag = $tags
}

if ($output_file) {
    $Parameters.OutputFile = $output_file
    $Parameters.OutputFormat = $output_format
}

# Run Pester tests
If (Test-Path -LiteralPath $path -PathType Leaf) {
    $test_parameters_check_mode_msg = ''
    if ($test_parameters.keys.count) {
        $Parameters.Script = @{Path = $Path ; Parameters = $test_parameters }
        $test_parameters_check_mode_msg = " with $($test_parameters.keys -join ',') parameters"
    }
    else {
        $Parameters.Script = $Path
    }

    if ($p.check_mode) {
        $result.output = "Run pester test in the file: $path$test_parameters_check_mode_msg"
    }
    else {
        $result.output = Invoke-Pester @Parameters
    }
}
else {
    $Parameters.Script = $path

    if ($p.check_mode) {
        $result.output = "Run Pester test(s): $path"
    }
    else {
        $result.output = Invoke-Pester @Parameters
    }
}

$result.changed = $true


}
catch {
    $result.failed = $true
    $result.msg = [string]$_.Exception.Message
}
if (Get-Command ConvertTo-Json -ErrorAction SilentlyContinue) {
    $json = ConvertTo-Json -InputObject $result -Depth 99 -Compress
    [IO.File]::WriteAllText((Join-Path $Directory 'result.json'), $json, (New-Object Text.UTF8Encoding($false)))
}
else {
    # PowerShell2 lacks ConvertTo-Json. Preserve Pester's duration properties
    # using the values exposed by TimeSpan itself before native CLIXML export.
    if ($result.output -and $result.output -isnot [string]) {
        foreach ($item in @($result.output) + @($result.output.TestResult)) {
            if ($item -and $item.Time -is [TimeSpan]) {
                $duration = @{}
                foreach ($property in $item.Time.PSObject.Properties) {
                    $duration[$property.Name] = $property.Value
                }
                $item.Time = $duration
            }
        }
    }
    $result | Export-Clixml -Path (Join-Path $Directory 'result.xml') -Depth 99 -Encoding UTF8
}
"""
# pylint: enable=duplicate-code

_PARAMETERS = (
    "path",
    "tags",
    "output_file",
    "output_format",
    "test_parameters",
    "version",
    "minimum_version",
)


def _engine():
    # Resolve this vendor's engine locally so missing-engine errors name Pester.
    # pylint: disable=duplicate-code
    root = os.environ.get("SystemRoot", r"C:\Windows")
    for system in ("Sysnative", "System32"):
        candidate = os.path.join(
            root, system, "WindowsPowerShell", "v1.0", "powershell.exe"
        )
        if os.path.isfile(candidate):
            return candidate
    # pylint: enable=duplicate-code
    raise OSError(
        "The installed Windows PowerShell engine required by Pester was not found."
    )


def _invoke(parameters):
    with tempfile.TemporaryDirectory(prefix="legacy-community-pester-") as directory:
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
        json_path, xml_path = (
            os.path.join(directory, name) for name in ("result.json", "result.xml")
        )
        if os.path.isfile(json_path):
            with open(json_path, "r", encoding="utf-8-sig") as result_file:
                result = json.load(result_file)
        elif os.path.isfile(xml_path):
            result = clixml.values(clixml.read(xml_path))
        else:
            raise OSError(
                "Pester did not return an operation result: "
                + stderr.decode("utf-8", "replace").strip()
            )
        if not isinstance(result, dict) or not isinstance(result.get("changed"), bool):
            raise ValueError("Pester returned an invalid operation result.")
        if process.returncode and not result.get("failed"):
            result.update(
                {"failed": True, "msg": "The installed Pester process failed."}
            )
        return result


def _execute(arguments):
    parameters = {
        name: as_string(arguments.get(name), name) for name in ("path", "output_file")
    }
    if not parameters["path"]:
        raise ValueError("path is required.")
    parameters["output_format"] = as_string(
        arguments.get("output_format", "NunitXML"), "output_format"
    )
    parameters["version"] = as_string(
        arguments.get("version", arguments.get("minimum_version")), "version"
    )
    parameters["tags"] = as_string_list(arguments.get("tags"), "tags")
    parameters["test_parameters"] = as_dictionary(
        arguments.get("test_parameters"), "test_parameters"
    )
    parameters["check_mode"] = as_bool(
        arguments.get("_ansible_check_mode", False), "_ansible_check_mode"
    )
    return _invoke(parameters)


def main():
    """Run the installed Pester command with the requested public options."""
    run_module(
        lambda: _execute(
            read_arguments(
                _PARAMETERS, "sustainablelobster.legacy_community_windows.win_pester"
            )
        )
    )


if __name__ == "__main__":
    main()
