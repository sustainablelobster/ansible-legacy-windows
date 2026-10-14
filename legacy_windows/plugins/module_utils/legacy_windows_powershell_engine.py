# SPDX-License-Identifier: GPL-3.0-or-later
"""Invoke PowerShell scripts through the installed engine."""

import ctypes
import json
import os
import shutil
import subprocess
import tempfile

# The installed engine compiles this small, independently authored host. Its
# standard PSHost API is necessary to preserve raw-host behavior and null RawUI.
_HOST_TYPE = r"""
using System;
using System.Collections.Generic;
using System.Collections.ObjectModel;
using System.Globalization;
using System.IO;
using System.Management.Automation;
using System.Management.Automation.Host;
using System.Security;

namespace LegacyWindows.PowerShell
{
    public sealed class ScriptHost : PSHost
    {
        private readonly PSHost original;
        private readonly ScriptUI ui;
        public ScriptHost(PSHost parent, TextWriter output, TextWriter error)
        {
            original = parent;
            ui = new ScriptUI(output, error);
        }
        public override CultureInfo CurrentCulture { get { return original.CurrentCulture; } }
        public override CultureInfo CurrentUICulture { get { return original.CurrentUICulture; } }
        public override Guid InstanceId { get { return original.InstanceId; } }
        public override string Name { get { return original.Name; } }
        public override Version Version { get { return original.Version; } }
        public override PSHostUserInterface UI { get { return ui; } }
        public override void EnterNestedPrompt() { original.EnterNestedPrompt(); }
        public override void ExitNestedPrompt() { original.ExitNestedPrompt(); }
        public override void NotifyBeginApplication() { original.NotifyBeginApplication(); }
        public override void NotifyEndApplication() { original.NotifyEndApplication(); }
        public override void SetShouldExit(int code) { original.SetShouldExit(code); }
    }

    public sealed class ScriptUI : PSHostUserInterface
    {
        private readonly TextWriter output;
        private readonly TextWriter error;
        public ScriptUI(TextWriter stdout, TextWriter stderr)
        {
            output = stdout;
            error = stderr;
        }
        public override PSHostRawUserInterface RawUI { get { return null; } }
        private static MethodInvocationException CannotRead()
        {
            return new MethodInvocationException(
                "PowerShell is in NonInteractive mode. Read and Prompt functionality is not available.");
        }
        public override string ReadLine() { throw CannotRead(); }
        public override SecureString ReadLineAsSecureString() { throw CannotRead(); }
        public override Dictionary<string, PSObject> Prompt(
            string caption, string message, Collection<FieldDescription> fields)
        { throw CannotRead(); }
        public override int PromptForChoice(string caption, string message,
            Collection<ChoiceDescription> choices, int defaultChoice)
        { throw CannotRead(); }
        public override PSCredential PromptForCredential(
            string caption, string message, string user, string target)
        { throw CannotRead(); }
        public override PSCredential PromptForCredential(string caption,
            string message, string user, string target,
            PSCredentialTypes types, PSCredentialUIOptions options)
        { throw CannotRead(); }
        public override void Write(string text) { output.Write(text); }
        public override void Write(ConsoleColor foreground, ConsoleColor background,
            string text) { output.Write(text); }
        public override void WriteLine(string text) { output.WriteLine(text); }
        public override void WriteErrorLine(string text) { error.WriteLine(text); }
        public override void WriteWarningLine(string text) { output.WriteLine("WARNING: " + text); }
        public override void WriteVerboseLine(string text) { output.WriteLine("VERBOSE: " + text); }
        public override void WriteDebugLine(string text) { output.WriteLine("DEBUG: " + text); }
        public override void WriteProgress(long source, ProgressRecord record) { }
    }
}
"""

_ENGINE_SCRIPT = (
    r"""
$ProgressPreference = 'SilentlyContinue'
$ErrorActionPreference = 'Stop'
$encoding = New-Object Text.UTF8Encoding $false
[Console]::InputEncoding = [Console]::OutputEncoding = $encoding
Add-Type -AssemblyName System.Web.Extensions
$jsonReader = New-Object Web.Script.Serialization.JavaScriptSerializer
$jsonReader.MaxJsonLength = [int]::MaxValue
$jsonReader.RecursionLimit = [int]::MaxValue
$request = $jsonReader.DeserializeObject([Console]::In.ReadToEnd())
Add-Type -TypeDefinition @'
"""
    + _HOST_TYPE
    + r"""
'@

# Keep only this adapter's compiler files in its owned TEMP/TMP. User scripts
# see their original process environment rather than an implicit override.
[Environment]::SetEnvironmentVariable('TEMP',$request.original_temp,'Process')
[Environment]::SetEnvironmentVariable('TMP',$request.original_tmp,'Process')

function Convert-ScriptValue($Value, [int]$Remaining) {
    if ($null -eq $Value) { return $null }
    if ($Value -is [DateTime] -or $Value -is [DateTimeOffset]) {
        return $Value.ToString('o')
    }
    if ($Value -is [Enum] -and $Remaining -ge 0) {
        return @{Type=$Value.GetType().FullName;String=$Value.ToString();Value=[int]$Value}
    }
    if ($Value -is [Type]) {
        if ($Remaining -lt 0) { return $Value.FullName }
        $base = $null
        if ($Value.BaseType) { $base = Convert-ScriptValue $Value.BaseType ($Remaining - 1) }
        return @{Name=$Value.Name;FullName=$Value.FullName;
            AssemblyQualifiedName=$Value.AssemblyQualifiedName;BaseType=$base}
    }
    if ($Value -is [string]) { return $Value.PSObject.BaseObject }
    if ($Value -is [switch]) { return $Value.IsPresent }
    if ($Value.PSObject.Methods['GetType'] -and $Value.GetType().IsValueType) {
        return $Value.PSObject.BaseObject
    }
    if ($Remaining -lt 0) { return [string]$Value }
    if ($Value -is [Collections.IList]) {
        $array = New-Object 'Collections.Generic.List[object]'
        foreach ($item in $Value) {
            $array.Add((Convert-ScriptValue $item ($Remaining - 1)))
        }
        return ,$array.ToArray()
    }
    $mapping = @{}
    foreach ($property in $Value.PSObject.Properties) {
        if ($Value -is [Collections.IDictionary] -and $property.MemberType -notin
            @('AliasProperty','ScriptProperty','NoteProperty')) { continue }
        $mapping[$property.Name] = Convert-ScriptValue $property.Value ($Remaining - 1)
    }
    if ($Value -is [Collections.IDictionary]) {
        foreach ($entry in $Value.GetEnumerator()) {
            $mapping[$entry.Key] = Convert-ScriptValue $entry.Value ($Remaining - 1)
        }
    }
    return $mapping
}

function Convert-ScriptException($Exception) {
    if ($null -eq $Exception) { return $null }
    return @{message=$Exception.Message;type=$Exception.GetType().FullName;
        help_link=$Exception.HelpLink;source=$Exception.Source;hresult=$Exception.HResult;
        inner_exception=(Convert-ScriptException $Exception.InnerException)}
}

function Test-ScriptPath([string]$Path) {
    try { $null = [IO.File]::GetAttributes($Path); return $true }
    catch [IO.FileNotFoundException], [IO.DirectoryNotFoundException] { return $false }
    catch { return Test-Path -Path $Path }
}

$result = @{changed=$false;failed=$false;result=@{};host_out='';host_err='';output=@();
    error=@();warning=@();verbose=@();debug=@();information=@()}
$skip = $false
if ($request.creates -and (Test-ScriptPath $request.creates)) {
    $result.msg = "skipped, since $($request.creates) exists"; $skip = $true
}
elseif ($request.removes -and -not (Test-ScriptPath $request.removes)) {
    $result.msg = "skipped, since $($request.removes) does not exist"; $skip = $true
}

$scriptText = $request.script
if (-not $skip -and -not $scriptText) {
    if (-not (Test-Path -LiteralPath $request.path)) {
        $result.failed = $true
        $result.msg = "Could not find or access '$($request.path)' on Windows host"
        $skip = $true
    }
    else { $scriptText = [IO.File]::ReadAllText($request.path, $encoding) }
}

$shouldProcess = $false
if (-not $skip) {
    $syntaxErrors = @()
    $ast = [Management.Automation.Language.Parser]::ParseInput(
        $scriptText, [ref]$null, [ref]$syntaxErrors)
    if ($syntaxErrors.Count -eq 0) {
        foreach ($attribute in $ast.ParamBlock.Attributes) {
            if ($attribute.TypeName.Name -ne 'CmdletBinding') { continue }
            foreach ($argument in $attribute.NamedArguments) {
                if ($argument.ArgumentName -eq 'SupportsShouldProcess' -and
                    ($argument.ExpressionOmitted -or $argument.Argument.ToString() -eq '$true')) {
                    $shouldProcess = $true
                }
            }
            break
        }
    }
    else {
        $shouldProcess = $scriptText -match '\[CmdletBinding\((?:[\w=\$]+,\s*)?SupportsShouldProcess(?:=\$true)?(?:,\s*[\w=\$]+)?\)\]'
    }
    if ($request.check_mode -and -not $shouldProcess) {
        $result.changed = $true
        $result.msg = 'skipped, running in check mode'
        $skip = $true
    }
}

if (-not $skip) {
    $stdoutWriter = [Console]::Out
    $stderrWriter = [Console]::Error
    $hostAdapter = New-Object LegacyWindows.PowerShell.ScriptHost -ArgumentList $Host,$stdoutWriter,$stderrWriter
    $runspace = [Management.Automation.Runspaces.RunspaceFactory]::CreateRunspace(
        $hostAdapter, [Management.Automation.Runspaces.InitialSessionState]::CreateDefault2())
    $pipeline = [Management.Automation.PowerShell]::Create()
    $reader = [Management.Automation.PowerShell]::Create()
    try {
        $runspace.Open()
        $pipeline.Runspace = $reader.Runspace = $runspace
        $runspace.SessionStateProxy.SetVariable('Ansible', [pscustomobject]@{
            PSTypeName='Ansible.Windows.WinPowerShell.Module'; CheckMode=$request.check_mode
            Verbosity=$request.verbosity;Result=@{};Diff=@{};Changed=$true;Failed=$false;Tmpdir=$request.tmpdir
        })
        $preference = 'SilentlyContinue'
        if ($request.error_action -eq 'continue') { $preference = 'Continue' }
        elseif ($request.error_action -eq 'stop') { $preference = 'Stop' }
        $runspace.SessionStateProxy.SetVariable('ErrorActionPreference', [Management.Automation.ActionPreference]$preference)
        if ($request.chdir) {
            $null = $pipeline.AddCommand('Set-Location').AddParameter('LiteralPath',$request.chdir).AddStatement()
        }
        if ($request.path) {
            # WinPS otherwise decodes BOM-less files as the system ANSI code page.
            # Keep the original script path and its invocation/error metadata.
            if ($PSVersionTable.PSVersion.Major -lt 6) {
                $facade = [Management.Automation.PSObject].Assembly.GetType('System.Management.Automation.ClrFacade')
                $field = $facade.GetField('_defaultEncoding', [Reflection.BindingFlags]'NonPublic,Static')
                $field.SetValue($null,$encoding)
            }
            $null = $pipeline.AddCommand($request.path)
        }
        else { $null = $pipeline.AddScript($scriptText) }
        $parameters = @{}
        if ($request.parameters) {
            foreach ($entry in $request.parameters.GetEnumerator()) {
                $parameters[$entry.Key] = $entry.Value
            }
        }
        foreach ($sensitive in $request.sensitive_parameters) {
            $value = $null
            if ($sensitive.username) {
                $secure = New-Object Security.SecureString
                if ($sensitive.password) { $secure = ConvertTo-SecureString $sensitive.password -AsPlainText -Force }
                $value = New-Object Management.Automation.PSCredential $sensitive.username,$secure
            }
            elseif ($null -ne $sensitive.value) {
                $value = New-Object Security.SecureString
                if ($sensitive.value) { $value = ConvertTo-SecureString $sensitive.value -AsPlainText -Force }
            }
            if ($null -ne $value) { $parameters[$sensitive.name] = $value }
        }
        if ($shouldProcess) { $parameters.Confirm = $false; $parameters.WhatIf = $request.check_mode }
        if ($parameters.Count) { $null = $pipeline.AddParameters($parameters) }
        $items = New-Object 'Collections.Generic.List[object]'
        try { $pipeline.Invoke(@(),$items) }
        catch [Management.Automation.RuntimeException] {
            $result.failed = $true
            $pipeline.Streams.Error.Add($_.Exception.ErrorRecord)
        }
        $ansible = $reader.AddScript('$Ansible').Invoke()[0]
        $result.changed = $ansible.Changed
        $result.failed = $result.failed -or $ansible.Failed
        $result.result = Convert-ScriptValue $ansible.Result $request.depth
        $result.output = Convert-ScriptValue $items $request.depth
        if ($request.diff_mode -and $ansible.Diff -is [Collections.IDictionary] -and $ansible.Diff.Count) {
            $result.diff = @{}
            foreach ($entry in $ansible.Diff.GetEnumerator()) {
                $result.diff[$entry.Key] = Convert-ScriptValue $entry.Value $request.depth
            }
        }
        $result.error = @($pipeline.Streams.Error | ForEach-Object {
            $record = @{output=($_ | Out-String);error_details=$null;
                exception=(Convert-ScriptException $_.Exception);
                target_object=(Convert-ScriptValue $_.TargetObject $request.depth);
                category_info=@{category=[string]$_.CategoryInfo.Category;
                    category_id=[int]$_.CategoryInfo.Category;activity=$_.CategoryInfo.Activity;
                    reason=$_.CategoryInfo.Reason;target_name=$_.CategoryInfo.TargetName;target_type=$_.CategoryInfo.TargetType};
                fully_qualified_error_id=$_.FullyQualifiedErrorId;script_stack_trace=$_.ScriptStackTrace;
                pipeline_iteration_info=$_.PipelineIterationInfo}
            if ($_.ErrorDetails) {
                $record.error_details = @{message=$_.ErrorDetails.Message;recommended_action=$_.ErrorDetails.RecommendedAction}
            }
            $record
        })
        foreach ($streamName in @('Warning','Verbose','Debug')) {
            $result[$streamName.ToLowerInvariant()] = @($pipeline.Streams.$streamName | ForEach-Object { $_.Message })
        }
        $result.information = @($pipeline.Streams.Information | ForEach-Object {
            @{message_data=(Convert-ScriptValue $_.MessageData $request.depth);source=$_.Source;
              time_generated=$_.TimeGenerated.ToUniversalTime().ToString('o');tags=@($_.Tags)}
        })
    }
    finally { $reader.Dispose(); $pipeline.Dispose(); $runspace.Dispose() }
}
[IO.File]::WriteAllText($request.result_path,($result | ConvertTo-Json -Depth 99 -Compress),$encoding)
"""
)


def _engine_path(executable):
    if executable:
        resolved = shutil.which(executable)
        if resolved:
            return resolved
        raise OSError("Could not find PowerShell executable '" + executable + "'")
    root = os.environ.get("SystemRoot", r"C:\Windows")
    for system in ("Sysnative", "System32"):
        path = os.path.join(root, system, "WindowsPowerShell", "v1.0", "powershell.exe")
        if os.path.isfile(path):
            return path
    raise OSError(
        "win_powershell requires an installed PowerShell 5.1 or newer engine; "
        "it is not available on this host"
    )


def _remove_scratch(path):
    # Python 3.4's shutil.rmtree can traverse Windows junctions. Never follow
    # a reparse point created by a script in this module-owned scratch tree.
    kernel = ctypes.WinDLL("kernel32", use_last_error=True)
    attributes = kernel.GetFileAttributesW
    attributes.argtypes = [ctypes.c_wchar_p]
    attributes.restype = ctypes.c_uint32
    value = attributes(path)
    if value == 0xFFFFFFFF:
        error = ctypes.get_last_error()
        if error in (2, 3):
            return
        raise ctypes.WinError(error)
    if value & 0x10:
        if not value & 0x400:
            for name in os.listdir(path):
                _remove_scratch(os.path.join(path, name))
        os.rmdir(path)
    else:
        if value & 1 and not value & 0x400:
            # Like Ansible's temporary-file cleanup, remove ReadOnly from an
            # owned ordinary file. Never follow a script-created reparse point.
            set_attributes = kernel.SetFileAttributesW
            set_attributes.argtypes = [ctypes.c_wchar_p, ctypes.c_uint32]
            set_attributes.restype = ctypes.c_int
            if not set_attributes(path, value & ~1):
                raise ctypes.WinError(ctypes.get_last_error())
        os.remove(path)


def _verify_engine_version(engine, arguments):
    version_command = (
        [engine]
        + arguments
        + [
            "-NoLogo",
            "-NoProfile",
            "-NonInteractive",
            "-Command",
            "$PSVersionTable.PSVersion.ToString()",
        ]
    )
    with subprocess.Popen(
        version_command, stdout=subprocess.PIPE, stderr=subprocess.PIPE
    ) as version_process:
        version_out, version_error = version_process.communicate()
    try:
        version = tuple(
            int(part) for part in version_out.decode("ascii").strip().split(".")[:2]
        )
    except (UnicodeError, ValueError) as error:
        raise ValueError(
            "Could not determine PowerShell engine version: "
            + version_error.decode("utf-8", "replace")
        ) from error
    if version < (5, 1):
        raise ValueError(
            "win_powershell requires PowerShell 5.1 or newer; selected engine is "
            + version_out.decode("ascii").strip()
        )


def _run_script(engine, arguments, request, scratch):
    argument = dict(
        request,
        tmpdir=scratch,
        result_path=os.path.join(scratch, "result.json"),
        original_temp=os.environ.get("TEMP"),
        original_tmp=os.environ.get("TMP"),
    )
    script_path = os.path.join(scratch, "engine.ps1")
    with open(script_path, "w", encoding="utf-8-sig") as script_file:
        script_file.write(_ENGINE_SCRIPT)
    command = [engine] + arguments
    # A file avoids Windows' command-line length limit for the host adapter.
    # ExecutionPolicy is process-scoped, like Ansible's PowerShell launcher.
    command += [
        "-NoLogo",
        "-NoProfile",
        "-NonInteractive",
        "-ExecutionPolicy",
        "Bypass",
        "-File",
        script_path,
    ]
    # Built-in Add-Type intermediates belong to the same owned scratch tree.
    environment = dict(os.environ, TEMP=scratch, TMP=scratch)
    with subprocess.Popen(
        command,
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        env=environment,
    ) as child:
        stdout, stderr = child.communicate(json.dumps(argument).encode("ascii"))
    if not os.path.isfile(argument["result_path"]):
        raise ValueError(
            "PowerShell engine returned no structured script result (exit "
            + str(child.returncode)
            + "): "
            + stderr.decode("utf-8", "replace").strip()
        )
    with open(argument["result_path"], "r", encoding="utf-8-sig") as result_file:
        result = json.load(result_file)
    result["host_out"] = stdout.decode("utf-8", "replace")
    result["host_err"] = stderr.decode("utf-8", "replace")
    return result


def invoke_script(request):
    """Run one script through a PowerShell engine subprocess.

    :param request: Validated options and check-mode/verbosity flags.
    :type request: dict
    :returns: Complete structured result and direct host text.
    :rtype: dict
    :raises OSError: If the requested engine is unavailable or cannot start.
    :raises ValueError: If engine prerequisites or its result protocol fail.
    """
    engine = _engine_path(request.get("executable"))
    arguments = []
    if request.get("executable"):
        arguments = request.get("arguments") or []
    _verify_engine_version(engine, arguments)
    scratch = tempfile.mkdtemp(prefix="legacy-windows-powershell-")
    try:
        return _run_script(engine, arguments, request, scratch)
    finally:
        _remove_scratch(scratch)
