#!/usr/bin/python
# -*- coding: utf-8 -*-
# Copyright 2026 sustainablelobster
# SPDX-License-Identifier: GPL-3.0-or-later

"""Execute commands through an explicitly selected Windows shell."""

# WANT_JSON

import base64
import ntpath
import os
import re
import subprocess
from xml.dom import minidom
from xml.parsers.expat import ExpatError

# The action plugin stages these Python 3.4-compatible helpers beside the payload.
from legacy_windows_module import (  # pylint: disable=import-error
    DOTNET_WHITESPACE,
    as_bool,
    as_path,
    as_string,
    read_arguments,
    run_module,
)
from legacy_windows_process import (  # pylint: disable=import-error
    resolve_executable,
    run_command,
    skip_message,
)

# Ansible requires standalone interface blocks; shared process result fields
# should retain consistent wording instead of changing prose to avoid repetition.
# pylint: disable=duplicate-code
DOCUMENTATION = r"""
---
module: win_shell
short_description: Run a command through a Windows shell
version_added: '1.0.0'
description:
  - Executes command text using the requested shell on a Windows target.
  - Defaults to Windows PowerShell at the standard system directory, independently
    of the Ansible connection's shell. Missing PowerShell does not select CMD instead.
  - The module payload requires Python 3.4.4 or newer. The selected shell must also be installed.
options:
  cmd:
    description:
      - Command text interpreted by the selected shell.
      - May also be supplied as a free-form argument without an option name.
      - Leading and trailing whitespace is removed before execution.
    type: str
    required: true
    aliases: [_raw_params]
  executable:
    description:
      - Shell executable name or path. Use an absolute path to avoid PATH-dependent
        executable selection.
      - Defaults to C(%SystemRoot%\System32\WindowsPowerShell\v1.0\powershell.exe).
      - C(powershell) and C(pwsh) receive an encoded PowerShell command. Other
        executable names must accept C(/c) followed by the command text.
      - A lowercase C(.exe) suffix is appended unless already present.
    type: path
  chdir:
    description:
      - Working directory of the child shell.
    type: path
  creates:
    description:
      - Skip when this literal path exists, before starting the shell.
      - Evaluated before O(removes), relative to the module's working directory.
    type: path
  removes:
    description:
      - Skip when this literal path does not exist, before starting the shell.
    type: path
  stdin:
    description:
      - Text sent to the shell's standard input as UTF-8, without an added newline.
    type: str
  no_profile:
    description:
      - Add the no-profile argument when the selected shell is PowerShell.
      - Has no effect for other shells.
    type: bool
    default: false
  output_encoding_override:
    description:
      - Encoding used to decode standard output and standard error instead of UTF-8.
      - A Unicode byte-order mark takes precedence. C(unicode) means UTF-16LE and
        C(shift_jis) uses Windows code page 932.
      - Encoding names use the target Python's text codecs; Python-specific IDNA,
        Punycode, and Unicode escape transforms are rejected.
      - Available encoding names and replacement behavior can differ from .NET.
    type: str
attributes:
  check_mode:
    support: none
    description: Skips without evaluating filesystem guards or starting a shell.
  diff_mode:
    support: none
notes:
  - Use M(sustainablelobster.legacy_windows.win_command) to invoke a native executable
    without shell interpretation when pipes, redirection, and shell expressions are
    not needed.
  - PowerShell CLIXML error strings are extracted from standard error; other
    serialized streams are discarded.
  - Malformed CLIXML keeps the original standard error and the upstream diagnostic
    marker, but reports Python's XML parser detail rather than .NET exception text.
  - Before a PowerShell command, an additional process of the selected executable
    checks its language mode and system policy without loading profiles. It has no
    user input and a 30-second timeout. Unknown results stop before the command runs.
  - The UTF-8 input-encoding preamble is used only when the selected shell reports
    FullLanguage and policy None. Known Audit or Enforce policy, or ConstrainedLanguage,
    omits the preamble. ConstrainedLanguage is not treated as a reported policy value.
  - This selected-shell check does not reproduce the upstream PowerShell parent
    runtime's trust context. Cross-version and PowerShell Core parent behavior,
    including its PSModulePath adjustment, remains unverified.
  - Each executed command reports a change, including commands with nonzero exit codes.
  - With C(async) and C(poll=0), retrieve results using M(sustainablelobster.legacy_windows.async_status).
  - Automatic polling with C(poll>0) requires the installed collection's
    C(plugins/action/_native_async_polling) directory on the controller action plugin path.
    Set C(action_plugins) in the project's C(ansible.cfg); installation alone does not activate the adapter.
author:
  - sustainablelobster
"""

EXAMPLES = r"""
- name: Read a PowerShell expression
  sustainablelobster.legacy_windows.win_shell:
    cmd: '[Environment]::OSVersion.VersionString'
    no_profile: true

- name: Use CMD explicitly on a host without PowerShell
  sustainablelobster.legacy_windows.win_shell: echo %COMPUTERNAME%
  args:
    executable: C:\Windows\System32\cmd.exe

- name: Write a file once using shell redirection
  sustainablelobster.legacy_windows.win_shell:
    cmd: echo configured>configured.txt
    executable: cmd
    chdir: C:\Build
    creates: C:\Build\configured.txt
"""

RETURN = r"""
cmd:
  description: User-supplied command text after leading and trailing whitespace removal.
  returned: after argument validation
  type: str
rc:
  description: Child exit code, launch error code, or zero for a filesystem skip.
  returned: after argument validation
  type: int
stdout:
  description: Decoded standard output with its original line endings.
  returned: after execution
  type: str
stderr:
  description: Decoded standard error, with PowerShell CLIXML error strings extracted.
  returned: after execution
  type: str
stdout_lines:
  description: Standard output divided into lines by Ansible.
  returned: after execution
  type: list
  elements: str
stderr_lines:
  description: Standard error divided into lines by Ansible.
  returned: after execution
  type: list
  elements: str
start:
  description: UTC time when process execution began.
  returned: after execution
  type: str
end:
  description: UTC time when process execution completed.
  returned: after execution
  type: str
delta:
  description: Elapsed execution time as hours, minutes, and seconds.
  returned: after execution
  type: str
msg:
  description: Explanation for a skipped or failed command.
  returned: skipped or failed
  type: str
"""
# pylint: enable=duplicate-code

_MODULE_NAME = "sustainablelobster.legacy_windows.win_shell"
_PARAMETERS = (
    "cmd",
    "_raw_params",
    "executable",
    "chdir",
    "creates",
    "removes",
    "stdin",
    "no_profile",
    "output_encoding_override",
)
_CLIXML = re.compile(r"(.*)#< CLIXML(.*)(<Objs.+</Objs>)(.*)", re.S | re.I)
_POLICY_SCRIPT = r"""
$ErrorActionPreference = 'Stop'
$ProgressPreference = 'SilentlyContinue'
try {
    $mode = $ExecutionContext.SessionState.LanguageMode
    if ($mode -eq 'ConstrainedLanguage') {
        'LEGACY_WINDOWS_POLICY:ConstrainedLanguage'
    } elseif ($mode -eq 'FullLanguage') {
        $policy = [System.Management.Automation.Security.SystemPolicy]::GetSystemLockdownPolicy()
        if (@('None', 'Audit', 'Enforce') -notcontains $policy) {
            throw 'Unrecognized system lockdown policy'
        }
        'LEGACY_WINDOWS_POLICY:FullLanguage:' + $policy
    } else {
        throw 'Unrecognized PowerShell language mode'
    }
} catch {
    Write-Error -ErrorRecord $_ -ErrorAction Continue
    exit 1
}
"""


def _parameters(arguments):
    if "cmd" not in arguments and "_raw_params" not in arguments:
        raise ValueError("missing required arguments: cmd")
    parameters = {}
    for name in _PARAMETERS:
        if name == "_raw_params":
            continue
        value = arguments.get(name)
        if name == "cmd":
            value = arguments.get("_raw_params", value)
        if name in ("executable", "chdir", "creates", "removes"):
            value = as_path(value, name)
            if value is not None and not value.strip(" "):
                raise ValueError(name + " must not be empty or contain only spaces.")
        elif name == "no_profile":
            value = arguments.get(name, False)
            if value is not None:
                value = as_bool(value, name)
        else:
            value = as_string(value, name)
        parameters[name] = value
    if parameters["cmd"] is None:
        raise ValueError("cmd must not be null.")
    return parameters


def _powershell_input_encoding(executable, working_directory):
    executable = resolve_executable(executable, working_directory)
    encoded = base64.b64encode(_POLICY_SCRIPT.encode("utf-16-le")).decode("ascii")
    command_line = '"{0}" -NoProfile -NonInteractive -EncodedCommand {1}'.format(
        executable, encoded
    )
    process = subprocess.Popen(
        command_line,
        executable=executable,
        cwd=working_directory or None,
        stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )
    try:
        with process:
            try:
                stdout, stderr = process.communicate(timeout=30)
            except BaseException as error:
                # Any interrupted read must stop this owned diagnostic before
                # Popen's context manager waits and closes the pipe handles.
                process.kill()
                process.communicate()
                if isinstance(error, subprocess.TimeoutExpired):
                    raise ValueError(
                        "PowerShell policy probe timed out after 30 seconds; "
                        "the requested command was not started."
                    ) from error
                raise
    finally:
        # Python 3.4's Popen context closes pipes and waits, but its Windows
        # process handle otherwise stays open until the object is finalized.
        # Linux-side analysis cannot see this Windows-only CPython member.
        process._handle.Close()  # pylint: disable=protected-access,no-member

    diagnostic = _format_stderr(stderr.decode("utf-8", "replace"))
    if process.returncode or diagnostic:
        raise ValueError(
            "PowerShell policy probe failed (exit code {0}): {1}".format(
                process.returncode, diagnostic or "no usable policy result"
            )
        )
    if stdout == b"LEGACY_WINDOWS_POLICY:FullLanguage:None\r\n":
        return True
    if stdout in (
        b"LEGACY_WINDOWS_POLICY:FullLanguage:Audit\r\n",
        b"LEGACY_WINDOWS_POLICY:FullLanguage:Enforce\r\n",
        b"LEGACY_WINDOWS_POLICY:ConstrainedLanguage\r\n",
    ):
        return False
    raise ValueError(
        "PowerShell policy probe returned an unrecognized result; "
        "the requested command was not started."
    )


def _command(parameters, command):
    executable = parameters["executable"]
    if not executable:
        executable = ntpath.join(
            os.environ["SystemRoot"],
            "System32",
            "WindowsPowerShell",
            "v1.0",
            "powershell.exe",
        )
    elif not executable.endswith(".exe"):
        executable += ".exe"
    shell = ntpath.splitext(ntpath.basename(executable))[0].lower()
    if shell not in ("powershell", "pwsh"):
        return executable, '"{0}" /c {1}'.format(executable, command)

    script = command
    if _powershell_input_encoding(executable, parameters["chdir"]):
        script = (
            "[Console]::InputEncoding = New-Object Text.UTF8Encoding $false; " + command
        )
    # .NET replaces unpaired UTF-16 surrogates without altering valid pairs.
    utf16 = script.encode("utf-16-le", "surrogatepass")
    utf16 = utf16.decode("utf-16-le", "replace").encode("utf-16-le")
    encoded = base64.b64encode(utf16).decode("ascii")
    arguments = []
    if parameters["no_profile"]:
        arguments.append("-noprofile")
    if not parameters["stdin"]:
        arguments.append("-noninteractive")
    arguments.extend(["-encodedcommand", encoded])
    return executable, '"{0}" {1}'.format(executable, " ".join(arguments))


def _xml_members(element, name):
    values = []
    for attribute in element.attributes.values():
        if attribute.name.lower() == name:
            values.append(attribute.value)
    for child in element.childNodes:
        if child.nodeType == child.ELEMENT_NODE and child.nodeName.lower() == name:
            values.append(
                "".join(
                    node.data
                    for node in child.childNodes
                    if node.nodeType == node.TEXT_NODE
                )
            )
    return values


def _format_stderr(stderr):
    match = _CLIXML.fullmatch(stderr)
    if not match:
        return stderr
    try:
        document = minidom.parseString(match.group(3))
        try:
            errors = []
            for child in document.documentElement.childNodes:
                if child.nodeType != child.ELEMENT_NODE:
                    continue
                names = _xml_members(child, "name") or [child.nodeName]
                streams = _xml_members(child, "s")
                if not any(name.lower() == "s" for name in names) or not any(
                    stream.lower() == "error" for stream in streams
                ):
                    continue
                text = [
                    node.data
                    for node in child.childNodes
                    if node.nodeType == node.TEXT_NODE
                ]
                if not text:
                    raise ValueError(
                        "You cannot call a method on a null-valued expression."
                    )
                errors.extend(
                    value.replace("_x000D__x000A_", "") + "\r\n" for value in text
                )
            merged = match.group(1) + match.group(2) + "".join(errors) + match.group(4)
            return merged.strip(DOTNET_WHITESPACE)
        finally:
            document.unlink()
    except (ExpatError, ValueError) as error:
        return "***EXCEPTION PARSING CLIXML: {0}***{1}".format(error, stderr)


def _execute():
    arguments = read_arguments(_PARAMETERS, _MODULE_NAME)
    if as_bool(arguments.get("_ansible_check_mode", False), "_ansible_check_mode"):
        return {
            "changed": False,
            "skipped": True,
            "msg": "remote module ({0}) does not support check mode".format(
                _MODULE_NAME
            ),
        }
    parameters = _parameters(arguments)
    command = parameters["cmd"].strip(DOTNET_WHITESPACE)
    skip = skip_message(parameters)
    if skip:
        result = {
            "changed": False,
            "skipped": True,
            "cmd": command,
            "rc": 0,
            "msg": skip,
        }
    else:
        try:
            executable, command_line = _command(parameters, command)
        except (OSError, ValueError) as error:
            result = {
                "changed": False,
                "failed": True,
                "rc": getattr(error, "winerror", None) or 2,
                "msg": "Failed to run: '': " + str(error),
            }
            command_line = ""
        else:
            result = run_command(executable, command_line, parameters)
        result["cmd"] = command
        if "stderr" in result:
            result["stderr"] = _format_stderr(result["stderr"])
        elif result.get("failed"):
            prefix = "Failed to run: '{0}': ".format(command_line)
            if result["msg"].startswith(prefix):
                result["msg"] = "Failed to run: '': " + result["msg"][len(prefix) :]
    if as_bool(
        arguments.get("_ansible_inject_invocation", False), "_ansible_inject_invocation"
    ):
        result["invocation"] = {"module_args": parameters}
    return result


def main():
    """Read the argument file and emit one Ansible JSON result.

    :raises SystemExit: After emitting the module result.
    """
    run_module(_execute)


if __name__ == "__main__":
    main()
