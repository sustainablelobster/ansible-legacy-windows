#!/usr/bin/python
# -*- coding: utf-8 -*-
# SPDX-License-Identifier: GPL-3.0-or-later

"""Execute PowerShell scripts through Python 3.4.4."""

# WANT_JSON

from legacy_windows_module import (  # pylint: disable=import-error
    read_arguments,
    run_module,
)
from legacy_windows_powershell import execute_script  # pylint: disable=import-error

# Ansible interfaces must be self-contained; repeated option/return text is
# interface documentation, not duplicated execution logic.
# pylint: disable=duplicate-code
DOCUMENTATION = r"""
---
module: win_powershell
short_description: Execute a PowerShell script with structured results
version_added: '1.0.0'
description:
  - Runs a PowerShell script.
  - Returns output objects and separate error, warning, verbose, debug and information streams.
  - A Python 3.4.4 payload owns the engine subprocess and its temporary resources.
options:
  script:
    description: Inline PowerShell text; supply exactly one of O(script) and O(path).
    type: str
  path:
    description:
      - UTF-8 script filename; supply exactly one of O(path) and O(script).
      - Controller files are read by the action unless O(remote_src=true).
    type: str
  remote_src:
    description: Read O(path) on the Windows target instead of the controller.
    type: bool
    default: false
  parameters:
    description: Script parameter names and their JSON values.
    type: dict
  sensitive_parameters:
    description:
      - Script parameters converted by the engine to SecureString or PSCredential.
      - Sensitive values are withheld from module invocation; usernames are not secrets.
      - Scripts are responsible for avoiding explicit writes or returns of their secrets.
    type: list
    elements: dict
    suboptions:
      name:
        description: Script parameter name.
        type: str
        required: true
      value:
        description: SecureString text; mutually exclusive with O(sensitive_parameters[].username) and password.
        type: str
      username:
        description: Credential username; requires the password field.
        type: str
      password:
        description: Credential password; requires the username field.
        type: str
  chdir:
    description: Initial PowerShell provider location for the user script.
    type: str
  creates:
    description: Skip execution if the engine finds this path or provider expression.
    type: str
  removes:
    description: Skip execution if the engine does not find this path or provider expression.
    type: str
  depth:
    description: Maximum structured-object depth; deeper complex values become strings.
    type: int
    default: 2
  error_action:
    description: Script error preference; stop treats nonterminating errors as failures.
    type: str
    choices: [silently_continue, continue, stop]
    default: continue
  executable:
    description: Optional PowerShell executable selected by the caller.
    type: str
  arguments:
    description: Executable arguments, not script parameter values.
    type: list
    elements: str
notes:
  - Requires PowerShell 5.1 or newer; it does not install an engine or enable remoting.
  - The script can set C($Ansible.Result), C(Changed), C(Failed), and C(Diff).
  - C($Ansible.CheckMode) and C(Verbosity) describe the current task.
  - C($Ansible.Tmpdir) is an owned scratch directory removed after script execution.
  - Check mode skips scripts without C([CmdletBinding(SupportsShouldProcess)]).
  - Direct host and console writes are returned separately from output objects.
  - Async tasks can use C(poll=0) followed by this collection's explicit Async Status action.
  - Automatic polling requires the collection's explicitly enabled polling adapter.
  - Controller script files are loaded before async launch, retaining the original task arguments.
author:
  - Joe Lustri
"""

EXAMPLES = r"""
- name: Return objects rather than console text
  sustainablelobster.legacy_windows.win_powershell:
    script: |
      $Ansible.Changed = $false
      @{name='example'; count=3}

- name: Load an adjacent controller script
  sustainablelobster.legacy_windows.win_powershell:
    path: files/example.ps1
    parameters:
      Name: example

- name: Make a script check-mode aware
  sustainablelobster.legacy_windows.win_powershell:
    script: |
      [CmdletBinding(SupportsShouldProcess)]
      param()
      $Ansible.Changed = $false
      $Ansible.Result = @{check=$Ansible.CheckMode}
"""

RETURN = r"""
result:
  description: Script-defined C($Ansible.Result), initially an empty dictionary.
  returned: After argument validation.
  type: raw
host_out:
  description: Direct host and console standard-output text, including line endings.
  returned: After argument validation.
  type: str
host_err:
  description: Direct host and console standard-error text, including line endings.
  returned: After argument validation.
  type: str
output:
  description: Serialized output-stream objects in their original order.
  returned: After argument validation.
  type: list
error:
  description: Error records including formatted output, exception, category, target and pipeline details.
  returned: After argument validation.
  type: list
  elements: dict
warning:
  description: Warning stream messages in their original order.
  returned: After argument validation.
  type: list
  elements: str
verbose:
  description: Verbose messages allowed by the script's preference.
  returned: After argument validation.
  type: list
  elements: str
debug:
  description: Debug messages allowed by the script's preference.
  returned: After argument validation.
  type: list
  elements: str
information:
  description: Information records with structured message_data, source, UTC time_generated and tags.
  returned: After argument validation.
  type: list
  elements: dict
"""
# pylint: enable=duplicate-code

_PARAMETERS = (
    "arguments",
    "chdir",
    "creates",
    "depth",
    "error_action",
    "executable",
    "parameters",
    "path",
    "remote_src",
    "removes",
    "script",
    "sensitive_parameters",
)


def _response():
    return execute_script(read_arguments(_PARAMETERS, "ansible.windows.win_powershell"))


def main():
    """Read one structured PowerShell request and emit its Ansible result.

    :raises SystemExit: After writing the complete result.
    """
    run_module(_response)


if __name__ == "__main__":
    main()
