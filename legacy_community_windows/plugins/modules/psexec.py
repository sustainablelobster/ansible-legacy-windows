#!/usr/bin/python
# -*- coding: utf-8 -*-

"""Run remote processes from the controller using the maintained PsExec client."""

# Copyright: (c) 2018, Jordan Borean <jborean93@gmail.com>
# SPDX-License-Identifier: GPL-3.0-or-later
# Adapted from community.windows 3.3.0.
# Copyright 2026 sustainablelobster

import traceback
from typing import Any

# Ansible and the optional SMB libraries do not distribute typing metadata.
from ansible.module_utils.basic import (  # type: ignore[import-untyped]
    AnsibleModule,
    missing_required_lib,
)
from ansible.module_utils.common.text.converters import (  # type: ignore[import-untyped]
    to_bytes,
    to_text,
)

_pypsexec_import_error: str | None = None
try:
    from pypsexec import client  # type: ignore[import-untyped]
    from pypsexec.exceptions import (  # type: ignore[import-untyped]
        PDUException,
        PypsexecException,
        SCMRException,
    )
    from pypsexec.paexec import ProcessPriority  # type: ignore[import-untyped]
    from smbprotocol.exceptions import (  # type: ignore[import-untyped]
        SMBAuthenticationError,
        SMBException,
        SMBResponseException,
    )

    HAS_PYPSEXEC = True
except ImportError:
    _pypsexec_import_error = traceback.format_exc()
    HAS_PYPSEXEC = False

_kerberos_import_error: str | None = None
try:
    # SMB's Kerberos authentication needs this GSSAPI extension specifically.
    from gssapi.raw import inquire_sec_context_by_oid  # pylint: disable=unused-import

    HAS_KERBEROS = True
except ImportError:
    _kerberos_import_error = traceback.format_exc()
    HAS_KERBEROS = False

DOCUMENTATION = r"""
---
module: psexec
short_description: Runs commands on a remote Windows host based on the PsExec
  model
description:
- Runs a remote command from a Linux host to a Windows host without WinRM being
  set up.
- Can be run on the Ansible controller to bootstrap Windows hosts to get them
  ready for WinRM.
options:
  hostname:
    description:
    - The remote Windows host to connect to, can be either an IP address or a
      hostname.
    type: str
    required: yes
  connection_username:
    description:
    - The username to use when connecting to the remote Windows host.
    - This user must be a member of the C(Administrators) group of the Windows
      host.
    - Required if the Kerberos requirements are not installed or the username
      is a local account to the Windows host.
    - Can be omitted to use the default Kerberos principal ticket in the
      local credential cache if the Kerberos library is installed.
    - If I(process_username) is not specified, then the remote process will run
      under a Network Logon under this account.
    type: str
  connection_password:
    description:
    - The password for I(connection_user).
    - Required if the Kerberos requirements are not installed or the username
      is a local account to the Windows host.
    - Can be omitted to use a Kerberos principal ticket for the principal set
      by I(connection_user) if the Kerberos library is installed and the
      ticket has already been retrieved with the C(kinit) command before.
    type: str
  port:
    description:
    - The port that the remote SMB service is listening on.
    type: int
    default: 445
  encrypt:
    description:
    - Will use SMB encryption to encrypt the SMB messages sent to and from the
      host.
    - This requires the SMB 3 protocol which is only supported from Windows
      Server 2012 or Windows 8, older versions like Windows 7 or Windows Server
      2008 (R2) must set this to C(no) and use no encryption.
    - When setting to C(no), the packets are in plaintext and can be seen by
      anyone sniffing the network, any process options are included in this.
    type: bool
    default: yes
  connection_timeout:
    description:
    - The timeout in seconds to wait when receiving the initial SMB negotiate
      response from the server.
    type: int
    default: 60
  executable:
    description:
    - The executable to run on the Windows host.
    type: str
    required: yes
  arguments:
    description:
    - Any arguments as a single string to use when running the executable.
    type: str
  working_directory:
    description:
    - Changes the working directory set when starting the process.
    type: str
    default: C:\Windows\System32
  asynchronous:
    description:
    - Will run the command as a detached process and the module returns
      immediately after starting the process while the process continues to
      run in the background.
    - The I(stdout) and I(stderr) return values will be null when this is set
      to C(yes).
    - The I(stdin) option does not work with this type of process.
    - The I(rc) return value is not set when this is C(yes)
    type: bool
    default: no
  load_profile:
    description:
    - Runs the remote command with the user's profile loaded.
    type: bool
    default: yes
  process_username:
    description:
    - The user to run the process as.
    - This can be set to run the process under an Interactive logon of the
      specified account which bypasses limitations of a Network logon used when
      this isn't specified.
    - If omitted then the process is run under the same account as
      I(connection_username) with a Network logon.
    - Set to C(System) to run as the builtin SYSTEM account, no password is
      required with this account.
    - If I(encrypt) is C(no), the username and password are sent as a simple
      XOR scrambled byte string that is not encrypted. No special tools are
      required to get the username and password just knowledge of the protocol.
    type: str
  process_password:
    description:
    - The password for I(process_username).
    - Required if I(process_username) is defined and not C(System).
    type: str
  integrity_level:
    description:
    - The integrity level of the process when I(process_username) is defined
      and is not equal to C(System).
    - When C(default), the default integrity level based on the system setup.
    - When C(elevated), the command will be run with Administrative rights.
    - When C(limited), the command will be forced to run with
      non-Administrative rights.
    type: str
    choices:
    - limited
    - default
    - elevated
    default: default
  interactive:
    description:
    - Will run the process as an interactive process that shows a process
      Window of the Windows session specified by I(interactive_session).
    - The I(stdout) and I(stderr) return values will be null when this is set
      to C(yes).
    - The I(stdin) option does not work with this type of process.
    type: bool
    default: no
  interactive_session:
    description:
    - The Windows session ID to use when displaying the interactive process on
      the remote Windows host.
    - This is only valid when I(interactive) is C(yes).
    - The default is C(0) which is the console session of the Windows host.
    type: int
    default: 0
  priority:
    description:
    - Set the command's priority on the Windows host.
    - See U(https://msdn.microsoft.com/en-us/library/windows/desktop/ms683211.aspx)
      for more details.
    type: str
    choices:
    - above_normal
    - below_normal
    - high
    - idle
    - normal
    - realtime
    default: normal
  show_ui_on_logon_screen:
    description:
    - Shows the process UI on the Winlogon secure desktop when
      I(process_username) is C(System).
    type: bool
    default: no
  process_timeout:
    description:
    - The timeout in seconds that is placed upon the running process.
    - A value of C(0) means no timeout.
    type: int
    default: 0
  stdin:
    description:
    - Data to send on the stdin pipe once the process has started.
    - This option has no effect when I(interactive) or I(asynchronous) is
      C(yes).
    type: str
requirements:
- pypsexec
- smbprotocol[kerberos] for optional Kerberos authentication
notes:
- This module requires the Windows host to have SMB configured and enabled,
  and port 445 opened on the firewall.
- This module will wait until the process is finished unless I(asynchronous)
  is C(yes), ensure the process is run as a non-interactive command to avoid
  infinite hangs waiting for input.
- The I(connection_username) must be a member of the local Administrator group
  of the Windows host. For non-domain joined hosts, the
  C(LocalAccountTokenFilterPolicy) should be set to C(1) to ensure this works,
  see U(https://support.microsoft.com/en-us/help/951016/description-of-user-account-control-and-remote-restrictions-in-windows).
- For more information on this module and the various host requirements, see
  U(https://github.com/jborean93/pypsexec).
seealso:
- module: ansible.builtin.raw
- module: sustainablelobster.legacy_windows.win_command
- module: sustainablelobster.legacy_community_windows.win_psexec
- module: sustainablelobster.legacy_windows.win_shell
author:
- Jordan Borean (@jborean93)
"""

EXAMPLES = r"""
- name: Run a cmd.exe command
  sustainablelobster.legacy_community_windows.psexec:
    hostname: server
    connection_username: username
    connection_password: password
    executable: cmd.exe
    arguments: /c echo Hello World

- name: Run a PowerShell command
  sustainablelobster.legacy_community_windows.psexec:
    hostname: server.domain.local
    connection_username: username@DOMAIN.LOCAL
    connection_password: password
    executable: powershell.exe
    arguments: Write-Host Hello World

- name: Send data through stdin
  sustainablelobster.legacy_community_windows.psexec:
    hostname: 192.168.1.2
    connection_username: username
    connection_password: password
    executable: powershell.exe
    arguments: '-'
    stdin: |
      Write-Host Hello World
      Write-Error Error Message
      exit 0

- name: Run the process as a different user
  sustainablelobster.legacy_community_windows.psexec:
    hostname: server
    connection_user: username
    connection_password: password
    executable: whoami.exe
    arguments: /all
    process_username: anotheruser
    process_password: anotherpassword

- name: Run the process asynchronously
  sustainablelobster.legacy_community_windows.psexec:
    hostname: server
    connection_username: username
    connection_password: password
    executable: cmd.exe
    arguments: /c rmdir C:\temp
    asynchronous: true

- name: Use Kerberos authentication with smbprotocol[kerberos]
  sustainablelobster.legacy_community_windows.psexec:
    hostname: host.domain.local
    connection_username: user@DOMAIN.LOCAL
    executable: C:\some\path\to\executable.exe
    arguments: /s

- name: Disable encryption to work with WIndows 7/Server 2008 (R2)
  sustainablelobster.legacy_community_windows.psexec:
    hostname: windows-pc
    connection_username: Administrator
    connection_password: Password01
    encrypt: false
    integrity_level: elevated
    process_username: Administrator
    process_password: Password01
    executable: powershell.exe
    arguments: >-
      (New-Object -ComObject
      Microsoft.Update.Session).CreateUpdateInstaller().IsBusy

- name: Download and run ConfigureRemotingForAnsible.ps1 to setup WinRM
  sustainablelobster.legacy_community_windows.psexec:
    hostname: >-
      {{ hostvars[inventory_hostname]["ansible_host"] |
         default(inventory_hostname) }}
    connection_username: '{{ ansible_user }}'
    connection_password: '{{ ansible_password }}'
    encrypt: true
    executable: powershell.exe
    arguments: '-'
    stdin: |
      $ErrorActionPreference = "Stop"
      $sec_protocols = (
        [Net.ServicePointManager]::SecurityProtocol -bor
        [Net.SecurityProtocolType]::SystemDefault
      )
      $sec_protocols = $sec_protocols -bor [Net.SecurityProtocolType]::Tls12
      [Net.ServicePointManager]::SecurityProtocol = $sec_protocols
      $url = "https://github.com/ansible/ansible-documentation/raw/devel/"
      $url += "examples/scripts/ConfigureRemotingForAnsible.ps1"
      Invoke-Expression ((New-Object Net.WebClient).DownloadString($url))
      exit
  delegate_to: localhost
"""

RETURN = r"""
msg:
  description: Any exception details when trying to run the process
  returned: module failed
  type: str
  sample: 'Received exception from remote PAExec service: Failed to start "invalid.exe". The system cannot find the file specified. [Err=0x2, 2]'
stdout:
  description: The stdout from the remote process
  returned: success and interactive or asynchronous is 'no'
  type: str
  sample: Hello World
stderr:
  description: The stderr from the remote process
  returned: success and interactive or asynchronous is 'no'
  type: str
  sample: Error [10] running process
pid:
  description: The process ID of the asynchronous process that was created
  returned: success and asynchronous is 'yes'
  type: int
  sample: 719
rc:
  description: The return code of the remote process
  returned: success and asynchronous is 'no'
  type: int
  sample: 0
"""


def _module_arguments() -> dict[str, Any]:
    return {
        "hostname": {"type": "str", "required": True},
        "connection_username": {"type": "str"},
        "connection_password": {"type": "str", "no_log": True},
        "port": {"type": "int", "default": 445},
        "encrypt": {"type": "bool", "default": True},
        "connection_timeout": {"type": "int", "default": 60},
        "executable": {"type": "str", "required": True},
        "arguments": {"type": "str"},
        "working_directory": {"type": "str", "default": r"C:\Windows\System32"},
        "asynchronous": {"type": "bool", "default": False},
        "load_profile": {"type": "bool", "default": True},
        "process_username": {"type": "str"},
        "process_password": {"type": "str", "no_log": True},
        "integrity_level": {
            "type": "str",
            "default": "default",
            "choices": ["default", "elevated", "limited"],
        },
        "interactive": {"type": "bool", "default": False},
        "interactive_session": {"type": "int", "default": 0},
        "priority": {
            "type": "str",
            "default": "normal",
            "choices": [
                "above_normal",
                "below_normal",
                "high",
                "idle",
                "normal",
                "realtime",
            ],
        },
        "show_ui_on_logon_screen": {"type": "bool", "default": False},
        "process_timeout": {"type": "int", "default": 0},
        "stdin": {"type": "str"},
    }


def _process_arguments(module: Any) -> dict[str, Any]:
    parameters = module.params
    username = parameters["process_username"]
    system_account = username is not None and username.lower() == "system"
    arguments = {
        name: parameters[name]
        for name in (
            "executable",
            "arguments",
            "asynchronous",
            "load_profile",
            "interactive",
            "interactive_session",
        )
    }
    arguments.update(
        {
            "run_elevated": parameters["integrity_level"] == "elevated",
            "run_limited": parameters["integrity_level"] == "limited",
            "username": None if system_account else username,
            "password": None if system_account else parameters["process_password"],
            "use_system_account": system_account,
            "working_dir": parameters["working_directory"],
            "priority": getattr(
                ProcessPriority, parameters["priority"].upper() + "_PRIORITY_CLASS"
            ),
            "show_ui_on_win_logon": parameters["show_ui_on_logon_screen"],
            "timeout_seconds": parameters["process_timeout"],
            "stdin": (
                to_bytes(parameters["stdin"], encoding="utf-8")
                if parameters["stdin"]
                else None
            ),
        }
    )
    return arguments


def _connect(module: Any, remote: Any) -> None:
    try:
        remote.connect(timeout=module.params["connection_timeout"])
    except SMBAuthenticationError as error:
        module.fail_json(msg=f"Failed to authenticate over SMB: {to_text(error)}")
    except SMBResponseException as error:
        module.fail_json(
            msg=f"Received unexpected SMB response when opening the connection: {to_text(error)}"
        )
    except PDUException as error:
        module.fail_json(
            msg=f"Received an exception with RPC PDU message: {to_text(error)}"
        )
    except SCMRException as error:
        module.fail_json(
            msg="Received an exception when dealing with SCMR on the Windows host: "
            + to_text(error)
        )
    except (SMBException, PypsexecException, OSError) as error:
        module.fail_json(msg=to_text(error))


def _run_process(module: Any, remote: Any, arguments: dict[str, Any]) -> dict[str, Any]:
    try:
        try:
            remote.create_service()
        except (SMBException, PypsexecException) as error:
            module.fail_json(msg=f"Failed to create PAExec service: {to_text(error)}")
        try:
            response = remote.run_executable(**arguments)
        except (SMBException, PypsexecException) as error:
            module.fail_json(
                msg=f"Received error when running remote process: {to_text(error)}"
            )
    finally:
        # Creating a service can fail after its executable has already been copied.
        try:
            remote.remove_service()
        except (SMBException, PypsexecException) as error:
            module.warn(
                f"Failed to cleanup PAExec service and executable: {to_text(error)}"
            )

    result: dict[str, Any] = {"changed": True}
    if module.params["asynchronous"]:
        result["pid"] = response[2]
    elif module.params["interactive"]:
        result["rc"] = response[2]
    else:
        result.update(stdout=response[0], stderr=response[1], rc=response[2])
    return result


def main() -> None:
    """Validate a controller request, execute it over SMB and return its result."""
    module = AnsibleModule(argument_spec=_module_arguments(), supports_check_mode=False)
    # Validate the account pair even when an optional library is unavailable.
    username = module.params["process_username"]
    if (
        username is not None
        and username.lower() != "system"
        and module.params["process_password"] is None
    ):
        module.fail_json(
            msg="parameters are required together when not running as System: "
            "process_username, process_password"
        )
    if not HAS_PYPSEXEC:
        module.fail_json(
            msg=missing_required_lib("pypsexec"), exception=_pypsexec_import_error
        )
    if (
        module.params["connection_username"] is None
        or module.params["connection_password"] is None
    ) and not HAS_KERBEROS:
        module.fail_json(
            msg=missing_required_lib("gssapi"), exception=_kerberos_import_error
        )

    arguments = _process_arguments(module)
    remote = client.Client(
        server=module.params["hostname"],
        username=module.params["connection_username"],
        password=module.params["connection_password"],
        port=module.params["port"],
        encrypt=module.params["encrypt"],
    )
    try:
        _connect(module, remote)
        result = _run_process(module, remote, arguments)
    finally:
        # Closing a failed process request must not leave its SMB session open.
        try:
            remote.disconnect()
        except (SMBException, PypsexecException) as error:
            module.warn(f"Failed to close the SMB connection: {to_text(error)}")
    module.exit_json(**result)


if __name__ == "__main__":
    main()
