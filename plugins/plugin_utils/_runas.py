"""Execute native Windows payloads through Ansible's existing runas options."""

# SPDX-License-Identifier: GPL-3.0-or-later

import json
from pathlib import Path
from typing import Any

from ansible.errors import AnsibleActionFail  # type: ignore[import-untyped]
from ansible.plugins.action import ActionBase, normal  # type: ignore[import-untyped]

_HELPERS = Path(__file__).resolve().parents[1] / "module_utils"
_RUNAS_HELPERS = (
    "legacy_windows_account.py",
    "legacy_windows_s4u.py",
    "legacy_windows_system_token.py",
    "legacy_windows_runas_token.py",
    "legacy_windows_runas.py",
)


def check_runas(action: Any) -> None:
    """Validate the resolved become method before any target files are staged.

    :param action: Ansible action with its resolved connection and become plugin.
    :raises AnsibleActionFail: If a become method other than runas is selected.
    """
    plugin = action._connection.become  # pylint: disable=protected-access
    if plugin and getattr(plugin, "name", None) != "runas":
        raise AnsibleActionFail(
            "Legacy Windows Python privilege escalation supports only runas"
        )


def stage_runas(action: Any) -> None:
    """Stage the runas closure only for tasks requesting privilege escalation.

    :param action: Ansible action with an existing task directory.
    """
    if not action._connection.become:  # pylint: disable=protected-access
        return
    shell = action._connection._shell  # pylint: disable=protected-access
    for name in _RUNAS_HELPERS:
        if name in action.EXTRA_MODULE_UTILS:
            continue
        action._transfer_file(  # pylint: disable=protected-access
            str(_HELPERS / name), shell.join_path(shell.tmpdir, name)
        )


def runas_command(
    action: Any, command: str, input_data: bytes | None
) -> tuple[str, bytes]:
    """Wrap one command without putting its become password in the command line.

    :param action: Ansible action with staged helpers and resolved runas options.
    :param command: Original task command, including literal environment prefix.
    :param input_data: Original stdin, or None.
    :returns: Wrapper command and stdin containing credentials and task input.
    :raises AnsibleActionFail: If runas options cannot be obtained.
    """
    plugin = action._connection.become  # pylint: disable=protected-access
    # Core 2.21 owns option binding and the released runas flag validation.
    # Core exposes the canonical flags through this private wrapper contract.
    # pylint: disable-next=protected-access
    _, parameters, secure = plugin._build_powershell_wrapper_action()
    user = parameters.get("BecomeUser")
    if not isinstance(user, str) or not user:
        raise AnsibleActionFail("Set become_user to the requested Windows account")
    request = {
        "username": user,
        "password": secure.get("BecomePassword"),
        "logon_type": parameters.get("LogonType", "Interactive"),
        "logon_flags": parameters.get("LogonFlags", "WithProfile"),
        "command": command,
    }
    shell = action._connection._shell  # pylint: disable=protected-access
    wrapper = shell.build_module_command(
        "",
        "#!" + shell.get_option("python_interpreter"),
        shell.join_path(shell.tmpdir, "legacy_windows_runas.py"),
    )
    return wrapper, json.dumps(request).encode("utf-8") + b"\n" + (input_data or b"")


# Concrete core actions retain their own run and result-processing lifecycle.
class NativeRunasExecution(ActionBase):  # type: ignore[misc]
    """Prepare native commands and wrap become without replacing core's lifecycle."""

    # This signature is Ansible's existing low-level command extension interface.
    # pylint: disable=too-many-arguments,too-many-positional-arguments
    def _low_level_execute_command(
        self,
        cmd: str,
        sudoable: bool = True,
        in_data: bytes | None = None,
        executable: str | None = None,
        encoding_errors: str = "surrogate_then_replace",
        chdir: str | None = None,
        process_result: Any = None,
    ) -> Any:
        # Core assembles async argv directly, bypassing build_module_command.
        # Prepare the complete command before Runas serializes it into stdin.
        shell = self._connection._shell  # pylint: disable=protected-access
        prepare_command = getattr(shell, "prepare_command", None)
        if prepare_command is not None:
            cmd = prepare_command(cmd)
        if sudoable and self._connection.become:
            if chdir:
                # Use core's shell command contract before wrapping its cwd change.
                # pylint: disable-next=protected-access
                cmd = self._connection._shell.append_command(f"cd {chdir}", cmd)
                chdir = None
            cmd, in_data = runas_command(self, cmd, in_data)
            sudoable = False
        return super()._low_level_execute_command(
            cmd,
            sudoable=sudoable,
            in_data=in_data,
            executable=executable,
            encoding_errors=encoding_errors,
            chdir=chdir,
            process_result=process_result,
        )


# Normal module execution and Async Status use different core run methods.
# Keep Ansible's fixed normal-action hierarchy instead of copying its lifecycle.
# pylint: disable-next=too-many-ancestors
class NativeRunasAction(NativeRunasExecution, normal.ActionModule):  # type: ignore[misc]
    """Keep the normal module lifecycle with native Windows command escalation."""
