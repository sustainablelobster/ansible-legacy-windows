"""Require native runas wrapping without leaking credentials into commands."""

# SPDX-License-Identifier: GPL-3.0-or-later
# These private action boundaries are Ansible's controller extension interface.
# pylint: disable=protected-access

import json
import ntpath
from pathlib import Path
from types import SimpleNamespace
from typing import Any
from unittest.mock import Mock

import pytest
from ansible.errors import AnsibleActionFail  # type: ignore[import-untyped]
from ansible.executor.module_common import modify_module  # type: ignore[import-untyped]
from ansible.parsing.dataloader import DataLoader  # type: ignore[import-untyped]
from ansible.plugins.action import normal  # type: ignore[import-untyped]
from ansible.template import Templar  # type: ignore[import-untyped]

from plugins.plugin_utils._module import PythonModuleAction
from plugins.plugin_utils._runas import (
    NativeRunasAction,
    check_runas,
    runas_command,
    stage_runas,
)
from plugins.shell.cmd import ShellModule

_REMOTE = r"C:\Users\Test User\Temp\ansible-tmp-owned"


# The test inherits Ansible's fixed normal-action hierarchy, not project layers.
class _RunasTestAction(NativeRunasAction):  # pylint: disable=too-many-ancestors
    """Supply the native payload action's existing helper-staging interface."""

    EXTRA_MODULE_UTILS: tuple[str, ...] = ()


@pytest.fixture(name="action")
def runas_action() -> Any:
    """Build an action with resolved, canonical core runas options.

    :returns: Action exposing transfer and execution boundaries for inspection.
    """
    instance = object.__new__(_RunasTestAction)
    become = SimpleNamespace(
        name="runas",
        _build_powershell_wrapper_action=Mock(
            return_value=(
                "become_wrapper.ps1",
                {"BecomeUser": "Test User"},
                {"BecomePassword": "test-secret λ"},
            )
        ),
    )
    instance._connection = SimpleNamespace(
        become=become,
        _shell=SimpleNamespace(
            tmpdir=r"C:\Temp\ansible-tmp-test",
            join_path=ntpath.join,
            join=lambda parts: " ".join('"' + part + '"' for part in parts),
            build_module_command=lambda _env, shebang, module: (
                '"' + shebang.removeprefix("#!") + '" "' + module + '"'
            ),
            get_option=lambda _name: r"C:\Python34\python.exe",
            append_command=lambda first, second: first + " && " + second,
        ),
    )
    instance._transfer_file = Mock()
    return instance


@pytest.mark.parametrize("plugin", [None, SimpleNamespace(name="runas")])
def test_supported_become_binding(action: Any, plugin: Any) -> None:
    action._connection.become = plugin
    check_runas(action)


@pytest.mark.parametrize("plugin", [object(), SimpleNamespace(name="sudo")])
def test_other_become_methods_fail_before_transfer(action: Any, plugin: Any) -> None:
    action._connection.become = plugin
    with pytest.raises(AnsibleActionFail, match="only runas"):
        check_runas(action)
    action._transfer_file.assert_not_called()


@pytest.mark.parametrize("existing", [(), ("legacy_windows_account.py",)])
def test_only_missing_runas_helpers_are_staged(
    action: Any, existing: tuple[str, ...]
) -> None:
    action.EXTRA_MODULE_UTILS = existing
    stage_runas(action)
    names = [Path(call.args[0]).name for call in action._transfer_file.call_args_list]
    # Independently assert the full helper closure, not the production constant.
    # pylint: disable=duplicate-code
    assert names == [
        name
        for name in (
            "legacy_windows_account.py",
            "legacy_windows_s4u.py",
            "legacy_windows_system_token.py",
            "legacy_windows_runas_token.py",
            "legacy_windows_runas.py",
        )
        if name not in existing
    ]
    # pylint: enable=duplicate-code
    for call in action._transfer_file.call_args_list:
        assert call.args[1] == ntpath.join(
            action._connection._shell.tmpdir, Path(call.args[0]).name
        )


def test_synchronous_tasks_without_become_stage_no_extra_helpers(action: Any) -> None:
    action._connection.become = None
    stage_runas(action)
    action._transfer_file.assert_not_called()


def test_credentials_and_binary_task_input_travel_only_through_stdin(
    action: Any,
) -> None:
    command = '"C:\\Python34\\python.exe" module.py arguments.json'
    wrapped, data = runas_command(action, command, b"\x00\xff\ninput")
    assert "test-secret" not in wrapped and "Test User" not in wrapped
    assert wrapped.endswith('"C:\\Temp\\ansible-tmp-test\\legacy_windows_runas.py"')
    header, original = data.split(b"\n", 1)
    assert original == b"\x00\xff\ninput"
    assert json.loads(header) == {
        "username": "Test User",
        "password": "test-secret λ",
        "logon_type": "Interactive",
        "logon_flags": "WithProfile",
        "command": command,
    }


@pytest.mark.parametrize(
    "interpreter", [r"C:\Python34\python.exe", r"C:\Program Files\Python34\python.exe"]
)
def test_runas_uses_complete_shell_boundary_without_changing_task_input(
    action: Any, monkeypatch: pytest.MonkeyPatch, interpreter: str
) -> None:
    shell = ShellModule()
    shell.tmpdir = r"C:\Users\Test User\Temp\ansible-tmp-owned"
    monkeypatch.setattr(shell, "get_option", lambda _name: interpreter)
    action._connection._shell = shell
    command = "literal original task command & %PATH% !name!"
    wrapped, data = runas_command(action, command, b"\x00\xff\ninput")
    arguments = shell.join(
        [interpreter, shell.join_path(shell.tmpdir, "legacy_windows_runas.py")]
    )
    expected = "(" + arguments + ")" if arguments.startswith('"') else arguments
    assert wrapped == expected
    header, original = data.split(b"\n", 1)
    assert original == b"\x00\xff\ninput"
    assert json.loads(header)["command"] == command
    assert "test-secret" not in wrapped


def test_core_canonical_flags_and_empty_password_are_not_reinterpreted(
    action: Any,
) -> None:
    action._connection.become._build_powershell_wrapper_action.return_value = (
        "become_wrapper.ps1",
        {
            "BecomeUser": "NT AUTHORITY\\SYSTEM",
            "LogonType": "Service",
            "LogonFlags": "None, WithProfile",
        },
        {},
    )
    _command, data = runas_command(action, "task", None)
    request = json.loads(data)
    assert request["password"] is None
    assert request["logon_type"] == "Service"
    assert request["logon_flags"] == "None, WithProfile"


@pytest.mark.parametrize("user", [None, "", 123])
def test_missing_or_invalid_become_user_is_actionable(action: Any, user: Any) -> None:
    action._connection.become._build_powershell_wrapper_action.return_value = (
        "become_wrapper.ps1",
        {"BecomeUser": user},
        {},
    )
    with pytest.raises(AnsibleActionFail, match="Set become_user"):
        runas_command(action, "task", None)


@pytest.mark.parametrize(
    "become,sudoable", [(False, True), (True, False), (True, True)]
)
def test_command_wrapper_preserves_core_result_processing(
    action: Any,
    monkeypatch: pytest.MonkeyPatch,
    become: bool,
    sudoable: bool,
) -> None:
    if not become:
        action._connection.become = None
    execute = Mock(return_value={"rc": 7, "stdout": "result"})
    monkeypatch.setattr(normal.ActionModule, "_low_level_execute_command", execute)
    process_result = Mock()
    assert action._low_level_execute_command(
        "literal-task",
        sudoable=sudoable,
        in_data=b"binary",
        process_result=process_result,
    ) == {"rc": 7, "stdout": "result"}
    args, kwargs = execute.call_args
    assert kwargs["process_result"] is process_result
    assert kwargs["executable"] is None and kwargs["chdir"] is None
    assert kwargs["encoding_errors"] == "surrogate_then_replace"
    if become and sudoable:
        assert "legacy_windows_runas.py" in args[0]
        header, original = kwargs["in_data"].split(b"\n", 1)
        assert json.loads(header)["command"] == "literal-task"
        assert original == b"binary" and kwargs["sudoable"] is False
    else:
        assert args == ("literal-task",)
        assert kwargs["in_data"] == b"binary" and kwargs["sudoable"] is sudoable


def _core_async_action(
    monkeypatch: pytest.MonkeyPatch,
    interpreter: str,
    environment: dict[str, str],
    become: Any,
) -> Any:
    shell = ShellModule()
    shell.tmpdir = _REMOTE
    options = {
        "python_interpreter": interpreter,
        "remote_tmp": "%TEMP%",
        "async_dir": r"C:\Owned\async",
        "admin_users": ["Administrator"],
    }
    monkeypatch.setattr(shell, "get_option", options.__getitem__)
    task = SimpleNamespace(
        action="sustainablelobster.legacy_windows.win_command",
        args={"argv": [interpreter, "-c", "pass"]},
        async_val=30,
        environment=[environment] if environment else [],
        check_mode=False,
        no_log=False,
        diff=False,
        delegate_to=None,
    )
    connection = SimpleNamespace(
        _shell=shell,
        become=become,
        socket_path=None,
        is_pipelining_enabled=lambda _wrap_async: False,
        transport="ssh",
        allow_executable=False,
        exec_command=Mock(
            return_value=(
                0,
                b'{"ansible_job_id":"j321","started":1,"finished":false}',
                b"",
            )
        ),
    )
    loader = DataLoader()
    instance = PythonModuleAction(
        task,
        connection,
        SimpleNamespace(executable=None, remote_user="ConnectionUser"),
        loader,
        Templar(loader=loader),
    )
    instance._supports_async = True
    instance._cleanup_remote_tmp = True
    monkeypatch.setattr(instance, "_transfer_data", Mock())
    configure_async = instance._configure_module

    def _configure(
        module_name: str, module_args: dict[str, Any], task_vars: dict[str, Any]
    ) -> tuple[Any, str]:
        if module_name == "ansible.legacy.async_wrapper":
            return configure_async(module_name, module_args, task_vars)
        # Resolve the source payload without a process-global collection install.
        # Real core modify_module still supplies its command/serialization contract.
        path = str(
            Path(__file__).resolve().parents[2] / "plugins/modules/win_command.py"
        )
        bits = modify_module(
            module_name=module_name,
            module_path=path,
            module_args=module_args,
            templar=instance._templar,
            task_vars=task_vars,
        )
        return bits, path

    monkeypatch.setattr(instance, "_configure_module", _configure)
    monkeypatch.setattr(
        "ansible.plugins.action.secrets.randbelow", lambda _maximum: 321
    )
    return instance


def _expected_core_async_command(
    shell: ShellModule, interpreter: str, environment: dict[str, str]
) -> str:
    module_path = ntpath.join(_REMOTE, "AnsiballZ_win_command.py")
    arguments = shell.join(
        [
            interpreter,
            ntpath.join(_REMOTE, "legacy_windows_async_wrapper.py"),
            "j321",
            "30",
            "false",
            module_path,
            interpreter,
            module_path,
            ntpath.join(_REMOTE, "args"),
        ]
    )
    prefix = shell.env_prefix(**environment, ANSIBLE_ASYNC_DIR=r"C:\Owned\async")
    assembled = prefix + " " + arguments
    return "(" + assembled + ")" if assembled.startswith('"') else assembled


@pytest.mark.parametrize(
    "interpreter", [r"C:\Python34\python.exe", r"C:\Program Files\Python34\python.exe"]
)
@pytest.mark.parametrize("environment", [{}, {"SENTINEL": "space & 50% ! café"}])
@pytest.mark.parametrize("become", [False, True])
def test_real_core_async_assembly_preserves_complete_command_boundary(
    action: Any,
    monkeypatch: pytest.MonkeyPatch,
    interpreter: str,
    environment: dict[str, str],
    become: bool,
) -> None:
    instance = _core_async_action(
        monkeypatch,
        interpreter,
        environment,
        action._connection.become if become else None,
    )
    shell = instance._connection._shell
    assert instance._execute_module(
        task_vars={"ansible_python_interpreter": interpreter}, wrap_async=True
    ) == {
        "ansible_job_id": "j321",
        "started": 1,
        "finished": False,
        "changed": True,
        "failed": False,
    }
    assert instance._task.environment == ([environment] if environment else [])
    assert shell.tmpdir is None

    expected = _expected_core_async_command(shell, interpreter, environment)
    execute = instance._connection.exec_command
    execute.assert_called_once()
    command = execute.call_args.args[0]
    input_data = execute.call_args.kwargs["in_data"]
    if become:
        header, original_input = input_data.split(b"\n", 1)
        request = json.loads(header)
        assert request["command"] == expected
        assert request["username"] == "Test User"
        assert request["password"] == "test-secret λ"
        assert original_input == b""
        assert "test-secret" not in command
        wrapper = shell.join(
            [interpreter, ntpath.join(_REMOTE, "legacy_windows_runas.py")]
        )
        assert command == ("(" + wrapper + ")" if wrapper.startswith('"') else wrapper)
        assert execute.call_args.kwargs["sudoable"] is False
    else:
        assert command == expected
        assert input_data is None
        assert execute.call_args.kwargs["sudoable"] is True
