"""Exercise controller-file transfer through the real shared helper stager."""

# SPDX-License-Identifier: GPL-3.0-or-later

import ntpath
from pathlib import Path
from types import SimpleNamespace
from typing import Any
from unittest.mock import MagicMock

import pytest

# Ansible's action interfaces do not distribute Python typing metadata.
from ansible.errors import AnsibleActionFail  # type: ignore[import-untyped]
from ansible.plugins.action import normal  # type: ignore[import-untyped]
from ansible_collections.sustainablelobster.legacy_windows.plugins.action.dsc3 import (
    ActionModule,
)


@pytest.fixture(name="action_case")
def action_fixture(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> Any:
    """Supply the shared stager's connection boundary and a normal result.

    :param monkeypatch: Scoped replacement for final normal execution.
    :param tmp_path: Owned controller file directory.
    :returns: Action, task, transfer recorder, cleanup recorder and execution record.
    """
    task = SimpleNamespace(args={"config": {}}, async_val=0, poll=0)
    shell = SimpleNamespace(tmpdir=r"C:\Owned\ansible-task", join_path=ntpath.join)
    action = object.__new__(ActionModule)
    # The harness supplies Ansible's private connection/task boundaries directly.
    action._task = task  # pylint: disable=protected-access
    action._connection = SimpleNamespace(  # pylint: disable=protected-access
        _shell=shell, become=False
    )
    transfer = MagicMock()
    cleanup = MagicMock()
    finder = MagicMock(return_value=str(tmp_path / "config.yml"))
    action._transfer_file = transfer  # pylint: disable=protected-access
    action._remove_tmp_path = cleanup  # pylint: disable=protected-access
    action._find_needle = finder  # pylint: disable=protected-access
    executions = []

    def execute(instance: ActionModule, *_: Any) -> dict[str, Any]:
        """Record arguments entering Ansible's normal execution.

        :param instance: Action with the transferred request arguments.
        :param _: Unused normal-action positional arguments.
        :returns: Normal result containing invocation metadata.
        """
        # Observe the arguments passed into normal execution, not a second stager.
        args = dict(instance._task.args)  # pylint: disable=protected-access
        executions.append(dict(args))
        return {"changed": False, "invocation": {"module_args": args}}

    monkeypatch.setattr(normal.ActionModule, "run", execute)
    return action, task, transfer, cleanup, finder, executions


@pytest.mark.parametrize("remote", [None, False, "false"])
def test_local_file_transfers_after_helpers_and_restores_invocation(
    action_case: Any, remote: Any
) -> None:
    action, task, transfer, cleanup, finder, executions = action_case
    original = {"config_file": "config.yml"}
    if remote is not None:
        original["remote_config_file"] = remote
    task.args = original
    result = action.run(task_vars={})
    assert len(transfer.call_args_list) == 4
    assert [ntpath.basename(call.args[1]) for call in transfer.call_args_list] == [
        "legacy_windows_module.py",
        "legacy_windows_process.py",
        "legacy_windows_text.py",
        "dsc-config-config.yml",
    ]
    finder.assert_called_once_with("files", "config.yml")
    assert executions == [
        {
            "config_file": r"C:\Owned\ansible-task\dsc-config-config.yml",
            "remote_config_file": True,
        }
    ]
    assert result["invocation"]["module_args"] == {
        "config_file": "config.yml",
        "remote_config_file": False,
    }
    assert task.args is original
    cleanup.assert_not_called()


def test_remote_file_is_not_transferred(action_case: Any) -> None:
    action, task, transfer, _, finder, executions = action_case
    task.args = {"config_file": r"C:\Owned\config.yml", "remote_config_file": True}
    result = action.run(task_vars={})
    assert len(transfer.call_args_list) == 3
    finder.assert_not_called()
    assert executions == [task.args]
    assert result["invocation"]["module_args"] == task.args


@pytest.mark.parametrize("wrap_async", [False, True])
def test_explicit_async_staging_preserves_remote_configuration(
    action_case: Any, wrap_async: bool
) -> None:
    action, task, transfer, _, finder, _ = action_case
    original = {"config_file": r"C:\Owned\config.yml", "remote_config_file": True}
    task.args = original
    # Core's forced-async path has no task limit but still needs native helpers.
    action._supports_async = True  # pylint: disable=protected-access
    # Exercise the shared action extension directly, before module execution.
    # pylint: disable-next=protected-access
    action._stage_module_utils(wrap_async=wrap_async)
    names = [ntpath.basename(call.args[1]) for call in transfer.call_args_list]
    assert names == [
        "legacy_windows_module.py",
        "legacy_windows_process.py",
        "legacy_windows_text.py",
    ] + (
        [
            "legacy_windows_wmi.py",
            "legacy_windows_async_native.py",
            "legacy_windows_async_worker.py",
        ]
        if wrap_async
        else []
    )
    assert task.args is original
    finder.assert_not_called()


def test_config_named_as_a_helper_cannot_overwrite_staged_code(
    action_case: Any,
) -> None:
    action, task, transfer, _, finder, _ = action_case
    task.args = {"config_file": "legacy_windows_module.py"}
    finder.return_value = "/owned/controller/legacy_windows_module.py"
    action.run(task_vars={})
    destinations = [call.args[1] for call in transfer.call_args_list]
    assert len(set(destinations)) == 4
    assert destinations[-1].endswith(r"\dsc-config-legacy_windows_module.py")


@pytest.mark.parametrize("position", range(4))
def test_transfer_failure_uses_shared_cleanup_and_restores_arguments(
    action_case: Any, position: int
) -> None:
    action, task, transfer, cleanup, _, executions = action_case
    original = {"config_file": "config.yml"}
    task.args = original
    transfer.side_effect = [None] * position + [OSError("transfer failed")]
    with pytest.raises(OSError, match="transfer failed"):
        action.run(task_vars={})
    cleanup.assert_called_once_with(r"C:\Owned\ansible-task")
    assert task.args is original and executions == []


@pytest.mark.parametrize(
    "args,async_value,message",
    [
        (
            {"config": {"resources": []}, "config_file": "config.yml"},
            0,
            "parameters are mutually exclusive: config, config_file",
        ),
        (
            {"config_file": "config.yml"},
            60,
            "async operations are not supported with local config_file",
        ),
    ],
)
def test_local_validation_precedes_remote_writes(
    action_case: Any, args: dict[str, Any], async_value: int, message: str
) -> None:
    action, task, transfer, cleanup, _, executions = action_case
    task.args, task.async_val = args, async_value
    with pytest.raises(AnsibleActionFail, match=message):
        action.run(task_vars={})
    transfer.assert_not_called()
    cleanup.assert_not_called()
    assert executions == []


@pytest.mark.parametrize(
    "args",
    [
        {"config": {"resources": []}},
        {"config_file": r"C:\Owned\config.yml", "remote_config_file": True},
    ],
)
def test_inline_and_remote_async_use_shared_worker_and_restore_args(
    action_case: Any, args: dict[str, Any]
) -> None:
    action, task, transfer, cleanup, finder, executions = action_case
    task.args, task.async_val = args, 60
    result = action.run(task_vars={})
    assert executions == [args]
    assert task.args is args
    assert result["changed"] is False
    assert [ntpath.basename(call.args[1]) for call in transfer.call_args_list] == [
        "legacy_windows_module.py",
        "legacy_windows_process.py",
        "legacy_windows_text.py",
        "legacy_windows_wmi.py",
        "legacy_windows_async_native.py",
        "legacy_windows_async_worker.py",
    ]
    finder.assert_not_called()
    cleanup.assert_not_called()
    assert action._supports_async is False  # pylint: disable=protected-access


@pytest.mark.parametrize("position", range(6))
def test_async_helper_transfer_failure_restores_original_arguments(
    action_case: Any, position: int
) -> None:
    action, task, transfer, cleanup, _, executions = action_case
    original: dict[str, Any] = {"config": {"resources": []}}
    task.args, task.async_val = original, 60
    transfer.side_effect = [None] * position + [OSError("async transfer failed")]
    with pytest.raises(OSError, match="async transfer failed"):
        action.run(task_vars={})
    cleanup.assert_called_once_with(r"C:\Owned\ansible-task")
    assert task.args is original and executions == []
    assert action._supports_async is False  # pylint: disable=protected-access


@pytest.mark.parametrize("remote", [None, False, "false"])
def test_local_async_rejection_leaves_exact_request_and_no_transfers(
    action_case: Any, remote: Any
) -> None:
    action, task, transfer, cleanup, finder, executions = action_case
    original = {"config_file": "config.yml"}
    if remote is not None:
        original["remote_config_file"] = remote
    task.args, task.async_val = original, 60
    with pytest.raises(
        AnsibleActionFail,
        match="async operations are not supported with local config_file",
    ):
        action.run(task_vars={})
    assert task.args is original
    transfer.assert_not_called()
    finder.assert_not_called()
    cleanup.assert_not_called()
    assert executions == []
