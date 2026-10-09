"""Exercise Ansible's real async-status action and native payload staging."""

# SPDX-License-Identifier: GPL-3.0-or-later

import ntpath
from pathlib import Path
from types import SimpleNamespace
from typing import Any

import pytest

# Ansible's controller extension interfaces lack distributed typing metadata.
from ansible import constants as C  # type: ignore[import-untyped]
from ansible.errors import AnsibleActionFail  # type: ignore[import-untyped]
from ansible.parsing.dataloader import DataLoader  # type: ignore[import-untyped]
from ansible.plugins.action import ActionBase  # type: ignore[import-untyped]
from ansible.template import Templar  # type: ignore[import-untyped]

from plugins.action.async_status import ActionModule  # pylint: disable=import-error
from plugins.plugin_utils._runas import NativeRunasExecution

_REMOTE = r"C:\Temp\ansible-tmp-status-test"
_CACHE = r"C:\Users\Test User\.ansible_async"


def _action(
    monkeypatch: pytest.MonkeyPatch,
    args: dict[str, Any],
    **options: Any,
) -> tuple[ActionModule, SimpleNamespace]:
    monkeypatch.setattr(C, "DEFAULT_KEEP_REMOTE_FILES", False)
    state = SimpleNamespace(transfers=[], calls=[], cleanup=[], response={})
    state.shell = SimpleNamespace(
        tmpdir=None, join_path=ntpath.join, remove=lambda path, recurse: (path, recurse)
    )
    task = SimpleNamespace(
        action="sustainablelobster.legacy_windows.async_status",
        args=args,
        async_val=0,
        check_mode=False,
    )
    for name, value in options.items():
        setattr(task, name, value)
    loader = DataLoader()
    action = ActionModule(
        task,
        SimpleNamespace(_shell=state.shell, become=None),
        None,
        loader,
        Templar(loader=loader),
    )

    def _make_tmp() -> str:
        state.shell.tmpdir = _REMOTE
        action._cleanup_remote_tmp = True  # pylint: disable=protected-access
        return _REMOTE

    def _transfer(source: str, destination: str) -> str:
        state.transfers.append((source, destination))
        return destination

    def _execute(_self: object, **kwargs: Any) -> dict[str, Any]:
        state.calls.append(kwargs)
        return dict(state.response)

    def _cleanup(command: object, **_kwargs: object) -> dict[str, int]:
        state.cleanup.append(command)
        return {"rc": 0}

    monkeypatch.setattr(action, "_make_tmp_path", _make_tmp)
    monkeypatch.setattr(action, "_transfer_file", _transfer)
    monkeypatch.setattr(action, "_get_async_dir", lambda: _CACHE)
    monkeypatch.setattr(action, "_low_level_execute_command", _cleanup)
    monkeypatch.setattr(ActionBase, "_execute_module", _execute)
    return action, state


@pytest.mark.parametrize("check", [False, True])
def test_standard_defaults_and_boolean_results_are_preserved(
    monkeypatch: pytest.MonkeyPatch, check: bool
) -> None:
    action, state = _action(monkeypatch, {"jid": "123.456"}, check_mode=check)
    state.response = {"started": 1, "finished": 0, "changed": False}
    variables: dict[str, object] = {"example": "preserved"}

    assert action.run(task_vars=variables) == {
        "started": True,
        "finished": False,
        "changed": False,
        "ansible_job_id": "123.456",
        "results_file": ntpath.join(_CACHE, "123.456"),
        "stdout": "",
        "stderr": "",
        "stdout_lines": [],
        "stderr_lines": [],
    }
    assert state.calls == [
        {
            "module_name": "sustainablelobster.legacy_windows.async_status",
            "module_args": {"jid": "123.456", "mode": "status", "_async_dir": _CACHE},
            "task_vars": variables,
        }
    ]
    assert len(state.transfers) == 1
    source, destination = state.transfers[0]
    assert Path(source).name == "legacy_windows_module.py"
    assert destination == ntpath.join(_REMOTE, "legacy_windows_module.py")
    assert state.cleanup == [(_REMOTE, True)]
    assert state.shell.tmpdir is None


def test_cleanup_uses_standard_erased_result_without_status_filename(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    action, state = _action(monkeypatch, {"jid": "123", "mode": "cleanup"})
    state.response = {"ansible_job_id": "123", "erased": ntpath.join(_CACHE, "123")}

    result = action.run()

    assert result["erased"] == ntpath.join(_CACHE, "123")
    assert result["started"] is result["finished"] is False
    assert "results_file" not in result
    assert state.cleanup == [(_REMOTE, True)]


@pytest.mark.parametrize("mode", ["status", "cleanup"])
def test_controller_job_directory_preserves_exact_cache_without_public_arguments(
    monkeypatch: pytest.MonkeyPatch, mode: str
) -> None:
    action, state = _action(monkeypatch, {"jid": "j123.456", "mode": mode})
    # Use the real native directory override, while observing only core's
    # ordinary configured-directory lookup for the subsequent direct task.
    monkeypatch.delattr(action, "_get_async_dir")
    monkeypatch.setattr(action, "get_shell_option", lambda *_args, **_kwargs: _CACHE)
    monkeypatch.setattr(action, "_remote_expand_user", lambda path: path)
    directory = "C:/owned fact cache/native-cache"
    arguments = dict(action._task.args)  # pylint: disable=protected-access
    result = action.run(task_vars={}, async_dir=directory)
    assert result["erased" if mode == "cleanup" else "results_file"] == ntpath.join(
        directory, "j123.456"
    )
    assert state.calls[0]["module_args"] == {
        "jid": "j123.456",
        "mode": mode,
        "_async_dir": directory,
    }
    assert action._task.args == arguments  # pylint: disable=protected-access
    assert action._native_job_async_dir is None  # pylint: disable=protected-access
    result = action.run(task_vars={})
    assert result["erased" if mode == "cleanup" else "results_file"] == ntpath.join(
        _CACHE, "j123.456"
    )
    assert state.calls[1]["module_args"]["_async_dir"] == _CACHE


@pytest.mark.parametrize(
    "arguments",
    [
        {},
        {"jid": "123", "mode": "invalid"},
        {"jid": "123", "other": True},
        {"jid": "123", "_async_dir": "C:/private/cache"},
    ],
)
def test_invalid_arguments_do_not_allocate_or_transfer(
    monkeypatch: pytest.MonkeyPatch, arguments: dict[str, Any]
) -> None:
    action, state = _action(monkeypatch, arguments)
    action._load_name = "async_status"  # pylint: disable=protected-access

    with pytest.raises(AnsibleActionFail):
        action.run()

    assert state.transfers == state.calls == state.cleanup == []


@pytest.mark.parametrize("keep", [False, True])
@pytest.mark.parametrize("failure", ["transfer", "module"])
def test_staging_and_execution_failure_honor_remote_file_policy(
    monkeypatch: pytest.MonkeyPatch, keep: bool, failure: str
) -> None:
    action, state = _action(monkeypatch, {"jid": "123"})
    monkeypatch.setattr(C, "DEFAULT_KEEP_REMOTE_FILES", keep)

    def _fail(*_args: Any, **_kwargs: Any) -> Any:
        raise OSError("unavailable")

    if failure == "transfer":
        monkeypatch.setattr(action, "_transfer_file", _fail)
    else:
        monkeypatch.setattr(ActionBase, "_execute_module", _fail)

    with pytest.raises(OSError, match="unavailable"):
        action.run()

    assert state.cleanup == ([] if keep else [(_REMOTE, True)])
    assert state.shell.tmpdir == (_REMOTE if keep else None)


def test_existing_directory_is_not_owned_or_removed(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    action, state = _action(monkeypatch, {"jid": "123"})
    state.shell.tmpdir = _REMOTE

    action.run()

    assert len(state.transfers) == 1
    assert state.cleanup == []
    assert state.shell.tmpdir == _REMOTE


@pytest.mark.parametrize("option", ["async", "become"])
def test_unsupported_execution_never_stages(
    monkeypatch: pytest.MonkeyPatch, option: str
) -> None:
    action, state = _action(
        monkeypatch, {"jid": "123"}, async_val=int(option == "async")
    )
    if option == "become":
        action._connection.become = object()  # pylint: disable=protected-access

    with pytest.raises(AnsibleActionFail):
        action.run()

    assert state.transfers == state.calls == state.cleanup == []


@pytest.mark.parametrize("mode", ["status", "cleanup"])
def test_runas_status_retains_one_core_invocation_and_stages_its_helpers(
    monkeypatch: pytest.MonkeyPatch, mode: str
) -> None:
    action, state = _action(monkeypatch, {"jid": "123.456", "mode": mode})
    # These core extension points are the execution contract being tested.
    # pylint: disable=protected-access
    action._connection.become = SimpleNamespace(name="runas")
    assert ActionModule._low_level_execute_command is (
        NativeRunasExecution._low_level_execute_command
    )
    # pylint: enable=protected-access
    result = action.run(task_vars={})
    # Keep each action's explicit helper closure visible in its own staging test.
    # pylint: disable=duplicate-code
    assert [Path(source).name for source, _target in state.transfers] == [
        "legacy_windows_module.py",
        "legacy_windows_account.py",
        "legacy_windows_s4u.py",
        "legacy_windows_system_token.py",
        "legacy_windows_runas_token.py",
        "legacy_windows_runas.py",
    ]
    # pylint: enable=duplicate-code
    assert len(state.calls) == 1
    assert state.calls[0]["module_args"] == {
        "jid": "123.456",
        "mode": mode,
        "_async_dir": _CACHE,
    }
    assert result["ansible_job_id"] == "123.456"
    assert len(state.cleanup) == 1
