"""Exercise native async routing against the installed core action ABI."""

# SPDX-License-Identifier: GPL-3.0-or-later
# These tests deliberately inspect the private core extension boundary.
# pylint: disable=protected-access

import ntpath
from pathlib import Path
from types import SimpleNamespace
from typing import Any
from unittest.mock import Mock

import pytest
from ansible import constants  # type: ignore[import-untyped]
from ansible.errors import AnsibleActionFail  # type: ignore[import-untyped]
from ansible.parsing.dataloader import DataLoader  # type: ignore[import-untyped]
from ansible.plugins.action import normal  # type: ignore[import-untyped]
from ansible.template import Templar  # type: ignore[import-untyped]

from plugins.plugin_utils._module import PythonModuleAction
from plugins.plugin_utils._runas import NativeRunasAction

_REMOTE = r"C:\Users\Test User\Temp\ansible-tmp-owned"
_ROOT = Path(__file__).resolve().parents[2]


def _action(
    monkeypatch: pytest.MonkeyPatch, *, core_cleanup: bool = False, **options: Any
) -> tuple[Any, list[Any]]:
    events: list[Any] = []
    shell = SimpleNamespace(tmpdir=None, join_path=ntpath.join)
    task = SimpleNamespace(
        action="sustainablelobster.legacy_windows.win_ping",
        args={},
        async_val=30,
        poll=0,
        check_mode=False,
        delegate_to=None,
        **options,
    )
    connection = SimpleNamespace(_shell=shell, become=None)
    loader = DataLoader()
    action = PythonModuleAction(task, connection, None, loader, Templar(loader=loader))

    def _mkdir() -> str:
        shell.tmpdir = _REMOTE
        action._cleanup_remote_tmp = True
        events.append(("mkdir",))
        return _REMOTE

    monkeypatch.setattr(action, "_make_tmp_path", _mkdir)
    monkeypatch.setattr(
        action,
        "_transfer_file",
        lambda source, target: events.append(("transfer", Path(source).name, target)),
    )

    def _execute(**kwargs: Any) -> dict[str, bool]:
        events.append(("execute", kwargs))
        return {"started": True, "changed": True}

    monkeypatch.setattr(action, "_execute_module", _execute)
    if not core_cleanup:
        monkeypatch.setattr(
            action, "_remove_tmp_path", lambda path: events.append(("cleanup", path))
        )
    return action, events


def test_poll_zero_uses_normal_core_lifecycle_and_does_not_mutate_task(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    action, events = _action(monkeypatch)
    task_fields = vars(action._task).copy()
    variables = {"sentinel": "value"}
    assert action.run(task_vars=variables) == {"started": True, "changed": False}
    assert events == [
        ("mkdir",),
        *[
            ("transfer", name, ntpath.join(_REMOTE, name))
            for name in (
                "legacy_windows_module.py",
                "legacy_windows_wmi.py",
                "legacy_windows_async_native.py",
                "legacy_windows_async_worker.py",
            )
        ],
        ("execute", {"task_vars": variables, "wrap_async": 30}),
    ]
    assert not action._supports_async
    assert vars(action._task) == task_fields


def test_sync_custom_async_capable_action_stages_no_watchdog(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    action, events = _action(monkeypatch)
    action._task.async_val = 0
    action._supports_async = True
    action._stage_module_utils()
    assert [event[1] for event in events if event[0] == "transfer"] == [
        "legacy_windows_module.py"
    ]


def test_synchronous_changed_result_is_not_rewritten(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    action, _events = _action(monkeypatch)
    action._task.async_val = 0
    assert action.run() == {"started": True, "changed": True}


def test_parallel_without_job_limit_stages_watchdog_and_uses_core_executor(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    action, events = _action(monkeypatch)
    action._task.async_val = 0
    original = vars(action._task).copy()
    variables = {"selected": "facts"}
    assert action.run_parallel(task_vars=variables) == {
        "started": True,
        "changed": False,
    }
    assert [event[1] for event in events if event[0] == "transfer"] == [
        "legacy_windows_module.py",
        "legacy_windows_wmi.py",
        "legacy_windows_async_native.py",
        "legacy_windows_async_worker.py",
    ]
    assert events[-1] == ("execute", {"task_vars": variables, "wrap_async": True})
    assert vars(action._task) == original
    assert not action._supports_async
    assert not action._parallel_execution


def test_synchronous_runas_retains_its_parent_and_only_become_helper_closure(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    action, events = _action(monkeypatch)
    action._task.async_val = 0
    action._connection.become = SimpleNamespace(name="runas")
    fields = vars(action._task).copy()
    assert isinstance(action, NativeRunasAction)
    assert action.run(task_vars={}) == {"started": True, "changed": True}
    # Keep this expected closure explicit and independent of production staging.
    # pylint: disable=duplicate-code
    assert [event[1] for event in events if event[0] == "transfer"] == [
        "legacy_windows_module.py",
        "legacy_windows_account.py",
        "legacy_windows_s4u.py",
        "legacy_windows_system_token.py",
        "legacy_windows_runas_token.py",
        "legacy_windows_runas.py",
    ]
    # pylint: enable=duplicate-code
    assert events[-2:] == [
        ("execute", {"task_vars": {}, "wrap_async": 0}),
        ("cleanup", _REMOTE),
    ]
    assert vars(action._task) == fields
    assert not action._supports_async


def test_parallel_dispatch_preserves_custom_action_validation(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    action, events = _action(monkeypatch)
    custom_run = Mock(side_effect=lambda **_kwargs: action._check_execution_support())
    monkeypatch.setattr(action, "run", custom_run)
    action._task.async_val = 0
    with pytest.raises(AnsibleActionFail, match="does not support async"):
        action.run_parallel()
    assert not action._parallel_execution
    assert not events
    custom_run.assert_called_once_with(task_vars=None)


@pytest.mark.parametrize("poll", [-1, 1, 15])
def test_automatic_poll_rejected_before_staging(
    monkeypatch: pytest.MonkeyPatch, poll: int
) -> None:
    action, events = _action(monkeypatch)
    action._task.poll = poll
    # Real default loader resolution runs in a fresh-process regression. Do not
    # initialize its process-global collection finder before other unit fixtures.
    monkeypatch.setattr(
        "plugins.plugin_utils._module.action_loader",
        SimpleNamespace(get=lambda name, class_only: SimpleNamespace()),
    )
    with pytest.raises(AnsibleActionFail, match="action_plugins.*ansible.cfg"):
        action.run()
    assert not events
    assert action._task.poll == poll and action._task.async_val == 30


@pytest.mark.parametrize("poll", [1, 15])
def test_automatic_poll_preserves_task_and_core_launch_with_explicit_handler(
    monkeypatch: pytest.MonkeyPatch, poll: int
) -> None:
    action, events = _action(monkeypatch)
    action._task.poll = poll
    monkeypatch.setattr(
        "plugins.plugin_utils._module.action_loader",
        SimpleNamespace(
            get=lambda name, class_only: SimpleNamespace(
                _supports_native_windows_polling=True
            )
        ),
    )
    fields = vars(action._task).copy()
    assert action.run(task_vars={}) == {"started": True, "changed": False}
    assert events[-1] == ("execute", {"task_vars": {}, "wrap_async": 30})
    assert vars(action._task) == fields
    assert not action._supports_async


def test_custom_multi_payload_action_guard_still_rejects_async(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    action, events = _action(monkeypatch)
    with pytest.raises(AnsibleActionFail, match="does not support async"):
        action._check_execution_support()
    assert not events


@pytest.mark.parametrize("plugin", [object(), SimpleNamespace(name="sudo")])
def test_other_become_methods_fail_before_async_staging(
    monkeypatch: pytest.MonkeyPatch, plugin: Any
) -> None:
    action, events = _action(monkeypatch)
    action._connection.become = plugin
    with pytest.raises(AnsibleActionFail, match="only runas"):
        action.run()
    assert not events


def test_async_runas_stages_both_closures_and_preserves_core_lifecycle(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    action, events = _action(monkeypatch)
    action._connection.become = SimpleNamespace(name="runas")
    fields = vars(action._task).copy()
    assert action.run(task_vars={}) == {"started": True, "changed": False}
    assert [event[1] for event in events if event[0] == "transfer"] == [
        "legacy_windows_module.py",
        "legacy_windows_wmi.py",
        "legacy_windows_async_native.py",
        "legacy_windows_async_worker.py",
        "legacy_windows_account.py",
        "legacy_windows_s4u.py",
        "legacy_windows_system_token.py",
        "legacy_windows_runas_token.py",
        "legacy_windows_runas.py",
    ]
    assert events[-1] == ("execute", {"task_vars": {}, "wrap_async": 30})
    assert vars(action._task) == fields
    assert not action._supports_async


def test_async_staging_deduplicates_existing_wmi_helper(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    action, events = _action(monkeypatch)
    # This is the inherited action's published uppercase helper-list contract.
    action.EXTRA_MODULE_UTILS = (
        "legacy_windows_wmi.py",
    )  # pylint: disable=invalid-name
    action.run()
    assert [event[1] for event in events if event[0] == "transfer"].count(
        "legacy_windows_wmi.py"
    ) == 1


@pytest.mark.parametrize("failure_index", [1, 2, 3, 4, 5])
@pytest.mark.parametrize("keep_files", [False, True])
@pytest.mark.parametrize("borrowed", [False, True])
def test_each_async_transfer_and_execution_failure_retains_core_ownership(
    monkeypatch: pytest.MonkeyPatch,
    failure_index: int,
    keep_files: bool,
    borrowed: bool,
) -> None:
    action, events = _action(monkeypatch, core_cleanup=True)
    shell = action._connection._shell
    if borrowed:
        shell.tmpdir = _REMOTE
    shell.remove = lambda path, recurse: ("remove", path, recurse)
    monkeypatch.setattr(constants, "DEFAULT_KEEP_REMOTE_FILES", keep_files)

    def _cleanup(command: Any, **kwargs: Any) -> dict[str, int]:
        events.append(("cleanup", command, kwargs))
        return {"rc": 0}

    monkeypatch.setattr(action, "_low_level_execute_command", _cleanup)
    transfer = action._transfer_file
    calls = 0

    def _transfer(source: str, target: str) -> None:
        nonlocal calls
        calls += 1
        if calls == failure_index:
            raise OSError("expected failure")
        transfer(source, target)

    monkeypatch.setattr(action, "_transfer_file", _transfer)
    if failure_index == 5:
        monkeypatch.setattr(
            action, "_execute_module", Mock(side_effect=OSError("expected failure"))
        )
    with pytest.raises(OSError, match="expected failure"):
        action.run()
    assert sum(event[0] == "transfer" for event in events) == failure_index - 1
    cleanup = [event for event in events if event[0] == "cleanup"]
    assert cleanup == (
        [("cleanup", ("remove", _REMOTE, True), {"sudoable": False})]
        if not borrowed and not keep_files
        else []
    )
    assert not action._supports_async
    assert action._task.async_val == 30 and action._task.poll == 0


@pytest.mark.parametrize("delegated", [False, True])
@pytest.mark.parametrize("keep_files", [False, True])
@pytest.mark.parametrize("borrowed", [False, True])
def test_parsed_failed_launch_uses_saved_staging_and_core_cleanup_policy(
    monkeypatch: pytest.MonkeyPatch,
    keep_files: bool,
    borrowed: bool,
    delegated: bool,
) -> None:
    action, events = _action(monkeypatch, core_cleanup=True)
    shell = action._connection._shell
    if borrowed:
        shell.tmpdir = _REMOTE
    action._task.delegate_to = "worker" if delegated else None
    shell.remove = lambda path, recurse: ("remove", path, recurse)
    monkeypatch.setattr(constants, "DEFAULT_KEEP_REMOTE_FILES", keep_files)

    def _execute(**kwargs: Any) -> dict[str, Any]:
        assert kwargs["wrap_async"] == 30
        # This is core's actual post-parse behavior even for failed-wrapper JSON.
        shell.tmpdir = None
        return {"failed": True, "msg": "failed to launch async task"}

    def _cleanup(command: Any, **kwargs: Any) -> dict[str, int]:
        events.append(("cleanup", command, kwargs))
        return {"rc": 0}

    monkeypatch.setattr(action, "_execute_module", _execute)
    monkeypatch.setattr(action, "_low_level_execute_command", _cleanup)
    assert action.run() == {
        "failed": True,
        "msg": "failed to launch async task",
        "changed": False,
    }
    assert [event for event in events if event[0] == "cleanup"] == (
        [("cleanup", ("remove", _REMOTE, True), {"sudoable": False})]
        if not borrowed and not keep_files
        else []
    )
    assert shell.tmpdir is None and not action._supports_async
    assert action._task.async_val == 30 and action._task.poll == 0


@pytest.mark.parametrize("delegated", [False, True])
def test_private_wrapper_uses_real_want_json_configuration_and_effective_vars(
    monkeypatch: pytest.MonkeyPatch, delegated: bool
) -> None:
    action, _events = _action(monkeypatch)
    action._supports_async = True
    variables: dict[str, Any] = {
        "ansible_python_interpreter": r"C:\Python34\python.exe",
        "ansible_win_async_startup_timeout": 11,
    }
    if delegated:
        action._task.delegate_to = "worker"
        variables = {
            "ansible_delegated_vars": {"worker": variables},
            "ansible_python_interpreter": "WRONG",
            "ansible_win_async_startup_timeout": 19,
        }
    bits, path = action._configure_module("ansible.legacy.async_wrapper", {}, variables)
    assert path == str(_ROOT / "plugins/module_utils/legacy_windows_async_wrapper.py")
    assert bits.module_style == "non_native_want_json"
    assert bits.shebang == r"#!C:\Python34\python.exe"
    assert b"_STARTUP_TIMEOUT = 11\n" in bits.b_module_data
    assert not bits.has_async and not bits.has_become
    compile(bits.b_module_data, "configured_wrapper", "exec")


def test_other_module_configuration_remains_core_owned(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    action, _events = _action(monkeypatch)
    fallback = Mock(return_value=("built", "source"))
    monkeypatch.setattr(normal.ActionModule, "_configure_module", fallback)
    assert action._configure_module("win_ping", {"data": "x"}, {}) == (
        "built",
        "source",
    )
    fallback.assert_called_once_with("win_ping", {"data": "x"}, {})


def test_declared_core_minimum_has_the_wrapper_argv_contract() -> None:
    assert constants.config.get_config_value("WIN_ASYNC_STARTUP_TIMEOUT") == 5
    source = Path(normal.__file__).with_name("__init__.py").read_text(encoding="utf-8")
    assert "'ansible.legacy.async_wrapper'" in source
    assert "async_limit, preserve_tmp, remote_module_path" in source
    assert "async_cmd.extend(module_cmd_args)" in source
