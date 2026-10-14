"""Exercise native Setup delegation without replacing core fact gathering."""

# SPDX-License-Identifier: GPL-3.0-or-later
# These tests inspect Ansible's private task and action-extension interfaces.
# pylint: disable=protected-access

import copy
from types import SimpleNamespace
from typing import Any
from unittest.mock import Mock

import pytest
from ansible import constants as C  # type: ignore[import-untyped]

# Ansible's action contracts lack distributed typing metadata.
from ansible.errors import AnsibleActionFail  # type: ignore[import-untyped]
from ansible.plugins.action import ActionBase  # type: ignore[import-untyped]
from ansible.plugins.action import gather_facts as core
from ansible_collections.sustainablelobster.legacy_windows.plugins.action import (
    gather_facts,
)

from tests.unit.test_async_status_action import _action as _status_action
from tests.unit.test_python_action import _action

_SETUP = "sustainablelobster.legacy_windows.setup"


def _gather_action(monkeypatch: pytest.MonkeyPatch) -> tuple[Any, SimpleNamespace]:
    action, _shell, _events = _action(gather_facts.ActionModule, monkeypatch)
    action._task.collections = ["sustainablelobster.legacy_windows"]
    action._task.copy = lambda: copy.copy(action._task)
    action._native_jobs = set()
    state = SimpleNamespace(
        resolved=_SETUP,
        result={"changed": False, "ansible_facts": {"module_setup": True}},
    )
    state.resolve = Mock(
        side_effect=lambda *_args, **_kw: SimpleNamespace(resolved_fqcn=state.resolved)
    )
    state.run = Mock(side_effect=lambda **_kw: state.result)
    state.load = Mock(return_value=SimpleNamespace(run=state.run))
    action._shared_loader_obj = SimpleNamespace(
        module_loader=SimpleNamespace(find_plugin_with_context=state.resolve),
        action_loader=SimpleNamespace(get=state.load),
    )
    return action, state


def test_native_setup_uses_its_existing_action_and_exact_arguments(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    action, state = _gather_action(monkeypatch)
    arguments: dict[str, object] = {"gather_subset": ["!all", "!min", "distribution"]}
    variables: dict[str, object] = {"inventory_hostname": "test"}
    assert (
        gather_facts.ActionModule._execute_module(
            action, module_name=_SETUP, module_args=arguments, task_vars=variables
        )
        is state.result
    )
    child = state.load.call_args.kwargs["task"]
    assert child is not action._task
    assert child.action == _SETUP and child.args == arguments
    assert child.args is not arguments
    assert action._task.action == "sustainablelobster.legacy_windows.win_ping"
    assert state.load.call_args.kwargs["connection"] is action._connection
    state.run.assert_called_once_with(task_vars=variables)


@pytest.mark.parametrize("failed", [False, True])
def test_complete_native_result_is_not_filtered_or_rewritten(
    monkeypatch: pytest.MonkeyPatch, failed: bool
) -> None:
    action, state = _gather_action(monkeypatch)
    state.result = {
        "failed": failed,
        "changed": False,
        "warnings": ["retained"],
        "ansible_facts": {"null": None, "rows": [2, 1]},
    }
    assert (
        gather_facts.ActionModule._execute_module(action, module_name=_SETUP)
        is state.result
    )


def _parallel_child(action: Any, state: Any) -> Any:
    child = SimpleNamespace(
        EXTRA_MODULE_UTILS=("legacy_windows_wmi.py",),
        _check_execution_support=Mock(),
        _stage_module_utils=Mock(),
        _execute_module=Mock(),
        run=Mock(),
        run_parallel=Mock(
            return_value={
                "started": True,
                "changed": True,
                "ansible_job_id": "j1.2",
                "results_file": r"C:\native-cache\j1.2",
            }
        ),
        _remove_tmp_path=Mock(),
    )

    def _load(_name: str, **options: Any) -> Any:
        child._task = options["task"]
        child._connection = action._connection
        return child

    state.load.side_effect = _load
    return child


@pytest.mark.parametrize("timeout", [0, 30])
def test_parallel_native_request_preserves_core_timeout_and_stages_its_action(
    monkeypatch: pytest.MonkeyPatch, timeout: int
) -> None:
    action, state = _gather_action(monkeypatch)
    action._task.args = {"gather_timeout": 99}
    action._task.async_val = timeout
    original = vars(action._task).copy()
    child = _parallel_child(action, state)
    arguments = {"gather_subset": ["distribution"], "gather_timeout": 2}
    assert gather_facts.ActionModule._execute_module(
        action, module_name=_SETUP, module_args=arguments, wrap_async=True
    ) == {
        "started": True,
        "changed": False,
        "ansible_job_id": "j1.2",
        "results_file": "C:/native-cache/j1.2",
    }
    assert child._task.async_val == timeout and child._task.poll == 0
    assert child.EXTRA_MODULE_UTILS == ("legacy_windows_wmi.py",)
    child.run_parallel.assert_called_once_with(task_vars=None)
    child.run.assert_not_called()
    child._check_execution_support.assert_not_called()
    child._stage_module_utils.assert_not_called()
    child._execute_module.assert_not_called()
    child._remove_tmp_path.assert_not_called()
    assert action._native_jobs == {"j1.2"}
    assert vars(action._task) == original


def test_parallel_native_become_is_preserved_through_the_selected_child_action(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    action, state = _gather_action(monkeypatch)
    action._task.args = {"gather_timeout": 30}
    action._connection.become = SimpleNamespace(name="runas")
    child = _parallel_child(action, state)
    variables: dict[str, object] = {
        "ansible_become_user": "requested",
        "ansible_become_password": "secret",
    }
    gather_facts.ActionModule._execute_module(
        action, module_name=_SETUP, wrap_async=True, task_vars=variables
    )
    assert child._connection is action._connection
    assert child._connection.become.name == "runas"
    child.run_parallel.assert_called_once_with(task_vars=variables)


@pytest.mark.parametrize("failure", ["stage", "execute", "parsed"])
def test_parallel_launch_failures_do_not_repeat_the_childs_owned_cleanup(
    monkeypatch: pytest.MonkeyPatch, failure: str
) -> None:
    action, state = _gather_action(monkeypatch)
    action._task.args = {"gather_timeout": 30}
    child = _parallel_child(action, state)
    if failure == "parsed":
        child.run_parallel.return_value = {
            "failed": True,
            "msg": "launch failed",
            "changed": True,
        }
    else:
        child.run_parallel.side_effect = OSError(failure + " failed")
    if failure == "parsed":
        with pytest.raises(AnsibleActionFail, match="launch failed") as caught:
            gather_facts.ActionModule._execute_module(
                action, module_name=_SETUP, wrap_async=True
            )
        assert caught.value.result == {
            "failed": True,
            "msg": "launch failed",
            "changed": False,
        }
    else:
        with pytest.raises(OSError, match=failure + " failed"):
            gather_facts.ActionModule._execute_module(
                action, module_name=_SETUP, wrap_async=True
            )
    child.run_parallel.assert_called_once_with(task_vars=None)
    child._remove_tmp_path.assert_not_called()
    assert action._native_jobs == set()


def test_parallel_without_timeout_detaches_without_inventing_a_job_deadline(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    action, state = _gather_action(monkeypatch)
    action._task.args = {}
    child = _parallel_child(action, state)
    result = gather_facts.ActionModule._execute_module(
        action, module_name=_SETUP, wrap_async=True
    )
    assert result["ansible_job_id"] == "j1.2"
    assert child._task.async_val == 0
    assert child._task.args == {}
    child.run_parallel.assert_called_once_with(task_vars=None)


def test_owned_parallel_status_uses_native_module_and_cleans_its_staging(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    action, state = _gather_action(monkeypatch)
    child = _parallel_child(action, state)
    child.run.return_value = {"finished": True, "ansible_facts": {"x": 1}}
    action._native_jobs.add("j1.2")
    arguments: dict[str, object] = {"jid": "j1.2", "_async_dir": r"C:\owned-cache"}
    assert gather_facts.ActionModule._execute_module(
        action, module_name="ansible.legacy.async_status", module_args=arguments
    ) == {"finished": True, "ansible_facts": {"x": 1}}
    assert state.load.call_args.args == (
        "sustainablelobster.legacy_windows.async_status",
    )
    assert child._task.async_val == 0
    child.run.assert_called_once_with(task_vars=None, async_dir=r"C:\owned-cache")
    assert child._task.args == {"jid": "j1.2"}
    assert arguments["_async_dir"] == r"C:\owned-cache"
    child._execute_module.assert_not_called()
    child._remove_tmp_path.assert_not_called()


def test_owned_parallel_status_passes_real_action_validation_and_exact_directory(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    action, _state = _gather_action(monkeypatch)
    action._native_jobs.add("j1.2")
    directory = "C:/owned fact directory/native-cache"
    observed: list[Any] = []

    def _child(module_name: str, arguments: dict[str, object]) -> Any:
        assert module_name == "sustainablelobster.legacy_windows.async_status"
        status, state = _status_action(monkeypatch, arguments)
        monkeypatch.delattr(status, "_get_async_dir")
        monkeypatch.setattr(
            status, "get_shell_option", lambda *_args, **_kw: "C:/wrong"
        )
        monkeypatch.setattr(status, "_remote_expand_user", lambda path: path)
        status._connection.become = SimpleNamespace(name="runas")
        state.response = {"finished": True, "ansible_facts": {"selected": True}}
        observed.append(state)
        return status

    monkeypatch.setattr(action, "_native_action", _child)
    result = gather_facts.ActionModule._execute_module(
        action,
        module_name="ansible.legacy.async_status",
        module_args={"jid": "j1.2", "_async_dir": directory},
        task_vars={},
    )
    assert result["finished"] and result["ansible_facts"] == {"selected": True}
    assert result["results_file"] == directory + "\\j1.2"
    assert observed[0].calls[0]["module_args"] == {
        "jid": "j1.2",
        "mode": "status",
        "_async_dir": directory,
    }
    assert len(observed[0].cleanup) == 1


def test_missing_native_action_is_actionable(monkeypatch: pytest.MonkeyPatch) -> None:
    action, state = _gather_action(monkeypatch)
    state.load.return_value = None
    with pytest.raises(AnsibleActionFail, match="fact action could not be loaded"):
        gather_facts.ActionModule._execute_module(action, module_name=_SETUP)


def test_other_fact_modules_preserve_the_complete_core_call(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    action, state = _gather_action(monkeypatch)
    state.resolved = "other.collection.facts"
    execute = Mock(return_value={"ansible_facts": {"other": True}})
    monkeypatch.setattr(core.ActionModule, "_execute_module", execute)
    arguments: dict[str, object] = {"option": True}
    variables: dict[str, object] = {}
    assert gather_facts.ActionModule._execute_module(
        action,
        module_name=state.resolved,
        module_args=arguments,
        tmp="existing",
        task_vars=variables,
        persist_files=True,
        delete_remote_tmp=False,
        wrap_async=True,
        ignore_unknown_opts=True,
    ) == {"ansible_facts": {"other": True}}
    execute.assert_called_once_with(
        module_name=state.resolved,
        module_args=arguments,
        tmp="existing",
        task_vars=variables,
        persist_files=True,
        delete_remote_tmp=False,
        wrap_async=True,
        ignore_unknown_opts=True,
    )
    state.load.assert_not_called()


def test_foreign_parallel_job_preserves_core_status_execution(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    action, state = _gather_action(monkeypatch)
    action._native_jobs.add("j1.2")
    state.resolved = "ansible.builtin.async_status"
    execute = Mock(return_value={"finished": True})
    monkeypatch.setattr(core.ActionModule, "_execute_module", execute)
    arguments: dict[str, object] = {"jid": "foreign", "_async_dir": "/foreign-cache"}
    assert gather_facts.ActionModule._execute_module(
        action, module_name="ansible.legacy.async_status", module_args=arguments
    ) == {"finished": True}
    assert execute.call_args.kwargs["module_name"] == "ansible.legacy.async_status"
    assert execute.call_args.kwargs["module_args"] is arguments
    state.load.assert_not_called()


def test_native_setup_keeps_selectors_and_resolved_module_defaults(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    action, state = _gather_action(monkeypatch)
    action._task.args = {
        "gather_subset": ["distribution"],
        "gather_timeout": 0,
        "filter": None,
    }
    apply_defaults = Mock(return_value={"gather_subset": ["distribution"]})
    monkeypatch.setattr(gather_facts, "_apply_action_arg_defaults", apply_defaults)
    assert action._get_module_args(_SETUP, {}) == {"gather_subset": ["distribution"]}
    apply_defaults.assert_called_once_with(
        _SETUP,
        action._task,
        {"gather_subset": ["distribution"], "gather_timeout": 0},
        action._templar,
    )
    assert state.resolve.call_args.kwargs["collection_list"] == [
        "sustainablelobster.legacy_windows"
    ]


def test_other_fact_module_argument_policy_is_owned_by_core(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    action, state = _gather_action(monkeypatch)
    state.resolved = "other.collection.facts"
    prepare = Mock(return_value={"other": True})
    monkeypatch.setattr(core.ActionModule, "_get_module_args", prepare)
    variables: dict[str, object] = {}
    assert action._get_module_args(state.resolved, variables) == {"other": True}
    prepare.assert_called_once_with(state.resolved, variables)


def test_resolved_collector_default_reaches_parallel_child_without_job_limit(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    action, state = _gather_action(monkeypatch)
    action._task.args = {"parallel": True}
    child = _parallel_child(action, state)
    monkeypatch.delattr(action, "_execute_module")
    monkeypatch.setattr(ActionBase, "run", Mock(return_value={}))
    monkeypatch.setattr(C.config, "get_config_value", Mock(return_value=[_SETUP]))
    monkeypatch.setattr(
        gather_facts,
        "_apply_action_arg_defaults",
        lambda _m, _t, args, _e: {"gather_timeout": 17, **args},
    )
    # The real core loop owns launch, polling and cleanup. Replace only this
    # job's terminal status; the selected action and resolved arguments remain.
    status = SimpleNamespace(run=Mock(return_value={"finished": True}))

    def _load(name: str, **options: Any) -> Any:
        selected = status if name.endswith(".async_status") else child
        selected._task = options["task"]
        return selected

    state.load.side_effect = _load
    action.run(task_vars={})
    assert child._task.args == {"gather_timeout": 17}
    assert child._task.async_val == 0
    child.run_parallel.assert_called_once_with(task_vars={})


def test_core_gathering_merges_native_facts_and_warnings(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    action, state = _gather_action(monkeypatch)
    state.result = {
        "changed": False,
        "ansible_facts": {"ansible_distribution": "Windows", "rows": [2, 1]},
        "warnings": ["original warning"],
    }
    action._task.args = {"parallel": False, "gather_subset": ["distribution"]}
    monkeypatch.delattr(action, "_execute_module")
    monkeypatch.setattr(ActionBase, "run", Mock(return_value={}))
    monkeypatch.setattr(C.config, "get_config_value", Mock(return_value=[_SETUP]))
    monkeypatch.setattr(
        gather_facts, "_apply_action_arg_defaults", lambda _m, _t, args, _e: args
    )
    assert action.run(task_vars={}) == {
        "ansible_facts": {
            "ansible_distribution": "Windows",
            "rows": [2, 1],
            "_ansible_facts_gathered": True,
        },
        "warnings": ["original warning"],
        "deprecations": [],
        "_ansible_verbose_override": True,
    }
    assert state.load.call_args.kwargs["task"].args == {
        "gather_subset": ["distribution"]
    }


def test_core_parallel_loop_keeps_become_through_launch_status_and_fact_merging(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    action, state = _gather_action(monkeypatch)
    action._task.args = {
        "parallel": True,
        "gather_timeout": 30,
        "gather_subset": ["user"],
    }
    become = SimpleNamespace(name="runas")
    action._connection.become = become
    launched = _parallel_child(action, state)
    status = SimpleNamespace(
        run=Mock(
            return_value={
                "finished": True,
                "changed": False,
                "ansible_facts": {"ansible_user_sid": "S-1-5-18", "module_setup": True},
            }
        )
    )
    selected: list[Any] = []

    def _load(name: str, **options: Any) -> Any:
        child = status if name.endswith(".async_status") else launched
        child._task = options["task"]
        child._connection = options["connection"]
        selected.append(child)
        return child

    state.load.side_effect = _load
    monkeypatch.delattr(action, "_execute_module")
    monkeypatch.setattr(ActionBase, "run", Mock(return_value={}))
    monkeypatch.setattr(C.config, "get_config_value", Mock(return_value=[_SETUP]))
    monkeypatch.setattr(
        gather_facts, "_apply_action_arg_defaults", lambda _m, _t, args, _e: args
    )
    result = action.run(task_vars={})
    assert result["ansible_facts"] == {
        "ansible_user_sid": "S-1-5-18",
        "module_setup": True,
        "_ansible_facts_gathered": True,
    }
    assert not result.get("changed", False)
    assert selected == [launched, status]
    assert all(child._connection.become is become for child in selected)
    assert launched._task.async_val == 0 and launched._task.poll == 0
    assert launched._task.args["gather_timeout"] == 30
    assert status._task.async_val == 0
    assert status._task.args == {"jid": "j1.2"}
    launched.run_parallel.assert_called_once_with(task_vars={})
    status.run.assert_called_once_with(task_vars={}, async_dir="C:/native-cache")
    assert action._task.async_val == 0
