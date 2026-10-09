"""Exercise complete controller update results, retries and reboot decisions."""

# SPDX-License-Identifier: GPL-3.0-or-later
# Controller connection and WUA result substitutes are not target proof.
# pylint: disable=protected-access

from ntpath import join as windows_join
from types import SimpleNamespace
from typing import Any
from unittest.mock import Mock

import pytest
from ansible.errors import (  # type: ignore[import-untyped]
    AnsibleActionFail,
    AnsibleConnectionFailure,
    AnsibleError,
)

from plugins.action import win_reboot, win_updates
from plugins.plugin_utils._module import PythonModuleAction
from plugins.plugin_utils._updates_hresult import describe_hresult


# These independent released flags are intentionally explicit test inputs.
def _round(  # pylint: disable=too-many-arguments
    identifier: str | None = "a",
    *,
    filtered: bool = False,
    installed: bool = False,
    downloaded: bool = False,
    required: bool = False,
    failed: bool = False,
) -> Any:
    result = win_updates._UpdateRound()
    updates = (
        []
        if identifier is None
        else [
            {
                "id": identifier,
                "title": "Security update",
                "kb": ["KB123", "not-prefixed"],
                "categories": ["Security Updates"],
            }
        ]
    )
    result.receive(
        "search_result",
        {
            "updates": updates,
            "filtered": (
                [{"id": identifier, "reasons": ["reject_list"]}] if filtered else []
            ),
        },
    )
    if downloaded:
        result.receive(
            "download_result",
            {"info": [{"id": identifier, "result_code": 2, "hresult": 0}]},
        )
    if installed:
        result.receive(
            "install_result",
            {
                "info": [
                    {
                        "id": identifier,
                        "result_code": 2,
                        "hresult": 0,
                        "reboot_required": required,
                    }
                ]
            },
        )
    result.receive(
        "exit",
        {
            "changed": installed or downloaded,
            "reboot_required": required,
            "failed": failed,
            "exception": (
                {"message": "WUA failed", "exception": "native trace"}
                if failed
                else None
            ),
        },
    )
    return result


@pytest.fixture(name="action")
def update_action(monkeypatch: pytest.MonkeyPatch) -> Any:
    """Retain the real base-action argument/early-directory lifecycle.

    :param monkeypatch: Scoped native-module, cleanup and reboot substitutions.
    :returns: Action and controllable operation recorders.
    """
    instance = object.__new__(win_updates.ActionModule)
    instance._task = SimpleNamespace(
        args={},
        action="sustainablelobster.legacy_windows.win_updates",
        check_mode=False,
        async_val=0,
        poll=15,
    )
    instance._connection = SimpleNamespace(
        become=None, _shell=SimpleNamespace(tmpdir="owned-temp", join_path=windows_join)
    )
    state = SimpleNamespace(
        round=Mock(return_value=_round()),
        cleanup=Mock(),
        reboot=Mock(return_value={"failed": False}),
        stage=Mock(),
    )
    monkeypatch.setattr(instance, "_round", state.round)
    monkeypatch.setattr(instance, "_remove_tmp_path", state.cleanup)
    monkeypatch.setattr(instance, "_reboot", state.reboot)
    monkeypatch.setattr(instance, "_stage_module_utils", state.stage)
    return instance, state


def test_whole_public_searched_projection_keeps_arrays_and_cached_flags(
    action: Any,
) -> None:
    instance, state = action
    instance._task.args = {"state": "searched"}
    assert instance.run() == {
        "changed": False,
        "reboot_required": False,
        "rebooted": False,
        "found_update_count": 1,
        "failed_update_count": 0,
        "installed_update_count": 0,
        "updates": {
            "a": {
                "id": "a",
                "title": "Security update",
                "kb": ["123", "not-prefixed"],
                "categories": ["Security Updates"],
                "downloaded": False,
                "installed": False,
            }
        },
        "filtered_updates": {},
    }
    instance.cleanup()
    state.cleanup.assert_called_once_with("owned-temp")


def test_filtered_result_is_excluded_from_counts_and_preserves_reason_order(
    action: Any,
) -> None:
    instance, state = action
    state.round.return_value = _round(filtered=True)
    result = instance.run()
    assert result["found_update_count"] == 0 and result["updates"] == {}
    assert result["filtered_updates"]["a"]["filtered_reasons"] == ["reject_list"]
    assert result["filtered_updates"]["a"]["downloaded"] is False


def test_successful_download_install_counts_and_no_reboot_default(action: Any) -> None:
    instance, state = action
    state.round.return_value = _round(downloaded=True, installed=True, required=True)
    result = instance.run()
    assert result["changed"] and result["reboot_required"] and not result["rebooted"]
    assert result["installed_update_count"] == 1 and result["failed_update_count"] == 0
    assert result["updates"]["a"]["downloaded"] and result["updates"]["a"]["installed"]
    state.reboot.assert_not_called()


def test_partial_hresult_failure_preserves_unsigned_code_and_numeric_diagnostic(
    action: Any,
) -> None:
    instance, state = action
    current = _round(installed=True, failed=True)
    current.install["a"].update(result_code=4, hresult=0x80240022)
    current.hresult = 0x80240022
    state.round.return_value = current
    result = instance.run()
    assert result["failed"] and result["changed"]
    assert result["failed_update_count"] == 1 and result["installed_update_count"] == 0
    diagnostic = "Windows Update HRESULT 0x80240022"
    assert result["updates"]["a"]["failure_msg"] == diagnostic
    assert result["updates"]["a"]["failure_hresult_code"] == 0x80240022
    assert result["msg"] == "WUA failed - " + diagnostic


@pytest.mark.parametrize("phase", ["download_result", "install_result"])
def test_failed_update_projects_native_description_and_unsigned_hresult(
    action: Any, phase: str
) -> None:
    instance, state = action
    current = _round(installed=True, failed=True)
    current.receive(
        phase,
        {
            "info": [
                {
                    "id": "a",
                    "result_code": 4,
                    "hresult": -2147024891,
                    "hresult_description": "Access is denied.",
                }
            ]
        },
    )
    state.round.return_value = current
    result = instance.run()
    assert result["updates"]["a"]["failure_hresult_code"] == 0x80070005
    assert result["updates"]["a"]["failure_msg"] == (
        "Access is denied. (Windows Update HRESULT 0x80070005)"
    )


def test_round_failure_preserves_provider_text_and_available_description(
    action: Any,
) -> None:
    instance, state = action
    current = _round(identifier=None)
    current.receive(
        "exit",
        {
            "changed": False,
            "reboot_required": False,
            "failed": True,
            "exception": {
                "message": "Provider-specific refusal",
                "hresult": -2147024891,
                "hresult_description": "Access is denied.",
            },
        },
    )
    state.round.return_value = current
    assert instance.run()["msg"] == (
        "Provider-specific refusal - Access is denied. "
        "(Windows Update HRESULT 0x80070005)"
    )


def test_sync_hresult_failure_keeps_the_native_provider_description(
    action: Any,
) -> None:
    instance, state = action
    current = _round(identifier=None)
    current.receive(
        "exit",
        {
            "changed": False,
            "reboot_required": False,
            "failed": True,
            "exception": {
                "message": "Updates are blocked by the local administrator policy.",
                "hresult": -2145124323,
            },
        },
    )
    state.round.return_value = current
    result = instance.run()
    assert current.hresult == 0x8024001D
    assert result["failed"] and not result["changed"]
    assert result["msg"] == (
        "Updates are blocked by the local administrator policy. - "
        "Windows Update HRESULT 0x8024001D"
    )


@pytest.mark.parametrize(
    "message,status,expected",
    [
        (
            "Searching for updates: WUA.EndSearch failed (HRESULT 0x80244011).",
            0x80244011,
            "Searching for updates: Exception from HRESULT: 0x80244011",
        ),
        (
            "WUA.EndSearch failed (HRESULT 0x80244011).",
            -2145107951,
            "Exception from HRESULT: 0x80244011",
        ),
        ("Actual provider description", 0x80244011, "Actual provider description"),
        (
            "WUA.EndSearch failed (HRESULT 0x80244011). Additional description",
            0x80244011,
            "WUA.EndSearch failed (HRESULT 0x80244011). Additional description",
        ),
        (
            "WUA.End.Search failed (HRESULT 0x80244011).",
            0x80244011,
            "WUA.End.Search failed (HRESULT 0x80244011).",
        ),
        (
            "WUA.EndSearch failed (HRESULT 0x80244011).",
            0x80240044,
            "WUA.EndSearch failed (HRESULT 0x80244011).",
        ),
    ],
)
def test_sync_exact_com_fallback_preserves_descriptions_and_hresult(
    message: str, status: int, expected: str
) -> None:
    current = _round(identifier=None)
    current.receive(
        "exit",
        {
            "changed": False,
            "reboot_required": False,
            "failed": True,
            "exception": {
                "message": message,
                "hresult": status,
                "exception": "raw trace",
            },
        },
    )
    assert current.message == expected
    assert current.hresult == status & 0xFFFFFFFF
    assert current.exception == "raw trace" and current.failed


def test_sync_runas_failure_matches_whole_released_managed_failure_result(
    action: Any,
) -> None:
    instance, state = action
    instance._connection.become = SimpleNamespace(name="runas")
    current = _round(identifier=None)
    current.receive(
        "exit",
        {
            "changed": False,
            "reboot_required": False,
            "failed": True,
            "exception": {
                "message": "Searching for updates: WUA.EndSearch failed (HRESULT 0x80244011).",
                "hresult": 0x80244011,
                "exception": "native trace",
            },
        },
    )
    state.round.return_value = current
    assert instance.run() == {
        "changed": False,
        "failed": True,
        "failed_update_count": 0,
        "filtered_updates": {},
        "found_update_count": 0,
        "installed_update_count": 0,
        "msg": (
            "Searching for updates: Exception from HRESULT: 0x80244011 - "
            "Windows Update HRESULT 0x80244011"
        ),
        "reboot_required": False,
        "rebooted": False,
        "updates": {},
        "exception": "native trace",
    }


def test_install_failure_overwrites_earlier_download_failure_like_source(
    action: Any,
) -> None:
    instance, state = action
    current = _round()
    current.download["a"] = {"result_code": 4, "hresult": 0x80240022}
    current.install["a"] = {"result_code": 4, "hresult": 0x8024000B}
    state.round.return_value = current
    result = instance.run()
    assert result["updates"]["a"]["failure_msg"] == "Windows Update HRESULT 0x8024000B"


def test_reboot_rounds_keep_earlier_updates_until_terminal_empty_search(
    action: Any,
) -> None:
    instance, state = action
    instance._task.args = {"reboot": True}
    state.round.side_effect = [
        _round("a", installed=True, required=True),
        _round("b", installed=True),
        _round(None),
    ]
    result = instance.run(task_vars={"inventory_hostname": "owned-host"})
    assert result["changed"] and result["rebooted"] and not result["reboot_required"]
    assert result["installed_update_count"] == result["found_update_count"] == 2
    assert set(result["updates"]) == {"a", "b"}
    assert state.round.call_count == 3
    state.reboot.assert_called_once_with(
        {"inventory_hostname": "owned-host"}, 1200, None
    )


@pytest.mark.parametrize("state", ["searched", "downloaded"])
def test_noninstall_state_finishes_after_first_reboot(action: Any, state: str) -> None:
    instance, boundaries = action
    instance._task.args = {"reboot": True, "state": state}
    boundaries.round.return_value = _round(required=True)
    result = instance.run()
    assert result["rebooted"] and not result["reboot_required"]
    assert boundaries.round.call_count == boundaries.reboot.call_count == 1


def test_check_mode_predicts_reboot_without_native_restart_or_second_round(
    action: Any,
) -> None:
    instance, state = action
    instance._task.args = {"reboot": True}
    instance._task.check_mode = True
    state.round.return_value = _round(required=True)
    result = instance.run()
    assert result["rebooted"] and result["changed"] and not result["reboot_required"]
    state.reboot.assert_not_called()
    assert state.round.call_count == 1


def test_one_failure_reboot_retry_then_second_failure_is_final(action: Any) -> None:
    instance, state = action
    instance._task.args = {"reboot": True}
    state.round.return_value = _round(failed=True)
    result = instance.run()
    assert result["failed"] and result["rebooted"] and result["msg"] == "WUA failed"
    assert state.round.call_count == 2 and state.reboot.call_count == 1


def test_searched_failure_never_requests_recovery_reboot(action: Any) -> None:
    instance, state = action
    instance._task.args = {"reboot": True, "state": "searched"}
    state.round.return_value = _round(failed=True)
    assert instance.run()["failed"]
    state.reboot.assert_not_called()


def test_external_shutdown_marker_skips_new_request_and_is_forwarded(
    action: Any,
) -> None:
    instance, state = action
    instance._task.args = {"reboot": True}
    first = _round(failed=True)
    first.boot_time = "134000000000000000"
    state.round.side_effect = [first, _round(None)]
    result = instance.run()
    assert result["rebooted"] and not result.get("failed")
    state.reboot.assert_called_once_with({}, 1200, first.boot_time)


def test_failed_reboot_preserves_changed_public_counts_and_original_reboot_facts(
    action: Any,
) -> None:
    instance, state = action
    instance._task.args = {"reboot": True}
    state.round.return_value = _round(installed=True, required=True)
    state.reboot.return_value = {
        "failed": True,
        "msg": "readiness timed out",
        "changed": True,
        "rebooted": True,
        "elapsed": 42,
    }
    result = instance.run()
    assert result["failed"] and result["elapsed"] == 42
    assert result["msg"] == "Failed to reboot host: readiness timed out"
    assert (
        result["installed_update_count"] == 1
        and result["changed"]
        and result["rebooted"]
    )


@pytest.mark.parametrize("limit", [1, 2])
def test_rollback_limit_counts_only_repeat_installed_update_rounds(
    action: Any, limit: int
) -> None:
    instance, state = action
    instance._task.args = {"reboot": True, "maximum_retries_on_failed_updates": limit}
    state.round.return_value = _round(installed=True, required=True)
    result = instance.run()
    assert result["failed"] and "update loop was detected" in result["msg"]
    assert state.round.call_count == limit + 1
    assert result["updates"]["a"]["failure_hresult_code"] == -1
    assert result["updates"]["a"]["failure_msg"] == "Windows Update HRESULT 0xFFFFFFFF"


@pytest.mark.parametrize("limit", [1, 2])
def test_rollback_sentinel_discards_the_replaced_provider_description(
    action: Any, limit: int
) -> None:
    instance, state = action
    instance._task.args = {"reboot": True, "maximum_retries_on_failed_updates": limit}
    first = _round(installed=True, required=True)
    repeated_failure = _round(installed=True, required=True, failed=True)
    repeated_failure.receive(
        "install_result",
        {
            "info": [
                {
                    "id": "a",
                    "result_code": 4,
                    "hresult": -2147024891,
                    "hresult_description": "Access is denied.",
                }
            ]
        },
    )
    state.round.side_effect = [first] + [repeated_failure] * limit

    result = instance.run()

    assert result["failed"] and "update loop was detected" in result["msg"]
    assert result["changed"] and result["rebooted"]
    assert result["failed_update_count"] == 1 and result["installed_update_count"] == 0
    assert result["updates"]["a"]["failure_hresult_code"] == -1
    assert result["updates"]["a"]["failure_msg"] == "Windows Update HRESULT 0xFFFFFFFF"
    assert state.round.call_count == limit + 1
    assert state.reboot.call_count == limit


@pytest.mark.parametrize("limit", [0, -1])
def test_zero_negative_retry_limit_fails_even_initial_empty_search_like_source(
    action: Any, limit: int
) -> None:
    instance, state = action
    instance._task.args = {"maximum_retries_on_failed_updates": limit}
    state.round.return_value = _round(None)
    result = instance.run()
    assert result["failed"] and result["found_update_count"] == 0
    assert "update loop was detected" in result["msg"]


def test_raw_controller_retry_string_is_not_silently_normalized(action: Any) -> None:
    instance, _state = action
    instance._task.args = {"maximum_retries_on_failed_updates": "1"}
    result = instance.run()
    assert result["failed"] and "not supported" in result["msg"]


@pytest.mark.parametrize(
    "arguments",
    [
        {"reboot": "invalid"},
        {"reboot_timeout": "invalid"},
        {"_operation": "start"},
        {"_operation_options": {"wait": True}},
        {"unknown": 1},
    ],
)
def test_real_base_and_controller_validation_precede_any_target_call(
    action: Any, arguments: dict[str, Any]
) -> None:
    instance, state = action
    instance._task.args = arguments
    with pytest.raises(AnsibleError):
        instance.run()
    state.round.assert_not_called()
    state.stage.assert_not_called()
    state.cleanup.assert_not_called()


@pytest.mark.parametrize("poll", [0, 15])
def test_async_reboot_remains_rejected_before_any_generic_launch(
    action: Any,
    poll: int,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    instance, state = action
    instance._task.args = {"reboot": True}
    instance._task.async_val = 10
    instance._task.poll = poll
    execution_support = Mock()
    monkeypatch.setattr(instance, "_check_execution_support", execution_support)
    with pytest.raises(
        AnsibleActionFail, match="async is not supported for this task when reboot=yes"
    ):
        instance.run()
    execution_support.assert_not_called()
    state.round.assert_not_called()
    state.stage.assert_not_called()
    state.cleanup.assert_not_called()


@pytest.mark.parametrize("test", [True, False])
@pytest.mark.parametrize("failed", [True, False])
def test_updates_async_reuses_accepted_normal_action_and_restores_task_arguments(
    action: Any, test: bool, failed: bool, monkeypatch: pytest.MonkeyPatch
) -> None:
    instance, state = action
    instance._task.async_val = 10
    instance._task.poll = 0
    original = {"_operation": "test"} if test else {"state": "searched"}
    instance._task.args = original
    launch = {"changed": False, "started": True, "finished": False}

    def normal_run(value: Any, tmp: Any, variables: Any) -> Any:
        """Return launch metadata after checking the real public task boundary.

        :param value: The action passed to its established normal lifecycle.
        :param tmp: Deprecated temporary-directory input.
        :param variables: Original task variables.
        :returns: The untouched generic async launch record.
        :raises AnsibleConnectionFailure: This parametrized launch fails.
        """
        assert value is instance and tmp is None and variables == {"task": "vars"}
        assert value._task.args == {
            **({} if test else {"state": "searched"}),
            "_operation": "test" if test else "start",
            "_operation_options": {"wait": True},
        }
        assert value.EXTRA_MODULE_UTILS[-1] == "legacy_windows_updates_async.py"
        if failed:
            raise AnsibleConnectionFailure("async frontend unavailable")
        return launch

    monkeypatch.setattr(PythonModuleAction, "run", normal_run)
    if failed:
        with pytest.raises(
            AnsibleConnectionFailure, match="async frontend unavailable"
        ):
            instance.run(task_vars={"task": "vars"})
    else:
        assert instance.run(task_vars={"task": "vars"}) == launch
    assert instance._task.args is original
    assert instance.EXTRA_MODULE_UTILS == win_updates._HELPERS
    state.round.assert_not_called()
    state.cleanup.assert_not_called()


def test_updates_async_poll_gt_zero_is_not_silently_coerced(
    action: Any, monkeypatch: pytest.MonkeyPatch
) -> None:
    # Querying the real loader before its finder is installed caches a missing
    # collection namespace and breaks unrelated action tests run afterward.
    monkeypatch.setattr(
        "plugins.plugin_utils._module.action_loader.get", Mock(return_value=object())
    )
    instance, state = action
    instance._task.async_val = 10
    instance._task.poll = 1
    with pytest.raises(AnsibleActionFail, match="poll: 0"):
        instance.run()
    state.round.assert_not_called()
    state.stage.assert_not_called()
    state.cleanup.assert_not_called()


@pytest.mark.parametrize("actor", ["Administrator", "NT AUTHORITY\\SYSTEM"])
@pytest.mark.parametrize("check", [False, True])
def test_updates_automatic_poll_retains_resolved_runas_and_original_task_variables(
    action: Any,
    monkeypatch: pytest.MonkeyPatch,
    actor: str,
    check: bool,
) -> None:
    instance, state = action
    instance._task.async_val, instance._task.poll = 300, 5
    instance._task.check_mode = check
    instance._task.args = {"state": "installed" if check else "searched"}
    instance._connection.become = SimpleNamespace(name="runas", user=actor)
    selected = SimpleNamespace(_supports_native_windows_polling=True)
    monkeypatch.setattr(
        "plugins.plugin_utils._module.action_loader.get", Mock(return_value=selected)
    )
    variables = {"ansible_async_dir": "owned-cache", "ansible_become_user": actor}
    normal = Mock(return_value={"started": True, "finished": False})
    monkeypatch.setattr(PythonModuleAction, "run", normal)
    assert instance.run(task_vars=variables) == {"started": True, "finished": False}
    normal.assert_called_once_with(instance, None, variables)
    assert instance._task.async_val == 300 and instance._task.poll == 5
    assert instance._task.check_mode is check
    assert instance._connection.become.user == actor
    assert instance._task.args == {"state": "installed" if check else "searched"}
    state.round.assert_not_called()
    state.cleanup.assert_not_called()


@pytest.mark.parametrize("failure_index", list(range(14)) + [None])
def test_async_launch_stages_exact_closure_and_cleans_transfer_failures(
    action: Any, failure_index: int | None, monkeypatch: pytest.MonkeyPatch
) -> None:
    instance, state = action
    instance._task.async_val = 60
    instance._task.poll = 0
    instance._task.args = {"_operation": "test"}
    monkeypatch.delattr(instance, "_stage_module_utils")
    transferred: list[str] = []

    def transfer(source: str, destination: str) -> str:
        """Record one helper transfer or fail at the selected boundary.

        :param source: Controller helper path.
        :param destination: Target staging path.
        :returns: The exact supplied destination.
        :raises AnsibleConnectionFailure: The selected transfer fails.
        """
        if len(transferred) == failure_index:
            raise AnsibleConnectionFailure("owned helper transfer offline")
        transferred.append(source.rsplit("/", 1)[-1])
        return destination

    launch = {"started": True, "finished": False, "changed": False}
    executed = Mock(return_value=launch)
    monkeypatch.setattr(instance, "_transfer_file", transfer)
    monkeypatch.setattr(instance, "_execute_module", executed)
    if failure_index is not None:
        with pytest.raises(
            AnsibleConnectionFailure, match="owned helper transfer offline"
        ):
            instance.run()
        executed.assert_not_called()
        state.cleanup.assert_called_once_with("owned-temp")
        assert len(transferred) == failure_index
    else:
        assert instance.run() == launch
        assert transferred == [
            "legacy_windows_module.py",
            *win_updates._HELPERS,
            "legacy_windows_updates_async.py",
            "legacy_windows_async_native.py",
            "legacy_windows_async_worker.py",
        ]
        executed.assert_called_once_with(task_vars={}, wrap_async=60)
        state.cleanup.assert_not_called()
    assert instance._task.args == {"_operation": "test"}
    assert instance.EXTRA_MODULE_UTILS == win_updates._HELPERS


@pytest.mark.parametrize("check", [False, True])
def test_updates_search_retains_resolved_runas_and_complete_public_projection(
    action: Any, check: bool
) -> None:
    instance, state = action
    instance._connection.become = SimpleNamespace(name="runas")
    instance._task.args = {"state": "installed" if check else "searched"}
    instance._task.check_mode = check
    variables = {"inventory_hostname": "owned-server"}
    result = instance.run(task_vars=variables)
    assert result["changed"] is False
    assert result["found_update_count"] == 1
    assert result["failed_update_count"] == result["installed_update_count"] == 0
    state.round.assert_called_once_with(variables, instance._task.args, False)
    assert instance._connection.become.name == "runas"
    state.cleanup.assert_called_once_with("owned-temp")
    state.reboot.assert_not_called()


def test_updates_rejects_other_become_methods_before_target_activity(
    action: Any,
) -> None:
    instance, state = action
    instance._connection.become = SimpleNamespace(name="sudo")
    with pytest.raises(
        AnsibleActionFail,
        match="privilege escalation supports only runas",
    ):
        instance.run()
    state.round.assert_not_called()
    state.stage.assert_not_called()
    state.cleanup.assert_not_called()


def test_updates_runas_stages_existing_token_helpers_for_every_native_operation(
    action: Any, monkeypatch: pytest.MonkeyPatch
) -> None:
    instance, state = action
    instance._connection.become = SimpleNamespace(name="runas")
    transferred = Mock()
    monkeypatch.setattr(instance, "_transfer_file", transferred)
    PythonModuleAction._stage_module_utils(instance)
    helpers = [call.args[0].rsplit("/", 1)[-1] for call in transferred.call_args_list]
    assert helpers == [
        "legacy_windows_module.py",
        *win_updates._HELPERS,
        "legacy_windows_runas.py",
    ]
    executed = Mock(return_value={"changed": False})
    monkeypatch.setattr(instance, "_execute_module", executed)
    instance._invocation = None
    variables = {"inventory_hostname": "owned-server"}
    for operation in ("start", "poll", "cancel"):
        instance._execute(variables, operation)
    assert [
        call.kwargs["module_args"]["_operation"] for call in executed.call_args_list
    ] == ["start", "poll", "cancel"]
    assert all(
        call.kwargs["task_vars"] is variables for call in executed.call_args_list
    )
    assert instance._connection.become.name == "runas"
    state.cleanup.assert_not_called()


def test_initial_staging_connection_failure_is_unreachable_with_complete_empty_counts(
    action: Any, monkeypatch: pytest.MonkeyPatch
) -> None:
    instance, state = action
    monkeypatch.delattr(instance, "_round")
    state.stage.side_effect = AnsibleConnectionFailure("initial stage offline")
    result = instance.run()
    assert result["unreachable"] and not result.get("failed")
    assert result["found_update_count"] == 0 and result["updates"] == {}
    assert result["msg"] == "initial stage offline"
    assert state.stage.call_count == 1


@pytest.mark.parametrize("primary", [True, False])
def test_cleanup_disconnect_preserves_primary_or_reports_healthy_failure(
    action: Any, primary: bool, monkeypatch: pytest.MonkeyPatch
) -> None:
    instance, state = action
    state.round.return_value = _round(installed=True, failed=primary)
    state.cleanup.side_effect = AnsibleConnectionFailure("cleanup offline")
    warning = Mock()
    verbose = Mock()
    monkeypatch.setattr(win_updates._DISPLAY, "warning", warning)
    monkeypatch.setattr(win_updates._DISPLAY, "vvvv", verbose)
    result = instance.run()
    instance.cleanup()
    assert (
        result["failed"] and result["changed"] and result["installed_update_count"] == 1
    )
    assert result["msg"] == (
        "WUA failed"
        if primary
        else "Failed to remove update task directory: cleanup offline"
    )
    assert state.cleanup.call_count == 1 and verbose.call_count == 1
    warning.assert_not_called()


def test_explicit_forced_cleanup_does_not_hide_new_failure(
    action: Any, monkeypatch: pytest.MonkeyPatch
) -> None:
    instance, _state = action
    force = Mock(side_effect=AnsibleConnectionFailure("forced cleanup offline"))
    monkeypatch.setattr(PythonModuleAction, "cleanup", force)
    with pytest.raises(AnsibleConnectionFailure, match="forced cleanup offline"):
        instance.cleanup(force=True)
    force.assert_called_once_with(force=True)


def test_poll_connection_retry_is_bounded_and_reuses_exact_unacknowledged_options(
    action: Any, monkeypatch: pytest.MonkeyPatch
) -> None:
    instance, _state = action
    instance._invocation = None
    execute = Mock(
        side_effect=[
            AnsibleConnectionFailure("transient poll"),
            {"output": [], "offset": 11},
        ]
    )
    monkeypatch.setattr(instance, "_execute_module", execute)
    assert instance._execute({}, "poll", options={"offset": 9}) == {
        "output": [],
        "offset": 11,
    }
    assert execute.call_count == 2
    assert execute.call_args_list[0].kwargs == execute.call_args_list[1].kwargs
    assert execute.call_args.kwargs["module_args"]["_operation_options"] == {
        "offset": 9
    }


@pytest.mark.parametrize("operation", ["start", "cancel", "poll"])
def test_connection_failure_final_classification_does_not_duplicate_mutations(
    action: Any, operation: str, monkeypatch: pytest.MonkeyPatch
) -> None:
    instance, _state = action
    instance._invocation = None
    execute = Mock(side_effect=AnsibleConnectionFailure("offline"))
    monkeypatch.setattr(instance, "_execute_module", execute)
    with pytest.raises(AnsibleConnectionFailure):
        instance._execute({}, operation)
    assert execute.call_count == (2 if operation == "poll" else 1)


def test_round_poll_failure_always_cancels_and_preserves_primary_exception(
    action: Any, monkeypatch: pytest.MonkeyPatch
) -> None:
    instance, _state = action
    monkeypatch.delattr(instance, "_round")
    primary = AnsibleConnectionFailure("poll offline")
    execute = Mock(
        side_effect=[
            {"cancel_options": {"nonce": "owned"}, "poll_options": {"offset": 0}},
            primary,
            OSError("cancel secondary"),
        ]
    )
    monkeypatch.setattr(instance, "_execute", execute)
    with pytest.raises(AnsibleConnectionFailure) as raised:
        instance._round({}, {}, False)
    assert raised.value is primary
    assert execute.call_args.args == ({}, "cancel")
    assert execute.call_args.kwargs == {"options": {"nonce": "owned"}}


def test_completed_round_cancel_failure_is_not_reported_as_success(
    action: Any, monkeypatch: pytest.MonkeyPatch
) -> None:
    instance, _state = action
    monkeypatch.delattr(instance, "_round")
    execute = Mock(
        side_effect=[
            {"cancel_options": {}, "poll_options": {}},
            {
                "offset": 1,
                "output": [
                    {
                        "task": "exit",
                        "result": {
                            "changed": True,
                            "reboot_required": False,
                            "failed": False,
                        },
                    }
                ],
            },
            OSError("cancel failed"),
        ]
    )
    monkeypatch.setattr(instance, "_execute", execute)
    with pytest.raises(OSError, match="cancel failed"):
        instance._round({}, {}, False)


@pytest.mark.parametrize(
    "value,ready", [(None, True), (0, True), (1, True), (2, False), (3, False)]
)
def test_updates_reboot_adds_cbs_to_accepted_readiness_not_a_second_wait(
    value: int | None, ready: bool, monkeypatch: pytest.MonkeyPatch
) -> None:
    instance = object.__new__(win_updates._UpdatesReboot)
    instance._reboot_variables = {}
    native_ready = Mock()
    monkeypatch.setattr(win_reboot.ActionModule, "_ready", native_ready)
    execute = Mock(return_value={"exists": value is not None, "value": value})
    monkeypatch.setattr(instance, "_execute_module", execute)
    if ready:
        instance._ready(None, "owned-success")
    else:
        with pytest.raises(ValueError, match="CBS is still servicing"):
            instance._ready(None, "owned-success")
    native_ready.assert_called_once_with(None, "owned-success")
    assert execute.call_args.kwargs["module_args"]["name"] == "ServicingInProgress"
    assert execute.call_args.kwargs["persist_files"]


def test_external_shutdown_reboot_defers_staging_until_boot_poll_and_never_requests_again(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    instance = object.__new__(win_updates._UpdatesReboot)
    instance.previous_boot = "old-boot"
    instance.staged = False
    stage, boot, request = Mock(), Mock(), Mock()
    monkeypatch.setattr(instance, "_stage_module_utils", stage)
    monkeypatch.setattr(win_reboot.ActionModule, "_changed_boot", boot)
    monkeypatch.setattr(win_reboot.ActionModule, "_request", request)
    assert instance._stage_and_read_boot(None) == "old-boot"
    stage.assert_not_called()
    instance._request({})
    request.assert_not_called()
    instance._changed_boot("old-boot", {})
    instance._changed_boot("old-boot", {})
    stage.assert_called_once_with()
    assert boot.call_count == 2


@pytest.mark.parametrize(
    "status,expected",
    [
        (0x8024000B, "Windows Update HRESULT 0x8024000B"),
        (0x00240005, "Windows Update HRESULT 0x00240005"),
        (12345, "Windows Update HRESULT 0x00003039"),
        (-1, "Windows Update HRESULT 0xFFFFFFFF"),
    ],
)
def test_controller_hresult_projection_formats_known_unknown_and_signed_codes(
    status: int, expected: str
) -> None:
    assert describe_hresult(status) == expected
