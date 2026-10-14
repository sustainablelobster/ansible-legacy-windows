"""Exercise reboot coordination through substituted controller connections."""

# SPDX-License-Identifier: GPL-3.0-or-later
# These connection/clock substitutes are controller-only evidence.
# Ansible's fake task/connection state must exercise its internal action fields.
# pylint: disable=protected-access

import random
import time
from ntpath import join as windows_join
from pathlib import Path
from types import SimpleNamespace
from typing import Any
from unittest.mock import Mock

import pytest

# Ansible's extension interfaces do not distribute typing metadata.
from ansible.errors import (  # type: ignore[import-untyped]
    AnsibleActionFail,
    AnsibleConnectionFailure,
    AnsibleError,
)
from ansible_collections.sustainablelobster.legacy_windows.plugins.action import (
    win_reboot,
)


@pytest.fixture(name="action")
def reboot_action(monkeypatch: pytest.MonkeyPatch) -> tuple[Any, Any]:
    """Supply a controller action with an explicit fake connection and clock.

    :param monkeypatch: Scoped transport and wall-clock substitutes.
    :returns: Action and retained calls, responses, timeout and cleanup state.
    """
    state = SimpleNamespace(calls=[], cleanup=[], time=0.0, timeout=30, responses={})
    instance = object.__new__(win_reboot.ActionModule)
    instance._task = SimpleNamespace(  # pylint: disable=protected-access
        args={},
        action="sustainablelobster.legacy_windows.win_reboot",
        check_mode=False,
        async_val=0,
    )
    instance._connection = SimpleNamespace(  # pylint: disable=protected-access
        become=None,
        _shell=SimpleNamespace(
            tmpdir=r"C:\Temp\ansible-tmp-reboot", join_path=windows_join
        ),
        close=Mock(),
        reset=Mock(),
        get_option=lambda _name: state.timeout,
        set_option=lambda _name, value: setattr(state, "timeout", value),
    )
    monkeypatch.setattr(
        instance, "_stage_module_utils", lambda: state.calls.append("stage")
    )
    monkeypatch.setattr(instance, "_remove_tmp_path", state.cleanup.append)
    monkeypatch.setattr(time, "monotonic", lambda: state.time)
    monkeypatch.setattr(random, "randint", lambda *_args: 0)
    monkeypatch.setattr(
        time,
        "sleep",
        lambda value: setattr(state, "time", state.time + value),
    )
    state.responses = {
        "boot": ["before", "after"],
        "request": [0],
        "ready": [0],
        "abort": [0],
    }

    def _execute(**kwargs: Any) -> dict[str, Any]:
        state.calls.append(kwargs)
        parameters = kwargs["module_args"]
        operation = parameters["_operation"]
        responses = state.responses[operation]
        value = responses.pop(0) if len(responses) > 1 else responses[0]
        if isinstance(value, Exception):
            raise value
        if isinstance(value, dict):
            return value
        if operation == "boot":
            return {"rc": 0, "stdout": value, "stderr": ""}
        return {"rc": value, "stdout": parameters.get("expected", ""), "stderr": ""}

    monkeypatch.setattr(instance, "_execute_module", _execute)
    return instance, state


@pytest.mark.parametrize("args", [{}, {"unknown": True}, {"reboot_timeout": object()}])
@pytest.mark.parametrize("method", [None, "runas", "sudo"])
def test_check_mode_never_validates_or_contacts_target(
    action: Any, args: Any, method: str | None
) -> None:
    instance, state = action
    instance._connection.become = SimpleNamespace(name=method) if method else None
    instance._task.check_mode = True  # pylint: disable=protected-access
    instance._task.args = args  # pylint: disable=protected-access
    assert instance.run() == {"changed": True, "elapsed": 0, "rebooted": True}
    assert state.calls == state.cleanup == []


@pytest.mark.parametrize(
    "name",
    ["connect_timeout", "post_reboot_delay", "pre_reboot_delay", "reboot_timeout"],
)
@pytest.mark.parametrize("value", [0, None, False, "", -1, 1, 2.5, "4.5"])
def test_numeric_defaults_and_alias_truthiness(name: str, value: Any) -> None:
    primary = win_reboot._parameters({name: value})  # pylint: disable=protected-access
    alias = win_reboot._parameters(
        {name + "_sec": value}
    )  # pylint: disable=protected-access
    assert primary == alias
    assert primary[name] >= (2 if name == "pre_reboot_delay" else 0)


def test_primary_truthy_value_precedes_alias() -> None:
    convert = win_reboot._parameters  # pylint: disable=protected-access
    assert (
        convert({"reboot_timeout": 4, "reboot_timeout_sec": 9})["reboot_timeout"] == 4
    )
    assert (
        convert({"reboot_timeout": 0, "reboot_timeout_sec": 9})["reboot_timeout"] == 9
    )
    assert convert({"shutdown_timeout": object()}) == convert({})


@pytest.mark.parametrize(
    "name", ["connect_timeout", "reboot_timeout", "post_reboot_delay"]
)
def test_invalid_numeric_argument_is_actionable(name: str) -> None:
    with pytest.raises(AnsibleError) as raised:
        win_reboot._parameters(
            {name: "not numeric"}
        )  # pylint: disable=protected-access
    assert str(raised.value) == (
        f"Invalid value given for '{name}': "
        "<class 'str'> cannot be converted to a float."
    )


@pytest.mark.parametrize("method", [None, "runas"])
def test_success_uses_distinct_boot_and_readiness_phases_and_cleans(
    action: Any, method: str | None
) -> None:
    instance, state = action
    instance._connection.become = SimpleNamespace(name=method) if method else None
    assert instance.run(task_vars={"retained": True}) == {
        "changed": True,
        "elapsed": 0,
        "failed": False,
        "unreachable": False,
        "rebooted": True,
    }
    calls = state.calls[1:]
    assert [call["module_args"]["_operation"] for call in calls] == [
        "boot",
        "request",
        "boot",
        "ready",
    ]
    assert all(call["persist_files"] for call in calls)
    assert all("delete_remote_tmp" not in call for call in calls)
    assert all(not call["wrap_async"] for call in calls)
    assert all(call["task_vars"] == {"retained": True} for call in calls)
    assert state.timeout == 30 and len(state.cleanup) == 1
    instance.cleanup()
    assert len(state.cleanup) == 1


def test_post_delay_counts_toward_elapsed_not_poll_deadline(action: Any) -> None:
    instance, state = action
    instance._task.args = {"post_reboot_delay": 8}  # pylint: disable=protected-access
    assert instance.run()["elapsed"] == 8
    assert state.time == 8


@pytest.mark.parametrize(
    "failure",
    [AnsibleConnectionFailure("offline"), AnsibleError("bad initial command")],
)
def test_initial_connection_failure_does_not_claim_a_reboot(
    action: Any, failure: Any
) -> None:
    instance, state = action
    state.responses["boot"] = [failure]
    result = instance.run()
    assert not result["changed"] and not result["rebooted"] and result["elapsed"] == 0
    assert result["unreachable"] == isinstance(failure, AnsibleConnectionFailure)
    assert result["failed"] != result["unreachable"]
    assert len(state.cleanup) == 1
    assert not any(
        call.get("module_args", {}).get("_operation") == "request"
        for call in state.calls
        if isinstance(call, dict)
    )


def test_failed_initial_boot_retains_complete_command_streams(action: Any) -> None:
    instance, state = action
    state.responses["boot"] = [
        {"rc": 7, "stdout": "full output", "stderr": "full error"}
    ]
    result = instance.run()
    assert result["failed"] and not result["changed"]
    assert (
        result["rc"] == 7
        and result["stdout"] == "full output"
        and result["stderr"] == "full error"
    )


def test_scheduled_shutdown_is_aborted_once_and_replaced(
    action: Any, monkeypatch: pytest.MonkeyPatch
) -> None:
    instance, state = action
    warning = Mock()
    monkeypatch.setattr(
        win_reboot._DISPLAY, "warning", warning
    )  # pylint: disable=protected-access
    state.responses["request"] = [1190, 0]
    assert not instance.run()["failed"]
    operations = [
        call["module_args"]["_operation"]
        for call in state.calls
        if isinstance(call, dict)
    ]
    assert operations == ["boot", "request", "abort", "request", "boot", "ready"]
    # Preserve the original public warning's hyphenated spelling.
    warning.assert_called_once_with(
        "A scheduled reboot was pre-empted by Ansible."  # codespell:ignore
    )


def test_repeated_scheduled_shutdown_failure_is_not_retried_forever(
    action: Any,
) -> None:
    instance, state = action
    state.responses["request"] = [1190]
    result = instance.run()
    assert result["failed"] and result["rc"] == 1190 and not result["rebooted"]


def test_shutdown_connection_loss_still_verifies_boot_and_readiness(
    action: Any,
) -> None:
    instance, state = action
    state.responses["request"] = [AnsibleConnectionFailure("shutdown disconnected")]
    assert instance.run()["rebooted"]
    assert state.calls[-1]["module_args"]["_operation"] == "ready"


@pytest.mark.parametrize("phase", ["boot", "ready"])
def test_phase_timeout_preserves_reboot_flags_and_separate_label(
    action: Any, phase: str
) -> None:
    instance, state = action
    instance._task.args = {"reboot_timeout": 3}  # pylint: disable=protected-access
    state.responses[phase] = ["before"] if phase == "boot" else [1]
    result = instance.run()
    assert result["failed"] and result["changed"] and result["rebooted"]
    assert result["elapsed"] >= 3
    label = "last boot time check" if phase == "boot" else "post-reboot test command"
    assert result["msg"] == f"Timed out waiting for {label} (timeout=3.0)"
    assert len(state.cleanup) == 1


@pytest.mark.parametrize(("timeout", "timeout_text"), [(-1, "0"), ("0", "0.0")])
@pytest.mark.parametrize("phase", ["boot", "ready"])
def test_zero_timeout_attempts_failing_phase_once_and_reports_failure(
    action: Any, timeout: Any, timeout_text: str, phase: str
) -> None:
    instance, state = action
    instance._task.args = {"reboot_timeout": timeout}
    state.responses[phase] = ["before"] if phase == "boot" else [1]
    result = instance.run()
    assert result["failed"] and result["changed"] and result["rebooted"]
    label = "last boot time check" if phase == "boot" else "post-reboot test command"
    assert result["msg"] == f"Timed out waiting for {label} (timeout={timeout_text})"
    operations = [
        call["module_args"]["_operation"]
        for call in state.calls
        if isinstance(call, dict)
    ]
    assert operations == (
        ["boot", "request", "boot"]
        if phase == "boot"
        else ["boot", "request", "boot", "ready"]
    )
    assert result["elapsed"] == 1 and len(state.cleanup) == 1


@pytest.mark.parametrize("timeout", [-1, "0"])
def test_zero_timeout_accepts_immediate_boot_and_readiness_success(
    action: Any, timeout: Any
) -> None:
    instance, state = action
    instance._task.args = {"reboot_timeout": timeout}
    assert instance.run() == {
        "changed": True,
        "elapsed": 0,
        "failed": False,
        "unreachable": False,
        "rebooted": True,
    }
    operations = [
        call["module_args"]["_operation"]
        for call in state.calls
        if isinstance(call, dict)
    ]
    assert operations == ["boot", "request", "boot", "ready"]


def test_transient_initial_staging_failure_retries_and_completes_reboot(
    action: Any, monkeypatch: pytest.MonkeyPatch
) -> None:
    instance, state = action
    staging = Mock(
        side_effect=[AnsibleConnectionFailure("offline during transfer"), None]
    )
    monkeypatch.setattr(instance, "_stage_module_utils", staging)
    result = instance.run()
    assert not result["failed"] and not result["unreachable"]
    assert result["changed"] and result["rebooted"]
    assert staging.call_count == 2
    assert state.time == 1 and len(state.cleanup) == 1
    assert [call["module_args"]["_operation"] for call in state.calls] == [
        "boot",
        "request",
        "boot",
        "ready",
    ]


@pytest.mark.parametrize(
    "failure",
    [
        AnsibleConnectionFailure("staging remains offline"),
        AnsibleError("transfer failed"),
    ],
)
def test_final_initial_staging_failure_retries_then_classifies_without_reboot(
    action: Any, monkeypatch: pytest.MonkeyPatch, failure: Any
) -> None:
    instance, state = action
    staging = Mock(side_effect=failure)
    monkeypatch.setattr(instance, "_stage_module_utils", staging)
    result = instance.run()
    assert not result["changed"] and not result["rebooted"] and result["elapsed"] == 0
    assert result["unreachable"] == isinstance(failure, AnsibleConnectionFailure)
    assert result["failed"] != result["unreachable"]
    assert result["msg"] == str(failure) and str(failure) in result["exception"]
    assert staging.call_count == 3 and state.time == 7
    assert state.calls == [] and len(state.cleanup) == 1


@pytest.mark.parametrize("recover", [False, True])
def test_real_base_run_defers_temporary_directory_creation_into_initial_retry(
    action: Any, monkeypatch: pytest.MonkeyPatch, recover: bool
) -> None:
    instance, state = action
    instance._connection._shell.tmpdir = None
    attempts = []

    def make_directory() -> None:
        attempts.append("make directory")
        if not recover or len(attempts) == 1:
            raise AnsibleConnectionFailure("offline during directory creation")
        instance._connection._shell.tmpdir = r"C:\Temp\ansible-tmp-reboot"

    transfers = Mock()
    monkeypatch.setattr(instance, "_make_tmp_path", make_directory)
    monkeypatch.setattr(instance, "_transfer_file", transfers)
    monkeypatch.delattr(instance, "_stage_module_utils")
    result = instance.run()
    instance.cleanup()
    assert len(attempts) == (2 if recover else 3)
    assert result["unreachable"] != recover and not result["failed"]
    assert result["changed"] == result["rebooted"] == recover
    if recover:
        assert transfers.call_count == 1 + len(instance.EXTRA_MODULE_UTILS)
        assert [call["module_args"]["_operation"] for call in state.calls] == [
            "boot",
            "request",
            "boot",
            "ready",
        ]
    else:
        assert result["msg"] == "offline during directory creation"
        assert result["elapsed"] == 0 and state.calls == []
        transfers.assert_not_called()
    assert len(state.cleanup) == 1


@pytest.mark.parametrize("args", [{"unknown": True}, {"reboot_timeout": "invalid"}])
def test_real_base_argument_validation_precedes_any_temporary_directory_creation(
    action: Any, monkeypatch: pytest.MonkeyPatch, args: dict[str, Any]
) -> None:
    instance, state = action
    instance._task.args = args
    instance._connection._shell.tmpdir = None
    staging = Mock()
    make_directory = Mock()
    monkeypatch.setattr(instance, "_stage_module_utils", staging)
    monkeypatch.setattr(instance, "_make_tmp_path", make_directory)
    with pytest.raises(AnsibleError):
        instance.run()
    instance.cleanup()
    staging.assert_not_called()
    make_directory.assert_not_called()
    assert state.calls == state.cleanup == []


@pytest.mark.parametrize("phase", ["initial", "request", "ready"])
def test_cleanup_disconnect_preserves_primary_failure_and_reboot_state(
    action: Any, monkeypatch: pytest.MonkeyPatch, phase: str
) -> None:
    instance, state = action
    if phase == "initial":
        state.responses["boot"] = [AnsibleConnectionFailure("initial host offline")]
    elif phase == "request":
        state.responses["request"] = [
            {"rc": 7, "stdout": "full output", "stderr": "full error"}
        ]
    else:
        instance._task.args = {"reboot_timeout": 3}
        state.responses["ready"] = [1]
    cleanup = Mock(side_effect=AnsibleConnectionFailure("cleanup host offline"))
    verbose = Mock()
    warning = Mock()
    monkeypatch.setattr(instance, "_remove_tmp_path", cleanup)
    monkeypatch.setattr(win_reboot._DISPLAY, "vvvv", verbose)
    monkeypatch.setattr(win_reboot._DISPLAY, "warning", warning)
    result = instance.run()
    instance.cleanup()
    assert result["unreachable"] == (phase == "initial")
    assert result["failed"] == (phase != "initial")
    assert result["changed"] == result["rebooted"] == (phase == "ready")
    assert result["elapsed"] == (3 if phase == "ready" else 0)
    assert "cleanup host offline" not in result["msg"]
    assert "cleanup host offline" not in result["exception"]
    if phase == "initial":
        assert result["msg"] == "initial host offline"
    elif phase == "request":
        assert result["msg"].endswith(": Reboot command failed")
        assert result["rc"] == 7
        assert result["stdout"] == "full output" and result["stderr"] == "full error"
    else:
        assert result["msg"] == (
            "Timed out waiting for post-reboot test command (timeout=3.0)"
        )
    cleanup.assert_called_once_with(r"C:\Temp\ansible-tmp-reboot")
    verbose.assert_called_once_with(
        "Failed to remove reboot task directory C:\\Temp\\ansible-tmp-reboot: "
        "cleanup host offline"
    )
    warning.assert_not_called()


@pytest.mark.parametrize(
    "failure",
    [AnsibleConnectionFailure("cleanup offline"), AnsibleError("access denied")],
)
def test_cleanup_failure_after_success_is_actionable_and_retains_successful_reboot(
    action: Any, monkeypatch: pytest.MonkeyPatch, failure: Any
) -> None:
    instance, _state = action
    instance._task.args = {"post_reboot_delay": 8}
    cleanup = Mock(side_effect=failure)
    verbose = Mock()
    warning = Mock()
    monkeypatch.setattr(instance, "_remove_tmp_path", cleanup)
    monkeypatch.setattr(win_reboot._DISPLAY, "vvvv", verbose)
    monkeypatch.setattr(win_reboot._DISPLAY, "warning", warning)
    result = instance.run()
    instance.cleanup()
    assert result["failed"] and not result["unreachable"]
    assert result["changed"] and result["rebooted"] and result["elapsed"] == 8
    assert result["msg"] == (
        "Failed to remove reboot task directory C:\\Temp\\ansible-tmp-reboot: "
        + str(failure)
    )
    assert str(failure) in result["exception"]
    cleanup.assert_called_once_with(r"C:\Temp\ansible-tmp-reboot")
    verbose.assert_called_once_with(result["msg"])
    warning.assert_not_called()


def test_explicit_forced_cleanup_retries_and_reports_a_persistent_disconnect(
    action: Any, monkeypatch: pytest.MonkeyPatch
) -> None:
    instance, _state = action
    cleanup = Mock(side_effect=AnsibleConnectionFailure("cleanup remains offline"))
    monkeypatch.setattr(instance, "_remove_tmp_path", cleanup)
    result = instance.run()
    retained = dict(result)
    instance.cleanup()
    assert cleanup.call_count == 1
    with pytest.raises(AnsibleConnectionFailure, match="cleanup remains offline"):
        instance.cleanup(force=True)
    assert cleanup.call_count == 2 and result == retained


def test_explicit_forced_cleanup_can_recover_after_a_reported_disconnect(
    action: Any, monkeypatch: pytest.MonkeyPatch
) -> None:
    instance, _state = action
    cleanup = Mock(side_effect=[AnsibleConnectionFailure("cleanup offline"), None])
    monkeypatch.setattr(instance, "_remove_tmp_path", cleanup)
    result = instance.run()
    instance.cleanup(force=True)
    assert cleanup.call_count == 2 and result["failed"]
    assert result["changed"] and result["rebooted"]


def test_unexpected_cleanup_exception_is_not_suppressed(
    action: Any, monkeypatch: pytest.MonkeyPatch
) -> None:
    instance, _state = action
    monkeypatch.setattr(
        instance, "_remove_tmp_path", Mock(side_effect=RuntimeError("cleanup bug"))
    )
    with pytest.raises(RuntimeError, match="cleanup bug"):
        instance.run()


@pytest.mark.parametrize("method", ["sudo", "su", "invalid"])
def test_other_become_methods_rejected_before_staging(action: Any, method: str) -> None:
    instance, state = action
    instance._connection.become = SimpleNamespace(name=method)
    with pytest.raises(AnsibleActionFail, match="supports only runas"):
        instance.run()
    assert state.calls == state.cleanup == []


def test_runas_binding_survives_reconnection_and_task_cleanup(action: Any) -> None:
    instance, state = action
    plugin = SimpleNamespace(name="runas")
    instance._connection.become = plugin
    state.responses["boot"] = [
        "before",
        AnsibleConnectionFailure("restart disconnected transport"),
        "after",
    ]
    result = instance.run()
    assert result["changed"] and result["rebooted"] and not result["failed"]
    instance._connection.reset.assert_called()
    assert instance._connection.become is plugin
    assert len(state.cleanup) == 1
    assert [
        call["module_args"]["_operation"]
        for call in state.calls
        if isinstance(call, dict)
    ] == ["boot", "request", "boot", "boot", "ready"]


@pytest.mark.parametrize("failure", ["initial", "request", "ready"])
def test_runas_failures_preserve_reboot_state_and_cleanup(
    action: Any, failure: str
) -> None:
    instance, state = action
    instance._connection.become = SimpleNamespace(name="runas")
    if failure == "initial":
        state.responses["boot"] = [
            {"failed": True, "msg": "Runas logon failed (Windows error 1326)."}
        ]
    elif failure == "request":
        state.responses["request"] = [{"rc": 5, "stdout": "", "stderr": "denied"}]
    else:
        instance._task.args = {"reboot_timeout": 3}
        state.responses["ready"] = [1]
    result = instance.run()
    assert result["failed"] and not result["unreachable"]
    assert result["changed"] == result["rebooted"] == (failure == "ready")
    assert len(state.cleanup) == 1
    if failure == "initial":
        assert all(
            call["module_args"]["_operation"] == "boot"
            for call in state.calls
            if isinstance(call, dict)
        )
        assert "1326" in result["stderr"]


def test_failed_runas_wrapper_retains_native_diagnostics(action: Any) -> None:
    instance, state = action
    instance._connection.become = SimpleNamespace(name="runas")
    state.responses["boot"] = [
        {
            "failed": True,
            "msg": "Module result deserialization failed: No start of json char found",
            "module_stdout": "wrapper output",
            "module_stderr": (
                "Native runas failed: [WinError 1332] "
                "No mapping between account names and security IDs was done."
            ),
        }
    ]
    result = instance.run()
    assert result["failed"] and not result["rebooted"] and not result["changed"]
    assert result["stdout"] == "wrapper output"
    assert "1332" in result["stderr"] and "security IDs" in result["stderr"]
    assert len(state.cleanup) == 1


def test_every_explicit_helper_exists() -> None:
    directory = Path(win_reboot.__file__).parents[1] / "module_utils"
    assert all(
        (directory / name).is_file()
        for name in win_reboot.ActionModule.EXTRA_MODULE_UTILS
    )
