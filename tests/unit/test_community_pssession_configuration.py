"""Exercise endpoint input and controller async/reconnection lifecycle contracts."""

# Copyright 2026 sustainablelobster
# SPDX-License-Identifier: GPL-3.0-or-later

import json
import sys
import time
from pathlib import Path
from types import ModuleType, SimpleNamespace
from typing import Any, cast

import pytest
from ansible.errors import (  # type: ignore[import-untyped]
    AnsibleActionFail,
    AnsibleConnectionFailure,
)
from ansible_collections.sustainablelobster.legacy_community_windows.plugins.action import (
    win_pssession_configuration as action_plugin,
)
from ansible_collections.sustainablelobster.legacy_windows.plugins.plugin_utils.runtime import (
    PythonModuleAction,
)

from tests.unit.payload_support import HELPER, ROOT, invoke_payload, load_module


@pytest.fixture(name="payload")
def payload_fixture(monkeypatch: pytest.MonkeyPatch) -> ModuleType:
    """Load the actual frontend with native Python3.4-compatible helpers.

    :param monkeypatch: Scoped helper import paths.
    :returns: Actual payload without invoking the Windows engine.
    """
    monkeypatch.syspath_prepend(str(HELPER.parent))
    monkeypatch.syspath_prepend(
        str(ROOT / "legacy_community_windows/plugins/module_utils")
    )
    return load_module(
        ROOT
        / "legacy_community_windows/plugins/modules/win_pssession_configuration.py",
        "community_session_configuration",
    )


def test_public_options_preserve_raw_lists_nested_definitions_and_check_diff_flags(
    payload: ModuleType,
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    requests: list[dict[str, Any]] = []

    def invoke(parameters: dict[str, Any]) -> dict[str, Any]:
        """Return an independently selected endpoint plan.

        :param parameters: Actual converted public option values.
        :returns: Plan with an independently chosen observable diff.
        """
        requests.append(parameters)
        return {"changed": True, "diff": {"before": {}, "after": {"Name": "Fixture"}}}

    monkeypatch.setattr(payload, "invoke", invoke)
    arguments = {
        "name": "Fixture",
        "processor_architecure": "AMD64",
        "session_type": "restricted_remote_server",
        "visible_cmdlets": [{"Name": "Get-Service", "Parameters": [{"Name": "Name"}]}],
        "role_definitions": {"DOMAIN\\Fixture": {"RoleCapabilities": "Restricted"}},
        "run_as_virtual_account": "yes",
        "guid": "5c0f796eb68c4715841fc8d04b475829",
        "_ansible_check_mode": True,
        "_ansible_diff": True,
    }
    argument_file = tmp_path / "session.json"
    argument_file.write_text(json.dumps(arguments), encoding="utf-8")
    monkeypatch.setattr(sys, "argv", [str(payload.__file__), str(argument_file)])
    status, result = invoke_payload(payload, capsys)
    assert status == 0 and result["changed"] is True
    assert result["diff"]["after"]["Name"] == "Fixture"
    request = requests[0]
    assert request["visible_cmdlets"] == arguments["visible_cmdlets"]
    assert request["role_definitions"] == arguments["role_definitions"]
    assert request["guid"] == arguments["guid"]
    assert request["processor_architecure"] == "amd64"
    assert request["run_as_virtual_account"] is True
    assert request["check_mode"] is True and request["diff_mode"] is True
    assert request["async_timeout"] == 300 and request["async_poll"] == 1


@pytest.mark.parametrize(
    "arguments",
    [
        {},
        {"name": "Fixture", "access_mode": "internet"},
        {"name": "Fixture", "run_as_credential_username": "FixtureUser"},
        {"name": "Fixture", "run_as_credential_password": "secret"},
        {"name": "Fixture", "async_poll": True},
        {"name": "Fixture", "visible_cmdlets": 12},
    ],
)
def test_invalid_public_options_fail_before_any_mutation(
    payload: ModuleType,
    arguments: dict[str, Any],
) -> None:
    with pytest.raises(ValueError):
        getattr(payload, "_parameters")(arguments)


# A child Ansible action's only public operation is run().
class Driver:  # pylint: disable=too-few-public-methods
    """Return independent child-action replies, including connection failures."""

    def __init__(self, responses: list[Any]) -> None:
        self.responses = responses
        self.calls = 0

    def run(self, **_arguments: Any) -> dict[str, Any]:
        """Return the next independent action response or raise its chosen error.

        :param _arguments: Parent-provided task variables, not interpreted here.
        :returns: Independent child-action result.
        :raises BaseException: A selected transport or interruption exception.
        """
        self.calls += 1
        response = self.responses.pop(0)
        if isinstance(response, BaseException):
            raise response
        return dict(response)


@pytest.fixture(name="controller")
def controller_fixture(monkeypatch: pytest.MonkeyPatch) -> SimpleNamespace:
    """Isolate only the ordinary executor and independently scripted child actions.

    :param monkeypatch: Scoped executor, connection and clock boundaries.
    :returns: Actual custom action plus independently controlled collaborators.
    """
    task = SimpleNamespace(args={}, check_mode=False, async_val=0, poll=15)
    state = SimpleNamespace(
        task=task,
        launch={"ansible_job_id": "owned-job", "started": True},
        launch_error=None,
        parent_calls=[],
        loaded=[],
        resets=[],
        status=Driver([{"finished": True, "changed": True}]),
        cleanup=Driver([{"erased": "owned-job"}]),
        ping=Driver([{"ping": "pong"}]),
    )
    action = object.__new__(action_plugin.ActionModule)
    monkeypatch.setattr(action, "_task", task, raising=False)
    monkeypatch.setattr(
        action,
        "_connection",
        SimpleNamespace(reset=lambda: state.resets.append(True)),
        raising=False,
    )

    def _parent_run(
        _action: object, _tmp: object, _task_vars: object
    ) -> dict[str, Any]:
        state.parent_calls.append((task.async_val, task.poll, task.check_mode))
        if state.launch_error:
            raise state.launch_error
        return dict(state.launch)

    def _load(name: str, arguments: dict[str, Any]) -> Driver:
        state.loaded.append((name, arguments))
        if name.endswith("win_ping"):
            return cast(Driver, state.ping)
        return cast(
            Driver,
            state.cleanup if arguments.get("mode") == "cleanup" else state.status,
        )

    monkeypatch.setattr(PythonModuleAction, "run", _parent_run)
    monkeypatch.setattr(action, "_load_action", _load)
    monkeypatch.setattr(time, "sleep", lambda _seconds: None)
    clock = iter(index / 2 for index in range(10000))
    monkeypatch.setattr(time, "monotonic", lambda: next(clock))
    state.action = action
    return state


def test_implicit_async_is_polled_cleaned_and_hidden_from_public_result(
    controller: SimpleNamespace,
) -> None:
    controller.status = Driver(
        [
            {"finished": False},
            {
                "finished": True,
                "changed": True,
                "ansible_job_id": "owned-job",
                "started": True,
                "output": "done",
            },
        ]
    )
    result = controller.action.run(task_vars={"fixture": "preserved"})
    assert result == {"changed": True, "output": "done"}
    assert controller.parent_calls == [(300, 0, False)]
    assert controller.status.calls == 2 and controller.cleanup.calls == 1
    assert controller.task.async_val == 0 and controller.task.poll == 15
    assert controller.loaded == [
        ("sustainablelobster.legacy_windows.async_status", {"jid": "owned-job"}),
        (
            "sustainablelobster.legacy_windows.async_status",
            {"jid": "owned-job", "mode": "cleanup"},
        ),
    ]


def test_check_mode_is_synchronous_and_creates_no_async_job(
    controller: SimpleNamespace,
) -> None:
    controller.task.check_mode = True
    controller.launch = {"changed": True, "diff": {"after": "preview"}}
    assert controller.action.run() == controller.launch
    assert controller.parent_calls == [(0, 15, True)]
    assert controller.loaded == []


@pytest.mark.parametrize(
    "arguments", [{"async_poll": 0}, {"async_timeout": -1}, {"async_poll": "bad"}]
)
def test_invalid_poll_controls_fail_without_starting_a_job(
    controller: SimpleNamespace,
    arguments: dict[str, Any],
) -> None:
    controller.task.args = arguments
    with pytest.raises(AnsibleActionFail):
        controller.action.run()
    assert controller.parent_calls == []


def test_external_async_is_rejected_before_starting_an_implicit_job(
    controller: SimpleNamespace,
) -> None:
    controller.task.async_val = 45
    with pytest.raises(AnsibleActionFail, match="external async"):
        controller.action.run()
    assert controller.parent_calls == []


def test_connection_failure_uses_existing_native_ping_and_resumes_polling(
    controller: SimpleNamespace,
) -> None:
    controller.status = Driver(
        [AnsibleConnectionFailure("owned restart"), {"finished": True, "changed": True}]
    )
    assert controller.action.run() == {"changed": True}
    assert controller.resets == [True]
    assert controller.ping.calls == 1
    assert controller.cleanup.calls == 1


def test_finished_module_failure_is_returned_and_cleaned_without_restarting_it(
    controller: SimpleNamespace,
) -> None:
    controller.status = Driver(
        [{"finished": True, "changed": True, "failed": True, "msg": "vendor rejected"}]
    )
    assert controller.action.run() == {
        "changed": True,
        "failed": True,
        "msg": "vendor rejected",
    }
    assert len(controller.parent_calls) == 1
    assert controller.cleanup.calls == 1 and controller.resets == []


def test_poll_interruption_restores_task_settings_and_attempts_owned_cleanup(
    controller: SimpleNamespace,
) -> None:
    controller.status = Driver([KeyboardInterrupt()])
    with pytest.raises(KeyboardInterrupt):
        controller.action.run()
    assert controller.task.async_val == 0 and controller.task.poll == 15
    assert controller.cleanup.calls == 1


def test_launch_failure_restores_original_task_settings(
    controller: SimpleNamespace,
) -> None:
    controller.launch_error = AnsibleConnectionFailure("failed launch")
    with pytest.raises(AnsibleConnectionFailure, match="failed launch"):
        controller.action.run()
    assert controller.task.async_val == 0 and controller.task.poll == 15
    assert controller.cleanup.calls == 0


def test_timeout_is_bounded_and_still_cleans_owned_status(
    controller: SimpleNamespace,
) -> None:
    controller.task.args = {"async_timeout": 1}
    controller.status = Driver([{"finished": False}])
    result = controller.action.run()
    assert result["failed"] is True and "async_timeout" in result["msg"]
    assert controller.cleanup.calls == 1


def test_cleanup_failure_does_not_hide_a_successful_module_result(
    controller: SimpleNamespace,
) -> None:
    controller.cleanup = Driver([OSError("fixture cleanup failed")])
    assert controller.action.run() == {"changed": True}
    assert controller.task.async_val == 0 and controller.task.poll == 15
