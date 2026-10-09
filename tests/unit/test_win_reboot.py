"""Check the reboot action's internal JSON phases without contacting Windows."""

# SPDX-License-Identifier: GPL-3.0-or-later

import json
import sys
from collections.abc import Callable
from pathlib import Path
from types import ModuleType
from typing import Any
from unittest.mock import Mock, call

import pytest

from tests.unit.payload_support import invoke_payload, load_payload

RequestRunner = Callable[[object], tuple[int, dict[str, Any]]]
OPERATIONS = (
    "observe_boot",
    "observe_readiness",
    "request_reboot",
    "abort_reboot",
)
RESULT = {"rc": 0, "stdout": "first line\r\nsecond 雪", "stderr": "diagnostic\nline"}


@pytest.fixture(name="native")
def reboot_operations() -> Mock:
    """Record each internal operation and return a fresh command result.

    :returns: Native-operation substitutes that do not access Windows.
    """
    native = Mock(spec=OPERATIONS)
    for name in OPERATIONS:
        getattr(native, name).side_effect = lambda *_args: dict(RESULT)
    return native


@pytest.fixture(name="payload")
def reboot_payload(native: Mock, monkeypatch: pytest.MonkeyPatch) -> ModuleType:
    """Load the frontend with its entire native boundary substituted.

    :param native: Recorders for the four reboot operations.
    :param monkeypatch: Scoped native-helper and import substitutions.
    :returns: Payload with real JSON argument binding and result serialization.
    """
    helper = ModuleType("legacy_windows_reboot_request")
    for name in OPERATIONS:
        monkeypatch.setattr(helper, name, getattr(native, name), raising=False)
    monkeypatch.setitem(sys.modules, "legacy_windows_reboot_request", helper)
    return load_payload("win_reboot", monkeypatch)


@pytest.fixture(name="run_request")
def reboot_invocation(
    payload: ModuleType,
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
) -> RequestRunner:
    """Run real argument files through the payload's JSON entry point.

    :param payload: Loaded frontend with native operations substituted.
    :param monkeypatch: Scoped script arguments.
    :param tmp_path: Isolated directory for the request file.
    :param capsys: Capture of the payload's JSON output.
    :returns: Runner for the internal action's argument document.
    """
    argument_file = tmp_path / "arguments.json"
    monkeypatch.setattr(sys, "argv", ["win_reboot.py", str(argument_file)])

    def _run_request(arguments: object) -> tuple[int, dict[str, Any]]:
        argument_file.write_text(json.dumps(arguments), encoding="utf-8")
        return invoke_payload(payload, capsys)

    return _run_request


@pytest.mark.parametrize(
    ("arguments", "expected_call"),
    [
        ({"_operation": "boot"}, call.observe_boot(None)),
        (
            {"_operation": "ready", "expected": "success-controller-token"},
            call.observe_readiness(None, "success-controller-token"),
        ),
        (
            {
                "_operation": "request",
                "delay": 7.9,
                "message": 'Restart "quoted" 雪',
                "default_readiness": True,
            },
            call.request_reboot(7.9, 'Restart "quoted" 雪', True),
        ),
        ({"_operation": "abort"}, call.abort_reboot()),
    ],
)
def test_each_phase_dispatches_once_and_preserves_complete_command_result(
    native: Mock,
    run_request: RequestRunner,
    arguments: dict[str, object],
    expected_call: Any,
) -> None:
    assert run_request(arguments) == (0, {**RESULT, "changed": False})
    assert native.mock_calls == [expected_call]


@pytest.mark.parametrize("phase", ["boot", "ready"])
@pytest.mark.parametrize(
    ("value", "expected"),
    [(None, None), ("", ""), ("Write-Output '雪'", "Write-Output '雪'"), (42, "42")],
)
def test_boot_and_readiness_commands_use_shared_string_binding(
    native: Mock,
    run_request: RequestRunner,
    phase: str,
    value: object,
    expected: str | None,
) -> None:
    arguments = {"_operation": phase, "command": value}
    if phase == "ready":
        arguments["expected"] = "success-token"
    assert run_request(arguments) == (0, {**RESULT, "changed": False})
    expected_call = (
        call.observe_boot(expected)
        if phase == "boot"
        else call.observe_readiness(expected, "success-token")
    )
    assert native.mock_calls == [expected_call]


@pytest.mark.parametrize(
    ("value", "expected"), [(True, True), (False, False), ("yes", True), ("off", False)]
)
def test_request_converts_numeric_delay_and_boolean_readiness_before_dispatch(
    native: Mock, run_request: RequestRunner, value: object, expected: bool
) -> None:
    assert run_request(
        {
            "_operation": "request",
            "delay": "2.5",
            "message": 42,
            "default_readiness": value,
        }
    ) == (0, {**RESULT, "changed": False})
    assert native.mock_calls == [call.request_reboot(2.5, "42", expected)]


def test_phase_argument_names_and_controller_flags_bind_case_insensitively(
    native: Mock, run_request: RequestRunner
) -> None:
    assert run_request(
        {
            "_OPERATION": "ready",
            "COMMAND": "exit 0",
            "EXPECTED": "success-token",
            "_ANSIBLE_IGNORE_UNKNOWN_OPTS": True,
            "ignored": "value",
        }
    ) == (0, {**RESULT, "changed": False})
    assert native.mock_calls == [call.observe_readiness("exit 0", "success-token")]


def test_nonzero_native_exit_is_returned_for_the_controller_to_interpret(
    native: Mock, run_request: RequestRunner
) -> None:
    native.abort_reboot.side_effect = None
    native.abort_reboot.return_value = {
        "rc": 1116,
        "stdout": "",
        "stderr": "No shutdown was in progress.",
    }
    assert run_request({"_operation": "abort"}) == (
        0,
        {
            "changed": False,
            "rc": 1116,
            "stdout": "",
            "stderr": "No shutdown was in progress.",
        },
    )
    native.abort_reboot.assert_called_once_with()


@pytest.mark.parametrize(
    "arguments", [{}, {"_operation": None}, {"_operation": "reboot"}]
)
def test_missing_or_unknown_internal_phase_fails_without_native_operations(
    native: Mock, run_request: RequestRunner, arguments: dict[str, object]
) -> None:
    assert run_request(arguments) == (
        1,
        {
            "changed": False,
            "failed": True,
            "msg": "win_reboot must be invoked through its controller action.",
        },
    )
    assert native.mock_calls == []


def test_public_options_cannot_bypass_the_controller_action(
    native: Mock, run_request: RequestRunner
) -> None:
    assert run_request({"_operation": "boot", "reboot_timeout": 900}) == (
        1,
        {
            "changed": False,
            "failed": True,
            "msg": (
                "Unsupported parameters for (sustainablelobster.legacy_windows.win_reboot) "
                "module: reboot_timeout. Supported parameters include: _operation, "
                "command, default_readiness, delay, expected, message"
            ),
        },
    )
    assert native.mock_calls == []


@pytest.mark.parametrize("arguments", [None, [], "invalid arguments"])
def test_non_mapping_arguments_fail_without_native_operations(
    native: Mock, run_request: RequestRunner, arguments: object
) -> None:
    assert run_request(arguments) == (
        1,
        {
            "changed": False,
            "failed": True,
            "msg": "The argument file must contain a JSON object.",
        },
    )
    assert native.mock_calls == []


@pytest.mark.parametrize("delay", [None, "not a number", [], {}])
def test_invalid_delay_fails_before_requesting_restart(
    native: Mock, run_request: RequestRunner, delay: object
) -> None:
    assert run_request(
        {
            "_operation": "request",
            "delay": delay,
            "message": "Restart",
            "default_readiness": True,
        }
    ) == (
        1,
        {
            "changed": False,
            "failed": True,
            "msg": "The internal reboot delay must be a number.",
        },
    )
    assert native.mock_calls == []


@pytest.mark.parametrize(
    ("arguments", "message"),
    [
        (
            {"_operation": "request", "message": "Restart", "default_readiness": True},
            "The internal reboot delay must be a number.",
        ),
        (
            {"_operation": "request", "delay": 2, "default_readiness": True},
            "The internal reboot message is required.",
        ),
        (
            {
                "_operation": "request",
                "delay": 2,
                "message": None,
                "default_readiness": True,
            },
            "The internal reboot message is required.",
        ),
        (
            {"_operation": "request", "delay": 2, "message": "Restart"},
            "Expected a boolean for default_readiness.",
        ),
        (
            {
                "_operation": "request",
                "delay": 2,
                "message": "Restart",
                "default_readiness": "perhaps",
            },
            "Expected a boolean for default_readiness.",
        ),
    ],
)
def test_missing_phase_arguments_and_invalid_readiness_fail_before_native_operations(
    native: Mock,
    run_request: RequestRunner,
    arguments: dict[str, object],
    message: str,
) -> None:
    assert run_request(arguments) == (
        1,
        {"changed": False, "failed": True, "msg": message},
    )
    assert native.mock_calls == []


@pytest.mark.parametrize(
    ("arguments", "operation"),
    [
        ({"_operation": "boot"}, "observe_boot"),
        ({"_operation": "ready", "expected": "success-token"}, "observe_readiness"),
        (
            {
                "_operation": "request",
                "delay": 2,
                "message": "Restart",
                "default_readiness": True,
            },
            "request_reboot",
        ),
        ({"_operation": "abort"}, "abort_reboot"),
    ],
)
@pytest.mark.parametrize(
    "error", [OSError("Native operation failed"), ValueError("Invalid boot time")]
)
def test_native_failures_emit_actionable_json_and_subsequent_phase_recovers(
    native: Mock,
    run_request: RequestRunner,
    arguments: dict[str, object],
    operation: str,
    error: Exception,
) -> None:
    boundary = getattr(native, operation)
    boundary.side_effect = error
    assert run_request(arguments) == (
        1,
        {"changed": False, "failed": True, "msg": str(error)},
    )
    assert len(native.mock_calls) == 1
    assert native.mock_calls[0][0] == operation
    boundary.side_effect = lambda *_args: dict(RESULT)
    assert run_request(arguments) == (0, {**RESULT, "changed": False})


def test_unexpected_native_failure_is_json_with_traceback_and_no_partial_result(
    native: Mock, run_request: RequestRunner
) -> None:
    native.observe_boot.side_effect = RuntimeError("Unexpected provider failure")
    code, result = run_request({"_operation": "boot"})
    assert code == 1
    assert result["changed"] is False
    assert result["failed"] is True
    assert result["msg"] == (
        "Unhandled exception while executing module: Unexpected provider failure"
    )
    assert "RuntimeError: Unexpected provider failure" in result["exception"]
    assert "rc" not in result and "stdout" not in result and "stderr" not in result
    assert native.mock_calls == [call.observe_boot(None)]
