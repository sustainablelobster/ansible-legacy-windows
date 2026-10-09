"""Check path payload behavior without accessing Windows or the lab."""

# SPDX-License-Identifier: GPL-3.0-or-later
# Direct frontend calls exercise argument binding and native operation ordering.
# pylint: disable=protected-access

import json
import sys
from pathlib import Path
from types import ModuleType
from typing import Any, Callable
from unittest.mock import Mock, call

import pytest

from tests.unit.payload_support import invoke_payload, load_payload

FIRST = r"C:\Application\bin"
SECOND = r"C:\Application\tools"
RequestRunner = Callable[[object], tuple[int, dict[str, Any]]]


@pytest.fixture(name="stored")
def stored_values() -> dict[tuple[str, str], str]:
    """Provide persistent values isolated to each frontend test.

    :returns: Values indexed by scope and variable name.
    """
    return {}


@pytest.fixture(name="native")
def native_operations(stored: dict[tuple[str, str], str]) -> Mock:
    """Record reads, writes, and notifications in execution order.

    :param stored: Registry substitute shared with the test.
    :returns: Native-operation recorder with a persistent string store.
    """
    native = Mock()
    native.read_value.side_effect = lambda name, scope: stored.get((scope, name), "")

    def set_value(name: str, value: str, scope: str) -> None:
        stored[(scope, name)] = value

    native.set_value.side_effect = set_value
    return native


@pytest.fixture(name="payload")
def path_payload(monkeypatch: pytest.MonkeyPatch, native: Mock) -> ModuleType:
    """Import the frontend with its native operations substituted.

    :param monkeypatch: Scoped imports and boundary substitutions.
    :param native: Recorder for persisted reads, writes, and notifications.
    :returns: Imported path payload using the real path-edit algorithm.
    """
    module = load_payload("win_path", monkeypatch)
    monkeypatch.setattr(module.paths, "read_value", native.read_value)
    monkeypatch.setattr(module.paths, "set_value", native.set_value)
    monkeypatch.setattr(module.environment, "broadcast_change", native.broadcast_change)
    # Native helper tests cover Windows comparison; these paths use ASCII only.
    monkeypatch.setattr(
        module.environment,
        "values_equal",
        lambda left, right, **_options: left.lower() == right.lower(),
    )
    return module


def _apply(
    payload: ModuleType, *, check: bool = False, **options: object
) -> dict[str, Any]:
    result: dict[str, Any] = payload._edit(payload._parameters(options), check)
    return result


@pytest.fixture(name="run_request")
def request_runner(
    payload: ModuleType,
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
) -> RequestRunner:
    """Run JSON requests through the payload's public entry point.

    :param payload: Imported payload with substituted native operations.
    :param monkeypatch: Scoped command-line replacement.
    :param tmp_path: Directory for the request file.
    :param capsys: Capture of the payload's JSON response.
    :returns: Request runner sharing this test's native state.
    """
    argument_file = tmp_path / "arguments.json"
    monkeypatch.setattr(sys, "argv", ["win_path.py", str(argument_file)])

    def _run_request(arguments: object) -> tuple[int, dict[str, Any]]:
        argument_file.write_text(json.dumps(arguments), encoding="utf-8")
        return invoke_payload(payload, capsys)

    return _run_request


def test_defaults_target_machine_path(payload: ModuleType) -> None:
    assert payload._parameters({"elements": [FIRST]}) == {
        "name": "PATH",
        "elements": [FIRST],
        "state": "present",
        "scope": "machine",
    }


def test_elements_are_required(payload: ModuleType, native: Mock) -> None:
    with pytest.raises(ValueError, match="missing required arguments: elements"):
        _apply(payload)
    assert native.mock_calls == []


@pytest.mark.parametrize(
    "supplied,expected",
    [
        (FIRST, [FIRST]),
        (FIRST + ", " + SECOND, [FIRST, SECOND]),
        ("\u00a0one\u2003,\ttwo\n", ["one", "two"]),
        ("", [""]),
        (None, []),
        ([], []),
        ([" one ", "two,three"], [" one ", "two,three"]),
        (0, ["0"]),
        (-(2**63), [str(-(2**63))]),
        (2**63 - 1, [str(2**63 - 1)]),
        ([True, 42, 1.5], ["True", "42", "1.5"]),
        ([[], {}], ["System.Object[]", "System.Collections.Hashtable"]),
    ],
)
def test_elements_follow_reference_list_binding(
    payload: ModuleType, supplied: object, expected: list[str]
) -> None:
    assert payload._parameters({"elements": supplied})["elements"] == expected


@pytest.mark.parametrize("supplied", [True, False, 1.5, {}, 2**63, -(2**63) - 1])
def test_nonlist_elements_fail_before_native_access(
    payload: ModuleType, native: Mock, supplied: object
) -> None:
    with pytest.raises(ValueError, match="Expected a list for elements"):
        _apply(payload, elements=supplied)
    assert native.mock_calls == []


@pytest.mark.parametrize(
    "options,message",
    [
        ({"state": "replace"}, "state must be one of"),
        ({"scope": "process"}, "scope must be one of"),
    ],
)
def test_invalid_choices_fail_before_native_access(
    payload: ModuleType, native: Mock, options: dict[str, Any], message: str
) -> None:
    with pytest.raises(ValueError, match=message):
        _apply(payload, elements=[FIRST], **options)
    assert native.mock_calls == []


@pytest.mark.parametrize("scope", ["machine", "user"])
def test_add_repeat_and_remove_write_before_notifying(
    payload: ModuleType, native: Mock, stored: dict[tuple[str, str], str], scope: str
) -> None:
    options: dict[str, Any] = {
        "name": "APPLICATION_PATH",
        "elements": [FIRST],
        "scope": scope,
    }
    assert _apply(payload, **options) == {"changed": True, "path_value": FIRST}
    assert native.mock_calls == [
        call.read_value("APPLICATION_PATH", scope),
        call.set_value("APPLICATION_PATH", FIRST, scope),
        call.broadcast_change(),
    ]
    assert stored == {(scope, "APPLICATION_PATH"): FIRST}

    native.reset_mock()
    assert _apply(payload, **options) == {"changed": False, "path_value": FIRST}
    assert native.mock_calls == [call.read_value("APPLICATION_PATH", scope)]

    native.reset_mock()
    assert _apply(payload, state="absent", **options) == {
        "changed": True,
        "path_value": "",
        "removed_idx": 0,
    }
    assert native.mock_calls == [
        call.read_value("APPLICATION_PATH", scope),
        call.set_value("APPLICATION_PATH", "", scope),
        call.broadcast_change(),
    ]
    assert stored == {(scope, "APPLICATION_PATH"): ""}

    native.reset_mock()
    assert _apply(payload, state="absent", **options) == {
        "changed": False,
        "path_value": "",
        "removed_idx": -1,
    }
    assert native.mock_calls == [call.read_value("APPLICATION_PATH", scope)]


def test_choices_are_case_insensitive(
    payload: ModuleType, native: Mock, stored: dict[tuple[str, str], str]
) -> None:
    stored[("user", "PATH")] = FIRST
    assert _apply(payload, elements=[FIRST], scope="USER", state="ABSENT") == {
        "changed": True,
        "path_value": "",
        "removed_idx": 0,
    }
    native.read_value.assert_called_once_with("PATH", "user")
    native.set_value.assert_called_once_with("PATH", "", "user")


@pytest.mark.parametrize("scope", ["machine", "user"])
@pytest.mark.parametrize("state", ["present", "absent"])
def test_check_mode_returns_real_prediction_without_writes_or_notifications(
    payload: ModuleType,
    native: Mock,
    stored: dict[tuple[str, str], str],
    scope: str,
    state: str,
) -> None:
    stored[(scope, "PATH")] = FIRST
    elements = [SECOND] if state == "present" else [FIRST]
    options: dict[str, Any] = {"elements": elements, "scope": scope, "state": state}
    predicted = _apply(payload, check=True, **options)
    assert predicted["changed"] is True
    assert stored == {(scope, "PATH"): FIRST}
    assert native.mock_calls == [call.read_value("PATH", scope)]
    assert _apply(payload, **options) == predicted


def test_returned_normalization_does_not_rewrite_unchanged_store(
    payload: ModuleType, native: Mock, stored: dict[tuple[str, str], str]
) -> None:
    original = FIRST + ";;" + SECOND + ";"
    stored[("machine", "PATH")] = original
    assert _apply(payload, elements=[FIRST]) == {
        "changed": False,
        "path_value": FIRST + ";" + SECOND,
    }
    assert stored == {("machine", "PATH"): original}
    assert native.mock_calls == [call.read_value("PATH", "machine")]


@pytest.mark.parametrize("state", ["present", "absent"])
def test_empty_request_returns_path_without_removal_index_or_mutation(
    payload: ModuleType,
    native: Mock,
    stored: dict[tuple[str, str], str],
    state: str,
) -> None:
    stored[("machine", "PATH")] = FIRST
    assert _apply(payload, elements=[], state=state) == {
        "changed": False,
        "path_value": FIRST,
    }
    assert native.mock_calls == [call.read_value("PATH", "machine")]


def test_null_state_leaves_existing_elements_without_writing(
    payload: ModuleType, native: Mock, stored: dict[tuple[str, str], str]
) -> None:
    stored[("machine", "PATH")] = FIRST
    assert _apply(payload, elements=[SECOND], state=None) == {
        "changed": False,
        "path_value": FIRST,
    }
    assert stored == {("machine", "PATH"): FIRST}
    assert native.mock_calls == [call.read_value("PATH", "machine")]


@pytest.mark.parametrize("name", [None, ""])
def test_null_or_empty_name_can_predict_default_value_change(
    payload: ModuleType, native: Mock, name: str | None
) -> None:
    assert _apply(payload, name=name, elements=[FIRST], check=True) == {
        "changed": True,
        "path_value": FIRST,
    }
    assert native.mock_calls == [call.read_value(name, "machine")]


def test_json_argument_names_check_flag_and_no_diff_support(
    native: Mock,
    run_request: RequestRunner,
) -> None:
    code, result = run_request(
        {
            "NAME": "APPLICATION_PATH",
            "ELEMENTS": ["C:\\Café 雪", r"%APPROOT%\bin"],
            "SCOPE": "USER",
            "STATE": "PRESENT",
            "_ANSIBLE_CHECK_MODE": "yes",
            "_ansible_diff": True,
        },
    )
    assert code == 0
    assert result == {"changed": True, "path_value": "C:\\Café 雪;%APPROOT%\\bin"}
    assert native.mock_calls == [call.read_value("APPLICATION_PATH", "user")]


@pytest.mark.parametrize(
    "case",
    [
        ([], "must contain a JSON object"),
        ({}, "missing required arguments: elements"),
        ({"elements": [], "unknown": True}, "Unsupported parameters"),
        ({"elements": [], "scope": "process"}, "scope must be one of"),
        ({"elements": [None]}, "elements must not contain null entries"),
        ({"elements": [], "_ansible_check_mode": "maybe"}, "Expected a boolean"),
    ],
)
def test_json_validation_failures_do_not_access_native_state(
    payload: ModuleType,
    run_request: RequestRunner,
    case: tuple[object, str],
) -> None:
    arguments, message = case
    code, result = run_request(arguments)
    assert code == 1 and result["failed"] is True and result["changed"] is False
    assert message in result["msg"]
    assert "path_value" not in result and "removed_idx" not in result
    assert "diff" not in result
    payload.paths.read_value.assert_not_called()
    payload.paths.set_value.assert_not_called()
    payload.environment.broadcast_change.assert_not_called()


def test_json_can_ignore_unsupported_arguments_when_requested(
    native: Mock,
    run_request: RequestRunner,
) -> None:
    code, result = run_request(
        {"elements": [], "unknown": True, "_ansible_ignore_unknown_opts": True},
    )
    assert code == 0 and result == {"changed": False, "path_value": ""}
    assert native.mock_calls == [call.read_value("PATH", "machine")]


@pytest.mark.parametrize("operation", ["read_value", "set_value", "broadcast_change"])
def test_native_failures_return_json_without_partial_path_results(
    payload: ModuleType,
    run_request: RequestRunner,
    operation: str,
) -> None:
    boundary = payload.environment if operation == "broadcast_change" else payload.paths
    getattr(boundary, operation).side_effect = OSError("native operation failed")
    code, result = run_request({"elements": [FIRST]})
    assert code == 1 and result == {
        "failed": True,
        "changed": False,
        "msg": "native operation failed",
    }
    if operation == "read_value":
        payload.paths.set_value.assert_not_called()
    if operation != "broadcast_change":
        payload.environment.broadcast_change.assert_not_called()


def test_notification_failure_keeps_write_and_repeated_request_recovers(
    payload: ModuleType,
    stored: dict[tuple[str, str], str],
    run_request: RequestRunner,
) -> None:
    payload.environment.broadcast_change.side_effect = OSError("notification failed")
    arguments = {"name": "APPLICATION_PATH", "scope": "user", "elements": [FIRST]}
    code, result = run_request(arguments)
    assert code == 1 and result["failed"] is True
    assert "path_value" not in result
    assert stored == {("user", "APPLICATION_PATH"): FIRST}

    payload.environment.broadcast_change.side_effect = None
    code, result = run_request(arguments)
    assert code == 0 and result == {"changed": False, "path_value": FIRST}
    payload.paths.set_value.assert_called_once_with("APPLICATION_PATH", FIRST, "user")
    payload.environment.broadcast_change.assert_called_once_with()
