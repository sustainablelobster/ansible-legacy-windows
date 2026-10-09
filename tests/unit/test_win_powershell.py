"""Verify structured PowerShell argument and declared-secret boundaries."""

# SPDX-License-Identifier: GPL-3.0-or-later

import sys
from typing import Any
from unittest.mock import MagicMock

import pytest

from tests.unit.payload_support import load_payload


@pytest.fixture(name="powershell")
def powershell_fixture(monkeypatch: pytest.MonkeyPatch) -> Any:
    """Load target helpers without starting a PowerShell process.

    :param monkeypatch: Scoped target helper imports.
    :returns: Loaded request helper.
    """
    load_payload("win_powershell", monkeypatch)
    return sys.modules["legacy_windows_powershell"]


def test_request_defaults_and_controller_flags(
    powershell: Any, monkeypatch: pytest.MonkeyPatch
) -> None:
    run = MagicMock(return_value={"changed": False, "output": [1]})
    monkeypatch.setattr(powershell, "invoke_script", run)
    assert powershell.execute_script({"script": "1", "_ansible_diff": True}) == {
        "changed": False,
        "output": [1],
    }
    request = run.call_args.args[0]
    assert request["depth"] == 2 and request["error_action"] == "continue"
    assert request["check_mode"] is False and request["diff_mode"] is True
    assert request["parameters"] is None and request["sensitive_parameters"] == []


@pytest.mark.parametrize(
    "arguments,message",
    [
        ({}, "one of the following is required"),
        ({"script": "1", "path": "test.ps1"}, "mutually exclusive"),
        ({"script": "1", "depth": "bad"}, "unable to convert to int"),
        ({"script": "1", "depth": 2**31}, "Int32"),
        ({"script": "1", "error_action": "bad"}, "error_action"),
        ({"script": "1", "sensitive_parameters": [{}]}, "name"),
        (
            {"script": "1", "sensitive_parameters": [{"name": "c", "username": "u"}]},
            "required together",
        ),
        (
            {
                "script": "1",
                "sensitive_parameters": [{"name": "c", "value": "v", "password": "p"}],
            },
            "mutually exclusive",
        ),
    ],
)
def test_invalid_request_does_not_start_engine(
    powershell: Any,
    monkeypatch: pytest.MonkeyPatch,
    arguments: dict[str, Any],
    message: str,
) -> None:
    run = MagicMock()
    monkeypatch.setattr(powershell, "invoke_script", run)
    with pytest.raises(ValueError, match=message):
        powershell.execute_script(arguments)
    run.assert_not_called()


def test_caller_selected_secret_outputs_are_not_changed(
    powershell: Any, monkeypatch: pytest.MonkeyPatch
) -> None:
    run = MagicMock(
        return_value={
            "result": {"secret": ["secret", "prefix secret suffix", "username"]},
            "host_out": "secret",
        }
    )
    monkeypatch.setattr(powershell, "invoke_script", run)
    result = powershell.execute_script(
        {
            "script": "1",
            "sensitive_parameters": [
                {"name": "c", "username": "username", "password": "secret"}
            ],
        }
    )
    assert result == {
        "result": {
            "secret": [
                "secret",
                "prefix secret suffix",
                "username",
            ]
        },
        "host_out": "secret",
    }


def test_sensitive_engine_failure_does_not_leak_declared_value(
    powershell: Any, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(
        powershell, "invoke_script", MagicMock(side_effect=OSError("failure secret"))
    )
    assert powershell.execute_script(
        {"script": "1", "sensitive_parameters": [{"name": "token", "value": "secret"}]}
    ) == {"changed": False, "failed": True, "msg": "failure ********"}


def test_numeric_caller_output_is_preserved_even_when_equal_to_secret(
    powershell: Any, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(
        powershell, "invoke_script", MagicMock(return_value={"output": [123, "123"]})
    )
    assert powershell.execute_script(
        {"script": "1", "sensitive_parameters": [{"name": "token", "value": "123"}]}
    ) == {"output": [123, "123"]}


@pytest.mark.parametrize(
    "value,kind,detail",
    [
        ({}, "Collections.Hashtable", "Input string was not in a correct format."),
        (True, "Boolean", "Input string was not in a correct format."),
        (2.5, "Decimal", "Input string was not in a correct format."),
        (2.0, "Decimal", "Input string was not in a correct format."),
        (2147483648, "Int64", "Value was either too large or too small for an Int32."),
        (2**63, "Decimal", "Value was either too large or too small for an Int32."),
        (
            79228162514264337593543950336,
            "Double",
            "Input string was not in a correct format.",
        ),
    ],
)
def test_depth_preserves_strict_basic_integer_diagnostics(
    powershell: Any,
    monkeypatch: pytest.MonkeyPatch,
    value: object,
    kind: str,
    detail: str,
) -> None:
    run = MagicMock()
    monkeypatch.setattr(powershell, "invoke_script", run)
    with pytest.raises(ValueError) as caught:
        powershell.execute_script({"script": "1", "depth": value})
    assert (
        str(caught.value) == f"argument for depth is of type System.{kind} and we were "
        f"unable to convert to int: {detail}"
    )
    run.assert_not_called()


def test_case_insensitive_error_action_keeps_caller_text_and_null_depth_is_zero(
    powershell: Any, monkeypatch: pytest.MonkeyPatch
) -> None:
    run = MagicMock(return_value={"changed": False})
    monkeypatch.setattr(powershell, "invoke_script", run)
    powershell.execute_script(
        {"script": "1", "depth": None, "error_action": "CONTINUE"}
    )
    assert run.call_args.args[0]["depth"] == 0
    assert run.call_args.args[0]["error_action"] == "CONTINUE"


def test_only_public_failure_message_is_sanitized(
    powershell: Any, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(
        powershell,
        "invoke_script",
        MagicMock(
            return_value={
                "changed": False,
                "failed": True,
                "msg": "secret",
                "error": [{"output": "secret"}],
            }
        ),
    )
    assert powershell.execute_script(
        {"script": "1", "sensitive_parameters": [{"name": "Token", "value": "secret"}]}
    ) == {
        "changed": False,
        "failed": True,
        "msg": "VALUE_SPECIFIED_IN_NO_LOG_PARAMETER",
        "error": [{"output": "secret"}],
    }
