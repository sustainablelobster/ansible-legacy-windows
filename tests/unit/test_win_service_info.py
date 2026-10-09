"""Exercise the service-info JSON payload without contacting Windows."""

# SPDX-License-Identifier: GPL-3.0-or-later
# Tests call the payload's private boundary helpers to replace only native reads.
# pylint: disable=protected-access

import json
import sys
from collections.abc import Callable
from pathlib import Path
from types import ModuleType
from typing import Any
from unittest.mock import Mock, call

import pytest

from tests.unit.payload_support import invoke_payload, load_payload, native_error


@pytest.fixture(name="payload")
def service_payload(monkeypatch: pytest.MonkeyPatch) -> ModuleType:
    """Load the payload with observable selection and service-read boundaries.

    :param monkeypatch: Scoped substitutions for native operations.
    :returns: Loaded payload with read-only native operations replaced.
    """
    module = load_payload("win_service_info", monkeypatch)
    monkeypatch.setattr(module.service_info, "select_names", Mock(return_value=[]))
    monkeypatch.setattr(module.service_info, "query_service", Mock())
    return module


@pytest.fixture(name="invoke")
def service_invocation(
    payload: ModuleType,
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
) -> Callable[[object], tuple[int, dict[str, Any]]]:
    """Bind argument-file setup and output capture to the payload.

    :param payload: Module with native reads replaced.
    :param monkeypatch: Scoped script-argument substitution.
    :param tmp_path: Isolated argument-file directory.
    :param capsys: JSON stdout capture.
    :returns: Callable accepting an argument document.
    """

    def _invoke(arguments: object) -> tuple[int, dict[str, Any]]:
        argument_file = tmp_path / "arguments.json"
        argument_file.write_text(json.dumps(arguments), encoding="utf-8")
        monkeypatch.setattr(sys, "argv", ["win_service_info.py", str(argument_file)])
        return invoke_payload(payload, capsys)

    return _invoke


def _record(name: str) -> dict[str, object]:
    return {
        "checkpoint": 0,
        "controls_accepted": ["stop"],
        "dependencies": ["RpcSs", "+Network"],
        "dependency_of": [],
        "description": "Service 雪",
        "desktop_interact": False,
        "display_name": "Display " + name,
        "error_control": "normal",
        "failure_actions": [{"type": {}, "delay_ms": 4294967295}],
        "failure_actions_on_non_crash_failure": False,
        "failure_command": None,
        "failure_reboot_msg": "",
        "failure_reset_period_sec": 86400,
        "launch_protection": "none",
        "load_order_group": "",
        "name": name,
        "path": r"C:\Windows\system32\svchost.exe -k Example",
        "pre_shutdown_timeout_ms": 10000,
        "preferred_node": None,
        "process_id": 100,
        "required_privileges": [],
        "service_exit_code": 0,
        "service_flags": [],
        "service_type": "win32_share_process",
        "sid_info": "unrestricted",
        "start_mode": "manual",
        "state": "started",
        "triggers": [],
        "username": "NT AUTHORITY\\SYSTEM",
        "wait_hint_ms": 0,
        "win32_exit_code": 0,
    }


@pytest.mark.parametrize("arguments", [{}, {"name": None}, {"name": ""}])
def test_all_service_requests_preserve_empty_and_null_names(
    payload: ModuleType,
    invoke: Callable[[object], tuple[int, dict[str, Any]]],
    arguments: dict[str, object],
) -> None:
    code, result = invoke(arguments)
    assert code == 0
    assert result == {"changed": False, "exists": False, "services": []}
    payload.service_info.select_names.assert_called_once_with(arguments.get("name"))
    payload.service_info.query_service.assert_not_called()


@pytest.mark.parametrize(
    ("value", "expected"),
    [
        ("RpcSs", "RpcSs"),
        (" RpcSs ", " RpcSs "),
        ("Rpc*", "Rpc*"),
        ("Rpc`Ss", "Rpc`Ss"),
        ("RpcSs\0ignored", "RpcSs\0ignored"),
        ("雪", "雪"),
        (False, "False"),
        (True, "True"),
        (0, "0"),
        (-1, "-1"),
        (1.5, "1.5"),
        ([], "System.Object[]"),
        (["RpcSs"], "System.Object[]"),
        ({}, "System.Collections.Hashtable"),
        ({"service": "RpcSs"}, "System.Collections.Hashtable"),
    ],
)
def test_name_conversion_uses_the_shared_upstream_string_rules(
    payload: ModuleType,
    invoke: Callable[[object], tuple[int, dict[str, Any]]],
    value: object,
    expected: str,
) -> None:
    code, result = invoke({"NAME": value})
    assert code == 0 and result["exists"] is False
    payload.service_info.select_names.assert_called_once_with(expected)


@pytest.mark.parametrize("check", [False, True])
def test_complete_records_and_selected_order_survive_repeated_reads(
    payload: ModuleType,
    invoke: Callable[[object], tuple[int, dict[str, Any]]],
    check: bool,
) -> None:
    names = ["zeta", "Alpha"]
    records = [_record(name) for name in names]
    assert all(len(record) == 31 for record in records)
    payload.service_info.select_names.return_value = names
    payload.service_info.query_service.side_effect = lambda name, _warnings: _record(
        name
    )
    expected = {"changed": False, "exists": True, "services": records}
    assert invoke({"name": "*", "_ansible_check_mode": check}) == (0, expected)
    assert invoke({"name": "*", "_ansible_check_mode": check}) == (0, expected)
    assert payload.service_info.query_service.call_args_list == [
        call("zeta", []),
        call("Alpha", []),
        call("zeta", []),
        call("Alpha", []),
    ]


def test_unavailable_fields_and_warnings_are_preserved_without_changing_exists(
    payload: ModuleType, invoke: Callable[[object], tuple[int, dict[str, Any]]]
) -> None:
    fields = (
        "failure_actions_on_non_crash_failure",
        "launch_protection",
        "pre_shutdown_timeout_ms",
        "preferred_node",
        "required_privileges",
        "sid_info",
        "start_mode",
        "triggers",
    )
    record = _record("legacy")
    record.update(dict.fromkeys(fields))

    def _read(_name: str, warnings: list[str]) -> dict[str, object]:
        warnings.extend("Unavailable: " + field for field in fields)
        return record

    payload.service_info.select_names.return_value = ["legacy"]
    payload.service_info.query_service.side_effect = _read
    expected = {
        "changed": False,
        "exists": True,
        "services": [record],
        "warnings": ["Unavailable: " + field for field in fields],
    }
    assert invoke({}) == (0, expected)
    assert invoke({"_ansible_check_mode": True}) == (0, expected)


@pytest.mark.parametrize("code", [2, 5])
def test_constructor_errors_skip_services_with_warnings_and_recover(
    payload: ModuleType,
    invoke: Callable[[object], tuple[int, dict[str, Any]]],
    code: int,
) -> None:
    error = payload.service_info.ServiceOpenError(native_error(code))
    payload.service_info.select_names.return_value = ["first", "second"]
    payload.service_info.query_service.side_effect = [error, _record("second")]
    status, result = invoke({})
    assert status == 0
    assert result == {
        "changed": False,
        "exists": True,
        "services": [_record("second")],
        "warnings": [
            f"Failed to open service 'first to get more info, ignoring: {error}"
        ],
    }
    payload.service_info.query_service.side_effect = [error, error]
    status, result = invoke({})
    assert status == 0 and result["exists"] is False and result["services"] == []
    assert len(result["warnings"]) == 2
    payload.service_info.query_service.side_effect = [
        _record("first"),
        _record("second"),
    ]
    status, result = invoke({})
    assert status == 0 and result["exists"] is True and "warnings" not in result


def test_skip_and_field_warnings_keep_service_and_field_order(
    payload: ModuleType, invoke: Callable[[object], tuple[int, dict[str, Any]]]
) -> None:
    error = payload.service_info.ServiceOpenError(native_error(5))

    def _read(name: str, warnings: list[str]) -> dict[str, object]:
        if name == "denied":
            raise error
        warnings.extend(["First unavailable field", "Second unavailable field"])
        return _record(name)

    payload.service_info.select_names.return_value = ["denied", "legacy"]
    payload.service_info.query_service.side_effect = _read
    status, result = invoke({})
    assert status == 0 and result["services"] == [_record("legacy")]
    assert result["warnings"] == [
        f"Failed to open service 'denied to get more info, ignoring: {error}",
        "First unavailable field",
        "Second unavailable field",
    ]


@pytest.mark.parametrize(
    ("code", "constructor"),
    [(2, False), (5, False), (87, False), (1060, False), (87, True), (1060, True)],
)
def test_fatal_reads_discard_partial_fields_and_warnings(
    payload: ModuleType,
    invoke: Callable[[object], tuple[int, dict[str, Any]]],
    code: int,
    constructor: bool,
) -> None:
    failure = native_error(code)
    if constructor:
        failure = payload.service_info.ServiceOpenError(failure)

    def _read(name: str, warnings: list[str]) -> dict[str, object]:
        if name == "first":
            warnings.append("Unavailable field on first")
            return _record(name)
        raise failure

    payload.service_info.select_names.return_value = ["first", "last"]
    payload.service_info.query_service.side_effect = _read
    status, result = invoke({})
    assert status == 1
    assert set(result) == {"changed", "failed", "msg", "exception"}
    assert result["changed"] is False and result["failed"] is True
    assert result["msg"] == "Unhandled exception while executing module: " + str(
        failure
    )
    payload.service_info.query_service.side_effect = lambda name, _warnings: _record(
        name
    )
    assert invoke({})[0] == 0


@pytest.mark.parametrize("pattern", ["[", "[]", "[z-a]", "System.Object[]"])
def test_malformed_pattern_failure_matches_wrapper_shape_and_recovers(
    payload: ModuleType,
    invoke: Callable[[object], tuple[int, dict[str, Any]]],
    pattern: str,
) -> None:
    message = "The specified wildcard character pattern is not valid: " + pattern
    payload.service_info.select_names.side_effect = ValueError(message)
    status, result = invoke({"name": pattern})
    assert status == 1
    assert set(result) == {"changed", "failed", "msg", "exception"}
    assert result["msg"] == "Unhandled exception while executing module: " + message
    payload.service_info.query_service.assert_not_called()
    payload.service_info.select_names.side_effect = None
    assert invoke({}) == (0, {"changed": False, "exists": False, "services": []})


def test_unknown_parameter_is_rejected_before_selection(
    payload: ModuleType, invoke: Callable[[object], tuple[int, dict[str, Any]]]
) -> None:
    status, result = invoke({"name": "RpcSs", "unknown": True})
    assert status == 1
    assert result == {
        "changed": False,
        "failed": True,
        "msg": "Unsupported parameters for (sustainablelobster.legacy_windows.win_service_info) "
        "module: unknown. Supported parameters include: name",
    }
    payload.service_info.select_names.assert_not_called()


def test_internal_ignore_unknown_flag_and_invocation_use_normalized_name(
    payload: ModuleType, invoke: Callable[[object], tuple[int, dict[str, Any]]]
) -> None:
    status, result = invoke(
        {
            "NAME": False,
            "unknown": True,
            "_ANSIBLE_IGNORE_UNKNOWN_OPTS": True,
            "_ANSIBLE_INJECT_INVOCATION": True,
            "_ansible_diff": True,
        }
    )
    assert status == 0
    assert result == {
        "changed": False,
        "exists": False,
        "services": [],
        "invocation": {"module_args": {"name": "False"}},
    }
    payload.service_info.select_names.assert_called_once_with("False")


@pytest.mark.parametrize("arguments", [None, [], "RpcSs"])
def test_non_object_arguments_fail_before_any_service_read(
    payload: ModuleType,
    invoke: Callable[[object], tuple[int, dict[str, Any]]],
    arguments: object,
) -> None:
    status, result = invoke(arguments)
    assert status == 1
    assert result["msg"] == "The argument file must contain a JSON object."
    payload.service_info.select_names.assert_not_called()
