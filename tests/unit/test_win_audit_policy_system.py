"""Exercise the public audit-policy interface and retained native observations."""

# SPDX-License-Identifier: GPL-3.0-or-later

import json
import sys
from pathlib import Path
from types import ModuleType
from typing import Any, Callable
from unittest.mock import Mock, call

import pytest

from tests.unit.payload_support import invoke_payload, load_payload

RequestRunner = Callable[[object], tuple[int, dict[str, Any]]]


@pytest.fixture(name="native")
def policy_operations() -> Mock:
    """Record native operations without Windows or persistent system changes.

    :returns: Native catalogue, read, and write recorder.
    """
    native = Mock()
    native.catalogue.return_value = (["System", "Object Access"], ["File System"])
    native.get_policy.return_value = {"file system": "no auditing"}
    native.set_policy.return_value = {"rc": 0, "stderr": ""}
    return native


@pytest.fixture(name="payload")
def policy_payload(monkeypatch: pytest.MonkeyPatch, native: Mock) -> ModuleType:
    """Load the real frontend with only its Windows boundaries replaced.

    :param monkeypatch: Scoped helper and collation replacements.
    :param native: Recorder for native policy operations.
    :returns: Frontend retaining its public JSON argument contract.
    """
    payload = load_payload("win_audit_policy_system", monkeypatch)
    for name in ("catalogue", "get_policy", "set_policy"):
        monkeypatch.setattr(payload.audit_policy, name, getattr(native, name))
    monkeypatch.setattr(
        payload.environment,
        "values_equal",
        lambda left, right: left.lower() == right.lower(),
    )
    return payload


@pytest.fixture(name="run_request")
def request_runner(
    payload: ModuleType,
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
) -> RequestRunner:
    """Invoke each request through a real argument file and JSON entry point.

    :param payload: Frontend using substituted native policy operations.
    :param monkeypatch: Scoped command-line arguments.
    :param tmp_path: Isolated argument-file directory.
    :param capsys: Captured module output.
    :returns: Public request runner.
    """
    argument_file = tmp_path / "arguments.json"
    monkeypatch.setattr(sys, "argv", ["win_audit_policy_system.py", str(argument_file)])

    def _run_request(arguments: object) -> tuple[int, dict[str, Any]]:
        argument_file.write_text(json.dumps(arguments), encoding="utf-8")
        return invoke_payload(payload, capsys)

    return _run_request


@pytest.mark.parametrize("audit_types", [None, [], "none", ["NONE"]])
def test_disabled_policy_is_unchanged_for_null_empty_and_none_flags(
    run_request: RequestRunner, native: Mock, audit_types: object
) -> None:
    assert run_request({"subcategory": "File System", "audit_type": audit_types}) == (
        0,
        {"changed": False, "current_audit_policy": {"file system": "no auditing"}},
    )
    assert native.mock_calls == [
        call.catalogue(),
        call.get_policy("subcategory", "File System"),
    ]


@pytest.mark.parametrize("audit_types", ["success", "SUCCESS", ["none", "success"]])
def test_check_mode_reports_real_current_policy_without_writing(
    run_request: RequestRunner, native: Mock, audit_types: object
) -> None:
    request = {
        "SUBCATEGORY": "FILE SYSTEM",
        "audit_type": audit_types,
        "_ansible_check_mode": True,
        "_ansible_diff": True,
    }
    assert run_request(request) == (
        0,
        {"changed": True, "current_audit_policy": {"file system": "no auditing"}},
    )
    assert native.mock_calls == [
        call.catalogue(),
        call.get_policy("subcategory", "FILE SYSTEM"),
        call.get_policy("subcategory", "FILE SYSTEM"),
    ]


@pytest.mark.parametrize(
    ("audit_types", "flags", "setting"),
    [
        ("success", (True, False), "success"),
        ("failure", (False, True), "failure"),
        ("success,failure", (True, True), "success and failure"),
        (["failure", "none", "success"], (True, True), "success and failure"),
        ([], (False, False), "no auditing"),
    ],
)
def test_real_write_reads_back_then_repeat_is_unchanged(
    run_request: RequestRunner,
    native: Mock,
    audit_types: object,
    flags: tuple[bool, bool],
    setting: str,
) -> None:
    before = {"file system": "failure" if setting == "no auditing" else "no auditing"}
    after = {"file system": setting}
    native.get_policy.side_effect = [before, after, after]
    request = {"subcategory": "File System", "audit_type": audit_types}
    assert run_request(request) == (0, {"changed": True, "current_audit_policy": after})
    assert run_request(request) == (
        0,
        {"changed": False, "current_audit_policy": after},
    )
    assert native.set_policy.call_args_list == [
        call("subcategory", "File System", *flags)
    ]


def test_category_changes_when_any_subcategory_differs(
    run_request: RequestRunner, native: Mock
) -> None:
    native.get_policy.return_value = {"first": "success", "second": "failure"}
    assert run_request(
        {"category": "system", "audit_type": "success", "_ansible_check_mode": True}
    ) == (
        0,
        {
            "changed": True,
            "current_audit_policy": {"first": "success", "second": "failure"},
        },
    )
    assert native.get_policy.call_args_list == [
        call("category", "system"),
        call("category", "system"),
    ]
    native.set_policy.assert_not_called()


@pytest.mark.parametrize("selector", [None, ""])
def test_supplied_empty_selector_returns_native_error_as_unchanged_success(
    run_request: RequestRunner, native: Mock, selector: str | None
) -> None:
    native.get_policy.return_value = "The parameter is incorrect.\r\r\n"
    assert run_request({"subcategory": selector, "audit_type": "success"}) == (
        0,
        {"changed": False, "current_audit_policy": native.get_policy.return_value},
    )
    native.set_policy.assert_not_called()
    native.get_policy.assert_called_once_with("subcategory", "")


@pytest.mark.parametrize(
    ("arguments", "message"),
    [
        (
            {"audit_type": "none"},
            "one of the following is required: subcategory, category",
        ),
        (
            {"subcategory": None, "category": "System", "audit_type": "none"},
            "parameters are mutually exclusive: subcategory, category",
        ),
        ({"subcategory": "File System"}, "missing required arguments: audit_type"),
        (
            {"subcategory": "File System", "audit_type": "invalid"},
            "value of audit_type must be one or more of: failure, none, success. "
            "Got no match for: invalid",
        ),
        (
            {"subcategory": "File System", "audit_type": "none", "unrelated": True},
            "Unsupported parameters",
        ),
    ],
)
def test_binding_failures_precede_all_native_operations(
    run_request: RequestRunner, native: Mock, arguments: dict[str, Any], message: str
) -> None:
    status, result = run_request(arguments)
    assert status == 1 and result["failed"] and result["changed"] is False
    assert message in result["msg"]
    assert native.mock_calls == []


@pytest.mark.parametrize("selector", ["category", "subcategory"])
def test_unknown_catalogue_name_fails_before_policy_read_or_write(
    run_request: RequestRunner, native: Mock, selector: str
) -> None:
    status, result = run_request({selector: "absent", "audit_type": "none"})
    assert status == 1 and result["changed"] is False
    assert result["msg"] == (
        "Invalid category provided"
        if selector == "category"
        else "Invalid sub category provided"
    )
    assert native.mock_calls == [call.catalogue()]


def test_setter_failure_retains_actual_partial_state_and_allows_recovery(
    run_request: RequestRunner, native: Mock
) -> None:
    before, partial = {"file system": "no auditing"}, {"file system": "failure"}
    native.get_policy.side_effect = [before, partial]
    native.set_policy.return_value = {"rc": 5, "stderr": "Access is denied.\r\n"}
    request = {"subcategory": "File System", "audit_type": "success"}
    assert run_request(request) == (
        1,
        {
            "changed": False,
            "failed": True,
            "msg": "Failed to set audit policy Access is denied.\r\n",
            "current_audit_policy": partial,
        },
    )
    native.set_policy.return_value = {"rc": 0, "stderr": ""}
    native.get_policy.side_effect = [partial, {"file system": "success"}]
    assert run_request(request) == (
        0,
        {"changed": True, "current_audit_policy": {"file system": "success"}},
    )


def test_catalogue_failure_is_actionable_and_precedes_policy_operations(
    run_request: RequestRunner, native: Mock
) -> None:
    native.catalogue.side_effect = OSError("auditpol.exe is unavailable")
    assert run_request({"subcategory": "File System", "audit_type": "none"}) == (
        1,
        {"changed": False, "failed": True, "msg": "auditpol.exe is unavailable"},
    )
    assert native.mock_calls == [call.catalogue()]
