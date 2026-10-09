"""Test automatic-logon results, secrecy, ordering, and recovery without Windows."""

# SPDX-License-Identifier: GPL-3.0-or-later

import json
import sys
from pathlib import Path
from types import ModuleType, SimpleNamespace
from typing import Any, Callable
from unittest.mock import MagicMock, Mock, call

import pytest

from tests.unit.payload_support import invoke_payload, load_payload

PASSWORD = "Fixture-Only-Secret"
Request = Callable[[dict[str, Any]], tuple[int, dict[str, Any]]]


@pytest.fixture(name="native")
def native_operations() -> Any:
    """Model Winlogon and LSA independently, recording the order of operations.

    :returns: Mutable native state and its operation recorder.
    """
    state = SimpleNamespace(values={"AutoAdminLogon": 0}, password=None, calls=Mock())
    state.calls.resolve_account.return_value = ("MACHINE", "TestUser")
    state.calls.read_values.side_effect = lambda: dict(state.values)
    state.calls.write_value.side_effect = lambda name, value: state.values.update(
        {name: value}
    )
    state.calls.delete_value.side_effect = state.values.pop
    state.calls.read_secret.side_effect = lambda: state.password
    state.calls.write_secret.side_effect = lambda value: setattr(
        state, "password", value
    )
    context = MagicMock()
    context.__enter__.return_value = SimpleNamespace(
        read=state.calls.read_secret, write=state.calls.write_secret
    )
    state.calls.SecretStore.return_value = context
    state.context = context
    return state


# This workflow keeps an independent fixture and expected-result oracle.
# pylint: disable=duplicate-code
@pytest.fixture(name="payload")
def auto_logon_payload(monkeypatch: pytest.MonkeyPatch, native: Any) -> ModuleType:
    """Load the payload with native operations and ASCII collation substituted.

    :param monkeypatch: Scoped replacement of native boundaries.
    :param native: Mutable native state and call recorder.
    :returns: Imported payload.
    """
    module = load_payload("win_auto_logon", monkeypatch)
    for name in (
        "resolve_account",
        "read_values",
        "write_value",
        "delete_value",
        "SecretStore",
    ):
        monkeypatch.setattr(module.auto_logon, name, getattr(native.calls, name))
    monkeypatch.setattr(
        module.environment,
        "values_equal",
        lambda left, right: (
            left is right
            if left is None or right is None
            else left.lower() == right.lower()
        ),
    )
    return module


# pylint: enable=duplicate-code


# This workflow keeps an independent fixture and expected-result oracle.
# pylint: disable=duplicate-code
@pytest.fixture(name="run_request")
def request_runner(
    payload: ModuleType,
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
) -> Request:
    """Exercise the public JSON entry point.

    :param payload: Imported payload with native substitutes.
    :param monkeypatch: Scoped argument-file command line.
    :param tmp_path: Per-test argument directory.
    :param capsys: Captured stdout and stderr.
    :returns: Public run_request callable.
    """
    argument_file = tmp_path / "arguments.json"
    monkeypatch.setattr(sys, "argv", ["win_auto_logon.py", str(argument_file)])

    def _run(arguments: dict[str, Any]) -> tuple[int, dict[str, Any]]:
        argument_file.write_text(json.dumps(arguments), encoding="utf-8")
        return invoke_payload(payload, capsys)

    return _run


# pylint: enable=duplicate-code


def test_enable_check_real_repeat_and_diff_never_contains_password(
    native: Any, run_request: Request
) -> None:
    native.values["DefaultPassword"] = "old-plaintext"
    arguments = {"username": "testuser", "password": PASSWORD, "_ansible_diff": True}
    before = {"state": "absent"}
    after = {"state": "present", "domain": "MACHINE", "username": "TestUser"}
    expected = {"changed": True, "diff": {"before": before, "after": after}}
    assert run_request(dict(arguments, _ansible_check_mode=True)) == (0, expected)
    assert native.values == {"AutoAdminLogon": 0, "DefaultPassword": "old-plaintext"}
    assert native.password is None
    native.calls.write_value.assert_not_called()
    native.calls.delete_value.assert_not_called()
    native.calls.write_secret.assert_not_called()
    native.calls.reset_mock()
    assert run_request(arguments) == (0, expected)
    assert native.calls.read_secret() == PASSWORD
    assert "DefaultPassword" not in native.values
    calls = native.calls.mock_calls
    assert calls.index(call.delete_value("DefaultPassword")) < calls.index(
        call.SecretStore()
    )
    assert calls.index(call.write_value("AutoAdminLogon", 1)) < calls.index(
        call.write_secret(PASSWORD)
    )
    native.calls.reset_mock()
    assert run_request(arguments) == (
        0,
        {"changed": False, "diff": {"before": after, "after": after}},
    )
    native.calls.write_value.assert_not_called()
    native.calls.write_secret.assert_not_called()


def test_count_password_change_and_omitted_count_removal(
    native: Any, run_request: Request
) -> None:
    arguments = {"username": "testuser", "password": PASSWORD, "logon_count": 2}
    assert run_request(arguments) == (0, {"changed": True})
    assert native.values["AutoLogonCount"] == 2
    assert run_request(arguments) == (0, {"changed": False})
    assert run_request({"username": "testuser", "password": "Different"}) == (
        0,
        {"changed": True},
    )
    assert "AutoLogonCount" not in native.values and native.password == "Different"


def test_disable_check_real_repeat_retains_zero_flag(
    native: Any, run_request: Request
) -> None:
    assert (
        run_request({"username": "testuser", "password": PASSWORD, "logon_count": 0})[0]
        == 0
    )
    before = dict(native.values)
    assert run_request({"state": "absent", "_ansible_check_mode": True}) == (
        0,
        {"changed": True},
    )
    assert native.values == before and native.password == PASSWORD
    assert run_request({"state": "absent", "password": "Ignored"}) == (
        0,
        {"changed": True},
    )
    assert native.values == {"AutoAdminLogon": 0} and native.password is None
    assert run_request({"state": "absent"}) == (0, {"changed": False})


def test_missing_disabled_flag_is_not_created(
    native: Any, run_request: Request
) -> None:
    native.values.clear()
    assert run_request({"state": "absent", "_ansible_diff": True}) == (
        0,
        {
            "changed": False,
            "diff": {"before": {"state": "absent"}, "after": {"state": "absent"}},
        },
    )
    assert native.values == {}


@pytest.mark.parametrize("password", [None, "", "lower", "LOWER", "a\0b", "雪😀"])
def test_password_values_are_not_returned(
    native: Any, run_request: Request, password: str | None
) -> None:
    assert run_request({"username": "testuser", "password": password})[0] == 0
    assert native.password == password
    assert run_request({"username": "testuser", "password": password}) == (
        0,
        {"changed": False},
    )


@pytest.mark.parametrize(
    "arguments,message",
    [
        (
            {},
            "state is present but all of the following are missing: username, password",
        ),
        (
            {"username": "testuser"},
            "state is present but all of the following are missing: password",
        ),
        (
            {"state": "invalid"},
            "value of state must be one of: absent, present. Got no match for: invalid",
        ),
    ],
)
def test_argument_failures_precede_native_access(
    native: Any, run_request: Request, arguments: dict[str, Any], message: str
) -> None:
    # This workflow keeps an independent fixture and expected-result oracle.
    # pylint: disable=duplicate-code
    assert run_request(arguments) == (
        1,
        {
            "changed": False,
            "failed": True,
            "msg": message,
            "exception": "(traceback unavailable)",
        },
    )
    # pylint: enable=duplicate-code
    assert native.calls.mock_calls == []


@pytest.mark.parametrize(
    "count,kind,reason",
    [
        (1.5, "System.Decimal", "Input string was not in a correct format."),
        (True, "System.Boolean", "Input string was not in a correct format."),
        ("invalid", "System.String", "Input string was not in a correct format."),
        (
            2147483648,
            "System.Int64",
            "Value was either too large or too small for an Int32.",
        ),
    ],
)
def test_measured_count_failures_precede_all_native_operations(
    native: Any, run_request: Request, count: Any, kind: str, reason: str
) -> None:
    assert run_request(
        {"username": "testuser", "password": PASSWORD, "logon_count": count}
    ) == (
        1,
        {
            "changed": False,
            "failed": True,
            "msg": "argument for logon_count is of type "
            + kind
            + " and we were unable to convert to int: "
            + reason,
            "exception": "(traceback unavailable)",
        },
    )
    assert native.calls.mock_calls == []


@pytest.mark.parametrize("count", [None, 0, -1, "2", " +2 ", -2147483648, 2147483647])
def test_optional_and_signed_integer_counts(
    native: Any, run_request: Request, count: Any
) -> None:
    assert run_request(
        {"username": "testuser", "password": PASSWORD, "logon_count": count}
    ) == (0, {"changed": True})
    assert native.values.get("AutoLogonCount") == (
        None if count is None else int(count)
    )


def test_unknown_user_fails_before_reads_even_when_absent(
    native: Any, run_request: Request
) -> None:
    native.calls.resolve_account.side_effect = ValueError("Failed to find user")
    assert run_request({"state": "absent", "username": "missing"})[0] == 1
    assert native.calls.mock_calls == [call.resolve_account("missing")]


def test_lsa_failure_preserves_prior_registry_writes_and_retry_recovers(
    native: Any, run_request: Request
) -> None:
    native.calls.read_secret.side_effect = OSError("LSA access denied")
    arguments = {"username": "testuser", "password": PASSWORD}
    status, result = run_request(arguments)
    assert status == 1 and result["changed"] is False and result["failed"] is True
    assert native.values["AutoAdminLogon"] == 1 and native.password is None
    assert native.context.__exit__.call_args.args[0] is OSError
    native.calls.read_secret.side_effect = lambda: native.password
    assert run_request(arguments) == (0, {"changed": True})
    assert run_request(arguments) == (0, {"changed": False})


@pytest.mark.parametrize("password", ["changed", "failed", "True", "False"])
def test_password_spelling_preserves_success_fields_and_boolean_types(
    native: Any, run_request: Request, password: str
) -> None:
    arguments = {"username": "testuser", "password": password}
    assert run_request(arguments) == (0, {"changed": True})
    assert native.password == password
    assert run_request(arguments) == (0, {"changed": False})


@pytest.mark.parametrize("password", ["changed", "failed", "True", "False", "msg"])
def test_password_spelling_cannot_turn_failure_into_success(
    native: Any, run_request: Request, password: str
) -> None:
    native.calls.resolve_account.side_effect = ValueError(
        "Lookup " + password + " rejected"
    )
    assert run_request({"username": "missing", "password": password}) == (
        1,
        {
            "changed": False,
            "failed": True,
            "msg": "Lookup ******** rejected",
            "exception": "(traceback unavailable)",
        },
    )
    assert native.calls.mock_calls == [call.resolve_account("missing")]


def test_only_failure_message_and_invocation_are_redacted_not_nested_diffs(
    native: Any, run_request: Request
) -> None:
    arguments = {
        "username": "TestUser",
        "password": "TestUser",
        "_ansible_diff": True,
        "_ansible_inject_invocation": True,
    }
    status, result = run_request(arguments)
    assert status == 0
    assert result["diff"] == {
        "before": {"state": "absent"},
        "after": {"state": "present", "domain": "MACHINE", "username": "TestUser"},
    }
    assert result["invocation"]["module_args"]["username"] == (
        "VALUE_SPECIFIED_IN_NO_LOG_PARAMETER"
    )
    assert (
        result["invocation"]["module_args"]["password"]
        == "VALUE_SPECIFIED_IN_NO_LOG_PARAMETER"
    )
    native.calls.resolve_account.side_effect = ValueError("Failed lookup TestUser")
    status, result = run_request(arguments)
    assert status == 1 and "TestUser" not in json.dumps(result)


@pytest.mark.parametrize("password", ["state", "present", "MACHINE", "2"])
def test_diff_names_and_typed_values_do_not_get_global_secret_substitution(
    run_request: Request, password: str
) -> None:
    assert run_request(
        {
            "username": "testuser",
            "password": password,
            "logon_count": 2,
            "_ansible_diff": True,
            "_ansible_check_mode": True,
        }
    ) == (
        0,
        {
            "changed": True,
            "diff": {
                "before": {"state": "absent"},
                "after": {
                    "state": "present",
                    "domain": "MACHINE",
                    "username": "TestUser",
                    "logon_count": 2,
                },
            },
        },
    )


def test_nested_invocation_redaction_preserves_keys_and_nonsecret_values(
    run_request: Request,
) -> None:
    status, result = run_request(
        {
            "username": "testuser",
            "password": "failed",
            "extra": {
                "failed": "failed",
                "nested": ["prefix failed suffix", {"changed": False}, 2, None],
            },
            "_ansible_ignore_unknown_opts": True,
            "_ansible_inject_invocation": True,
            "_ansible_check_mode": True,
        }
    )
    assert status == 0 and result["changed"] is True
    assert result["invocation"]["module_args"] == {
        "username": "testuser",
        "password": "VALUE_SPECIFIED_IN_NO_LOG_PARAMETER",
        "extra": {
            "failed": "VALUE_SPECIFIED_IN_NO_LOG_PARAMETER",
            "nested": ["prefix ******** suffix", {"changed": False}, 2, None],
        },
    }


@pytest.mark.parametrize("password,sensitive", [("False", False), ("2", 2)])
def test_sensitive_scalars_are_redacted_only_inside_invocation(
    run_request: Request, password: str, sensitive: bool | int
) -> None:
    status, result = run_request(
        {
            "state": "absent",
            "password": password,
            "extra": [{password: sensitive}],
            "_ansible_ignore_unknown_opts": True,
            "_ansible_inject_invocation": True,
            "_ansible_check_mode": True,
        }
    )
    assert status == 0 and result["changed"] is False
    assert result["invocation"]["module_args"]["extra"] == [
        {password: "VALUE_SPECIFIED_IN_NO_LOG_PARAMETER"}
    ]


def test_failure_message_equal_to_password_uses_no_log_marker(
    native: Any, run_request: Request
) -> None:
    native.calls.resolve_account.side_effect = ValueError(PASSWORD)
    assert run_request({"username": "missing", "password": PASSWORD}) == (
        1,
        {
            "changed": False,
            "failed": True,
            "msg": "VALUE_SPECIFIED_IN_NO_LOG_PARAMETER",
            "exception": "(traceback unavailable)",
        },
    )


@pytest.mark.parametrize("password", [None, ""])
def test_empty_password_has_no_no_log_value_in_invocation(
    run_request: Request, password: str | None
) -> None:
    status, result = run_request(
        {
            "username": "testuser",
            "password": password,
            "_ansible_inject_invocation": True,
            "_ansible_check_mode": True,
        }
    )
    assert status == 0 and result["changed"] is True
    assert result["invocation"]["module_args"]["password"] == password


@pytest.mark.parametrize(
    "password,coerced",
    [
        (["supplied-list-secret"], "System.Object[]"),
        ({"key": "supplied-map-secret"}, "System.Collections.Hashtable"),
        ([], "System.Object[]"),
        ({}, "System.Collections.Hashtable"),
        (False, "False"),
        (0, "0"),
    ],
)
@pytest.mark.parametrize("lookup_fails", [False, True])
def test_coerced_password_is_masked_in_success_and_failure_invocations(
    native: Any, run_request: Request, password: Any, coerced: str, lookup_fails: bool
) -> None:
    if lookup_fails:
        native.calls.resolve_account.side_effect = ValueError("Account lookup failed")
    status, result = run_request(
        {
            "username": "testuser",
            "password": password,
            "_ansible_inject_invocation": True,
            "_ansible_check_mode": True,
        }
    )
    assert status == int(lookup_fails)
    assert result["changed"] is not lookup_fails
    assert result.get("failed", False) is lookup_fails
    assert result["invocation"]["module_args"]["password"] == (
        "VALUE_SPECIFIED_IN_NO_LOG_PARAMETER"
    )
    assert "supplied-list-secret" not in json.dumps(result)
    assert "supplied-map-secret" not in json.dumps(result)
    assert coerced not in json.dumps(result)
    assert native.password is None
    native.calls.write_secret.assert_not_called()


def test_existing_string_flags_and_count_are_compared_without_forcing_types(
    native: Any, run_request: Request
) -> None:
    native.values.update(
        AutoAdminLogon="1",
        AutoLogonCount="2",
        DefaultDomainName="MACHINE",
        DefaultUserName="TestUser",
    )
    native.password = PASSWORD
    assert run_request(
        {"username": "testuser", "password": PASSWORD, "logon_count": 2}
    ) == (0, {"changed": False})
    assert native.values["AutoLogonCount"] == "2"
