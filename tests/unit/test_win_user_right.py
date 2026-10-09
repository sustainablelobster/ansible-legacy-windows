"""Exercise user-right results, SID set semantics, and partial failures."""

# SPDX-License-Identifier: GPL-3.0-or-later

import json
import sys
from contextlib import contextmanager
from pathlib import Path
from types import SimpleNamespace
from typing import Any
from unittest.mock import Mock, call

import pytest

from tests.unit.payload_support import invoke_payload, load_payload

RIGHT = "SeCreatePagefilePrivilege"
NAMES = {
    "BA": "BUILTIN\\Administrators",
    "SY": "NT AUTHORITY\\SYSTEM",
    "BG": "BUILTIN\\Guests",
}


@pytest.fixture(name="runner")
def payload_runner(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> Any:
    """Load the payload with persistent isolated LSA assignments.

    :param monkeypatch: Scoped native and argument-file substitutions.
    :param tmp_path: Controller-only request directory.
    :param capsys: JSON protocol capture.
    :returns: Request callable, assignment list, and native call recorders.
    """
    payload = load_payload("win_user_right", monkeypatch)
    state: list[str] = []
    policy = Mock()
    policy.accounts.side_effect = lambda _name: list(state)
    policy.add.side_effect = lambda sid, _name: state.append(sid)
    policy.remove.side_effect = lambda sid, _name: state.remove(sid)
    lifecycle = Mock()

    @contextmanager
    def _policy() -> Any:
        lifecycle.open()
        try:
            yield policy
        finally:
            lifecycle.close()

    resolve = Mock(side_effect=lambda value: "BA" if value == "S-1-5-32-544" else value)
    monkeypatch.setattr(payload.user_right, "open_policy", _policy)
    monkeypatch.setattr(payload.owner, "resolve_owner", resolve)
    monkeypatch.setattr(
        payload.accounts, "sid_to_name", lambda sid: NAMES.get(sid, sid)
    )
    path = tmp_path / "arguments.json"
    monkeypatch.setattr(sys, "argv", ["win_user_right.py", str(path)])

    def _run(arguments: dict[str, Any]) -> tuple[int, dict[str, Any]]:
        path.write_text(json.dumps(arguments), encoding="utf-8")
        return invoke_payload(payload, capsys)

    return SimpleNamespace(
        run=_run,
        state=state,
        policy=policy,
        resolve=resolve,
        lifecycle=lifecycle,
        payload=payload,
    )


@pytest.mark.parametrize("check", [False, True])
@pytest.mark.parametrize("diff", [False, True])
def test_empty_assignment_noop(runner: Any, check: bool, diff: bool) -> None:
    expected: dict[str, Any] = {"changed": False, "added": [], "removed": []}
    if diff:
        expected["diff"] = {"before": {RIGHT: []}, "after": {RIGHT: []}}
    assert runner.run(
        {
            "name": RIGHT,
            "users": [],
            "_ansible_check_mode": check,
            "_ansible_diff": diff,
        }
    ) == (0, expected)
    assert runner.policy.mock_calls == [call.accounts(RIGHT)]
    assert runner.lifecycle.mock_calls == [call.open(), call.close()]


def test_check_actual_and_repeat_deduplicate_resolved_sids(runner: Any) -> None:
    args = {"name": RIGHT, "users": ["BA", "S-1-5-32-544", "SY"], "_ansible_diff": True}
    expected = {
        "changed": True,
        "added": [NAMES["BA"], NAMES["SY"]],
        "removed": [],
        "diff": {"before": {RIGHT: []}, "after": {RIGHT: [NAMES["BA"], NAMES["SY"]]}},
    }
    assert runner.run(dict(args, _ansible_check_mode=True)) == (0, expected)
    assert runner.state == []
    runner.policy.reset_mock()
    assert runner.run(args) == (0, expected)
    assert runner.state == ["BA", "SY"]
    assert runner.policy.mock_calls == [
        call.accounts(RIGHT),
        call.add("BA", RIGHT),
        call.add("SY", RIGHT),
    ]
    assert runner.run(args) == (
        0,
        {
            "changed": False,
            "added": [],
            "removed": [],
            "diff": {
                "before": {RIGHT: [NAMES["BA"], NAMES["SY"]]},
                "after": {RIGHT: [NAMES["BA"], NAMES["SY"]]},
            },
        },
    )


def test_set_adds_first_then_removes_in_native_order(runner: Any) -> None:
    runner.state[:] = ["BG", "BA"]
    code, result = runner.run({"name": RIGHT, "users": ["SY"], "_ansible_diff": True})
    assert code == 0
    assert result == {
        "changed": True,
        "added": [NAMES["SY"]],
        "removed": [NAMES["BG"], NAMES["BA"]],
        "diff": {
            "before": {RIGHT: [NAMES["BG"], NAMES["BA"]]},
            "after": {RIGHT: [NAMES["SY"]]},
        },
    }
    assert runner.policy.mock_calls == [
        call.accounts(RIGHT),
        call.add("SY", RIGHT),
        call.remove("BG", RIGHT),
        call.remove("BA", RIGHT),
    ]


def test_remove_uses_request_order_and_leaves_others(runner: Any) -> None:
    runner.state[:] = ["BG", "BA", "SY"]
    assert runner.run(
        {"name": RIGHT, "users": ["SY", "BG", "SY"], "action": "REMOVE"}
    ) == (0, {"changed": True, "added": [], "removed": [NAMES["SY"], NAMES["BG"]]})
    assert runner.state == ["BA"]


def test_add_scalar_list_and_orphan_name_fallback(runner: Any) -> None:
    assert runner.run(
        {"name": RIGHT, "users": "BA, S-1-5-21-1-2-3-9999", "action": "add"}
    ) == (
        0,
        {"changed": True, "added": [NAMES["BA"], "S-1-5-21-1-2-3-9999"], "removed": []},
    )
    assert runner.run({"name": RIGHT, "users": []}) == (
        0,
        {"changed": True, "added": [], "removed": [NAMES["BA"], "S-1-5-21-1-2-3-9999"]},
    )


@pytest.mark.parametrize(
    "arguments,message",
    [
        ({}, "missing required arguments: users, name"),
        ({"users": []}, "missing required arguments: name"),
        ({"name": RIGHT}, "missing required arguments: users"),
        (
            {"name": RIGHT, "users": [], "action": "invalid"},
            "value of action must be one of: add, remove, set. Got no match for: invalid",
        ),
    ],
)
def test_binding_failure_does_not_open_policy(
    runner: Any, arguments: dict[str, Any], message: str
) -> None:
    assert runner.run(dict(arguments, _ansible_diff=True)) == (
        1,
        {
            "changed": False,
            "failed": True,
            "msg": message,
            "exception": "(traceback unavailable)",
        },
    )
    runner.lifecycle.assert_not_called()
    assert runner.lifecycle.mock_calls == []


@pytest.mark.parametrize("check", [False, True])
@pytest.mark.parametrize(
    "value,kind",
    [
        (True, "System.Boolean"),
        ({}, "System.Collections.Hashtable"),
        (1.5, "System.Decimal"),
        (1e30, "System.Double"),
        (2**63, "System.Decimal"),
        (2**96, "System.Double"),
    ],
)
def test_invalid_list_type_fails_before_native_calls(
    runner: Any, value: Any, kind: str, check: bool
) -> None:
    runner.state[:] = ["BA"]
    assert runner.run(
        {
            "name": RIGHT,
            "users": value,
            "_ansible_diff": True,
            "_ansible_check_mode": check,
        }
    ) == (
        1,
        {
            "changed": False,
            "failed": True,
            "msg": f"argument for users is of type {kind} and we were unable to "
            f"convert to list: {kind} cannot be converted to a list",
            "exception": "(traceback unavailable)",
        },
    )
    assert runner.state == ["BA"]
    assert runner.lifecycle.mock_calls == []
    assert runner.policy.mock_calls == []
    runner.resolve.assert_not_called()


def test_identity_failure_precedes_enumeration_and_retains_empty_results(
    runner: Any,
) -> None:
    runner.resolve.side_effect = ["BA", OSError(1332, "no mapping")]
    assert runner.run(
        {"name": RIGHT, "users": ["BA", "missing"], "_ansible_diff": True}
    ) == (
        1,
        {
            "changed": False,
            "added": [],
            "removed": [],
            "diff": {"before": "", "after": ""},
            "failed": True,
            "msg": "Failed to translate the account 'missing' to a SID",
            "exception": "(traceback unavailable)",
        },
    )
    assert runner.policy.mock_calls == []
    assert runner.lifecycle.mock_calls == [call.open(), call.close()]


@pytest.mark.parametrize(
    "error,message",
    [
        (ValueError("unknown"), "the specified right BadRight is not a valid right"),
        (
            OSError(5, "denied"),
            "failed to enumerate eixsting accounts with the right BadRight: denied",
        ),
    ],
)
def test_enumeration_failure_retains_diff_placeholders(
    runner: Any, error: Exception, message: str
) -> None:
    runner.policy.accounts.side_effect = error
    assert runner.run({"name": "BadRight", "users": [], "_ansible_diff": True}) == (
        1,
        {
            "changed": False,
            "added": [],
            "removed": [],
            "diff": {"before": "", "after": ""},
            "failed": True,
            "msg": message,
            "exception": "(traceback unavailable)",
        },
    )


@pytest.mark.parametrize("value", [None, "", [""]])
def test_null_or_empty_user_fails_without_clearing_assignments(
    runner: Any, value: Any
) -> None:
    runner.state[:] = ["BA"]
    assert runner.run({"name": RIGHT, "users": value, "_ansible_diff": True}) == (
        1,
        {
            "changed": False,
            "failed": True,
            "msg": "Unhandled exception while executing module: Cannot bind "
            "argument to parameter 'InputObject' because it is an empty string.",
            "exception": "(traceback unavailable)",
        },
    )
    assert runner.state == ["BA"]
    assert runner.policy.mock_calls == []
    assert runner.lifecycle.mock_calls == [call.open(), call.close()]


def test_null_list_element_fails_before_initializing_policy(runner: Any) -> None:
    assert runner.run({"name": RIGHT, "users": [None], "_ansible_diff": True}) == (
        1,
        {
            "changed": False,
            "failed": True,
            "msg": 'Unhandled exception while executing module: Exception calling "Create" '
            'with "2" argument(s): "Object reference not set to an instance of an object."',
            "exception": "(traceback unavailable)",
        },
    )
    assert runner.lifecycle.mock_calls == []


@pytest.mark.parametrize("value", [None, ""])
def test_null_or_empty_right_reaches_native_invalid_right_failure(
    runner: Any, value: Any
) -> None:
    runner.policy.accounts.side_effect = ValueError("unknown")
    assert runner.run({"name": value, "users": [], "_ansible_diff": True}) == (
        1,
        {
            "changed": False,
            "added": [],
            "removed": [],
            "diff": {"before": "", "after": ""},
            "failed": True,
            "msg": "the specified right  is not a valid right",
            "exception": "(traceback unavailable)",
        },
    )
    runner.policy.accounts.assert_called_once_with("")


def test_null_action_has_set_semantics(runner: Any) -> None:
    runner.state[:] = ["BG"]
    assert runner.run({"name": RIGHT, "users": ["BA"], "action": None}) == (
        0,
        {"changed": True, "added": [NAMES["BA"]], "removed": [NAMES["BG"]]},
    )
    assert runner.state == ["BA"]


def test_late_add_failure_preserves_earlier_change_and_does_not_remove(
    runner: Any,
) -> None:
    runner.state[:] = ["BG"]
    runner.policy.add.side_effect = [None, OSError(5, "denied")]
    code, result = runner.run(
        {"name": RIGHT, "users": ["BA", "SY"], "_ansible_diff": True}
    )
    assert code == 1
    assert result == {
        "changed": True,
        "added": [NAMES["BA"]],
        "removed": [],
        "diff": {"before": {RIGHT: [NAMES["BG"]]}, "after": ""},
        "failed": True,
        "msg": "Failed to add account NT AUTHORITY\\SYSTEM to right "
        + RIGHT
        + ": denied",
        "exception": "(traceback unavailable)",
    }
    runner.policy.remove.assert_not_called()
    assert runner.lifecycle.mock_calls[-1] == call.close()


def test_remove_failure_preserves_previous_successes(runner: Any) -> None:
    runner.state[:] = ["BG", "BA"]
    runner.policy.remove.side_effect = [None, OSError(5, "denied")]
    code, result = runner.run({"name": RIGHT, "users": [], "_ansible_diff": True})
    assert code == 1
    assert result["changed"] is True
    assert result["removed"] == [NAMES["BG"]]
    assert (
        result["msg"]
        == "Failed to remove account BUILTIN\\Administrators from right "
        + RIGHT
        + ": denied"
    )
    assert result["diff"]["after"] == ""
