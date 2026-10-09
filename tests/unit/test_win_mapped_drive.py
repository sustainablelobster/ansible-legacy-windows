"""Exercise mapped-drive results, no-op behavior, and ordered partial failures."""

# SPDX-License-Identifier: GPL-3.0-or-later

import json
import sys
from pathlib import Path
from types import SimpleNamespace
from typing import Any
from unittest.mock import MagicMock, Mock, call

import pytest

from tests.unit.payload_support import invoke_payload, load_payload

FIRST = r"\\server\share\first"
SECOND = r"\\server\share\second"


@pytest.fixture(name="runner")
def mapping_runner(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> Any:
    """Load the entrypoint with remembered mappings and native call recorders.

    :param monkeypatch: Scoped replacement of native operations and argument path.
    :param tmp_path: Private controller-side argument directory.
    :param capsys: JSON protocol capture.
    :returns: Request callable, mapping state, payload, and native recorder.
    """
    payload = load_payload("win_mapped_drive", monkeypatch)
    state: list[dict[str, str]] = []
    native = Mock()
    native.remembered.side_effect = lambda: list(state)
    native.add.side_effect = lambda drive, path, *_credentials: state.append(
        {"drive": drive, "path": path}
    )
    native.remove.side_effect = lambda _drive: state.clear()
    context = MagicMock()
    context.__enter__.return_value = native
    monkeypatch.setattr(payload.mapped_drive, "open_mappings", lambda: context)
    monkeypatch.setattr(payload.mapped_drive, "logical_drives", lambda: ["C"])
    monkeypatch.setattr(payload.mapped_drive, "clear_username", native.clear_username)
    # This mapping workflow owns its case-insensitive environment oracle.
    # pylint: disable=duplicate-code
    monkeypatch.setattr(
        payload.environment,
        "values_equal",
        lambda left, right: (
            left is right
            if left is None or right is None
            else left.lower() == right.lower()
        ),
    )
    # pylint: enable=duplicate-code
    argument_file = tmp_path / "arguments.json"
    monkeypatch.setattr(sys, "argv", ["win_mapped_drive.py", str(argument_file)])

    def _run(arguments: dict[str, Any]) -> tuple[int, dict[str, Any]]:
        argument_file.write_text(json.dumps(arguments), encoding="utf-8")
        return invoke_payload(payload, capsys)

    return SimpleNamespace(run=_run, state=state, native=native, context=context)


def test_create_check_actual_repeat_and_case_insensitive_noop(runner: Any) -> None:
    args = {"letter": "M", "path": FIRST, "_ansible_diff": True}
    expected = {
        "changed": True,
        "diff": {"before": "", "after": {"letter": "M", "path": FIRST}},
    }
    assert runner.run(dict(args, _ansible_check_mode=True)) == (0, expected)
    assert runner.state == []
    runner.native.add.assert_not_called()
    assert runner.run(args) == (0, expected)
    assert runner.state == [{"drive": "M:", "path": FIRST}]
    assert runner.run(args) == (
        0,
        {
            "changed": False,
            "diff": {
                "before": {"letter": "M", "path": FIRST},
                "after": {"letter": "M", "path": FIRST},
            },
        },
    )
    assert runner.run({"letter": "m", "path": FIRST.upper()}) == (0, {"changed": False})
    runner.native.add.assert_called_once_with("M:", FIRST, None, None)


def test_retarget_and_explicit_credentials_cleanup_are_ordered(runner: Any) -> None:
    runner.state[:] = [{"drive": "M:", "path": FIRST}]
    args = {"letter": "M", "path": SECOND, "username": "account", "password": "secret"}
    assert runner.run(dict(args, _ansible_check_mode=True)) == (0, {"changed": True})
    assert runner.state[0]["path"] == FIRST
    runner.native.reset_mock()
    assert runner.run(args) == (0, {"changed": True})
    assert runner.native.mock_calls == [
        call.remembered(),
        call.remove("M:"),
        call.add("M:", SECOND, "account", "secret"),
        call.clear_username("M"),
    ]
    runner.native.reset_mock()
    assert runner.run(args) == (0, {"changed": False})
    assert runner.native.mock_calls == [call.remembered()]


def test_failed_retarget_keeps_disconnection_but_drops_pending_diff(
    runner: Any,
) -> None:
    runner.state[:] = [{"drive": "M:", "path": FIRST}]
    runner.native.add.side_effect = OSError(53, "Failed to map drive")
    code, result = runner.run({"letter": "M", "path": SECOND, "_ansible_diff": True})
    assert code == 1 and result["failed"] is True and result["changed"] is False
    assert "diff" not in result
    assert result["msg"] == (
        'Unhandled exception while executing module: Exception calling "Invoke" '
        'with "2" argument(s): "Failed to map drive"'
    )
    assert runner.state == []
    runner.native.clear_username.assert_not_called()
    runner.context.__exit__.assert_called_once()


def test_failed_removal_uses_original_direct_call_count_and_drops_diff(
    runner: Any,
) -> None:
    runner.state[:] = [{"drive": "M:", "path": FIRST}]
    runner.native.remove.side_effect = OSError(2250, "Failed to remove drive")
    code, result = runner.run({"letter": "M", "state": "absent", "_ansible_diff": True})
    assert code == 1 and result == {
        "changed": False,
        "failed": True,
        "msg": (
            "Unhandled exception while executing module: Exception calling "
            '"RemoveMappedDrive" with "2" argument(s): "Failed to remove drive"'
        ),
        "exception": "(traceback unavailable)",
    }
    assert runner.state == [{"drive": "M:", "path": FIRST}]
    runner.native.add.assert_not_called()


def test_absent_path_guard_check_real_repeat_and_no_path(runner: Any) -> None:
    runner.state[:] = [{"drive": "M:", "path": FIRST}]
    args = {"letter": "M", "state": "absent", "_ansible_diff": True}
    expected_diff = {"before": {"letter": "M", "path": FIRST}, "after": ""}
    code, result = runner.run(dict(args, path=SECOND))
    assert code == 1 and result == {
        "changed": False,
        "failed": True,
        "diff": expected_diff,
        "exception": "(traceback unavailable)",
        "msg": "did not delete mapped drive M, the target path is pointing "
        "to a different location at " + FIRST,
    }
    assert runner.run(dict(args, path=FIRST.upper(), _ansible_check_mode=True)) == (
        0,
        {"changed": True, "diff": expected_diff},
    )
    assert runner.state
    assert runner.run(args) == (0, {"changed": True, "diff": expected_diff})
    assert runner.run(args) == (
        0,
        {"changed": False, "diff": {"before": "", "after": ""}},
    )


@pytest.mark.parametrize("check", [False, True])
def test_physical_drive_failure_has_diff_but_does_not_write(
    runner: Any, check: bool
) -> None:
    assert runner.run(
        {
            "letter": "c",
            "path": FIRST,
            "_ansible_check_mode": check,
            "_ansible_diff": True,
        }
    ) == (
        1,
        {
            "changed": False,
            "failed": True,
            "diff": {"before": "", "after": ""},
            "exception": "(traceback unavailable)",
            "msg": "failed to create mapped drive c, this letter is in use "
            "and is pointing to a non UNC path",
        },
    )
    runner.native.add.assert_not_called()
    runner.native.remove.assert_not_called()


@pytest.mark.parametrize(
    "arguments,message",
    [
        ({}, "missing required arguments: letter"),
        (
            {"letter": "M"},
            "state is present but all of the following are missing: path",
        ),
        (
            {"letter": "ZZ", "state": "absent"},
            "letter must be a single letter from A-Z, was: ZZ",
        ),
        (
            {"letter": None, "state": "absent"},
            "letter must be a single letter from A-Z, was: ",
        ),
        (
            {"letter": "M", "state": "invalid"},
            "value of state must be one of: absent, present. Got no match for: invalid",
        ),
        (
            {"letter": "M", "path": ""},
            "argument for path is of type System.String and we were unable to "
            "convert to path: The path is not of a legal form.",
        ),
        (
            {"letter": "M", "path": "bad|path"},
            "argument for path is of type System.String and we were unable to "
            "convert to path: string value contains invalid path characters, "
            "cannot convert to path",
        ),
    ],
)
def test_binding_failures_do_not_enumerate_or_initialize_diff(
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
    assert runner.native.mock_calls == []
    runner.context.__enter__.assert_not_called()


def test_explicit_empty_credentials_remain_distinct_from_null(runner: Any) -> None:
    assert runner.run(
        {"letter": "M", "path": FIRST, "username": "", "password": ""}
    ) == (0, {"changed": True})
    runner.native.add.assert_called_once_with("M:", FIRST, "", "")
    runner.native.clear_username.assert_called_once_with("M")


@pytest.mark.parametrize(
    "arguments,secret",
    [
        ({"password": "username", "invalid": True}, "username"),
        ({"password": "secret-option", "secret-option": True}, "secret-option"),
        ({"password": "letter"}, "letter"),
        ({"PASSWORD": "username", "invalid": True}, "username"),
    ],
)
def test_password_is_hidden_before_real_reader_and_parameter_validation(
    runner: Any, arguments: dict[str, Any], secret: str
) -> None:
    code, result = runner.run(arguments)
    assert code == 1 and result["failed"] and not result["changed"]
    assert secret not in json.dumps(result)
    assert "********" in result["msg"]
    assert "diff" not in result
    runner.context.__enter__.assert_not_called()


def test_allow_unknown_reader_does_not_weaken_argument_rejection(runner: Any) -> None:
    code, result = runner.run({"invalid": True, "state": "absent"})
    assert code == 1 and result["msg"] == (
        "Unsupported parameters for "
        "(sustainablelobster.legacy_windows.win_mapped_drive) module: invalid. "
        "Supported parameters include: letter, password, path, state, username"
    )
    runner.context.__enter__.assert_not_called()
    assert runner.run(
        {
            "letter": "M",
            "state": "absent",
            "invalid": True,
            "_ansible_ignore_unknown_opts": True,
        }
    ) == (0, {"changed": False})
