"""Exercise ACL inheritance decisions and JSON results without Windows access."""

# SPDX-License-Identifier: GPL-3.0-or-later
# Native boundary substitutes below do not establish Windows runtime support.
# pylint: disable=protected-access

import json
import sys
from pathlib import Path
from types import ModuleType
from typing import Any
from unittest.mock import Mock, call

import pytest

from tests.unit.payload_support import invoke_payload, load_payload

_PATH = r"C:\Café 雪 [literal] 'file' % ! &.txt"
_REGISTRY_PATH = r"HKCU:\Software\Café 雪 [literal]"


@pytest.fixture(name="payload")
def inheritance_payload(monkeypatch: pytest.MonkeyPatch) -> ModuleType:
    """Load the payload with a writable in-memory ACL boundary.

    :param monkeypatch: Scoped native Windows replacements.
    :returns: Payload whose initial ACL permits inheritance.
    """
    module = load_payload("win_acl_inheritance", monkeypatch)
    monkeypatch.setattr(module.inheritance, "normalize_path", lambda path: path)
    read = Mock(return_value={"protected": False, "dacl": b"ACL", "registry": False})
    read.side_effect = lambda path: read.return_value.copy()
    monkeypatch.setattr(module.inheritance, "read_acl", read)
    monkeypatch.setattr(
        module.inheritance,
        "write_acl",
        Mock(side_effect=lambda path, acl: read.return_value.update(acl)),
    )
    monkeypatch.setattr(
        module.inheritance,
        "set_protection",
        Mock(
            side_effect=lambda acl, protected, preserve: {**acl, "protected": protected}
        ),
    )
    monkeypatch.setattr(
        module.inheritance, "remove_explicit_duplicates", Mock(side_effect=dict)
    )
    return module


def _manage(
    payload: ModuleType,
    *,
    check_mode: bool = False,
    **options: object,
) -> dict[str, Any]:
    result: dict[str, Any] = payload._manage(
        payload._parameters({"path": _PATH, **options}), check_mode
    )
    return result


@pytest.mark.parametrize("path", [_PATH, _REGISTRY_PATH])
@pytest.mark.parametrize("protected", [False, True])
@pytest.mark.parametrize("state", ["absent", "present"])
@pytest.mark.parametrize("reorganize", [False, True])
@pytest.mark.parametrize("check_mode", [False, True])
# Keep each independent input visible in the transition matrix.
# pylint: disable-next=too-many-arguments,too-many-positional-arguments
def test_state_transition_idempotence_and_check_mode(
    payload: ModuleType,
    path: str,
    protected: bool,
    state: str,
    reorganize: bool,
    check_mode: bool,
) -> None:
    stored = payload.inheritance.read_acl.return_value
    stored.update(protected=protected, registry=path == _REGISTRY_PATH)
    before = "absent" if protected else "present"
    changed = before != state
    result = _manage(
        payload, path=path, state=state, reorganize=reorganize, check_mode=check_mode
    )
    assert result == {
        "changed": changed,
        "diff": {"before": {"state": before}, "after": {"state": state}},
    }
    assert stored["protected"] is (protected if check_mode else state == "absent")
    assert payload.inheritance.read_acl.call_args_list == [call(path)] * (
        1 if check_mode else 2
    )
    writes = 2 if reorganize and state == "present" else 1
    assert payload.inheritance.write_acl.call_count == (
        writes if changed and not check_mode else 0
    )
    assert payload.inheritance.remove_explicit_duplicates.call_count == int(
        changed and reorganize and state == "present"
    )
    if changed:
        assert payload.inheritance.set_protection.call_args.args[1:] == (
            state == "absent",
            reorganize if state == "absent" else False,
        )
    else:
        payload.inheritance.set_protection.assert_not_called()
    if not check_mode:
        assert not _manage(payload, path=path, state=state, reorganize=reorganize)[
            "changed"
        ]
        assert payload.inheritance.write_acl.call_count == (writes if changed else 0)


@pytest.mark.parametrize("check_mode", [False, True])
def test_reorganization_uses_the_existing_snapshot_without_an_intermediate_read(
    payload: ModuleType, check_mode: bool
) -> None:
    payload.inheritance.read_acl.return_value["protected"] = True
    sequence = Mock()
    for name in (
        "read_acl",
        "set_protection",
        "write_acl",
        "remove_explicit_duplicates",
    ):
        sequence.attach_mock(getattr(payload.inheritance, name), name)
    result = _manage(payload, state="present", reorganize=True, check_mode=check_mode)
    assert result["changed"]
    assert [item[0] for item in sequence.mock_calls] == (
        ["read_acl", "set_protection", "remove_explicit_duplicates"]
        if check_mode
        else [
            "read_acl",
            "set_protection",
            "write_acl",
            "remove_explicit_duplicates",
            "write_acl",
            "read_acl",
        ]
    )
    snapshot = payload.inheritance.remove_explicit_duplicates.call_args.args[0]
    assert snapshot["protected"] is False
    if not check_mode:
        assert payload.inheritance.write_acl.call_args_list[0].args[1] is snapshot


@pytest.mark.parametrize("code, path", [(2, _PATH), (3, _PATH), (123, r"C:\Windows\*")])
def test_missing_paths_report_the_expanded_literal_path(
    payload: ModuleType, code: int, path: str
) -> None:
    error = OSError("missing native object")
    setattr(error, "winerror", code)
    payload.inheritance.read_acl.side_effect = error
    assert _manage(payload, path=path) == {
        "changed": False,
        "failed": True,
        "msg": path + " does not exist",
    }
    payload.inheritance.set_protection.assert_not_called()
    payload.inheritance.write_acl.assert_not_called()


@pytest.mark.parametrize("state", ["absent", "present"])
def test_protection_failure_has_operation_context_and_no_writes(
    payload: ModuleType, state: str
) -> None:
    payload.inheritance.read_acl.return_value["protected"] = state == "present"
    payload.inheritance.set_protection.side_effect = ValueError("ACL is not canonical")
    result = _manage(payload, state=state)
    operation = "enable" if state == "present" else "disable"
    assert result["changed"] is False and result["failed"] is True
    assert (
        result["msg"]
        == f"Failed to {operation} inheritance of '{_PATH}': ACL is not canonical"
    )
    assert "ValueError: ACL is not canonical" in result["exception"]
    assert "after" not in result["diff"]
    payload.inheritance.write_acl.assert_not_called()


@pytest.mark.parametrize(
    "stage", ["first_read", "first_write", "deduplicate", "second_write", "last_read"]
)
def test_failure_preserves_upstream_change_reporting_and_allows_recovery(
    payload: ModuleType, stage: str
) -> None:
    backend = payload.inheritance
    backend.read_acl.return_value["protected"] = True
    error = OSError("native access denied")
    read = backend.read_acl.side_effect
    write = backend.write_acl.side_effect
    if stage == "first_read":
        backend.read_acl.side_effect = error
    elif stage == "last_read":
        backend.read_acl.side_effect = [backend.read_acl.return_value.copy(), error]
    elif stage == "deduplicate":
        backend.remove_explicit_duplicates.side_effect = error
    elif stage == "first_write":
        backend.write_acl.side_effect = error
    else:

        def fail_second_write(path: str, acl: dict[str, object]) -> None:
            if backend.write_acl.call_count == 2:
                raise error
            write(path, acl)

        backend.write_acl.side_effect = fail_second_write

    result = _manage(payload, state="present", reorganize=True)
    assert result["changed"] is (stage == "last_read")
    assert result["failed"] is True
    context = {
        "first_read": f"Failed to find '{_PATH}': ",
        "last_read": f"Failed to get acl of '{_PATH}': ",
    }.get(stage, "")
    assert result["msg"] == context + "native access denied"
    assert "OSError: native access denied" in result["exception"]
    if stage == "first_read":
        assert "diff" not in result
    else:
        assert result["diff"] == {"before": {"state": "absent"}}
    assert backend.read_acl.return_value["protected"] is (
        stage in ("first_read", "first_write")
    )

    backend.read_acl.side_effect = read
    backend.write_acl.side_effect = write
    backend.remove_explicit_duplicates.side_effect = dict
    recovered = _manage(payload, state="present", reorganize=True)
    assert not recovered.get("failed")
    assert recovered["changed"] is (stage in ("first_read", "first_write"))
    assert backend.read_acl.return_value["protected"] is False


def test_after_diff_comes_from_the_final_native_read(payload: ModuleType) -> None:
    payload.inheritance.write_acl.side_effect = None
    result = _manage(payload)
    assert result == {
        "changed": True,
        "diff": {"before": {"state": "present"}, "after": {"state": "present"}},
    }


@pytest.mark.parametrize("state", [None, "PRESENT", "ABSENT"])
def test_nullable_and_case_insensitive_state(
    payload: ModuleType, state: str | None
) -> None:
    result = _manage(payload, state=state)
    assert result["changed"] is (state == "ABSENT")
    assert result["diff"]["after"]["state"] == (
        "absent" if state == "ABSENT" else "present"
    )


@pytest.mark.parametrize(
    "reorganize, expected", [(None, False), (False, False), ("yes", True), (1, True)]
)
def test_parameter_defaults_and_nullable_reorganization(
    payload: ModuleType, reorganize: object, expected: bool
) -> None:
    assert payload._parameters({"path": _PATH}) == {
        "path": _PATH,
        "state": "absent",
        "reorganize": False,
    }
    assert (
        payload._parameters({"path": _PATH, "reorganize": reorganize})["reorganize"]
        is expected
    )


@pytest.mark.parametrize(
    "arguments, message",
    [
        ({}, "missing required arguments: path"),
        (
            {"path": _PATH, "state": "invalid"},
            "value of state must be one of: absent, present. Got no match for: invalid",
        ),
        (
            {"path": _PATH, "reorganize": "invalid"},
            "argument for reorganize is of type System.String and we were unable "
            "to convert to bool: The value 'invalid' is not a valid boolean. "
            "Valid booleans include: y, yes, on, 1, true, t, 1.0, "
            "n, no, off, 0, false, f, 0.0",
        ),
    ],
)
def test_argument_validation_precedes_native_reads(
    payload: ModuleType, arguments: dict[str, object], message: str
) -> None:
    with pytest.raises(ValueError) as caught:
        payload._parameters(arguments)
    assert str(caught.value) == message
    payload.inheritance.read_acl.assert_not_called()


@pytest.mark.parametrize(
    "path, message",
    [
        (None, "You cannot call a method on a null-valued expression."),
        ("", "Cannot bind argument to parameter 'Path' because it is an empty string."),
    ],
)
# The JSON boundary needs the input, expected message, and scoped I/O fixtures.
# pylint: disable-next=too-many-arguments,too-many-positional-arguments
def test_null_and_blank_paths_preserve_measured_messages_without_fake_tracebacks(
    payload: ModuleType,
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
    path: str | None,
    message: str,
) -> None:
    arguments = tmp_path / "arguments.json"
    arguments.write_text(json.dumps({"path": path}), encoding="utf-8")
    monkeypatch.setattr(sys, "argv", ["win_acl_inheritance.py", str(arguments)])
    status, result = invoke_payload(payload, capsys)
    assert status == 1
    assert result == {
        "changed": False,
        "failed": True,
        "msg": "Unhandled exception while executing module: " + message,
    }
    payload.inheritance.read_acl.assert_not_called()
    payload.inheritance.write_acl.assert_not_called()


@pytest.mark.parametrize("diff", [False, True])
@pytest.mark.parametrize("failure", [False, True])
# The JSON boundary needs file, capture, and native fixtures together.
# pylint: disable-next=too-many-arguments,too-many-positional-arguments
def test_json_entrypoint_filters_diff_and_preserves_error_status(
    payload: ModuleType,
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
    diff: bool,
    failure: bool,
) -> None:
    arguments = tmp_path / "arguments.json"
    arguments.write_text(
        json.dumps({"PATH": _PATH, "_ansible_diff": diff}), encoding="utf-8"
    )
    monkeypatch.setattr(sys, "argv", ["win_acl_inheritance.py", str(arguments)])
    if failure:
        payload.inheritance.write_acl.side_effect = OSError("denied")
    status, result = invoke_payload(payload, capsys)
    assert status == int(failure)
    assert result["changed"] is not failure
    assert result.get("failed", False) is failure
    assert ("diff" in result) is diff


def test_json_check_mode_avoids_security_writes(
    payload: ModuleType, monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    arguments = tmp_path / "arguments.json"
    arguments.write_text(
        json.dumps({"path": _PATH, "_ansible_check_mode": True}), encoding="utf-8"
    )
    monkeypatch.setattr(sys, "argv", ["win_acl_inheritance.py", str(arguments)])
    assert payload._execute() == {"changed": True}
    payload.inheritance.write_acl.assert_not_called()
