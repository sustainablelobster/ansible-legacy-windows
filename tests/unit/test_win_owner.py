"""Exercise ownership decisions and JSON results without accessing Windows."""

# SPDX-License-Identifier: GPL-3.0-or-later
# Payload tests replace native security operations; they do not prove Windows support.
# pylint: disable=protected-access

import json
import sys
from pathlib import Path
from types import ModuleType
from typing import Any
from unittest.mock import MagicMock, Mock, call

import pytest

from tests.unit.payload_support import invoke_payload, load_payload

_PATH = r"C:\Café 雪 [literal] 'file' % ! &.txt"
_CURRENT = "S-1-5-18"
_DESIRED = "S-1-5-32-544"
_USER = "Administrators"


@pytest.fixture(name="payload")
def owner_payload(monkeypatch: pytest.MonkeyPatch) -> ModuleType:
    """Load the payload with explicit metadata and ownership substitutes.

    :param monkeypatch: Scoped native Windows replacements.
    :returns: Payload with a file owned by a different account by default.
    """
    module = load_payload("win_owner", monkeypatch)
    monkeypatch.setattr(
        module.filesystem, "file_info", Mock(return_value={"attributes": 0})
    )
    monkeypatch.setattr(module.ownership, "resolve_owner", Mock(return_value=_DESIRED))
    monkeypatch.setattr(module.ownership, "get_owner", Mock(return_value=_CURRENT))
    monkeypatch.setattr(module.ownership, "set_owner", Mock())
    monkeypatch.setattr(
        module.ownership, "ownership_privileges", Mock(return_value=MagicMock())
    )
    return module


def _manage(
    payload: ModuleType,
    path: str | Path = _PATH,
    *,
    check_mode: bool = False,
    **options: object,
) -> dict[str, Any]:
    result: dict[str, Any] = payload._manage(
        payload._parameters({"path": str(path), "user": _USER, **options}),
        check_mode,
    )
    return result


@pytest.mark.parametrize("directory", [False, True])
@pytest.mark.parametrize("matching", [False, True])
@pytest.mark.parametrize("check_mode", [False, True])
def test_only_different_owner_changes(
    payload: ModuleType, directory: bool, matching: bool, check_mode: bool
) -> None:
    payload.filesystem.file_info.return_value = {"attributes": 0x10 if directory else 0}
    payload.ownership.get_owner.return_value = _DESIRED if matching else _CURRENT
    assert _manage(payload, check_mode=check_mode) == {"changed": not matching}
    payload.filesystem.file_info.assert_called_once_with(_PATH)
    payload.ownership.resolve_owner.assert_called_once_with(_USER)
    payload.ownership.get_owner.assert_called_once_with(_PATH)
    context = payload.ownership.ownership_privileges.return_value
    context.__enter__.assert_called_once()
    context.__exit__.assert_called_once_with(None, None, None)
    if matching or check_mode:
        payload.ownership.set_owner.assert_not_called()
    else:
        payload.ownership.set_owner.assert_called_once_with(_PATH, _DESIRED)


@pytest.mark.parametrize("recurse", [False, None, True])
def test_recurse_on_file_never_enumerates_or_warns(
    payload: ModuleType, monkeypatch: pytest.MonkeyPatch, recurse: bool | None
) -> None:
    listing = Mock(side_effect=AssertionError("file must not be enumerated"))
    monkeypatch.setattr(payload.os, "listdir", listing)
    assert _manage(payload, recurse=recurse) == {"changed": True}
    listing.assert_not_called()


@pytest.mark.parametrize("recurse", [False, None])
def test_nonrecursive_directory_leaves_descendants_untouched(
    payload: ModuleType, monkeypatch: pytest.MonkeyPatch, recurse: bool | None
) -> None:
    payload.filesystem.file_info.return_value = {"attributes": 0x10}
    listing = Mock(side_effect=AssertionError("nonrecursive directory was listed"))
    monkeypatch.setattr(payload.os, "listdir", listing)
    assert _manage(payload, recurse=recurse) == {"changed": True}
    payload.ownership.set_owner.assert_called_once_with(_PATH, _DESIRED)
    listing.assert_not_called()


@pytest.mark.parametrize("check_mode", [False, True])
@pytest.mark.parametrize("matching_root", [False, True])
def test_recursive_tree_compares_each_owner_and_preserves_file_bytes(
    payload: ModuleType, tmp_path: Path, check_mode: bool, matching_root: bool
) -> None:
    directory = tmp_path / "hidden Café 雪 [nested]"
    directory.mkdir()
    first, second = tmp_path / "file % ! &.txt", directory / "O'Brien.txt"
    first.write_bytes(b"unchanged\x00first")
    second.write_bytes(b"unchanged\xffsecond")
    owners = {
        str(tmp_path): _DESIRED if matching_root else _CURRENT,
        str(directory): _CURRENT,
        str(first): _DESIRED,
        str(second): _CURRENT,
    }
    original = owners.copy()
    payload.filesystem.file_info.side_effect = lambda path: {
        "attributes": (0x10 if Path(path).is_dir() else 0) | 0x2
    }
    payload.ownership.get_owner.side_effect = owners.__getitem__
    payload.ownership.set_owner.side_effect = owners.__setitem__

    assert _manage(payload, tmp_path, recurse=True, check_mode=check_mode) == {
        "changed": True
    }
    assert set(
        item.args[0] for item in payload.ownership.get_owner.call_args_list
    ) == set(owners)
    assert payload.ownership.get_owner.call_count == len(owners)
    assert first.read_bytes() == b"unchanged\x00first"
    assert second.read_bytes() == b"unchanged\xffsecond"
    if check_mode:
        assert owners == original
        payload.ownership.set_owner.assert_not_called()
    else:
        assert all(value == _DESIRED for value in owners.values())
        expected_writes = sum(value != _DESIRED for value in original.values())
        assert payload.ownership.set_owner.call_count == expected_writes
        assert _manage(payload, tmp_path, recurse=True) == {"changed": False}
        assert payload.ownership.set_owner.call_count == expected_writes


@pytest.mark.parametrize("path", [_PATH, "", None])
def test_missing_path_precedes_account_resolution(
    payload: ModuleType, path: str | None
) -> None:
    payload.filesystem.file_info.return_value = None
    parameters = payload._parameters({"path": path, "user": "not-an-account"})
    assert payload._manage(parameters) == {
        "changed": False,
        "failed": True,
        "msg": f"{path or ''} file or directory does not exist on the host",
    }
    payload.ownership.resolve_owner.assert_not_called()
    payload.ownership.ownership_privileges.assert_not_called()


def test_resolution_failure_does_not_enable_privileges_or_touch_owner(
    payload: ModuleType,
) -> None:
    payload.ownership.resolve_owner.side_effect = ValueError("cannot resolve principal")
    result = _manage(payload)
    assert result["changed"] is False and result["failed"] is True
    assert result["msg"] == "cannot resolve principal"
    assert "ValueError: cannot resolve principal" in result["exception"]
    payload.ownership.ownership_privileges.assert_not_called()
    payload.ownership.get_owner.assert_not_called()


def test_unknown_principal_retains_upstream_context_and_native_diagnostics(
    payload: ModuleType,
) -> None:
    error = OSError("No mapping between account names and security IDs was done.")
    setattr(error, "winerror", 1332)
    payload.ownership.resolve_owner.side_effect = error
    result = _manage(payload, user="invalid-user")
    assert result["changed"] is False and result["failed"] is True
    assert result["msg"] == (
        "Failed to translate 'invalid-user' to a SecurityIdentifier: "
        "Some or all identity references could not be translated."
    )
    assert "OSError: " + str(error) in result["exception"]
    payload.ownership.ownership_privileges.assert_not_called()
    payload.ownership.get_owner.assert_not_called()


@pytest.mark.parametrize("stage", ["enter", "read", "write", "exit"])
def test_native_failure_is_wrapped_and_preserves_only_successful_changes(
    payload: ModuleType, stage: str
) -> None:
    context = payload.ownership.ownership_privileges.return_value
    operation = {
        "enter": context.__enter__,
        "read": payload.ownership.get_owner,
        "write": payload.ownership.set_owner,
        "exit": context.__exit__,
    }[stage]
    operation.side_effect = OSError("native access denied")
    result = _manage(payload)
    assert result["changed"] is (stage == "exit")
    assert result["failed"] is True
    assert result["msg"] == (
        f"an error occurred when attempting to change owner on {_PATH} "
        f"for {_USER}: native access denied"
    )
    assert "OSError: native access denied" in result["exception"]
    if stage != "enter":
        context.__exit__.assert_called_once()
    operation.side_effect = None
    assert _manage(payload) == {"changed": True}


@pytest.mark.parametrize(
    "check_mode, failure",
    [(False, name) for name in ("enumeration", "missing_child", "read", "write")]
    + [(True, name) for name in ("enumeration", "missing_child", "read")],
)
def test_recursive_failure_retains_earlier_change_and_restores_privileges(
    payload: ModuleType,
    monkeypatch: pytest.MonkeyPatch,
    check_mode: bool,
    failure: str,
) -> None:
    payload.filesystem.file_info.side_effect = [
        {"attributes": 0x10},
        None if failure == "missing_child" else {"attributes": 0},
    ]
    listing = Mock(return_value=["child"])
    if failure == "enumeration":
        listing.side_effect = OSError("cannot list directory")
    monkeypatch.setattr(payload.os, "listdir", listing)
    if failure == "read":
        payload.ownership.get_owner.side_effect = [
            _CURRENT,
            OSError("cannot read child"),
        ]
    if failure == "write":
        payload.ownership.set_owner.side_effect = [None, OSError("cannot set child")]

    result = _manage(payload, recurse=True, check_mode=check_mode)

    assert result["changed"] and result["failed"]
    assert result["msg"].startswith(
        f"an error occurred when attempting to change owner on {_PATH} for {_USER}:"
    )
    assert "Traceback" in result["exception"]
    if check_mode:
        payload.ownership.set_owner.assert_not_called()
    else:
        assert payload.ownership.set_owner.call_args_list[0] == call(_PATH, _DESIRED)
    payload.ownership.ownership_privileges.return_value.__exit__.assert_called_once()


def test_unexpected_later_failure_does_not_erase_completed_work(
    payload: ModuleType, monkeypatch: pytest.MonkeyPatch
) -> None:
    payload.filesystem.file_info.return_value = {"attributes": 0x10}
    monkeypatch.setattr(
        payload.os, "listdir", Mock(side_effect=RuntimeError("provider failed"))
    )
    result = _manage(payload, recurse=True)
    assert result["changed"] and result["failed"]
    assert "RuntimeError: provider failed" in result["exception"]


@pytest.mark.parametrize(
    "recurse, expected", [(False, False), (None, False), ("yes", True), (1, True)]
)
def test_argument_defaults_and_nullable_recursion(
    payload: ModuleType, recurse: object, expected: bool
) -> None:
    assert payload._parameters({"path": _PATH, "user": _USER}) == {
        "path": _PATH,
        "user": _USER,
        "recurse": False,
    }
    assert (
        payload._parameters({"path": _PATH, "user": _USER, "recurse": recurse})[
            "recurse"
        ]
        is expected
    )


@pytest.mark.parametrize(
    "arguments, message",
    [
        ({}, "missing required arguments: path, user"),
        ({"path": _PATH}, "missing required arguments: user"),
        ({"user": _USER}, "missing required arguments: path"),
        (
            {"path": _PATH, "user": _USER, "recurse": "invalid"},
            "Expected a boolean for recurse.",
        ),
    ],
)
def test_invalid_arguments_fail_before_native_calls(
    payload: ModuleType, arguments: dict[str, object], message: str
) -> None:
    with pytest.raises(ValueError) as caught:
        payload._parameters(arguments)
    assert str(caught.value) == message
    payload.filesystem.file_info.assert_not_called()


def test_environment_expansion_preserves_literal_filename(
    payload: ModuleType, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv("OWNER_TEST_ROOT", r"C:\Café 雪")
    assert _manage(payload, r"%OWNER_TEST_ROOT%\[entry] 'quoted'.txt")["changed"]
    payload.filesystem.file_info.assert_called_once_with(
        r"C:\Café 雪\[entry] 'quoted'.txt"
    )


@pytest.mark.parametrize("failure", [False, True])
def test_json_entrypoint_preserves_change_and_exit_status(
    payload: ModuleType,
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
    failure: bool,
) -> None:
    arguments = tmp_path / "arguments.json"
    arguments.write_text(json.dumps({"PATH": _PATH, "USER": _USER}), encoding="utf-8")
    monkeypatch.setattr(sys, "argv", ["win_owner.py", str(arguments)])
    if failure:
        payload.ownership.set_owner.side_effect = OSError("denied")
    status, result = invoke_payload(payload, capsys)
    assert status == int(failure)
    assert result["changed"] is not failure
    assert result.get("failed", False) is failure


def test_json_check_mode_avoids_owner_writes(
    payload: ModuleType, monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    arguments = tmp_path / "arguments.json"
    arguments.write_text(
        json.dumps({"path": _PATH, "user": _USER, "_ansible_check_mode": True}),
        encoding="utf-8",
    )
    monkeypatch.setattr(sys, "argv", ["win_owner.py", str(arguments)])
    assert payload._execute() == {"changed": True}
    payload.ownership.set_owner.assert_not_called()
