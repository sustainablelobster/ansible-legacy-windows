"""Exercise compression decisions and JSON results with native calls replaced."""

# SPDX-License-Identifier: GPL-3.0-or-later
# Payload calls expose behavior without invoking Windows WMI on the controller.
# pylint: disable=protected-access

import json
import sys
from pathlib import Path
from types import ModuleType
from typing import Any
from unittest.mock import Mock

import pytest

from tests.unit.payload_support import invoke_payload, load_payload

_PATH = r"C:\Café 雪 [literal] 'file'.txt"
_SUCCESS = "The request was successful."
_FILE_WARNING = "The recurse option has no effect when path is not a folder."


@pytest.fixture(name="payload")
def compression_payload(monkeypatch: pytest.MonkeyPatch) -> ModuleType:
    """Load the payload and replace native metadata and mutation boundaries.

    :param monkeypatch: Scoped replacements for native Windows calls.
    :returns: Loaded payload with an existing uncompressed file by default.
    """
    module = load_payload("win_file_compression", monkeypatch)
    monkeypatch.setattr(
        module.filesystem, "file_info", Mock(return_value={"attributes": 0})
    )
    monkeypatch.setattr(
        module.compression,
        "volume_info",
        Mock(return_value={"filesystem": "NTFS", "supports_compression": True}),
    )
    monkeypatch.setattr(module.compression, "set_compression", Mock(return_value=0))
    return module


def _manage(
    payload: ModuleType,
    path: str | Path = _PATH,
    *,
    check_mode: bool = False,
    **options: object,
) -> dict[str, Any]:
    result: dict[str, Any] = payload._manage(
        payload._parameters({"path": str(path), **options}), check_mode
    )
    return result


@pytest.mark.parametrize("is_directory", [False, True])
@pytest.mark.parametrize("state", ["present", "absent"])
@pytest.mark.parametrize("check_mode", [False, True])
def test_predicts_and_applies_only_required_changes(
    payload: ModuleType, is_directory: bool, state: str, check_mode: bool
) -> None:
    compressed = state == "absent"
    attributes = (0x10 if is_directory else 0) | (0x800 if compressed else 0)
    payload.filesystem.file_info.return_value = {"attributes": attributes}

    assert _manage(payload, state=state, check_mode=check_mode) == {
        "changed": True,
        "rc": 0,
        "msg": _SUCCESS,
    }
    payload.filesystem.file_info.assert_called_once_with(_PATH)
    payload.compression.volume_info.assert_called_once_with(_PATH)
    if check_mode:
        payload.compression.set_compression.assert_not_called()
    else:
        payload.compression.set_compression.assert_called_once_with(
            _PATH, is_directory, not compressed, False
        )


@pytest.mark.parametrize("state", ["present", "absent"])
def test_repeated_operation_is_idempotent(payload: ModuleType, state: str) -> None:
    info = {"attributes": 0x800 if state == "absent" else 0}
    payload.filesystem.file_info.return_value = info

    def _set_compression(
        path: str, is_directory: bool, compressed: bool, recurse: bool
    ) -> int:
        assert path == _PATH and not is_directory and not recurse
        info["attributes"] = 0x800 if compressed else 0
        return 0

    payload.compression.set_compression.side_effect = _set_compression
    assert _manage(payload, state=state)["changed"] is True
    assert _manage(payload, state=state) == {
        "changed": False,
        "rc": 0,
        "msg": _SUCCESS,
    }
    assert payload.compression.set_compression.call_count == 1


@pytest.mark.parametrize("force", [False, True])
@pytest.mark.parametrize("check_mode", [False, True])
def test_root_mismatch_does_not_scan_before_recursive_change(
    payload: ModuleType,
    monkeypatch: pytest.MonkeyPatch,
    force: bool,
    check_mode: bool,
) -> None:
    payload.filesystem.file_info.return_value = {"attributes": 0x10}
    listdir = Mock(side_effect=AssertionError("an unnecessary traversal occurred"))
    monkeypatch.setattr(payload.os, "listdir", listdir)

    result = _manage(payload, recurse=True, force=force, check_mode=check_mode)

    assert result == {"changed": True, "rc": 0, "msg": _SUCCESS}
    listdir.assert_not_called()
    if check_mode:
        payload.compression.set_compression.assert_not_called()
    else:
        payload.compression.set_compression.assert_called_once_with(
            _PATH, True, True, True
        )


@pytest.mark.parametrize(
    "recurse, force", [(False, False), (False, True), (True, False)]
)
def test_unchanged_root_skips_children_without_recursive_force(
    payload: ModuleType,
    monkeypatch: pytest.MonkeyPatch,
    recurse: bool,
    force: bool,
) -> None:
    payload.filesystem.file_info.return_value = {"attributes": 0x810}
    listdir = Mock(side_effect=AssertionError("an unnecessary traversal occurred"))
    monkeypatch.setattr(payload.os, "listdir", listdir)

    assert _manage(payload, recurse=recurse, force=force) == {
        "changed": False,
        "rc": 0,
        "msg": _SUCCESS,
    }
    listdir.assert_not_called()
    payload.compression.set_compression.assert_not_called()


@pytest.mark.parametrize("state", ["present", "absent"])
@pytest.mark.parametrize("check_mode", [False, True])
@pytest.mark.parametrize("mismatched_child", [None, "directory", "file"])
def test_recursive_force_finds_nested_mismatches_and_preserves_contents(
    payload: ModuleType,
    tmp_path: Path,
    state: str,
    check_mode: bool,
    mismatched_child: str | None,
) -> None:
    directory = tmp_path / "hidden [directory]"
    directory.mkdir()
    child = directory / "Café 雪.txt"
    child.write_bytes(b"unchanged content")
    compressed = state == "present"
    mismatch = (
        None
        if mismatched_child is None
        else {"directory": directory, "file": child}[mismatched_child]
    )

    def _file_info(path: str) -> dict[str, int]:
        entry = Path(path)
        attributes = 0x10 if entry.is_dir() else 0
        if entry == directory:
            attributes |= 0x2
        if compressed != (entry == mismatch):
            attributes |= 0x800
        return {"attributes": attributes}

    payload.filesystem.file_info.side_effect = _file_info

    assert _manage(
        payload, tmp_path, state=state, recurse=True, check_mode=check_mode
    ) == {
        "changed": mismatched_child is not None,
        "rc": 0,
        "msg": _SUCCESS,
    }
    assert child.read_bytes() == b"unchanged content"
    if mismatched_child is None or check_mode:
        payload.compression.set_compression.assert_not_called()
    else:
        payload.compression.set_compression.assert_called_once_with(
            str(tmp_path), True, compressed, True
        )


def test_descendant_scan_stops_on_first_mismatch(
    payload: ModuleType, monkeypatch: pytest.MonkeyPatch
) -> None:
    payload.filesystem.file_info.side_effect = [
        {"attributes": 0x810},
        {"attributes": 0},
        AssertionError("later entry should not be checked"),
    ]
    monkeypatch.setattr(payload.os, "listdir", lambda _path: ["first", "later"])

    assert _manage(payload, recurse=True)["changed"] is True
    assert payload.filesystem.file_info.call_count == 2


@pytest.mark.parametrize("attributes, changed", [(0, True), (0x800, False)])
def test_recurse_on_file_preserves_warning_and_provider_argument(
    payload: ModuleType, attributes: int, changed: bool
) -> None:
    payload.filesystem.file_info.return_value = {"attributes": attributes}

    assert _manage(payload, recurse=True) == {
        "changed": changed,
        "rc": 0,
        "msg": _SUCCESS,
        "warnings": [_FILE_WARNING],
    }
    if changed:
        payload.compression.set_compression.assert_called_once_with(
            _PATH, False, True, True
        )
    else:
        payload.compression.set_compression.assert_not_called()


@pytest.mark.parametrize("check_mode", [False, True])
def test_missing_path_fails_without_querying_wmi(
    payload: ModuleType, check_mode: bool
) -> None:
    payload.filesystem.file_info.return_value = None

    assert _manage(payload, check_mode=check_mode) == {
        "changed": False,
        "failed": True,
        "rc": 0,
        "msg": f"Path to item, {_PATH}, does not exist.",
    }
    payload.compression.volume_info.assert_not_called()
    payload.compression.set_compression.assert_not_called()


@pytest.mark.parametrize("check_mode", [False, True])
def test_unsupported_volume_retains_file_warning(
    payload: ModuleType, check_mode: bool
) -> None:
    payload.compression.volume_info.return_value = {
        "filesystem": "FAT32",
        "supports_compression": False,
    }

    assert _manage(payload, recurse=True, check_mode=check_mode) == {
        "changed": False,
        "failed": True,
        "rc": 0,
        "warnings": [_FILE_WARNING],
        # The upstream message contains this spelling; test it literally.
        "msg": (
            f"Path, {_PATH}, is not on a filesystemi 'FAT32' "  # codespell:ignore filesystemi
            "that supports file based compression."
        ),
    }
    payload.compression.set_compression.assert_not_called()


@pytest.mark.parametrize(
    "code, message",
    [
        (2, "Access was denied."),
        (8, "An unspecified failure occurred."),
        (9, "The name specified was not valid."),
        (10, "The object specified already exists."),
        (11, "The file system is not NTFS."),
        (12, "The platform is not Windows."),
        (13, "The drive is not the same."),
        (14, "The directory is not empty."),
        (15, "There has been a sharing violation."),
        (16, "The start file specified was not valid."),
        (17, "A privilege required for the operation is not held."),
        (21, "A parameter specified is not valid."),
        (99, None),
    ],
)
def test_provider_failure_retains_attempted_change_and_return_code(
    payload: ModuleType, code: int, message: str | None
) -> None:
    payload.compression.set_compression.return_value = code

    assert _manage(payload) == {
        "changed": True,
        "failed": True,
        "rc": code,
        "msg": message,
    }


@pytest.mark.parametrize("stage", ["metadata", "volume", "mutation"])
def test_native_error_retains_change_status_and_allows_next_request(
    payload: ModuleType, stage: str
) -> None:
    operation = {
        "metadata": payload.filesystem.file_info,
        "volume": payload.compression.volume_info,
        "mutation": payload.compression.set_compression,
    }[stage]
    operation.side_effect = OSError("native access denied")

    assert _manage(payload) == {
        "changed": stage == "mutation",
        "failed": True,
        "rc": 0,
        "msg": "native access denied",
    }
    operation.side_effect = None
    assert _manage(payload) == {"changed": True, "rc": 0, "msg": _SUCCESS}


@pytest.mark.parametrize("failure", ["enumeration", "missing_child"])
def test_recursive_read_failure_does_not_start_a_mutation(
    payload: ModuleType, monkeypatch: pytest.MonkeyPatch, failure: str
) -> None:
    payload.filesystem.file_info.side_effect = [{"attributes": 0x810}, None]
    if failure == "enumeration":
        monkeypatch.setattr(
            payload.os, "listdir", Mock(side_effect=OSError("cannot list directory"))
        )
    else:
        monkeypatch.setattr(payload.os, "listdir", lambda _path: ["vanished"])

    result = _manage(payload, recurse=True)

    assert result["failed"] and not result["changed"] and result["rc"] == 0
    assert result["msg"].startswith(
        "cannot list directory"
        if failure == "enumeration"
        else "Filesystem entry no longer exists:"
    )
    payload.compression.set_compression.assert_not_called()


def test_parameter_defaults_and_boolean_conversion(payload: ModuleType) -> None:
    assert payload._parameters({"path": _PATH}) == {
        "path": _PATH,
        "state": "present",
        "recurse": False,
        "force": True,
    }
    assert payload._parameters(
        {"path": _PATH, "state": "ABSENT", "recurse": "yes", "force": 0}
    ) == {"path": _PATH, "state": "absent", "recurse": True, "force": False}


@pytest.mark.parametrize(
    "options, message",
    [
        ({}, "missing required arguments: path"),
        (
            {"path": _PATH, "state": "invalid"},
            "value of state must be one of: absent, present. Got no match for: invalid",
        ),
        ({"path": _PATH, "recurse": "invalid"}, "Expected a boolean for recurse."),
        ({"path": _PATH, "force": "invalid"}, "Expected a boolean for force."),
    ],
)
def test_invalid_arguments_fail_before_native_access(
    payload: ModuleType, options: dict[str, object], message: str
) -> None:
    with pytest.raises(ValueError) as error:
        payload._parameters(options)
    assert str(error.value) == message
    payload.filesystem.file_info.assert_not_called()


@pytest.mark.parametrize("compressed", [False, True])
def test_null_force_keeps_an_unchanged_root_without_scanning(
    payload: ModuleType, monkeypatch: pytest.MonkeyPatch, compressed: bool
) -> None:
    payload.filesystem.file_info.return_value = {
        "attributes": 0x10 | (0x800 if compressed else 0)
    }
    scan = Mock(side_effect=AssertionError("null force must not scan descendants"))
    monkeypatch.setattr(payload.os, "listdir", scan)
    result = _manage(
        payload, state="present" if compressed else "absent", recurse=True, force=None
    )
    assert result == {"changed": False, "rc": 0, "msg": _SUCCESS}
    scan.assert_not_called()
    payload.compression.set_compression.assert_not_called()


@pytest.mark.parametrize("state", ["present", "absent"])
def test_null_recursion_uses_the_measured_false_provider_argument(
    payload: ModuleType, state: str
) -> None:
    payload.filesystem.file_info.return_value = {
        "attributes": 0x10 | (0x800 if state == "absent" else 0)
    }
    result = _manage(payload, state=state, recurse=None)
    assert result == {"changed": True, "rc": 0, "msg": _SUCCESS}
    payload.compression.set_compression.assert_called_once_with(
        _PATH, True, state == "present", False
    )


def test_environment_expansion_is_literal_and_not_globbed(
    payload: ModuleType, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv("COMPRESSION_TEST", r"C:\Café 雪")

    assert _manage(payload, r"%COMPRESSION_TEST%\[literal].txt")["changed"]
    payload.filesystem.file_info.assert_called_once_with(r"C:\Café 雪\[literal].txt")


@pytest.mark.parametrize("case", [(0, 0), (2, 1)])
def test_entrypoint_emits_only_json_and_correct_exit_status(
    payload: ModuleType,
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
    case: tuple[int, int],
) -> None:
    provider_rc, expected_exit = case
    arguments = tmp_path / "arguments.json"
    arguments.write_text(json.dumps({"PATH": _PATH, "RECURSE": True}), encoding="utf-8")
    monkeypatch.setattr(sys, "argv", ["win_file_compression.py", str(arguments)])
    payload.compression.set_compression.return_value = provider_rc

    exit_code, result = invoke_payload(payload, capsys)

    assert exit_code == expected_exit
    assert result["changed"] and result["rc"] == provider_rc
    assert result["warnings"] == [_FILE_WARNING]
    assert result.get("failed", False) is (provider_rc != 0)


def test_check_mode_from_json_does_not_write(
    payload: ModuleType, monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    arguments = tmp_path / "arguments.json"
    arguments.write_text(
        json.dumps({"path": _PATH, "_ansible_check_mode": True}), encoding="utf-8"
    )
    monkeypatch.setattr(sys, "argv", ["win_file_compression.py", str(arguments)])

    assert payload._execute() == {"changed": True, "rc": 0, "msg": _SUCCESS}
    payload.compression.set_compression.assert_not_called()
