"""Check win_stat results and failures with Windows API boundaries replaced."""

# SPDX-License-Identifier: GPL-3.0-or-later
# Direct payload calls isolate result behavior from the JSON entry point.
# pylint: disable=protected-access

import json
import ntpath
import sys
from pathlib import Path
from types import ModuleType
from typing import Any
from unittest.mock import Mock

import pytest

from tests.unit.payload_support import load_payload

PATH = r"C:\Data\Café [literal].txt"
EPOCH = 116444736000000000
FILE = {
    "attributes": 32,
    "creation_time": EPOCH + 10000001,
    "access_time": EPOCH + 20000002,
    "modification_time": EPOCH + 30000003,
    "size": 1234,
}


@pytest.fixture(name="payload")
def stat_payload(monkeypatch: pytest.MonkeyPatch) -> ModuleType:
    """Replace native queries with deterministic metadata for one regular file.

    :param monkeypatch: Scoped helper replacements; no Windows host is contacted.
    :returns: The imported payload with observable native-query mocks.
    """
    module = load_payload("win_stat", monkeypatch)
    monkeypatch.setattr(module.links, "enable_backup_privilege", Mock())
    monkeypatch.setattr(module.links, "get_link_info", Mock(return_value=None))
    monkeypatch.setattr(module.filesystem, "file_info", Mock(return_value=FILE))
    monkeypatch.setattr(
        module.filesystem, "full_path", Mock(side_effect=ntpath.normpath)
    )
    monkeypatch.setattr(module.filesystem, "owner", Mock(return_value=r"HOST\user"))
    monkeypatch.setattr(
        module.filesystem, "checksum", Mock(return_value="012345abcdef")
    )
    monkeypatch.setattr(module.filesystem, "shares", Mock(return_value=[]))
    monkeypatch.setattr(module.filesystem, "directory_size", Mock(return_value=2468))
    return module


def _inspect(payload: ModuleType, **options: object) -> dict[str, Any]:
    result: dict[str, Any] = payload._inspect(
        payload._parameters({"path": PATH, **options})
    )
    return result


def test_file_metadata_is_complete_and_unchanged_on_repeat(payload: ModuleType) -> None:
    expected = {
        "changed": False,
        "stat": {
            "exists": True,
            "attributes": "Archive",
            "path": PATH,
            "filename": "Café [literal].txt",
            "extension": ".txt",
            "creationtime": float(10000001) * 1e-7,
            "lastaccesstime": float(20000002) * 1e-7,
            "lastwritetime": float(30000003) * 1e-7,
            "owner": r"HOST\user",
            "isarchive": True,
            "ishidden": False,
            "isreadonly": False,
            "isdir": False,
            "isreg": True,
            "islnk": False,
            "isjunction": False,
            "isshared": False,
            "nlink": 1,
            "hlnk_targets": [],
            "size": 1234,
            "checksum": "012345abcdef",
        },
    }
    assert _inspect(payload) == expected
    assert _inspect(payload) == expected
    payload.filesystem.shares.assert_not_called()
    payload.filesystem.directory_size.assert_not_called()
    payload.filesystem.checksum.assert_called_with(PATH, "sha1")


def test_missing_entry_contains_no_other_stat_fields(payload: ModuleType) -> None:
    payload.filesystem.file_info.return_value = None

    assert _inspect(payload) == {"changed": False, "stat": {"exists": False}}
    payload.links.get_link_info.assert_not_called()
    payload.filesystem.owner.assert_not_called()
    payload.filesystem.checksum.assert_not_called()


@pytest.mark.parametrize("value", [False, None, "no", "0", 0])
def test_disabled_queries_omit_fields(payload: ModuleType, value: object) -> None:
    result = _inspect(payload, get_size=value, get_checksum=value)

    assert "size" not in result["stat"]
    assert "checksum" not in result["stat"]
    payload.filesystem.checksum.assert_not_called()


@pytest.mark.parametrize(
    "algorithm", ["md5", "sha1", "sha256", "sha384", "sha512", "SHA256"]
)
def test_hash_algorithm_selected_case_insensitively(
    payload: ModuleType, algorithm: str
) -> None:
    assert (
        _inspect(payload, checksum_algorithm=algorithm)["stat"]["checksum"]
        == "012345abcdef"
    )
    payload.filesystem.checksum.assert_called_once_with(PATH, algorithm.lower())


def test_null_algorithm_is_unused_when_checksum_disabled(payload: ModuleType) -> None:
    result = _inspect(payload, checksum_algorithm=None, get_checksum=False)

    assert result["stat"]["exists"] is True
    payload.filesystem.checksum.assert_not_called()


def test_checksum_failure_keeps_empty_initial_stat_and_link_warning(
    payload: ModuleType,
) -> None:
    payload.links.get_link_info.side_effect = NotImplementedError(
        "Name enumeration unavailable"
    )
    payload.filesystem.checksum.side_effect = OSError("File is locked")

    result = _inspect(payload)

    assert result == {
        "changed": False,
        "failed": True,
        "stat": {"exists": False},
        "msg": (
            "Failed to get hash of file, set get_checksum to False "
            "to ignore this error: File is locked"
        ),
        "warnings": [
            "Failed to check/get link info for file: Name enumeration unavailable"
        ],
    }
    payload.filesystem.checksum.side_effect = None
    assert _inspect(payload)["stat"]["exists"] is True


def test_owner_failure_is_null_without_warning(payload: ModuleType) -> None:
    payload.filesystem.owner.side_effect = OSError("Access denied")

    result = _inspect(payload)

    assert result["stat"]["owner"] is None
    assert "warnings" not in result


def test_unmapped_owner_sddl_is_preserved(payload: ModuleType) -> None:
    payload.filesystem.owner.return_value = "O:S-1-5-21-1-2-3-9999"

    assert _inspect(payload)["stat"]["owner"] == "O:S-1-5-21-1-2-3-9999"


@pytest.mark.parametrize("names", [[], ["Data"], ["Data", "Archive$"]])
def test_directory_size_and_share_cardinality(
    payload: ModuleType, names: list[str]
) -> None:
    payload.filesystem.file_info.return_value = {**FILE, "attributes": 16}
    payload.filesystem.shares.return_value = names

    result = _inspect(payload)["stat"]

    assert result["isdir"] is True
    assert result["isreg"] is False
    assert result["size"] == 2468
    assert result["isshared"] is bool(names)
    assert result.get("sharename") == (names[0] if len(names) == 1 else names or None)
    assert "checksum" not in result
    assert "extension" not in result
    payload.filesystem.checksum.assert_not_called()
    payload.filesystem.directory_size.assert_called_once_with(PATH)


def test_directory_failures_warn_only_for_shares_and_reset_size(
    payload: ModuleType,
) -> None:
    payload.filesystem.file_info.return_value = {**FILE, "attributes": 16}
    payload.filesystem.shares.side_effect = OSError("Share query denied")
    payload.filesystem.directory_size.side_effect = OSError("Cannot traverse child")

    result = _inspect(payload)

    assert result["stat"]["size"] == 0
    assert result["stat"]["isshared"] is False
    assert "sharename" not in result["stat"]
    assert result["warnings"] == [
        f"Failed to check share info for '{PATH}': Share query denied"
    ]


def test_directory_size_can_be_disabled(payload: ModuleType) -> None:
    payload.filesystem.file_info.return_value = {**FILE, "attributes": 16}

    assert "size" not in _inspect(payload, get_size=False)["stat"]
    payload.filesystem.directory_size.assert_not_called()


@pytest.mark.parametrize("kind", ["symbolic", "junction"])
@pytest.mark.parametrize("relative", [False, True])
def test_unfollowed_link_keeps_its_metadata_and_original_target(
    payload: ModuleType, kind: str, relative: bool
) -> None:
    target = r"..\target" if relative else r"C:\target"
    payload.links.get_link_info.return_value = {
        "type": kind,
        "target": target,
        "relative": relative,
    }

    result = _inspect(payload)["stat"]

    assert result["path"] == PATH
    assert result["lnk_source"] == r"C:\target"
    assert result["lnk_target"] == target
    assert result["isreg"] is False
    assert result["islnk"] is (kind == "symbolic")
    assert result["isjunction"] is (kind == "junction")
    payload.filesystem.checksum.assert_called_once_with(PATH, "sha1")


def test_followed_chain_returns_final_metadata_but_hashes_original_path(
    payload: ModuleType,
) -> None:
    payload.links.get_link_info.side_effect = [
        {"type": "symbolic", "target": r"..\junction", "relative": True},
        {"type": "junction", "target": r"C:\target", "relative": False},
        None,
    ]

    result = _inspect(payload, follow=True)["stat"]

    assert result["path"] == r"C:\target"
    assert result["filename"] == "target"
    assert result["islnk"] is False
    assert result["isjunction"] is False
    assert "lnk_target" not in result
    assert payload.filesystem.file_info.call_count == 3
    payload.filesystem.checksum.assert_called_once_with(PATH, "sha1")


def test_followed_broken_link_returns_missing(payload: ModuleType) -> None:
    payload.links.get_link_info.return_value = {
        "type": "junction",
        "target": r"C:\missing",
        "relative": False,
    }
    payload.filesystem.file_info.side_effect = [FILE, None]

    assert _inspect(payload, follow=True) == {
        "changed": False,
        "stat": {"exists": False},
    }
    payload.filesystem.checksum.assert_not_called()


def test_hard_link_excludes_current_spelling_case_insensitively(
    payload: ModuleType,
) -> None:
    targets = [r"C:\other.txt", PATH.upper(), r"C:\another.txt"]
    payload.links.get_link_info.return_value = {"type": "hard", "target": targets}

    result = _inspect(payload, follow=True)["stat"]

    assert result["path"] == PATH
    assert result["lnk_type"] == "hard"
    assert result["nlink"] == 3
    assert result["hlnk_targets"] == [targets[0], targets[2]]
    assert result["isreg"] is True
    assert result["islnk"] is False
    assert "lnk_source" not in result


@pytest.mark.parametrize(
    "error",
    [OSError("Denied"), ValueError("Unknown tag"), NotImplementedError("Unsupported")],
)
def test_link_query_failure_preserves_ordinary_metadata(
    payload: ModuleType, error: Exception
) -> None:
    payload.links.get_link_info.side_effect = error

    result = _inspect(payload)

    assert result["stat"]["nlink"] == 1
    assert result["stat"]["hlnk_targets"] == []
    assert result["stat"]["isreg"] is True
    assert result["warnings"] == [
        "Failed to check/get link info for file: " + str(error)
    ]


@pytest.mark.parametrize(
    "bits,text,flags",
    [
        (0, "0", (False, False, False)),
        (35, "ReadOnly, Hidden, Archive", (True, True, True)),
        (128, "Normal", (False, False, False)),
        (0x10023, "65571", (False, False, False)),
        (0x80000023, "-2147483613", (False, False, False)),
    ],
)
def test_attribute_text_and_boolean_flags(
    payload: ModuleType, bits: int, text: str, flags: tuple[bool, bool, bool]
) -> None:
    payload.filesystem.file_info.return_value = {**FILE, "attributes": bits}

    stat = _inspect(payload)["stat"]

    assert stat["attributes"] == text
    assert (stat["isreadonly"], stat["ishidden"], stat["isarchive"]) == flags


@pytest.mark.parametrize(
    "path,name,extension",
    [
        (r"C:\dir\.gitignore", ".gitignore", ".gitignore"),
        (r"C:\dir\file.tar.gz", "file.tar.gz", ".gz"),
        (r"C:\dir\plain", "plain", ""),
        (r"C:\dir\trailing.", "trailing.", ""),
    ],
)
def test_file_names_and_extensions(
    payload: ModuleType, path: str, name: str, extension: str
) -> None:
    result = _inspect(payload, path=path)["stat"]

    assert result["filename"] == name
    assert result["extension"] == extension


def test_drive_root_filename_retains_root_path(payload: ModuleType) -> None:
    payload.filesystem.file_info.return_value = {**FILE, "attributes": 16}

    assert _inspect(payload, path="C:\\")["stat"]["filename"] == "C:\\"


def test_aliases_override_canonical_in_declared_order(payload: ModuleType) -> None:
    parameters = payload._parameters(
        {"path": "canonical", "dest": "destination", "name": "named"}
    )
    assert parameters["path"] == "named"
    assert (
        payload._parameters({"path": "canonical", "dest": "destination"})["path"]
        == "destination"
    )


@pytest.mark.parametrize(
    "arguments,message",
    [
        ({}, "missing required arguments: path"),
        ({"path": ""}, "path must not be empty"),
        ({"path": "   "}, "path must not be empty"),
        (
            {"path": PATH, "checksum_algorithm": "sha224"},
            "checksum_algorithm must be one of",
        ),
        (
            {"path": PATH, "checksum_algorithm": " sha1 "},
            "checksum_algorithm must be one of",
        ),
        ({"path": PATH, "get_checksum": "maybe"}, "Expected a boolean"),
        ({"path": PATH, "follow": "\x1ctrue\x1f"}, "Expected a boolean"),
    ],
)
def test_invalid_parameters_fail_before_queries(
    payload: ModuleType, arguments: dict[str, object], message: str
) -> None:
    with pytest.raises(ValueError, match=message):
        payload._parameters(arguments)
    payload.filesystem.file_info.assert_not_called()


def test_null_path_fails_with_initial_stat(payload: ModuleType) -> None:
    assert _inspect(payload, path=None) == {
        "changed": False,
        "failed": True,
        "stat": {"exists": False},
        "msg": "path must not be null.",
    }
    payload.filesystem.file_info.assert_not_called()


@pytest.mark.parametrize("check_mode", [False, True])
def test_json_entrypoint_reads_same_metadata_in_check_mode(
    payload: ModuleType,
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
    check_mode: bool,
) -> None:
    arguments = tmp_path / "arguments.json"
    arguments.write_text(
        json.dumps({"PATH": PATH, "_ansible_check_mode": check_mode}), encoding="utf-8"
    )
    monkeypatch.setattr(sys, "argv", ["win_stat.py", str(arguments)])

    with pytest.raises(SystemExit) as stopped:
        payload.main()

    assert stopped.value.code == 0
    result = json.loads(capsys.readouterr().out)
    assert result["stat"]["exists"] is True
    assert result["changed"] is False


def test_unknown_argument_is_a_protocol_failure_before_execution(
    payload: ModuleType,
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    arguments = tmp_path / "arguments.json"
    arguments.write_text(json.dumps({"path": PATH, "unknown": 1}), encoding="utf-8")
    monkeypatch.setattr(sys, "argv", ["win_stat.py", str(arguments)])

    with pytest.raises(SystemExit) as stopped:
        payload.main()

    assert stopped.value.code == 1
    result = json.loads(capsys.readouterr().out)
    assert result["changed"] is False
    assert result["failed"] is True
    assert "Unsupported parameters" in result["msg"]
    payload.links.enable_backup_privilege.assert_not_called()
