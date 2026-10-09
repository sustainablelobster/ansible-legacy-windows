"""Exercise copy behavior against local files, replacing only Windows boundaries."""

# SPDX-License-Identifier: GPL-3.0-or-later
# Direct calls expose the payload protocol without starting a Windows process.
# pylint: disable=protected-access

import base64
import datetime
import hashlib
import json
import os
import shutil
import sys
import zipfile
from pathlib import Path
from types import ModuleType
from typing import Any
from unittest.mock import Mock

import pytest

from tests.unit.payload_support import invoke_payload, load_payload


def _info(path: str) -> dict[str, int] | None:
    try:
        data = os.lstat(path)
    except (FileNotFoundError, NotADirectoryError):
        return None
    return {
        "attributes": (16 if os.path.isdir(path) else 0)
        | (0x400 if os.path.islink(path) else 0),
        "size": data.st_size,
    }


def _entries(path: str) -> list[dict[str, Any]]:
    entries = []
    for name in sorted(os.listdir(path)):
        info = _info(os.path.join(path, name))
        assert info is not None
        entries.append({"name": name, **info})
    return entries


def _checksum(path: str, algorithm: str) -> str:
    assert algorithm == "sha1"
    return hashlib.sha1(Path(path).read_bytes()).hexdigest()


def _copy(source: str, target: str, **_options: object) -> None:
    shutil.copy2(source, target)


@pytest.fixture(name="payload")
def copy_payload(monkeypatch: pytest.MonkeyPatch) -> ModuleType:
    """Load the payload with local filesystem stand-ins and deterministic backups.

    :param monkeypatch: Scoped replacements for native operations.
    :returns: The loaded payload; no Windows hosts are contacted.
    """
    module = load_payload("win_copy", monkeypatch)
    helper = sys.modules["legacy_windows_copy"]
    monkeypatch.setattr(helper.metadata, "file_info", _info)
    monkeypatch.setattr(helper.metadata, "directory_entries", _entries)
    monkeypatch.setattr(helper.metadata, "checksum", _checksum)
    monkeypatch.setattr(helper.filesystem, "remove_path", os.unlink)
    monkeypatch.setattr(helper.filesystem, "set_file_time", Mock())
    monkeypatch.setattr(
        helper.native_time,
        "local_ticks_to_file_time",
        lambda ticks: ticks - 504911232000000000,
    )
    monkeypatch.setattr(helper, "copy_file", _copy)
    monkeypatch.setattr(
        helper, "_backup_name", lambda path: path + ".123.20260930-010203.bak"
    )
    return module


def _run(payload: ModuleType, **arguments: Any) -> dict[str, Any]:
    check = arguments.pop("check_mode", False)
    diff = arguments.pop("diff_mode", False)
    arguments = {
        name: str(value) if isinstance(value, Path) else value
        for name, value in arguments.items()
    }
    result: dict[str, Any] = payload.execute_copy(
        payload._parameters(arguments), check, diff
    )
    return result


def _archive(path: Path, entries: dict[str, bytes]) -> None:
    with zipfile.ZipFile(path, "w", compression=zipfile.ZIP_DEFLATED) as archive:
        for name, content in entries.items():
            directory = name.endswith("/")
            encoded = base64.b64encode(name.rstrip("/").encode("utf-8")).decode("ascii")
            archive.writestr(encoded + ("/" if directory else ""), content)


def test_remote_file_create_repeat_replace_backup_and_force_false(
    payload: ModuleType, tmp_path: Path
) -> None:
    source, target = tmp_path / "source", tmp_path / "target"
    source.write_bytes(b"one")
    arguments = {
        "src": source,
        "dest": target,
        "_copy_mode": "remote",
        "diff_mode": True,
    }
    result = _run(payload, **arguments)
    assert result == {
        "changed": True,
        "src": str(source),
        "dest": str(target),
        "operation": "file_copy",
        "original_basename": "source",
        "checksum": _checksum(str(source), "sha1"),
        "size": 3,
        "diff": {"prepared": "+" + str(target) + "\n"},
    }
    assert target.read_bytes() == b"one"
    result = _run(payload, **arguments, backup=True)
    assert result["changed"] is False
    assert result["diff"] == {"prepared": ""}
    assert "backup_file" not in result
    source.write_bytes(b"two")
    result = _run(payload, **arguments, force=False)
    assert not result["changed"] and result["checksum"] is None
    assert target.read_bytes() == b"one"
    result = _run(payload, **arguments, backup=True)
    assert result["changed"] and target.read_bytes() == b"two"
    assert Path(result["backup_file"]).read_bytes() == b"one"
    assert result["diff"]["prepared"] == f"-{target}\n+{target}\n"


@pytest.mark.parametrize("existing", [False, True])
def test_remote_check_mode_predicts_without_copying_files(
    payload: ModuleType, tmp_path: Path, existing: bool
) -> None:
    source, target = tmp_path / "source", tmp_path / "target"
    source.write_bytes(b"new content")
    if existing:
        target.write_bytes(b"old")
    result = _run(
        payload,
        src=source,
        dest=target,
        _copy_mode="remote",
        check_mode=True,
        backup=True,
    )
    assert result["changed"]
    assert result["size"] == (3 if existing else None)
    assert result["backup_file"] == (
        str(target) + ".123.20260930-010203.bak" if existing else None
    )
    assert not list(tmp_path.glob("*.bak"))
    assert target.read_bytes() == b"old" if existing else not target.exists()


def test_remote_check_mode_missing_slash_directory_matches_parent_creation(
    payload: ModuleType, tmp_path: Path
) -> None:
    source = tmp_path / "source"
    source.write_bytes(b"data")
    target = tmp_path / "missing"
    result = _run(
        payload,
        src=source,
        dest=str(target) + "/",
        _copy_mode="remote",
        check_mode=True,
    )
    assert result["changed"] and result["size"] is None
    assert target.is_dir()
    assert not list(target.iterdir())


@pytest.mark.parametrize("trailing", [False, True])
def test_remote_directory_name_contents_empty_directories_and_repeat(
    payload: ModuleType, tmp_path: Path, trailing: bool
) -> None:
    source = tmp_path / "source"
    (source / "empty").mkdir(parents=True)
    (source / "nested").mkdir()
    (source / "nested" / "Café 雪.txt").write_bytes(b"12345")
    (source / ".hidden").write_bytes(b"123")
    destination = tmp_path / "output"
    arguments = {
        "src": str(source) + ("/" if trailing else ""),
        "dest": destination,
        "_copy_mode": "remote",
    }
    result = _run(payload, **arguments, diff_mode=True)
    target = destination if trailing else destination / source.name
    assert result["changed"] and result["size"] == 8
    assert result["operation"] == "folder_copy" and result["dest"] == str(target)
    assert (target / "empty").is_dir()
    assert (target / "nested" / "Café 雪.txt").read_bytes() == b"12345"
    assert (target / ".hidden").read_bytes() == b"123"
    assert not _run(payload, **arguments)["changed"]


@pytest.mark.parametrize("spelling", [".", "./.", "nested/.."])
def test_remote_directory_dot_components_preserve_source_folder_name(
    payload: ModuleType,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    spelling: str,
) -> None:
    source = tmp_path / "source"
    (source / "nested").mkdir(parents=True)
    (source / "data.txt").write_bytes(b"data")
    monkeypatch.chdir(source)
    destination = tmp_path / "output"
    arguments = {"src": spelling, "dest": destination, "_copy_mode": "remote"}
    predicted = _run(payload, **arguments, check_mode=True)
    assert predicted["changed"] and not destination.exists()
    result = _run(payload, **arguments)
    assert result["changed"] and result["size"] == 4
    assert result["src"] == spelling
    assert result["dest"] == str(destination / "source")
    assert (destination / "source" / "data.txt").read_bytes() == b"data"
    assert not (destination / "data.txt").exists()
    assert not _run(payload, **arguments)["changed"]


def test_remote_directory_check_mode_does_not_create_tree(
    payload: ModuleType, tmp_path: Path
) -> None:
    source = tmp_path / "source"
    (source / "nested").mkdir(parents=True)
    (source / "nested" / "file").write_bytes(b"data")
    destination = tmp_path / "output"
    result = _run(
        payload, src=source, dest=destination, _copy_mode="remote", check_mode=True
    )
    assert result["changed"] and result["size"] is None
    assert not destination.exists()


def test_remote_empty_contents_to_absent_destination_fails_without_mutation(
    payload: ModuleType,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    source = tmp_path / "empty"
    source.mkdir()
    target = tmp_path / "missing"
    arguments = tmp_path / "arguments.json"
    arguments.write_text(
        json.dumps(
            {
                "src": str(source) + "/",
                "dest": str(target),
                "_copy_mode": "remote",
                "_ansible_diff": True,
            }
        ),
        encoding="utf-8",
    )
    monkeypatch.setattr(sys, "argv", ["win_copy.py", str(arguments)])
    exit_code, result = invoke_payload(payload, capsys)
    assert exit_code == 1
    assert set(result) == {"changed", "failed", "msg", "exception"}
    assert result["failed"] and not result["changed"]
    assert result["msg"] == (
        "Unhandled exception while executing module: "
        f"Cannot find path '{target}' because it does not exist."
    )
    assert "RuntimeError:" in result["exception"]
    assert not target.exists()

    (source / "file").write_bytes(b"recovered")
    exit_code, result = invoke_payload(payload, capsys)
    assert exit_code == 0 and result["changed"]
    assert "exception" not in result and "failed" not in result
    assert result["operation"] == "folder_copy" and result["size"] == 9
    assert (target / "file").read_bytes() == b"recovered"


@pytest.mark.parametrize("mode", ["single", "remote"])
def test_file_copy_parent_failures_then_recovery(
    payload: ModuleType, tmp_path: Path, mode: str
) -> None:
    source = tmp_path / "source"
    source.write_bytes(b"data")
    parent = tmp_path / "parent"
    target = parent / "target"
    result = _run(payload, src=source, dest=target, _copy_mode=mode)
    assert result["failed"] and not result["changed"]
    assert result["msg"] == f"Destination directory '{parent}' does not exist"
    parent.write_bytes(b"blocking")
    result = _run(payload, src=source, dest=target, _copy_mode=mode)
    assert result["failed"] and "currently a file" in result["msg"]
    parent.unlink()
    parent.mkdir()
    assert _run(payload, src=source, dest=target, _copy_mode=mode)["changed"]
    assert target.read_bytes() == b"data"


def test_single_always_copies_and_returns_only_protocol_fields(
    payload: ModuleType, tmp_path: Path
) -> None:
    source = tmp_path / "staged"
    source.write_bytes(b"data")
    result = _run(
        payload,
        src=source,
        dest=str(tmp_path) + "/",
        _original_basename="name",
        backup=True,
        diff_mode=True,
    )
    assert result == {"changed": True, "backup_file": None, "diff": {}}
    assert (tmp_path / "name").read_bytes() == b"data"
    assert _run(payload, src=source, dest=tmp_path / "name")["changed"]


def test_remote_force_false_does_not_read_hashes(
    payload: ModuleType, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    source, target = tmp_path / "source", tmp_path / "target"
    source.write_bytes(b"source")
    digest = Mock(side_effect=AssertionError("checksum must not be read"))
    monkeypatch.setattr(sys.modules["legacy_windows_copy"].metadata, "checksum", digest)
    result = _run(payload, src=source, dest=target, _copy_mode="remote", force=False)
    assert result["changed"] and result["checksum"] is None
    assert not _run(payload, src=source, dest=target, _copy_mode="remote", force=False)[
        "changed"
    ]
    digest.assert_not_called()


def test_query_selects_only_differing_files_and_missing_directories(
    payload: ModuleType, tmp_path: Path
) -> None:
    (tmp_path / "same").write_bytes(b"same")
    (tmp_path / "different").write_bytes(b"old")
    (tmp_path / "present-dir").mkdir()
    files = [
        {
            "src": "/local/same",
            "dest": "same",
            "checksum": _checksum(str(tmp_path / "same"), "sha1"),
        },
        {"src": "/local/new", "dest": "different", "checksum": "new"},
        {"src": "/local/missing", "dest": "missing", "checksum": "new"},
    ]
    directories = [{"dest": "present-dir"}, {"dest": "new-dir"}]
    result = _run(
        payload, dest=tmp_path, _copy_mode="query", files=files, directories=directories
    )
    assert result == {
        "changed": False,
        "files": files[1:],
        "directories": directories[1:],
        "symlinks": [],
    }
    result = _run(payload, dest=tmp_path, _copy_mode="query", files=files, force=False)
    assert result["files"] == files[2:]
    assert not (tmp_path / "missing").exists()


def test_query_joins_file_basename_for_directory_destination(
    payload: ModuleType, tmp_path: Path
) -> None:
    (tmp_path / "name").write_bytes(b"same")
    entry = {
        "src": "/local/name",
        "dest": "",
        "checksum": _checksum(str(tmp_path / "name"), "sha1"),
    }
    assert (
        _run(payload, dest=tmp_path, _copy_mode="query", files=[entry])["files"] == []
    )
    (tmp_path / "name").unlink()
    (tmp_path / "name").mkdir()
    result = _run(payload, dest=tmp_path, _copy_mode="query", files=[entry])
    assert result["failed"] and "already a directory" in result["msg"]


@pytest.mark.parametrize("child", ["blocking", "blocking/child"])
def test_query_directory_conflicts_fail(
    payload: ModuleType, tmp_path: Path, child: str
) -> None:
    (tmp_path / "blocking").write_bytes(b"data")
    result = _run(
        payload, dest=tmp_path, _copy_mode="query", directories=[{"dest": child}]
    )
    assert result["failed"] and not result["changed"]
    assert "already a file" in result["msg"]


def test_explode_unicode_nested_binary_empty_directories_and_check_mode(
    payload: ModuleType, tmp_path: Path
) -> None:
    source, target = tmp_path / "source.zip", tmp_path / "output"
    _archive(source, {"nested/雪.txt": b"\x00\xffdata", "empty/": b""})
    result = _run(
        payload, src=source, dest=target, _copy_mode="explode", check_mode=True
    )
    assert result == {"changed": True} and not target.exists()
    result = _run(payload, src=source, dest=target, _copy_mode="explode", backup=True)
    assert result == {"changed": True}
    assert (target / "nested" / "雪.txt").read_bytes() == b"\x00\xffdata"
    assert (target / "empty").is_dir()
    _archive(source, {"nested/雪.txt": b"changed"})
    assert _run(payload, src=source, dest=target, _copy_mode="explode")["changed"]
    assert (target / "nested" / "雪.txt").read_bytes() == b"changed"
    assert not list(target.rglob("*.bak"))


def test_explode_restores_zip_local_last_write_time_after_closing_output(
    payload: ModuleType, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    source, target = tmp_path / "source.zip", tmp_path / "output"
    encoded = base64.b64encode(b"data").decode("ascii")
    entry = zipfile.ZipInfo(encoded, date_time=(2001, 2, 3, 4, 5, 6))
    with zipfile.ZipFile(source, "w") as archive:
        archive.writestr(entry, b"contents")
    helper = sys.modules["legacy_windows_copy"]

    def _set_time(path: str, directory: bool, field: str, timestamp: int) -> None:
        assert Path(path).read_bytes() == b"contents"
        assert directory is False and field == "modification_time"
        expected = datetime.datetime(2001, 2, 3, 4, 5, 6) - datetime.datetime(
            1601, 1, 1
        )
        assert timestamp == (expected.days * 86400 + expected.seconds) * 10000000

    setter = Mock(side_effect=_set_time)
    monkeypatch.setattr(helper.filesystem, "set_file_time", setter)
    assert _run(payload, src=source, dest=target, _copy_mode="explode") == {
        "changed": True
    }
    setter.assert_called_once()


@pytest.mark.parametrize(
    "name",
    [
        "../escape",
        "a/../../escape",
        "/absolute",
        "C:\\absolute",
        "C:relative",
        "file:stream",
        "a./escape",
        "a /escape",
        "a\\..\\escape",
    ],
)
def test_explode_rejects_unsafe_paths_before_writing_entry(
    payload: ModuleType, tmp_path: Path, name: str
) -> None:
    source = tmp_path / "source.zip"
    _archive(source, {name: b"unsafe"})
    target = tmp_path / "output"
    result = _run(payload, src=source, dest=target, _copy_mode="explode")
    assert result["failed"] and "Unsafe copy archive path" in result["msg"]
    assert not target.exists()


def test_explode_rejects_existing_destination_links(
    payload: ModuleType, tmp_path: Path
) -> None:
    source = tmp_path / "source.zip"
    _archive(source, {"linked/escape": b"unsafe"})
    target, outside = tmp_path / "output", tmp_path / "outside"
    target.mkdir()
    outside.mkdir()
    (target / "linked").symlink_to(outside, target_is_directory=True)
    result = _run(payload, src=source, dest=target, _copy_mode="explode")
    assert result["failed"] and "reparse point" in result["msg"]
    assert not list(outside.iterdir())


def test_failure_retains_completed_tree_changes_and_allows_recovery(
    payload: ModuleType, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    source, target = tmp_path / "source", tmp_path / "output"
    source.mkdir()
    (source / "first").write_bytes(b"one")
    (source / "second").write_bytes(b"two")
    helper = sys.modules["legacy_windows_copy"]

    def _fail_second(src: str, dest: str, **kwargs: Any) -> None:
        if src.endswith("second"):
            raise OSError("fixture locked")
        _copy(src, dest, **kwargs)

    monkeypatch.setattr(helper, "copy_file", _fail_second)
    result = _run(payload, src=source, dest=target, _copy_mode="remote")
    assert result["failed"] and result["changed"]
    assert (target / "source" / "first").read_bytes() == b"one"
    monkeypatch.setattr(helper, "copy_file", _copy)
    result = _run(payload, src=source, dest=target, _copy_mode="remote")
    assert result["changed"] and "failed" not in result
    assert (target / "source" / "second").read_bytes() == b"two"


@pytest.mark.parametrize(
    "arguments",
    [
        {},
        {"dest": "x"},
        {"src": "x", "dest": ""},
        {"src": "x", "dest": "y", "_copy_mode": "unknown"},
        {"src": "x", "dest": "y", "force": "wrong"},
        {"dest": "x", "_copy_mode": "query", "files": [1]},
    ],
)
def test_invalid_parameters_fail_before_filesystem_access(
    payload: ModuleType, arguments: dict[str, Any]
) -> None:
    with pytest.raises(ValueError):
        payload._parameters(arguments)


def test_argument_file_normalizes_case_expands_environment_and_allows_legacy_extras(
    payload: ModuleType, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    arguments = tmp_path / "arguments.json"
    arguments.write_text(
        json.dumps(
            {
                "DEST": "%COPY_ROOT%",
                "_COPY_MODE": "QUERY",
                "unsupported_legacy_option": True,
            }
        ),
        encoding="utf-8",
    )
    monkeypatch.setenv("COPY_ROOT", str(tmp_path))
    monkeypatch.setattr(sys, "argv", ["win_copy.py", str(arguments)])
    assert payload._execute() == {
        "changed": False,
        "files": [],
        "directories": [],
        "symlinks": [],
    }
