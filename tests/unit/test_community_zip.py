"""Inspect generated archive contents and nonmutating ZIP behavior."""

# Copyright 2026 sustainablelobster
# SPDX-License-Identifier: GPL-3.0-or-later
# The request implementation is the module's directly observable boundary.
# pylint: disable=protected-access

import zipfile
from pathlib import Path
from types import ModuleType
from typing import Any

import pytest

from tests.unit.payload_support import HELPER, ROOT, load_module


@pytest.fixture(name="payload")
def zip_payload(monkeypatch: pytest.MonkeyPatch) -> ModuleType:
    """Load ZIP creation with the target-compatible argument helper.

    :param monkeypatch: Scoped import path changes.
    :returns: Imported ZIP frontend.
    """
    monkeypatch.syspath_prepend(str(HELPER.parent))
    return load_module(
        ROOT / "legacy_community_windows/plugins/modules/win_zip.py",
        "tested_community_zip",
    )


@pytest.mark.parametrize("contents_only", [False, True])
def test_unicode_tree_and_empty_directories_are_archived(
    payload: ModuleType, tmp_path: Path, contents_only: bool
) -> None:
    source = tmp_path / "Café 雪"
    (source / "empty").mkdir(parents=True)
    (source / "nested").mkdir()
    (source / "nested" / "data.txt").write_bytes(b"payload")
    destination = tmp_path / "tree.zip"
    result = payload._compress(
        {
            "src": str(source) + ("\\*" if contents_only else ""),
            "dest": str(destination),
        }
    )
    prefix = "" if contents_only else source.name + "/"
    assert result == {"changed": True}
    with zipfile.ZipFile(destination) as archive:
        assert sorted(archive.namelist()) == [
            prefix + "empty/",
            prefix + "nested/data.txt",
        ]
        assert archive.read(prefix + "nested/data.txt") == b"payload"


def test_single_file_and_existing_destination_are_idempotent(
    payload: ModuleType, tmp_path: Path
) -> None:
    source = tmp_path / "file.txt"
    source.write_bytes(b"first")
    destination = tmp_path / "file.ZIP"
    arguments = {"src": str(source), "dest": str(destination)}
    assert payload._compress(arguments)["changed"] is True
    original = destination.read_bytes()
    source.write_bytes(b"changed")
    assert payload._compress(arguments)["changed"] is False
    assert destination.read_bytes() == original


def test_check_mode_creates_no_archive(payload: ModuleType, tmp_path: Path) -> None:
    source = tmp_path / "source"
    source.mkdir()
    destination = tmp_path / "predicted.zip"
    assert payload._compress(
        {"src": str(source), "dest": str(destination), "_ansible_check_mode": True}
    ) == {"changed": True}
    assert not destination.exists()


def test_destination_in_source_does_not_include_itself(
    payload: ModuleType, tmp_path: Path
) -> None:
    source = tmp_path / "source"
    source.mkdir()
    (source / "file.txt").write_bytes(b"content")
    destination = source / "output.zip"
    payload._compress({"src": str(source) + "\\*", "dest": str(destination)})
    with zipfile.ZipFile(destination) as archive:
        assert archive.namelist() == ["file.txt"]


def test_empty_source_directory_with_root_is_retained(
    payload: ModuleType, tmp_path: Path
) -> None:
    source = tmp_path / "empty"
    source.mkdir()
    destination = tmp_path / "empty.zip"
    payload._compress({"src": str(source), "dest": str(destination)})
    with zipfile.ZipFile(destination) as archive:
        assert archive.namelist() == ["empty/"]


@pytest.mark.parametrize(
    "arguments,message",
    [({}, "required"), ({"src": "missing", "dest": "archive.zip"}, "does not exist")],
)
def test_invalid_source_is_actionable(
    payload: ModuleType, arguments: dict[str, Any], message: str
) -> None:
    with pytest.raises(ValueError, match=message):
        payload._compress(arguments)


def test_invalid_extension_rejected(payload: ModuleType, tmp_path: Path) -> None:
    source = tmp_path / "file.txt"
    source.write_bytes(b"data")
    with pytest.raises(ValueError, match="need to be zip"):
        payload._compress({"src": str(source), "dest": str(tmp_path / "invalid.txt")})


def test_failed_compression_removes_partial_owned_archive(
    payload: ModuleType, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    source = tmp_path / "source.txt"
    source.write_bytes(b"data")
    destination = tmp_path / "failed.zip"

    def fail(*_arguments: object) -> None:
        raise OSError("controlled ZIP read failure")

    monkeypatch.setattr(payload.zipfile.ZipFile, "write", fail)
    with pytest.raises(OSError, match="controlled ZIP read failure"):
        payload._compress({"src": str(source), "dest": str(destination)})
    assert not destination.exists()
