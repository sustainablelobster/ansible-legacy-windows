"""Exercise archive extraction, traversal protection and public guard behavior."""

# Copyright 2026 sustainablelobster
# SPDX-License-Identifier: GPL-3.0-or-later
# Direct helper calls isolate vendor-process boundaries while retaining formats.
# pylint: disable=protected-access

import base64
import bz2
import gzip
import io
import sys
import tarfile
import zipfile
from pathlib import Path
from types import ModuleType
from typing import Any, Callable, Literal
from unittest.mock import MagicMock, Mock

import pytest

from tests.unit.payload_support import HELPER, ROOT, load_module


@pytest.fixture(name="payload")
def unzip_payload(monkeypatch: pytest.MonkeyPatch) -> ModuleType:
    """Load archive extraction with the actual target helper closure.

    :param monkeypatch: Scoped import path additions.
    :returns: Loaded extraction frontend.
    """
    monkeypatch.syspath_prepend(str(HELPER.parent))
    monkeypatch.syspath_prepend(
        str(ROOT / "legacy_community_windows/plugins/module_utils")
    )
    return load_module(
        ROOT / "legacy_community_windows/plugins/modules/win_unzip.py",
        "tested_community_unzip",
    )


def _apply(
    payload: ModuleType, source: Path, destination: Path, **options: object
) -> dict[str, Any]:
    check_mode = options.pop("check", False)
    result: dict[str, Any] = payload.extract(
        payload._parameters({"src": str(source), "dest": str(destination), **options}),
        check_mode,
    )
    return result


def _zip(path: Path, members: dict[str, bytes]) -> None:
    with zipfile.ZipFile(path, "w", compression=zipfile.ZIP_DEFLATED) as archive:
        for name, data in members.items():
            archive.writestr(name, data)


def test_unicode_zip_extracts_overwrites_and_repeats(
    payload: ModuleType, tmp_path: Path
) -> None:
    source = tmp_path / "archive.zip"
    destination = tmp_path / "output"
    _zip(
        source, {"Café 雪.txt": b"payload", "empty/": b"", "nested/file.txt": b"nested"}
    )
    assert _apply(payload, source, destination)["changed"] is True
    assert (destination / "Café 雪.txt").read_bytes() == b"payload"
    assert (destination / "empty").is_dir()
    (destination / "Café 雪.txt").write_bytes(b"changed externally")
    assert _apply(payload, source, destination)["changed"] is True
    assert (destination / "Café 雪.txt").read_bytes() == b"payload"


def test_creates_guard_precedes_source_validation(
    payload: ModuleType, tmp_path: Path
) -> None:
    destination = tmp_path / "existing"
    destination.mkdir()
    result = _apply(
        payload,
        tmp_path / "missing.zip",
        destination,
        creates=str(destination),
        delete_archive=True,
    )
    assert result["changed"] is False
    assert result["skipped"] is True
    assert result["removed"] is False


def test_check_mode_does_not_extract_or_delete(
    payload: ModuleType, tmp_path: Path
) -> None:
    source = tmp_path / "archive.zip"
    _zip(source, {"file.txt": b"payload"})
    destination = tmp_path / "predicted"
    result = _apply(payload, source, destination, check=True, delete_archive=True)
    assert result["changed"] is True
    assert result["removed"] is True
    assert source.exists()
    assert not destination.exists()


@pytest.mark.usefixtures("payload")
@pytest.mark.parametrize("legacy_extractor", [True, False])
@pytest.mark.parametrize("preview", [True, False])
def test_cabinet_names_use_the_installed_extractor_and_preview_never_runs_it(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    legacy_extractor: bool,
    preview: bool,
) -> None:
    helper = sys.modules["legacy_community_windows_unzip"]
    monkeypatch.setattr(
        helper.os.path,
        "isfile",
        lambda name: name.endswith("extrac32.exe") == legacy_extractor,
    )
    process = MagicMock()
    process.__enter__.return_value = process
    process.communicate.return_value = (b"", b"")
    process.returncode = 0
    launch = Mock(return_value=process)
    monkeypatch.setattr(helper.subprocess, "Popen", launch)
    source, destination = str(tmp_path / "input.cab"), str(tmp_path / "out")
    assert helper._expand_cabinet(source, destination, preview) is True
    if preview:
        launch.assert_not_called()
        assert not Path(destination).exists()
    else:
        command = launch.call_args.args[0]
        assert command[0].endswith("extrac32.exe" if legacy_extractor else "expand.exe")
        assert command[1:] == (
            ["/Y", "/E", "/L", destination, source]
            if legacy_extractor
            else [source, "-F:*", destination]
        )
        assert Path(destination).is_dir()


def test_successful_extraction_deletes_archive_with_alias(
    payload: ModuleType, tmp_path: Path
) -> None:
    source = tmp_path / "archive.zip"
    _zip(source, {"file.txt": b"payload"})
    destination = tmp_path / "output"
    result = _apply(payload, source, destination, rm=True)
    assert result["removed"] is True
    assert not source.exists()
    assert (destination / "file.txt").read_bytes() == b"payload"


def test_native_cabinet_failure_preserves_the_source_even_when_deletion_requested(
    payload: ModuleType, monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    helper = sys.modules["legacy_community_windows_unzip"]
    is_file = helper.os.path.isfile
    monkeypatch.setattr(
        helper.os.path,
        "isfile",
        lambda name: str(name).endswith("extrac32.exe") or is_file(name),
    )
    process = MagicMock()
    process.__enter__.return_value = process
    process.communicate.return_value = (b"not a cabinet", b"")
    process.returncode = 1
    monkeypatch.setattr(helper.subprocess, "Popen", Mock(return_value=process))
    source = tmp_path / "invalid.cab"
    source.write_bytes(b"not a cabinet")
    with pytest.raises(ValueError, match="CAB/MSU extraction failed"):
        _apply(payload, source, tmp_path / "output", delete_archive=True)
    assert source.read_bytes() == b"not a cabinet"


@pytest.mark.usefixtures("payload")
def test_missing_cabinet_utilities_fail_before_creating_output(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    helper = sys.modules["legacy_community_windows_unzip"]
    monkeypatch.setattr(helper.os.path, "isfile", lambda _name: False)
    launch = Mock()
    monkeypatch.setattr(helper.subprocess, "Popen", launch)
    destination = tmp_path / "missing-output"
    with pytest.raises(ValueError, match="extrac32.exe or expand.exe is required"):
        helper._expand_cabinet("input.cab", str(destination), False)
    launch.assert_not_called()
    assert not destination.exists()


@pytest.mark.parametrize(
    "mode,suffix",
    [("w", ".tar"), ("w:gz", ".tar.gz"), ("w:bz2", ".tar.bz2"), ("w:xz", ".tar.xz")],
)
def test_tar_formats_extract_nested_content(
    payload: ModuleType,
    tmp_path: Path,
    mode: Literal["w", "w:gz", "w:bz2", "w:xz"],
    suffix: str,
) -> None:
    source = tmp_path / ("archive" + suffix)
    with tarfile.open(source, mode) as archive:
        member = tarfile.TarInfo("nested/Café 雪.txt")
        member.size = 7
        archive.addfile(member, io.BytesIO(b"payload"))
    destination = tmp_path / "output"
    assert _apply(payload, source, destination)["changed"] is True
    assert (destination / "nested/Café 雪.txt").read_bytes() == b"payload"


@pytest.mark.parametrize(
    "suffix,compress", [(".gz", gzip.compress), (".bz2", bz2.compress)]
)
def test_single_stream_formats(
    payload: ModuleType, tmp_path: Path, suffix: str, compress: Callable[[bytes], bytes]
) -> None:
    source = tmp_path / ("data.log" + suffix)
    source.write_bytes(compress(b"payload"))
    destination = tmp_path / "output"
    assert _apply(payload, source, destination)["changed"] is True
    assert (destination / "data.log").read_bytes() == b"payload"


def test_recursive_nested_archives_are_extracted_and_removed(
    payload: ModuleType, tmp_path: Path
) -> None:
    inner = io.BytesIO()
    with zipfile.ZipFile(inner, "w") as archive:
        archive.writestr("log.gz", gzip.compress(b"nested payload"))
    source = tmp_path / "outer.zip"
    _zip(source, {"folder/inner.zip": inner.getvalue()})
    destination = tmp_path / "output"
    result = _apply(payload, source, destination, recurse=True, delete_archive=True)
    assert result["changed"] is True
    assert result["removed"] is True
    assert (destination / "log").read_bytes() == b"nested payload"
    assert not source.exists()
    assert not list(destination.rglob("*.zip"))
    assert not list(destination.rglob("*.gz"))


@pytest.mark.parametrize(
    "name",
    [
        "../outside.txt",
        "..\\outside.txt",
        "/absolute.txt",
        "C:\\outside.txt",
        "C:outside.txt",
        "nested/../../outside.txt",
        "nested/file:stream",
        ".. /outside.txt",
        "NUL",
        "folder/COM1.txt",
        "folder/file.",
        "folder/file ",
    ],
)
def test_unsafe_zip_members_are_rejected_before_any_extraction(
    payload: ModuleType, tmp_path: Path, name: str
) -> None:
    source = tmp_path / "unsafe.zip"
    _zip(source, {"safe.txt": b"must not be written", name: b"unsafe"})
    destination = tmp_path / "output"
    with pytest.raises(ValueError, match="outside|safe Windows"):
        _apply(payload, source, destination)
    assert not destination.exists()
    assert source.exists()


def test_internal_relative_segments_cannot_escape_but_are_supported(
    payload: ModuleType, tmp_path: Path
) -> None:
    source = tmp_path / "safe.zip"
    _zip(source, {"nested/../rabbit.txt": b"payload"})
    destination = tmp_path / "output"
    _apply(payload, source, destination)
    assert (destination / "rabbit.txt").read_bytes() == b"payload"


@pytest.mark.parametrize("kind", [tarfile.SYMTYPE, tarfile.LNKTYPE, tarfile.FIFOTYPE])
def test_tar_links_and_special_files_are_rejected(
    payload: ModuleType, tmp_path: Path, kind: bytes
) -> None:
    source = tmp_path / "unsafe.tar"
    with tarfile.open(source, "w") as archive:
        member = tarfile.TarInfo("link")
        member.type = kind
        member.linkname = "../outside"
        archive.addfile(member)
    with pytest.raises(ValueError, match="links and special files"):
        _apply(payload, source, tmp_path / "output")
    assert not (tmp_path / "output").exists()


def test_existing_symlink_cannot_redirect_extraction(
    payload: ModuleType, tmp_path: Path
) -> None:
    outside = tmp_path / "outside"
    outside.mkdir()
    destination = tmp_path / "output"
    destination.mkdir()
    (destination / "redirect").symlink_to(outside, target_is_directory=True)
    source = tmp_path / "unsafe.zip"
    _zip(source, {"redirect/outside.txt": b"unsafe"})
    with pytest.raises(ValueError, match="link or reparse point"):
        _apply(payload, source, destination)
    assert not list(outside.iterdir())


def test_pscx_fallback_uses_encoded_literal_arguments_without_shell(
    payload: ModuleType, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    helper = sys.modules["legacy_community_windows_unzip"]
    source = tmp_path / "archive's.7z"
    source.write_bytes(b"vendor fixture")
    process = MagicMock(returncode=0)
    process.__enter__.return_value = process
    process.communicate.return_value = (b"", b"")
    popen = Mock(return_value=process)
    monkeypatch.setattr(helper.shutil, "which", lambda _name: "powershell.exe")
    monkeypatch.setattr(helper.subprocess, "Popen", popen)
    result = _apply(
        payload,
        source,
        tmp_path / "destination",
        password="literal'password",
        check=True,
    )
    command = popen.call_args.args[0]
    script = base64.b64decode(command[-1]).decode("utf-16-le")
    assert "-LiteralPath '" in script
    assert "archive''s.7z" in script
    assert "literal''password" in script
    assert "-WhatIf" in script
    assert result["pscx_status"] == "present"
    assert "shell" not in popen.call_args.kwargs


def test_additional_format_explains_missing_engine(
    payload: ModuleType, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    source = tmp_path / "archive.7z"
    source.write_bytes(b"fixture")
    helper = sys.modules["legacy_community_windows_unzip"]
    monkeypatch.setattr(helper.shutil, "which", lambda _name: None)
    with pytest.raises(ValueError, match="PSCX"):
        _apply(payload, source, tmp_path / "output")


@pytest.mark.parametrize("arguments", [{}, {"src": "file.zip"}, {"dest": "output"}])
def test_required_paths_are_validated(
    payload: ModuleType, arguments: dict[str, Any]
) -> None:
    with pytest.raises(ValueError, match="Missing required argument"):
        payload._parameters(arguments)
