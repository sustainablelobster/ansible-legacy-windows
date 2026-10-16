"""Verify file version resource conversion and public read-only failures."""

# Copyright 2026 sustainablelobster
# SPDX-License-Identifier: GPL-3.0-or-later
# Native API records are substituted to test parsing on the controller.
# pylint: disable=protected-access

import ctypes
import json
import sys
from pathlib import Path
from types import ModuleType
from typing import Any
from unittest.mock import Mock

import pytest

from tests.unit.payload_support import HELPER, ROOT, invoke_payload, load_module


@pytest.fixture(name="payload")
def version_payload(monkeypatch: pytest.MonkeyPatch) -> ModuleType:
    """Load the native frontend without accessing a Windows host.

    :param monkeypatch: Scoped import path additions.
    :returns: Imported file version module.
    """
    monkeypatch.syspath_prepend(str(HELPER.parent))
    return load_module(
        ROOT / "legacy_community_windows/plugins/modules/win_file_version.py",
        "tested_community_file_version",
    )


def test_native_fixed_and_translated_version_fields(
    payload: ModuleType, monkeypatch: pytest.MonkeyPatch
) -> None:
    fixed = (ctypes.c_uint32 * 13)(0xFEEF04BD, 0, (2 << 16) | 17, (9 << 16) | 42)
    translations = (ctypes.c_uint16 * 2)(0x0411, 0x04B0)
    file_version = ctypes.create_unicode_buffer("2.17.9 release 雪")
    product_version = ctypes.create_unicode_buffer("Product 2026")
    records: dict[str, tuple[Any, int]] = {
        "\\": (fixed, ctypes.sizeof(fixed)),
        "\\VarFileInfo\\Translation": (translations, ctypes.sizeof(translations)),
        "\\StringFileInfo\\041104B0\\FileVersion": (file_version, len(file_version)),
        "\\StringFileInfo\\041104B0\\ProductVersion": (
            product_version,
            len(product_version),
        ),
    }

    def query(
        _library: object, _resource: object, name: str
    ) -> tuple[ctypes.c_void_p | None, int]:
        """Return a substituted native resource pointer and its reported size.

        :param name: Resource subblock to look up.
        :returns: The matching buffer pointer and size, or a missing-record pair.
        :rtype: tuple
        """
        record = records.get(name)
        if not record:
            return None, 0
        buffer, size = record
        return ctypes.cast(buffer, ctypes.c_void_p), size

    monkeypatch.setattr(payload, "_query", query)
    result = payload._fields(None, None)
    assert result == {
        "file_major_part": "2",
        "file_minor_part": "17",
        "file_build_part": "9",
        "file_private_part": "42",
        "file_version_raw": "2.17.9.42",
        "file_version": "2.17.9 release 雪",
        "product_version": "Product 2026",
    }


@pytest.mark.parametrize("suffix", [".exe", ".dll", ".EXE", ".DLL"])
def test_resource_free_files_return_empty_strings_and_zero_components(
    payload: ModuleType, tmp_path: Path, monkeypatch: pytest.MonkeyPatch, suffix: str
) -> None:
    path = tmp_path / ("unversioned" + suffix)
    path.write_bytes(b"not a version resource")
    library = Mock()
    library.GetFileVersionInfoSizeW.return_value = 0
    monkeypatch.setattr(payload, "_library", lambda: library)
    result = payload._inspect({"path": str(path), "_ansible_check_mode": True})
    assert result["changed"] is False
    assert result["win_file_version"]["file_version"] == ""
    assert result["win_file_version"]["file_version_raw"] == "0.0.0.0"
    assert result["win_file_version"]["file_major_part"] == "0"
    assert result["win_file_version"]["path"] == str(path)


@pytest.mark.parametrize(
    "arguments, message",
    [({}, "Missing required argument"), ({"path": "missing.exe"}, "does not exist")],
)
# Each argument is a separately scoped pytest fixture or a failure-case input;
# bundling them would obscure the fixture lifecycle and parameterized contract.
def test_missing_paths_return_json_failure(  # pylint: disable=too-many-arguments,too-many-positional-arguments
    payload: ModuleType,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
    arguments: dict[str, Any],
    message: str,
) -> None:
    path = tmp_path / "arguments.json"
    path.write_text(json.dumps(arguments), encoding="utf-8")
    monkeypatch.setattr(sys, "argv", ["win_file_version.py", str(path)])
    code, result = invoke_payload(payload, capsys)
    assert code == 1
    assert result["failed"] is True
    assert result["changed"] is False
    assert message in result["msg"]


def test_non_executable_file_is_rejected(payload: ModuleType, tmp_path: Path) -> None:
    path = tmp_path / "file.txt"
    path.write_bytes(b"text")
    with pytest.raises(ValueError, match="must be DLL or EXE"):
        payload._inspect({"path": str(path)})


@pytest.mark.parametrize("size", [1, 51])
def test_truncated_native_version_record_fails(
    payload: ModuleType, monkeypatch: pytest.MonkeyPatch, size: int
) -> None:
    fixed = (ctypes.c_uint32 * 13)()
    monkeypatch.setattr(
        payload,
        "_query",
        lambda *_arguments: (ctypes.cast(fixed, ctypes.c_void_p), size),
    )
    with pytest.raises(OSError, match="truncated"):
        payload._fields(None, None)
