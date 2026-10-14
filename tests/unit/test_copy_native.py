"""Verify native copy metadata, archive validation, and handle-free API boundaries."""

# SPDX-License-Identifier: GPL-3.0-or-later
# Native substitutes test Windows calls without contacting a Windows host.
# pylint: disable=protected-access

import base64
import ctypes
import datetime
from types import ModuleType, SimpleNamespace
from unittest.mock import Mock

import pytest

from tests.unit.payload_support import ROOT, load_module, native_error


@pytest.fixture(name="helper")
def copy_helper(monkeypatch: pytest.MonkeyPatch) -> ModuleType:
    """Load the independently staged target helper.

    :param monkeypatch: Scoped path for its existing target dependencies.
    :returns: The helper without calling Windows APIs.
    """
    monkeypatch.syspath_prepend(str(ROOT / "legacy_windows/plugins/module_utils"))
    return load_module(
        ROOT / "legacy_windows/plugins/module_utils/legacy_windows_copy.py",
        "tested_copy_native",
    )


@pytest.fixture(name="kernel")
def copy_kernel(helper: ModuleType, monkeypatch: pytest.MonkeyPatch) -> Mock:
    """Substitute native calls while retaining their declared ctypes signatures.

    :param helper: Loaded target helper.
    :param monkeypatch: Scoped substitutions.
    :returns: The native library substitute.
    """
    kernel = Mock()
    monkeypatch.setattr(helper, "os", SimpleNamespace(name="nt"))
    monkeypatch.setattr(ctypes, "WinDLL", Mock(return_value=kernel), raising=False)
    monkeypatch.setattr(ctypes, "WinError", native_error, raising=False)
    monkeypatch.setattr(ctypes, "get_last_error", lambda: 5, raising=False)
    monkeypatch.setattr(helper.filesystem, "file_info", Mock(return_value=None))
    monkeypatch.setattr(helper.filesystem, "set_attributes", Mock())
    return kernel


@pytest.mark.parametrize("overwrite", [False, True])
def test_native_copy_preserves_os_metadata_and_uses_unicode_paths(
    helper: ModuleType, kernel: Mock, overwrite: bool
) -> None:
    helper.copy_file("C:\\雪 source", "C:\\destination", overwrite=overwrite)
    kernel.CopyFileW.assert_called_once_with(
        "C:\\雪 source", "C:\\destination", not overwrite
    )
    assert kernel.CopyFileW.argtypes == [
        ctypes.c_wchar_p,
        ctypes.c_wchar_p,
        ctypes.c_int,
    ]
    assert kernel.CopyFileW.restype is ctypes.c_int
    helper.filesystem.file_info.assert_not_called()
    helper.filesystem.set_attributes.assert_not_called()


def test_force_clears_blocking_attributes_before_native_copy(
    helper: ModuleType, kernel: Mock
) -> None:
    helper.filesystem.file_info.return_value = {"attributes": 39}
    helper.copy_file("source", "target", force=True)
    helper.filesystem.set_attributes.assert_called_once_with("target", 32)
    kernel.CopyFileW.assert_called_once_with("source", "target", False)


def test_failed_copy_restores_original_attributes(
    helper: ModuleType, kernel: Mock
) -> None:
    helper.filesystem.file_info.return_value = {"attributes": 39}
    kernel.CopyFileW.return_value = 0
    with pytest.raises(OSError) as failure:
        helper.copy_file("source", "target", force=True)
    assert failure.value.errno == 5
    assert helper.filesystem.set_attributes.call_args_list == [
        (("target", 32),),
        (("target", 39),),
    ]


def test_failed_attribute_recovery_remains_visible(
    helper: ModuleType, kernel: Mock
) -> None:
    helper.filesystem.file_info.return_value = {"attributes": 1}
    helper.filesystem.set_attributes.side_effect = [
        None,
        OSError("fixture restore denied"),
    ]
    kernel.CopyFileW.return_value = 0
    with pytest.raises(OSError, match="could not restore destination attributes"):
        helper.copy_file("source", "target", force=True)


def test_non_windows_copy_fails_explicitly(
    helper: ModuleType, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(helper, "os", SimpleNamespace(name="posix"))
    with pytest.raises(ValueError, match="Windows target"):
        helper.copy_file("source", "target")


def test_backup_name_uses_native_calendar_and_local_wall_time(
    helper: ModuleType, monkeypatch: pytest.MonkeyPatch
) -> None:
    now = datetime.datetime(2026, 9, 30, 1, 2, 3)
    monkeypatch.setattr(
        helper, "datetime", SimpleNamespace(datetime=SimpleNamespace(now=lambda: now))
    )
    monkeypatch.setattr(helper.calendar, "get_culture", lambda: {"calendar_id": 7})
    monkeypatch.setattr(helper.os, "getpid", lambda: 123)
    assert helper._backup_name("C:\\file") == "C:\\file.123.25690930-010203.bak"


@pytest.mark.parametrize("suffix", ["", "/", "\\"])
def test_archive_name_protocol_decodes_utf8(helper: ModuleType, suffix: str) -> None:
    encoded = base64.b64encode("nested/雪.txt".encode()).decode()
    assert helper._archive_entry(encoded + suffix) == (
        ["nested", "雪.txt"],
        bool(suffix),
    )


@pytest.mark.parametrize("encoded", ["abc", "abcde", "????", "YQ==x", "//8="])
def test_invalid_archive_names_fail(helper: ModuleType, encoded: str) -> None:
    with pytest.raises((ValueError, UnicodeError)):
        helper._archive_entry(encoded)


def test_tree_size_skips_reparse_points_and_unreadable_subdirectories(
    helper: ModuleType, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(helper.metadata, "file_info", lambda _path: {"attributes": 16})

    def _entries(path: str) -> list[dict[str, object]]:
        if path.endswith("denied"):
            raise OSError("denied")
        return [
            {"name": "file", "attributes": 32, "size": 12},
            {"name": "link", "attributes": 0x410, "size": 0},
            {"name": "denied", "attributes": 16, "size": 0},
        ]

    monkeypatch.setattr(helper.metadata, "directory_entries", _entries)
    assert helper._size("root") == 12
