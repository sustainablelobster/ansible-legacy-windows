"""Exercise the bounded cache fixture's native identity and rename guards."""

# SPDX-License-Identifier: GPL-3.0-or-later
# API substitutes are controller-only evidence, not Windows recovery proof.
# pylint: disable=protected-access

from pathlib import Path
from types import ModuleType, SimpleNamespace
from typing import Any
from unittest.mock import Mock

import pytest

from tests.unit.payload_support import ROOT, load_module


@pytest.fixture(name="fixture")
def cache_fixture() -> ModuleType:
    """Load the dedicated read/move fixture without calling Windows APIs.

    :returns: Its isolated native fixture module.
    """
    return load_module(
        ROOT / "tests/integration/fixtures/win_updates_cache.py", "tested_update_cache"
    )


def test_windows_cache_path_is_native_extended_local_path(fixture: ModuleType) -> None:
    def get_directory(buffer: Any, _size: int) -> int:
        """Fill the native output buffer.

        :param buffer: Native writable directory buffer.
        :returns: Its literal character count.
        """
        buffer.value = r"C:\WINDOWS"
        return len(buffer.value)

    assert fixture._path(
        SimpleNamespace(GetWindowsDirectoryW=get_directory)
    ).startswith("\\\\?\\C:\\WINDOWS")


@pytest.mark.parametrize("actual,backup_exists", [("other", False), ("owned", True)])
def test_cache_prepare_rejects_identity_changes_and_existing_sibling_before_move(
    fixture: ModuleType,
    monkeypatch: pytest.MonkeyPatch,
    actual: str,
    backup_exists: bool,
) -> None:
    path = r"C:\WINDOWS\SoftwareDistribution"
    monkeypatch.setattr(fixture, "_libraries", lambda: (None, None))
    monkeypatch.setattr(fixture, "_path", lambda _kernel: path)
    monkeypatch.setattr(fixture, "_identity", lambda *_args: actual)
    monkeypatch.setattr(fixture.os.path, "lexists", lambda _path: backup_exists)
    rename = Mock()
    monkeypatch.setattr(fixture.os, "rename", rename)
    with pytest.raises(OSError):
        fixture.prepare(
            {"identity": "owned", "backup": path + ".legacy-updates-public-v2-110"}
        )
    rename.assert_not_called()


def test_only_exact_absent_same_volume_sibling_can_be_moved(
    fixture: ModuleType, monkeypatch: pytest.MonkeyPatch
) -> None:
    path = r"C:\WINDOWS\SoftwareDistribution"
    backup = path + ".legacy-updates-public-v2-110"
    identity = {"path": path, "file_id": [1, 2], "security": "unchanged"}
    monkeypatch.setattr(fixture, "_libraries", lambda: (None, None))
    monkeypatch.setattr(fixture, "_path", lambda _kernel: path)
    monkeypatch.setattr(
        fixture, "_identity", lambda _kernel, _security, p: dict(identity, path=p)
    )
    monkeypatch.setattr(fixture.os.path, "lexists", lambda _path: False)
    rename = Mock()
    monkeypatch.setattr(fixture.os, "rename", rename)
    with pytest.raises(OSError, match="exact absent sibling"):
        fixture.prepare({"identity": identity, "backup": r"C:\other"})
    rename.assert_not_called()
    result = fixture.prepare({"identity": identity, "backup": backup})
    rename.assert_called_once_with(path, backup)
    assert result == {"original": identity, "backup": dict(identity, path=backup)}


def test_hash_journal_keeps_all_bytes_write_time_length_and_attributes(
    fixture: ModuleType, tmp_path: Path
) -> None:
    path = tmp_path / "exact.bin"
    path.write_bytes(b"\x00unchanged\xff")
    result = fixture._file(
        SimpleNamespace(GetFileAttributesW=lambda _path: 32), str(tmp_path), str(path)
    )
    assert result["path"] == "exact.bin" and result["length"] == 11
    assert result["mtime_ns"] == path.stat().st_mtime_ns
    assert result["attributes"] == 32
    assert result["sha256"] == fixture.hashlib.sha256(path.read_bytes()).hexdigest()


def test_reparse_child_is_rejected_before_tree_can_descend(
    fixture: ModuleType, monkeypatch: pytest.MonkeyPatch
) -> None:
    kernel = SimpleNamespace(
        GetFileAttributesW=lambda path: 0x410 if path.endswith("child") else 16
    )
    monkeypatch.setattr(fixture, "_libraries", lambda: (kernel, None))
    monkeypatch.setattr(fixture, "_path", lambda _kernel: "/cache")
    monkeypatch.setattr(fixture, "_identity", lambda *_args: {})

    def tree(_root: str) -> Any:
        """Expose a reparse child before any descent.

        :returns: Iterator exposing one parent row before forbidden traversal.
        """
        yield "/cache", ["child"], []
        pytest.fail("The rejected reparse child must never be traversed")

    monkeypatch.setattr(fixture.os, "walk", tree)
    with pytest.raises(OSError, match="reparse point"):
        fixture.observe()
