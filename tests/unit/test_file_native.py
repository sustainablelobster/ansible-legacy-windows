"""Check native filesystem boundaries without contacting Windows hosts."""

# SPDX-License-Identifier: GPL-3.0-or-later
# Native API substitutes verify calls and ownership, not Windows execution.
# pylint: disable=protected-access

import ctypes
import os
from pathlib import Path
from types import ModuleType, SimpleNamespace
from typing import Any
from unittest.mock import Mock

import pytest

from tests.unit.payload_support import ROOT, load_module, native_error


@pytest.fixture(name="helper")
def file_helper() -> ModuleType:
    """Load the Python 3.4 filesystem helper with the developer interpreter.

    :returns: The imported helper without accessing Windows.
    """
    source = ROOT / "plugins/module_utils/legacy_windows_file.py"
    return load_module(source, "tested_file_native")


@pytest.fixture(name="kernel")
def native_calls(helper: ModuleType, monkeypatch: pytest.MonkeyPatch) -> Mock:
    """Provide controllable Windows API results without opening real handles.

    :param helper: Imported target helper.
    :param monkeypatch: Scoped substitutions for Windows-only ctypes facilities.
    :returns: Mock kernel32 library with one valid disk handle.
    """
    kernel = Mock()
    kernel.CreateFileW.return_value = 123
    kernel.GetFileType.return_value = 1
    monkeypatch.setattr(helper, "os", SimpleNamespace(name="nt"))
    monkeypatch.setattr(
        helper.ctypes, "WinDLL", Mock(return_value=kernel), raising=False
    )
    monkeypatch.setattr(
        helper.ctypes, "get_last_error", Mock(return_value=5), raising=False
    )
    monkeypatch.setattr(helper.ctypes, "WinError", native_error, raising=False)
    return kernel


def test_metadata_keeps_link_attributes_and_all_timestamp_digits(
    helper: ModuleType, kernel: Mock
) -> None:
    path = "C:\\fixture\\雪 [link]"

    def _attributes(actual_path: str, level: int, pointer: Any) -> int:
        assert actual_path == path
        assert level == 0
        data = ctypes.cast(pointer, ctypes.POINTER(helper._AttributeData)).contents
        data.attributes = 0x411
        data.access_time.low = 0x9ABCDEF1
        data.access_time.high = 0x12345678
        data.modification_time.low = 0xFFFFFFFF
        data.modification_time.high = 0x12345679
        return 1

    kernel.GetFileAttributesExW.side_effect = _attributes

    assert helper.file_info(path) == {
        "attributes": 0x411,
        "access_time": 0x123456789ABCDEF1,
        "modification_time": 0x12345679FFFFFFFF,
    }
    kernel.CreateFileW.assert_not_called()


@pytest.mark.parametrize("error", [2, 3, 5, 21, 32])
def test_only_file_and_parent_not_found_mean_missing(
    helper: ModuleType, kernel: Mock, error: int
) -> None:
    kernel.GetFileAttributesExW.return_value = 0
    helper.ctypes.get_last_error.return_value = error

    if error in (2, 3):
        assert helper.file_info("C:\\fixture\\missing") is None
    else:
        with pytest.raises(OSError) as failure:
            helper.file_info("C:\\fixture\\missing")
        assert failure.value.errno == error


def test_current_time_preserves_native_ticks(helper: ModuleType, kernel: Mock) -> None:
    def _now(pointer: Any) -> None:
        timestamp = ctypes.cast(pointer, ctypes.POINTER(helper._FileTime)).contents
        timestamp.low = 0xFFFFFFFF
        timestamp.high = 0x01234567

    kernel.GetSystemTimeAsFileTime.side_effect = _now

    assert helper.current_file_time() == 0x01234567FFFFFFFF


def test_empty_file_creation_uses_create_mode_and_closes(
    helper: ModuleType, kernel: Mock
) -> None:
    helper.create_empty_file("C:\\fixture\\empty")

    kernel.CreateFileW.assert_called_once_with(
        "C:\\fixture\\empty", 0x40000000, 1, None, 2, 0x00100000, None
    )
    kernel.CloseHandle.assert_called_once_with(123)
    kernel.WriteFile.assert_not_called()


def test_empty_file_creation_failure_does_not_close_invalid_handle(
    helper: ModuleType, kernel: Mock
) -> None:
    kernel.CreateFileW.return_value = ctypes.c_void_p(-1).value

    with pytest.raises(OSError) as failure:
        helper.create_empty_file("C:\\fixture\\missing\\empty")

    assert failure.value.errno == 5
    kernel.CloseHandle.assert_not_called()


def test_empty_file_creation_rejects_non_disk_and_closes(
    helper: ModuleType, kernel: Mock
) -> None:
    kernel.GetFileType.return_value = 2

    with pytest.raises(ValueError, match="Only disk"):
        helper.create_empty_file("NUL")

    kernel.CloseHandle.assert_called_once_with(123)


@pytest.mark.parametrize("directory", [False, True])
@pytest.mark.parametrize("field", ["access_time", "modification_time"])
@pytest.mark.parametrize("ticks", [0, 0x123456789ABCDEF1, 2650467743999999999])
def test_each_timestamp_write_uses_its_own_dotnet_handle(
    helper: ModuleType, kernel: Mock, directory: bool, field: str, ticks: int
) -> None:
    writes = []

    def _set(handle: int, creation: Any, access: Any, modification: Any) -> int:
        assert handle == 123
        assert creation is None
        pointer = access if field == "access_time" else modification
        assert (modification if field == "access_time" else access) is None
        timestamp = ctypes.cast(pointer, ctypes.POINTER(helper._FileTime)).contents
        writes.append((timestamp.high << 32) | timestamp.low)
        return 1

    kernel.SetFileTime.side_effect = _set

    helper.set_file_time("C:\\fixture\\[entry]", directory, field, ticks)

    kernel.CreateFileW.assert_called_once_with(
        "C:\\fixture\\[entry]",
        0x40000000,
        6 if directory else 3,
        None,
        3,
        0x02000000 if directory else 0x00100000,
        None,
    )
    assert writes == [ticks]
    kernel.CloseHandle.assert_called_once_with(123)


@pytest.mark.parametrize("ticks", [-1, 2650467744000000000, 1.5, "time"])
def test_invalid_filetime_is_checked_after_open_and_still_closes(
    helper: ModuleType, kernel: Mock, ticks: object
) -> None:
    with pytest.raises(ValueError, match="between 1601 and 9999"):
        helper.set_file_time("C:\\fixture\\file", False, "access_time", ticks)

    kernel.CreateFileW.assert_called_once()
    kernel.SetFileTime.assert_not_called()
    kernel.CloseHandle.assert_called_once_with(123)


def test_open_failure_precedes_invalid_filetime(
    helper: ModuleType, kernel: Mock
) -> None:
    kernel.CreateFileW.return_value = ctypes.c_void_p(-1).value

    with pytest.raises(OSError) as failure:
        helper.set_file_time("C:\\fixture\\file", False, "access_time", -1)

    assert failure.value.errno == 5
    kernel.SetFileTime.assert_not_called()
    kernel.CloseHandle.assert_not_called()


def test_timestamp_failure_closes_handle_and_keeps_native_error(
    helper: ModuleType, kernel: Mock
) -> None:
    kernel.SetFileTime.return_value = 0
    with pytest.raises(OSError) as failure:
        helper.set_file_time("C:\\fixture\\file", False, "modification_time", 1)

    assert failure.value.errno == 5
    kernel.CloseHandle.assert_called_once_with(123)


@pytest.mark.parametrize("kind", [0, 2, 3])
@pytest.mark.parametrize("operation", ["read", "timestamp"])
def test_non_disk_handles_are_rejected_and_closed(
    helper: ModuleType, kernel: Mock, kind: int, operation: str
) -> None:
    kernel.GetFileType.return_value = kind

    with pytest.raises(ValueError, match="Only disk"):
        if operation == "read":
            helper.read_prefix("C:\\fixture\\entry", 8192)
        else:
            helper.set_file_time("C:\\fixture\\entry", False, "access_time", 1)

    kernel.ReadFile.assert_not_called()
    kernel.SetFileTime.assert_not_called()
    kernel.CloseHandle.assert_called_once_with(123)


@pytest.mark.parametrize("contents", [b"", b"one\0\xff", b"a" * 8192])
def test_prefix_read_is_bounded_binary_and_uses_dotnet_sharing(
    helper: ModuleType, kernel: Mock, contents: bytes
) -> None:
    def _read(handle: int, buffer: Any, count: int, received: Any, overlap: Any) -> int:
        assert handle == 123
        assert count == 8192
        assert overlap is None
        ctypes.memmove(buffer, contents, len(contents))
        ctypes.cast(received, ctypes.POINTER(ctypes.c_uint32)).contents.value = len(
            contents
        )
        return 1

    kernel.ReadFile.side_effect = _read

    assert helper.read_prefix("C:\\fixture\\雪 [literal]", 8192) == contents
    kernel.CreateFileW.assert_called_once_with(
        "C:\\fixture\\雪 [literal]", 0x80000000, 1, None, 3, 0x00100000, None
    )
    kernel.ReadFile.assert_called_once()
    kernel.CloseHandle.assert_called_once_with(123)


def test_zero_prefix_count_opens_and_closes_without_reading(
    helper: ModuleType, kernel: Mock
) -> None:
    assert helper.read_prefix("C:\\fixture\\file", 0) == b""
    kernel.CreateFileW.assert_called_once()
    kernel.ReadFile.assert_not_called()
    kernel.CloseHandle.assert_called_once_with(123)


def test_read_failure_closes_and_keeps_native_error(
    helper: ModuleType, kernel: Mock
) -> None:
    kernel.ReadFile.return_value = 0

    with pytest.raises(OSError) as failure:
        helper.read_prefix("C:\\fixture\\file", 8192)

    assert failure.value.errno == 5
    kernel.CloseHandle.assert_called_once_with(123)


@pytest.mark.parametrize("count", [-1, 0x100000000, 1.5, None])
def test_invalid_read_bound_fails_before_opening(
    helper: ModuleType, kernel: Mock, count: object
) -> None:
    with pytest.raises(ValueError, match="Read count"):
        helper.read_prefix("C:\\fixture\\file", count)

    kernel.CreateFileW.assert_not_called()


@pytest.mark.parametrize(
    ("function", "native"),
    [("remove_file", "DeleteFileW"), ("remove_directory", "RemoveDirectoryW")],
)
@pytest.mark.parametrize("success", [False, True])
def test_removal_passes_one_literal_entry_without_opening_or_traversing(
    helper: ModuleType, kernel: Mock, function: str, native: str, success: bool
) -> None:
    path = "C:\\fixture\\雪 [link]"
    getattr(kernel, native).return_value = int(success)
    if success:
        getattr(helper, function)(path)
    else:
        with pytest.raises(OSError) as failure:
            getattr(helper, function)(path)
        assert failure.value.errno == 5

    getattr(kernel, native).assert_called_once_with(path)
    kernel.CreateFileW.assert_not_called()
    kernel.GetFileAttributesExW.assert_not_called()
    kernel.SetFileAttributesW.assert_not_called()


@pytest.mark.parametrize("success", [False, True])
def test_attribute_update_passes_exact_bits_and_surfaces_failure(
    helper: ModuleType, kernel: Mock, success: bool
) -> None:
    kernel.SetFileAttributesW.return_value = int(success)
    if success:
        helper.set_attributes("C:\\fixture\\readonly", 0x22)
    else:
        with pytest.raises(OSError) as failure:
            helper.set_attributes("C:\\fixture\\readonly", 0x22)
        assert failure.value.errno == 5

    kernel.SetFileAttributesW.assert_called_once_with("C:\\fixture\\readonly", 0x22)


@pytest.fixture(name="removal")
def removal_fixture(
    helper: ModuleType, monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> SimpleNamespace:
    """Use real owned trees with controllable Windows metadata and failures.

    :param helper: Imported target helper.
    :param monkeypatch: Scoped native boundary substitutions.
    :param tmp_path: Owned local fixture directory.
    :returns: Root, metadata, observed operations, and injectable native errors.
    """
    root = tmp_path / "tree"
    root.mkdir()
    fixture = SimpleNamespace(
        root=root,
        attributes={},
        order={},
        visited=[],
        deleted=[],
        changed_attributes=[],
        delete_errors={},
        attribute_errors={},
        read_errors={},
    )
    native_listdir = os.listdir

    def _info(path: str) -> dict[str, int] | None:
        if path in fixture.read_errors:
            raise fixture.read_errors[path]
        if not os.path.lexists(path):
            return None
        default = 0x10 if Path(path).is_dir() else 0x80
        if Path(path).is_symlink():
            default |= 0x400
        return {"attributes": fixture.attributes.get(path, default)}

    def _listdir(path: str) -> list[str]:
        fixture.visited.append(path)
        names = native_listdir(path)
        if path in fixture.order:
            names = [name for name in fixture.order[path] if name in names]
            assert set(names) == set(native_listdir(path))
        return names

    def _attributes(path: str, value: int) -> None:
        fixture.changed_attributes.append((path, value))
        if (path, value) in fixture.attribute_errors:
            raise fixture.attribute_errors[path, value]
        fixture.attributes[path] = value

    def _delete(path: str) -> None:
        if path in fixture.delete_errors:
            raise fixture.delete_errors[path]
        entry = Path(path)
        if entry.is_symlink() or not entry.is_dir():
            entry.unlink()
        else:
            entry.rmdir()
        fixture.deleted.append(path)

    monkeypatch.setattr(helper, "file_info", _info)
    monkeypatch.setattr(helper, "set_attributes", _attributes)
    monkeypatch.setattr(helper, "remove_file", _delete)
    monkeypatch.setattr(helper, "remove_directory", _delete)
    monkeypatch.setattr(helper.os, "listdir", _listdir)
    monkeypatch.setattr(helper.ctypes, "WinError", native_error, raising=False)
    return fixture


@pytest.mark.parametrize("check_mode", [False, True])
def test_remove_missing_root_is_unchanged(
    helper: ModuleType, removal: SimpleNamespace, check_mode: bool
) -> None:
    assert helper.remove_path(str(removal.root / "missing"), check_mode) is False
    assert removal.visited == removal.deleted == removal.changed_attributes == []


def test_remove_tree_keeps_native_order_and_two_pass_directory_grouping(
    helper: ModuleType, removal: SimpleNamespace
) -> None:
    root = removal.root
    native_order = ["_a.txt", "0-hidden.txt", "z-dir", "ä.txt", "a-dir", "a.txt"]
    for name in native_order:
        if name.endswith("-dir"):
            (root / name).mkdir()
        else:
            (root / name).touch()
    hidden_directory = root / "hidden-dir"
    hidden_directory.mkdir()
    (hidden_directory / "first.txt").touch()
    (hidden_directory / "last-dir").mkdir()
    removal.attributes[str(root / "0-hidden.txt")] = 0x7
    removal.attributes[str(hidden_directory)] = 0x17
    removal.order[str(root)] = native_order + ["hidden-dir"]
    removal.order[str(hidden_directory)] = ["first.txt", "last-dir"]

    assert helper.remove_path(str(root)) is True

    assert [str(Path(path).relative_to(root)) for path in removal.deleted] == [
        "z-dir",
        "a-dir",
        "_a.txt",
        "ä.txt",
        "a.txt",
        "hidden-dir/last-dir",
        "hidden-dir/first.txt",
        "hidden-dir",
        "0-hidden.txt",
        ".",
    ]
    assert not root.exists()


def test_check_mode_visits_only_visible_ordinary_directories_without_mutation(
    helper: ModuleType, removal: SimpleNamespace
) -> None:
    root = removal.root
    visible = root / "visible"
    hidden = root / "hidden"
    visible.mkdir()
    hidden.mkdir()
    (visible / "readonly").touch()
    (hidden / "unvisited").touch()
    removal.attributes[str(hidden)] = 0x12
    removal.attributes[str(visible / "readonly")] = 0x5
    before = dict(removal.attributes)

    assert helper.remove_path(str(root), check_mode=True) is True

    assert removal.visited == [str(root), str(visible)]
    assert removal.attributes == before
    assert removal.deleted == removal.changed_attributes == []
    assert (visible / "readonly").exists()
    assert (hidden / "unvisited").exists()


@pytest.mark.parametrize("hidden", [False, True])
@pytest.mark.parametrize("directory", [False, True])
def test_recursive_removal_leaves_link_targets_intact(
    helper: ModuleType, removal: SimpleNamespace, hidden: bool, directory: bool
) -> None:
    target = removal.root.parent / "retained-target"
    if directory:
        target.mkdir()
        marker = target / "marker"
    else:
        marker = target
    marker.write_bytes(b"retained")
    link = removal.root / "link"
    link.symlink_to(target, target_is_directory=directory)
    removal.attributes[str(link)] = 0x400 | (0x10 if directory else 0) | int(hidden) * 2

    assert helper.remove_path(str(removal.root)) is True

    assert marker.read_bytes() == b"retained"
    assert str(link) not in removal.visited
    link_changes = [
        value for path, value in removal.changed_attributes if path == str(link)
    ]
    assert link_changes == ([0x400] if hidden and not directory else [])


@pytest.mark.parametrize("directory", [False, True])
@pytest.mark.parametrize("check_mode", [False, True])
def test_direct_broken_links_are_never_traversed_or_force_modified(
    helper: ModuleType, removal: SimpleNamespace, directory: bool, check_mode: bool
) -> None:
    link = removal.root / "broken"
    link.symlink_to(removal.root / "missing", target_is_directory=directory)
    removal.attributes[str(link)] = 0x407 | (0x10 if directory else 0)

    assert helper.remove_path(str(link), check_mode=check_mode) is True

    assert os.path.lexists(link) is check_mode
    assert removal.visited == removal.changed_attributes == []


def test_visible_readonly_link_fails_before_hidden_link_then_recovers(
    helper: ModuleType, removal: SimpleNamespace
) -> None:
    target = removal.root.parent / "retained-target"
    target.write_bytes(b"retained")
    visible = removal.root / "visible-link"
    hidden = removal.root / "hidden-link"
    for link, attributes in [(visible, 0x401), (hidden, 0x403)]:
        link.symlink_to(target)
        removal.attributes[str(link)] = attributes
    removal.delete_errors[str(visible)] = OSError(5, "access denied")

    with pytest.raises(OSError) as failure:
        helper.remove_path(str(removal.root))

    assert failure.value.errno == 5
    assert failure.value.filename == str(visible)
    assert removal.deleted == removal.changed_attributes == []
    assert visible.is_symlink() and hidden.is_symlink()
    assert target.read_bytes() == b"retained"

    removal.delete_errors.clear()
    removal.attributes[str(visible)] = 0x400
    assert helper.remove_path(str(removal.root)) is True
    assert removal.deleted == [str(visible), str(hidden), str(removal.root)]
    assert removal.changed_attributes == [
        (str(hidden), 0x400),
        (str(removal.root), 0x10),
    ]
    assert target.read_bytes() == b"retained"


@pytest.mark.parametrize("attributes", [0x5, 0x7])
def test_failed_delete_restores_attributes_and_preserves_partial_progress(
    helper: ModuleType, removal: SimpleNamespace, attributes: int
) -> None:
    root = removal.root
    for name in ["a-before", "b-locked", "z-after"]:
        (root / name).touch()
        removal.attributes[str(root / name)] = attributes
    directory = root / "z-directory"
    directory.mkdir()
    removal.attributes[str(directory)] = 0x10 | (attributes & 0x2)
    locked = str(root / "b-locked")
    removal.order[str(root)] = ["a-before", "b-locked", "z-after", "z-directory"]
    removal.delete_errors[locked] = OSError(32, "sharing violation")

    with pytest.raises(OSError) as failure:
        helper.remove_path(str(root))

    assert failure.value.errno == 32
    assert failure.value.filename == locked
    assert locked in str(failure.value)
    assert removal.deleted == [str(directory), str(root / "a-before")]
    assert sorted(entry.name for entry in root.iterdir()) == ["b-locked", "z-after"]
    assert removal.attributes[locked] == attributes
    assert removal.changed_attributes[-2:] == [(locked, 0), (locked, attributes)]

    removal.delete_errors.clear()
    assert helper.remove_path(str(root)) is True
    assert not root.exists()


def test_failed_attribute_clear_does_not_delete_or_attempt_restoration(
    helper: ModuleType, removal: SimpleNamespace
) -> None:
    entry = removal.root / "readonly"
    entry.touch()
    path = str(entry)
    removal.attributes[path] = 0x5
    removal.attribute_errors[path, 0] = OSError(5, "access denied")

    with pytest.raises(OSError) as failure:
        helper.remove_path(path)

    assert failure.value.errno == 5
    assert failure.value.filename == path
    assert entry.exists()
    assert removal.attributes[path] == 0x5
    assert removal.changed_attributes == [(path, 0)]
    assert removal.deleted == []


def test_failed_attribute_restoration_reports_both_failures(
    helper: ModuleType, removal: SimpleNamespace
) -> None:
    entry = removal.root / "readonly"
    entry.touch()
    path = str(entry)
    removal.attributes[path] = 0x5
    removal.delete_errors[path] = OSError(32, "sharing violation")
    removal.attribute_errors[path, 0x5] = OSError(5, "recovery access denied")

    with pytest.raises(OSError) as failure:
        helper.remove_path(path)

    assert failure.value.errno == 32
    assert failure.value.filename == path
    assert "sharing violation" in str(failure.value)
    assert "restore original attributes: [Errno 5] recovery access denied" in str(
        failure.value
    )
    assert removal.attributes[path] == 0
    assert entry.exists()


@pytest.mark.parametrize("check_mode", [False, True])
def test_metadata_failure_reports_actual_child_and_stops_without_mutation(
    helper: ModuleType, removal: SimpleNamespace, check_mode: bool
) -> None:
    entry = removal.root / "inaccessible"
    entry.touch()
    removal.read_errors[str(entry)] = OSError(5, "access denied")

    with pytest.raises(OSError) as failure:
        helper.remove_path(str(removal.root), check_mode)

    assert failure.value.errno == 5
    assert failure.value.filename == str(entry)
    assert removal.deleted == removal.changed_attributes == []
