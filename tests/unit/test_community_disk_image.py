"""Observe native image state, drive mapping, preview and exact handle ownership."""

# Copyright 2026 sustainablelobster
# SPDX-License-Identifier: GPL-3.0-or-later
# Native boundary substitutions retain the actual image-management decisions.
# pylint: disable=protected-access

import ctypes
import sys
from contextlib import nullcontext
from types import ModuleType
from typing import Any
from unittest.mock import MagicMock, Mock

import pytest

from tests.unit.payload_support import HELPER, ROOT, load_module


@pytest.fixture(name="payload")
def disk_image_payload(monkeypatch: pytest.MonkeyPatch) -> ModuleType:
    """Load image management with a stateful native handle substitute.

    :param monkeypatch: Scoped imports and native image operations.
    :returns: Loaded payload with a recorded image object.
    """
    monkeypatch.syspath_prepend(str(HELPER.parent))
    monkeypatch.syspath_prepend(
        str(ROOT / "legacy_community_windows/plugins/module_utils")
    )
    module = load_module(
        ROOT / "legacy_community_windows/plugins/modules/win_disk_image.py",
        "tested_disk_image",
    )
    image = MagicMock()
    image.__enter__.return_value = image
    image.physical_path.return_value = None
    image.mount_paths.return_value = ["X:\\"]

    def _attach() -> None:
        image.physical_path.return_value = r"\\.\PhysicalDrive5"

    image.attach.side_effect = _attach
    image.detach.side_effect = lambda: setattr(
        image.physical_path, "return_value", None
    )
    monkeypatch.setattr(module, "DiskImage", Mock(return_value=image))
    monkeypatch.setattr(module.time, "sleep", Mock())
    return module


def test_attach_repeat_preview_detach_and_absent_repeat(payload: ModuleType) -> None:
    options = {"image_path": "fixture.vhd"}
    assert payload._manage({**options, "_ansible_check_mode": True}) == {
        "changed": True
    }
    image = payload.DiskImage.return_value
    image.attach.assert_not_called()
    assert payload._manage(options) == {"changed": True, "mount_paths": ["X:\\"]}
    assert payload._manage(options) == {"changed": False, "mount_paths": ["X:\\"]}
    assert payload._manage(
        {**options, "state": "absent", "_ansible_check_mode": True}
    ) == {"changed": True}
    image.detach.assert_not_called()
    assert payload._manage({**options, "state": "absent"}) == {"changed": True}
    assert payload._manage({**options, "state": "absent"}) == {"changed": False}
    image.attach.assert_called_once_with()
    image.detach.assert_called_once_with()


def test_attached_preview_reports_real_paths_without_writes(
    payload: ModuleType,
) -> None:
    image = payload.DiskImage.return_value
    image.physical_path.return_value = r"\\.\PhysicalDrive5"
    assert payload._manage(
        {"image_path": "fixture.vhd", "_ansible_check_mode": True}
    ) == {
        "changed": False,
        "mount_paths": ["X:\\"],
    }
    image.attach.assert_not_called()
    image.detach.assert_not_called()


def test_attach_without_drive_letter_retains_changed_failure(
    payload: ModuleType,
) -> None:
    payload.DiskImage.return_value.mount_paths.return_value = []
    result = payload._manage({"image_path": "fixture.vhd"})
    assert result["failed"] is True and result["changed"] is True
    assert "drive letter" in result["msg"]
    assert payload.time.sleep.call_count == 5


@pytest.mark.parametrize(
    "options",
    [
        {},
        {"image_path": ""},
        {"image_path": "fixture.vhd", "state": "unknown"},
        {"image_path": r"\\server\share\image.iso"},
        {"image_path": r"\\?\UNC\server\share\image.iso"},
    ],
)
def test_invalid_requests_fail_before_opening_native_image(
    payload: ModuleType, options: dict[str, object]
) -> None:
    with pytest.raises(ValueError):
        payload._manage(options)
    payload.DiskImage.assert_not_called()


def test_missing_provider_is_not_counted_as_success(payload: ModuleType) -> None:
    payload.DiskImage.return_value.__enter__.side_effect = OSError(
        "provider unavailable"
    )
    with pytest.raises(OSError, match="provider unavailable"):
        payload._manage({"image_path": "fixture.vhd"})


@pytest.mark.usefixtures("payload")
def test_drive_letter_mapping_uses_disk_number_and_device_type() -> None:
    native = sys.modules["legacy_community_windows_disk_image"]
    kernel = Mock()
    kernel.GetLogicalDrives.return_value = (1 << 2) | (1 << 23) | (1 << 24)
    kernel.CreateFileW.side_effect = [2, 23, 24]

    def _number(
        handle: int,
        _code: int,
        _input: object,
        _input_size: int,
        output: Any,
        _output_size: int,
        _used: object,
        _overlapped: object,
    ) -> int:
        record = ctypes.cast(output, ctypes.POINTER(native._DeviceNumber)).contents
        record.kind = 2 if handle == 24 else 7
        record.number = 5 if handle != 2 else 0
        return 1

    kernel.DeviceIoControl.side_effect = _number
    assert native._drive_paths(kernel, r"\\.\PhysicalDrive5") == ["X:\\"]
    assert kernel.CloseHandle.call_count == 3
    with pytest.raises(ValueError, match="Unrecognized attached device"):
        native._drive_paths(kernel, "not a device")


@pytest.mark.usefixtures("payload")
@pytest.mark.parametrize(
    "suffix,device,attach_access,flags",
    [
        ("vhd", 2, 0xE0000, 4),
        ("vhdx", 3, 0xE0000, 4),
        ("iso", 1, 0xD0000, 5),
    ],
)
def test_native_handle_modes_persistent_attach_and_cleanup(
    monkeypatch: pytest.MonkeyPatch,
    suffix: str,
    device: int,
    attach_access: int,
    flags: int,
) -> None:
    native = sys.modules["legacy_community_windows_disk_image"]
    disk, kernel = Mock(), Mock()
    access_modes = []

    def _open(
        storage: Any,
        _path: str,
        access: int,
        _flags: int,
        parameters: Any,
        output: Any,
    ) -> int:
        assert (
            ctypes.cast(storage, ctypes.POINTER(native._StorageType)).contents.device
            == device
        )
        assert (
            ctypes.cast(parameters, ctypes.POINTER(native._VersionOne)).contents.version
            == 1
        )
        access_modes.append(access)
        ctypes.cast(output, ctypes.POINTER(ctypes.c_void_p))[0] = 9
        return 0

    disk.OpenVirtualDisk.side_effect = _open
    disk.GetVirtualDiskPhysicalPath.return_value = 55
    disk.AttachVirtualDisk.return_value = 0
    disk.DetachVirtualDisk.return_value = 0
    monkeypatch.setattr(native, "_libraries", lambda: (disk, kernel))
    monkeypatch.setattr(native, "ownership_privileges", lambda _names: nullcontext())
    with native.DiskImage("fixture." + suffix) as image:
        assert image.physical_path() is None
        image.attach()
        image.detach()
    assert access_modes == [0xD0000, attach_access]
    assert disk.AttachVirtualDisk.call_args.args[2] == flags
    assert kernel.CloseHandle.call_count == 2
