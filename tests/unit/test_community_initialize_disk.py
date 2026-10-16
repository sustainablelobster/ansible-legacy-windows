"""Exercise selected-disk initialization and its published native control ABI."""

# Copyright 2026 sustainablelobster
# SPDX-License-Identifier: GPL-3.0-or-later
# Native device operations are substituted; public decisions remain real.
# pylint: disable=protected-access

import ctypes
import json
import struct
import sys
from contextlib import nullcontext
from pathlib import Path
from types import ModuleType
from typing import Any
from unittest.mock import MagicMock, Mock

import pytest

from tests.unit.payload_support import HELPER, ROOT, load_module


@pytest.fixture(name="payload")
def initialize_payload(monkeypatch: pytest.MonkeyPatch) -> ModuleType:
    """Load real disk decisions around a stateful native device substitute.

    :param monkeypatch: Scoped target helpers and selected native disk.
    :returns: Loaded target payload.
    """
    monkeypatch.syspath_prepend(str(HELPER.parent))
    monkeypatch.syspath_prepend(
        str(ROOT / "legacy_community_windows/plugins/module_utils")
    )
    module = load_module(
        ROOT / "legacy_community_windows/plugins/modules/win_initialize_disk.py",
        "tested_initialize_disk",
    )
    device = MagicMock()
    device.__enter__.return_value = device
    state = {"style": "raw", "partition_count": 0, "uniqueid": None, "attributes": 0}
    device.read_layout.side_effect = state.copy
    device.bring_online.side_effect = lambda: state.update(attributes=0)
    device.clear.side_effect = lambda: state.update(
        style="raw", partition_count=0, uniqueid=None
    )
    device.initialize.side_effect = lambda style: state.update(
        style=style, uniqueid="new-owned-id"
    )
    monkeypatch.setattr(module, "Disk", Mock(return_value=device))
    monkeypatch.setattr(module, "select_disk", Mock(return_value=r"\\.\PhysicalDrive7"))
    return module


def test_raw_preview_initialize_repeat_and_forced_style_change(
    payload: ModuleType,
) -> None:
    options = {"disk_number": 7, "style": "gpt"}
    device = payload.Disk.return_value
    assert payload._manage({**options, "_ansible_check_mode": True}) == {
        "changed": True
    }
    device.initialize.assert_not_called()
    assert all(not call.kwargs.get("writable") for call in payload.Disk.call_args_list)
    assert payload._manage(options) == {"changed": True}
    assert payload._manage(options) == {"changed": False}
    device.initialize.assert_called_once_with("gpt")
    device.clear.assert_not_called()
    assert payload._manage({**options, "style": "mbr", "force": True}) == {
        "changed": True
    }
    device.clear.assert_called_once_with()
    assert device.read_layout()["style"] == "mbr"


def test_different_existing_style_requires_force_before_any_write(
    payload: ModuleType,
) -> None:
    device = payload.Disk.return_value
    device.read_layout.side_effect = None
    device.read_layout.return_value = {"style": "mbr", "attributes": 0}
    with pytest.raises(ValueError, match="force must be true"):
        payload._manage({"disk_number": 7, "style": "gpt"})
    device.clear.assert_not_called()
    device.initialize.assert_not_called()


def test_bringing_initialized_disk_online_preserves_existing_partitions(
    payload: ModuleType,
) -> None:
    device = payload.Disk.return_value
    device.read_layout.side_effect = None
    device.read_layout.return_value = {"style": "gpt", "attributes": 3}
    assert payload._manage({"disk_number": 7}) == {"changed": True}
    device.bring_online.assert_called_once_with()
    device.clear.assert_not_called()
    device.initialize.assert_not_called()


def test_force_with_online_disabled_clears_but_does_not_reinitialize(
    payload: ModuleType,
) -> None:
    payload._manage({"disk_number": 7})
    device = payload.Disk.return_value
    device.initialize.reset_mock()
    assert payload._manage({"disk_number": 7, "force": True, "online": False}) == {
        "changed": True
    }
    device.clear.assert_called_once_with()
    device.initialize.assert_not_called()
    assert device.read_layout()["style"] == "raw"


def test_readonly_disk_with_online_disabled_fails_without_modifying_it(
    payload: ModuleType,
) -> None:
    device = payload.Disk.return_value
    device.read_layout.side_effect = None
    device.read_layout.return_value = {"style": "raw", "attributes": 2}
    with pytest.raises(ValueError, match="read-only"):
        payload._manage({"disk_number": 7, "online": False})
    device.bring_online.assert_not_called()
    device.initialize.assert_not_called()


@pytest.mark.parametrize("style", ["mbr", "gpt"])
@pytest.mark.parametrize("preview", [False, True])
def test_matching_initialized_readonly_disk_is_unchanged_when_online_is_disabled(
    payload: ModuleType, style: str, preview: bool
) -> None:
    device = payload.Disk.return_value
    device.read_layout.side_effect = None
    device.read_layout.return_value = {"style": style, "attributes": 2}
    assert payload._manage(
        {
            "disk_number": 7,
            "style": style,
            "online": False,
            "_ansible_check_mode": preview,
        }
    ) == {"changed": False}
    device.bring_online.assert_not_called()
    device.clear.assert_not_called()
    device.initialize.assert_not_called()
    assert all(not call.kwargs.get("writable") for call in payload.Disk.call_args_list)


@pytest.mark.parametrize("value", [1.9, -0.1, 1.0, True, False, "1.9", 2**31])
def test_invalid_numeric_selector_cannot_resolve_or_clear_a_different_disk(
    payload: ModuleType, value: object
) -> None:
    with pytest.raises(ValueError, match="nonnegative integer"):
        payload._manage({"disk_number": value, "force": True})
    payload.select_disk.assert_not_called()
    payload.Disk.assert_not_called()


def test_unknown_option_is_rejected_before_disk_access(
    payload: ModuleType, monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    arguments = {"disk_number": 7, "onine": False}
    filename = tmp_path / "arguments.json"
    filename.write_text(json.dumps(arguments), encoding="utf-8")
    monkeypatch.setattr(sys, "argv", ["payload.py", str(filename)])
    monkeypatch.setattr(payload, "run_module", lambda handler: handler())
    with pytest.raises(ValueError, match="onine"):
        payload.main()
    payload.select_disk.assert_not_called()
    payload.Disk.assert_not_called()


@pytest.mark.parametrize(
    "options",
    [
        {},
        {"disk_number": 7, "path": "other"},
        {"disk_number": -1},
        {"disk_number": "bad"},
        {"uniqueid": ""},
        {"path": ""},
        {"disk_number": 7, "style": "invalid"},
    ],
)
def test_invalid_request_does_not_open_a_disk(
    payload: ModuleType, options: dict[str, object]
) -> None:
    with pytest.raises(ValueError):
        payload._manage(options)
    payload.select_disk.assert_not_called()
    payload.Disk.assert_not_called()


@pytest.mark.usefixtures("payload")
@pytest.mark.parametrize("style,code", [("mbr", 0), ("gpt", 1)])
def test_native_initialize_uses_create_disk_not_a_command_or_existing_layout(
    monkeypatch: pytest.MonkeyPatch, style: str, code: int
) -> None:
    native = sys.modules["legacy_community_windows_disk"]
    device = native.Disk("owned")
    monkeypatch.setattr(device, "read_layout", Mock(return_value={"style": "raw"}))
    calls = Mock()
    monkeypatch.setattr(device, "_control", calls)
    privileges = Mock(return_value=nullcontext())
    monkeypatch.setattr(native, "ownership_privileges", privileges)
    monkeypatch.setattr(native.os, "urandom", bytes)
    device.initialize(style)
    args = calls.call_args_list[0].args
    assert args[0] == 0x7C058
    assert ctypes.sizeof(args[1]) == 24 and args[1].style == code
    raw = bytes(args[1].parameters)
    assert any(raw[:4] if style == "mbr" else raw[:16])
    if style == "gpt":
        assert struct.unpack_from("<I", raw, 16)[0] == 128
    assert calls.call_args_list[1].args == (0x70140,)
    privileges.assert_called_once_with(("SeManageVolumePrivilege",))


@pytest.mark.usefixtures("payload")
def test_native_refuses_to_reinitialize_nonraw_disk(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    native = sys.modules["legacy_community_windows_disk"]
    device = native.Disk("owned")
    monkeypatch.setattr(device, "read_layout", Mock(return_value={"style": "mbr"}))
    control = Mock()
    monkeypatch.setattr(device, "_control", control)
    with pytest.raises(ValueError, match="non-raw"):
        device.initialize("gpt")
    control.assert_not_called()


@pytest.mark.usefixtures("payload")
def test_legacy_empty_mbr_record_without_signature_is_a_raw_disk(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    native = sys.modules["legacy_community_windows_disk"]
    device = native.Disk("owned")
    monkeypatch.setattr(
        device, "_control", Mock(side_effect=[struct.pack("<III", 0, 0, 0), bytes(16)])
    )
    assert device.read_layout() == {
        "style": "raw",
        "partition_count": 0,
        "uniqueid": None,
        "attributes": 0,
    }


@pytest.mark.usefixtures("payload")
def test_native_online_attributes_use_published_structure_and_mask(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    native = sys.modules["legacy_community_windows_disk"]
    device = native.Disk("owned")
    control = Mock()
    monkeypatch.setattr(device, "_control", control)
    monkeypatch.setattr(native, "ownership_privileges", lambda _names: nullcontext())
    device.bring_online()
    code, record = control.call_args_list[0].args
    assert code == 0x7C0F4
    assert ctypes.sizeof(record) == record.version == 40
    assert record.persist == 1 and record.attributes == 0 and record.mask == 3
    assert bytes(record.reserved) == bytes(3)
    assert list(record.reserved2) == [0, 0, 0, 0]
    assert control.call_args_list[1].args == (0x70140,)


@pytest.mark.usefixtures("payload")
@pytest.mark.parametrize("status,unavailable", [(1, True), (50, True), (5, False)])
def test_missing_legacy_attributes_are_null_but_access_denial_is_not_hidden(
    monkeypatch: pytest.MonkeyPatch, status: int, unavailable: bool
) -> None:
    native = sys.modules["legacy_community_windows_disk"]
    device = native.Disk("owned")
    error = OSError("native attribute query")
    setattr(error, "winerror", status)
    monkeypatch.setattr(
        device, "_control", Mock(side_effect=[struct.pack("<III", 0, 4, 0x1234), error])
    )
    if unavailable:
        assert device.read_layout() == {
            "style": "mbr",
            "partition_count": 4,
            "uniqueid": "00001234",
            "attributes": None,
        }
    else:
        with pytest.raises(OSError):
            device.read_layout()


@pytest.mark.usefixtures("payload")
@pytest.mark.parametrize(
    "selector",
    [{"disk_number": 7}, {"path": "native-interface"}, {"uniqueid": "REAL-STORAGE-ID"}],
)
def test_modern_native_selector_keeps_storage_provider_identity(
    monkeypatch: pytest.MonkeyPatch, selector: dict[str, Any]
) -> None:
    native = sys.modules["legacy_community_windows_disk"]
    connection = MagicMock()
    connection.__enter__.return_value = connection
    connection.query.return_value = [
        {"Number": 7, "UniqueId": "real-storage-id", "Path": "native-interface"}
    ]
    monkeypatch.setattr(native, "WmiConnection", Mock(return_value=connection))
    assert native.select_disk(selector) == r"\\.\PhysicalDrive7"
