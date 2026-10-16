"""Exercise storage fact values, filtering, native decoding and capability errors."""

# Copyright 2026 sustainablelobster
# SPDX-License-Identifier: GPL-3.0-or-later
# Only provider/device boundaries are substituted; facts and filters are real.
# pylint: disable=protected-access

import struct
import sys
from types import ModuleType
from typing import Any
from unittest.mock import MagicMock, Mock

import pytest

from tests.unit.payload_support import HELPER, ROOT, load_module

_DIRECTORY = ROOT / "legacy_community_windows/plugins/module_utils"


@pytest.fixture(name="payload")
def facts_payload(monkeypatch: pytest.MonkeyPatch) -> ModuleType:
    """Load native fact projection around separate modern and legacy providers.

    :param monkeypatch: Scoped imports and native provider substitutions.
    :returns: The real fact-collection helper.
    """
    monkeypatch.syspath_prepend(str(HELPER.parent))
    monkeypatch.syspath_prepend(str(_DIRECTORY))
    module = load_module(
        _DIRECTORY / "legacy_community_windows_disk_facts.py", "tested_disk_facts"
    )
    monkeypatch.setattr(module, "require_administrator", Mock())
    return module


def _connection(rows: dict[str, list[dict[str, Any]]]) -> MagicMock:
    connection = MagicMock()
    connection.__enter__.return_value = connection
    connection.missing_properties = set()

    def _query(query: str, _properties: Any) -> list[dict[str, Any]]:
        if query.startswith("ASSOCIATORS"):
            return rows.get("associations", [])
        return rows.get(query.split()[-1], [])

    connection.query.side_effect = _query
    return connection


def _modern(payload: ModuleType, monkeypatch: pytest.MonkeyPatch) -> MagicMock:
    connection = _connection(
        {
            "MSFT_Disk": [
                {
                    "Number": 7,
                    "Size": "67108864",
                    "BusType": 11,
                    "PartitionStyle": 1,
                    "OperationalStatus": [0xD010],
                }
            ],
            "MSFT_PhysicalDisk": [
                {
                    "DeviceId": "7",
                    "__PATH": "owned-physical",
                    "Size": "67108864",
                    "OperationalStatus": [2],
                    "HealthStatus": 0,
                    "BusType": 11,
                    "Usage": 1,
                    "SupportedUsages": [1, 2, 3, 4, 5],
                    "CannotPoolReason": [7],
                    "CanPool": False,
                }
            ],
            "MSFT_Partition": [
                {
                    "DiskNumber": 7,
                    "PartitionNumber": 1,
                    "Size": "65000000",
                    "Offset": "1048576",
                    "MbrType": 7,
                    "DriveLetter": 90,
                    "AccessPaths": ["Z:\\", "volume-guid"],
                }
            ],
            "MSFT_Volume": [
                {
                    "Path": "volume-guid",
                    "Size": "65000000",
                    "SizeRemaining": "64000000",
                    "FileSystem": "NTFS",
                    "FileSystemLabel": "Owned",
                    "HealthStatus": 0,
                    "DriveType": 3,
                    "AllocationUnitSize": 4096,
                }
            ],
        }
    )
    monkeypatch.setattr(payload, "FactsConnection", Mock(return_value=connection))
    return connection


def _virtio_descriptor() -> bytes:
    raw = bytearray(107)
    struct.pack_into("<II", raw, 0, 40, 108)
    struct.pack_into("<IIIII", raw, 12, 76, 85, 102, 0xFFFFFFFF, 1)
    raw[76:85] = b"Red Hat \0"
    raw[85:92] = b"VirtIO\0"
    raw[102:107] = b"0001\0"
    return bytes(raw)


def _native_disk(
    monkeypatch: pytest.MonkeyPatch, descriptor: bytes
) -> tuple[ModuleType, MagicMock]:
    native = sys.modules["legacy_community_windows_disk_facts_native"]
    disk = MagicMock()
    disk.__enter__.return_value = disk
    disk.read_layout.return_value = {
        "style": "mbr",
        "uniqueid": "12345678",
        "attributes": None,
    }
    layout = bytearray(48 + 144)
    struct.pack_into("<II", layout, 0, 0, 1)
    struct.pack_into("<I4xqqI", layout, 48, 0, 1048576, 65000000, 1)
    layout[80] = 7
    geometry = bytearray(32)
    struct.pack_into("<q", geometry, 24, 67108864)
    alignment = bytearray(28)
    struct.pack_into("<I", alignment, 20, 4096)
    disk._control.side_effect = [
        bytes(layout),
        bytes(geometry),
        descriptor,
        bytes(alignment),
    ]
    monkeypatch.setattr(native, "Disk", Mock(return_value=disk))
    return native, disk


def test_modern_facts_keep_released_names_native_values_and_nested_shapes(
    payload: ModuleType, monkeypatch: pytest.MonkeyPatch
) -> None:
    connection = _modern(payload, monkeypatch)
    result = payload.collect_facts({})
    disk = result["ansible_facts"]["ansible_disks"][0]
    assert result["changed"] is False
    assert disk["number"] == 7 and disk["size"] == 67108864
    assert disk["bus_type"] == "SATA" and disk["partition_style"] == "MBR"
    assert disk["operational_status"] == "Online"
    assert disk["physical_disk"]["health_status"] == "Healthy"
    assert disk["physical_disk"]["cannot_pool_reason"] == "Insufficient Capacity"
    assert disk["physical_disk"]["supported_usages"] == {
        "Count": 5,
        "value": ["Auto-Select", "Manual-Select", "Hot Spare", "Retired", "Journal"],
    }
    part = disk["partitions"][0]
    assert part["number"] == 1 and part["drive_letter"] == "Z" and part["type"] == "IFS"
    assert part["mbr_type"] == 7 and "gpt_type" not in part
    assert part["volumes"][0]["allocation_unit_size"] == 4096
    assert part["volumes"][0]["drive_type"] == "Fixed"
    partition_calls = [
        call
        for call in connection.query.call_args_list
        if call.args[0] == "SELECT * FROM MSFT_Partition"
    ]
    assert "Type" not in partition_calls[0].args[1]
    connection.call_method.assert_not_called()


def test_volumes_filter_includes_partitions_without_unrequested_groups(
    payload: ModuleType, monkeypatch: pytest.MonkeyPatch
) -> None:
    _modern(payload, monkeypatch)
    disk = payload.collect_facts({"filter": ["volumes"]})["ansible_facts"][
        "ansible_disks"
    ][0]
    assert disk["partitions"][0]["volumes"][0]["label"] == "Owned"
    assert "physical_disk" not in disk and "win32_disk_drive" not in disk


@pytest.mark.parametrize(
    "access,label",
    [
        (0, "Unknown"),
        (1, "Readable"),
        (2, "Writeable"),
        (3, "Read/Write"),
        (4, "Write Once"),
    ],
)
def test_virtual_disk_access_uses_native_class_values(
    payload: ModuleType, access: int, label: str
) -> None:
    assert (
        payload._storage_group({"Access": access}, payload._VIRTUAL_FIELDS)["access"]
        == label
    )


def test_empty_filter_returns_base_disks_only_and_sorts_numbers(
    payload: ModuleType, monkeypatch: pytest.MonkeyPatch
) -> None:
    connection = _modern(payload, monkeypatch)
    original = connection.query.side_effect

    def _query(query: str, fields: Any) -> list[dict[str, Any]]:
        rows: list[dict[str, Any]] = original(query, fields)
        return (
            rows + [{"Number": 2, "Size": "500"}]
            if "MSFT_Disk" == query.split()[-1]
            else rows
        )

    connection.query.side_effect = _query
    result = payload.collect_facts({"filter": [], "_ansible_check_mode": True})
    assert [disk["number"] for disk in result["ansible_facts"]["ansible_disks"]] == [
        2,
        7,
    ]
    assert all(
        "partitions" not in disk and "physical_disk" not in disk
        for disk in result["ansible_facts"]["ansible_disks"]
    )


def test_null_filter_uses_the_documented_default(
    payload: ModuleType, monkeypatch: pytest.MonkeyPatch
) -> None:
    _modern(payload, monkeypatch)
    assert payload.collect_facts({"filter": None}) == payload.collect_facts({})


def test_invalid_filter_fails_before_contacting_a_provider(
    payload: ModuleType, monkeypatch: pytest.MonkeyPatch
) -> None:
    factory = Mock()
    monkeypatch.setattr(payload, "FactsConnection", factory)
    with pytest.raises(ValueError, match="filter must"):
        payload.collect_facts({"filter": ["bogus"]})
    factory.assert_not_called()


def test_administrator_requirement_is_checked_before_reading_disks(
    payload: ModuleType, monkeypatch: pytest.MonkeyPatch
) -> None:
    payload.require_administrator.side_effect = PermissionError("elevated rights")
    factory = Mock()
    monkeypatch.setattr(payload, "FactsConnection", factory)
    with pytest.raises(PermissionError):
        payload.collect_facts({})
    factory.assert_not_called()


@pytest.mark.parametrize(
    "status,fall_back", [(0x8004100E, True), (0x80041010, True), (0x80041003, False)]
)
def test_legacy_provider_fallback_is_capability_based_not_access_denial(
    payload: ModuleType, monkeypatch: pytest.MonkeyPatch, status: int, fall_back: bool
) -> None:
    error = OSError("native provider")
    setattr(error, "hresult", status)
    modern, legacy = _connection({}), _connection({})
    modern.__enter__.side_effect = error
    factory = Mock(side_effect=[modern, legacy])
    monkeypatch.setattr(payload, "FactsConnection", factory)
    if fall_back:
        result = payload.collect_facts({})
        assert result["ansible_facts"]["ansible_disks"] == [] and result["warnings"]
        assert factory.call_count == 2
    else:
        with pytest.raises(OSError):
            payload.collect_facts({})
        assert factory.call_count == 1


def test_legacy_facts_return_real_layout_volume_guid_cluster_size_and_nulls(
    payload: ModuleType, monkeypatch: pytest.MonkeyPatch
) -> None:
    error = OSError("missing namespace")
    setattr(error, "hresult", 0x8004100E)
    modern = _connection({})
    modern.__enter__.side_effect = error
    legacy = _connection(
        {
            "Win32_DiskDrive": [
                {
                    "Index": 7,
                    "DeviceID": "owned-device",
                    "Size": "67108864",
                    "Model": "Native disk",
                    "Manufacturer": "Native",
                    "FirmwareRevision": "1",
                    "SerialNumber": None,
                    "BytesPerSector": 512,
                }
            ],
            "Win32_DiskPartition": [
                {
                    "__PATH": "owned-partition",
                    "DiskIndex": 7,
                    "StartingOffset": "1048576",
                }
            ],
            "associations": [
                {
                    "Size": "65000000",
                    "FreeSpace": "64000000",
                    "FileSystem": "NTFS",
                    "VolumeName": "Owned",
                    "DriveType": 3,
                    "DeviceID": "Z:",
                }
            ],
        }
    )
    monkeypatch.setattr(payload, "FactsConnection", Mock(side_effect=[modern, legacy]))
    monkeypatch.setattr(
        payload,
        "describe_disk",
        Mock(
            return_value={
                "layout": {"style": "mbr", "uniqueid": "12345678", "attributes": 0},
                "device": {"bus_type": 11, "serial_number": "native-serial"},
                "sector_size": 4096,
                "partitions": [
                    {
                        "number": 1,
                        "offset": 1048576,
                        "size": 65000000,
                        "mbr_type": 7,
                        "active": False,
                    }
                ],
            }
        ),
    )
    monkeypatch.setattr(
        payload,
        "volume_details",
        Mock(return_value={"path": "actual-volume-guid", "allocation_unit_size": 4096}),
    )
    result = payload.collect_facts({})
    disk = result["ansible_facts"]["ansible_disks"][0]
    assert disk["serial_number"] == "native-serial" and disk["unique_id"] == "12345678"
    assert (
        disk["bootable"] is None
        and disk["system_disk"] is None
        and disk["clustered"] is None
    )
    assert disk["partition_count"] == 1 and disk["sector_size"] == 4096
    part = disk["partitions"][0]
    assert part["access_paths"] == ["Z:\\", "actual-volume-guid"]
    assert part["volumes"][0]["allocation_unit_size"] == 4096
    assert "_drive_path" not in part["volumes"][0]
    assert result["warnings"] and result["changed"] is False
    legacy.call_method.assert_not_called()


@pytest.mark.usefixtures("payload")
def test_native_partition_records_keep_native_numbers_not_wmi_indexes() -> None:
    native = sys.modules["legacy_community_windows_disk_facts_native"]
    raw = bytearray(48 + 2 * 144)
    struct.pack_into("<II", raw, 0, 0, 2)
    struct.pack_into("<I4xqqI", raw, 48, 0, 1048576, 67108864, 3)
    raw[48 + 32] = 7
    raw[48 + 33] = 1
    assert native._partition_entries(bytes(raw)) == [
        {
            "number": 3,
            "offset": 1048576,
            "size": 67108864,
            "mbr_type": 7,
            "active": True,
        }
    ]
    assert native._partition_entries(struct.pack("<III", 0, 0, 0)) == []
    with pytest.raises(ValueError, match="truncated"):
        native._partition_entries(struct.pack("<II", 0, 2))


@pytest.mark.usefixtures("payload")
@pytest.mark.parametrize("qemu", [False, True])
def test_observed_legacy_descriptors_keep_valid_fields_without_a_serial(
    qemu: bool,
) -> None:
    native = sys.modules["legacy_community_windows_disk_facts_native"]
    raw = bytearray(_virtio_descriptor())
    if qemu:
        struct.pack_into("<I", raw, 4, 107)
        raw[76:85] = b"QEMU    \0"
        raw[85:102] = b"QEMU HARDDISK   \0"
        raw[102:107] = b"2.5+\0"
    warnings: list[str] = []
    assert native._device_descriptor(bytes(raw), "owned-disk", warnings) == {
        "bus_type": 1,
        "manufacturer": "QEMU" if qemu else "Red Hat",
        "model": "QEMU HARDDISK" if qemu else "VirtIO",
        "firmware_version": "2.5+" if qemu else "0001",
        "serial_number": None,
    }
    assert len(warnings) == 1
    assert all(
        value in warnings[0] for value in ("owned-disk", "serial_number", "4294967295")
    )


@pytest.mark.usefixtures("payload")
def test_valid_serial_string_is_retained_without_warnings() -> None:
    native = sys.modules["legacy_community_windows_disk_facts_native"]
    raw = bytearray(_virtio_descriptor())
    struct.pack_into("<I", raw, 24, 92)
    raw[92:99] = b"serial\0"
    warnings: list[str] = []
    device = native._device_descriptor(bytes(raw), "owned-disk", warnings)
    assert device["serial_number"] == "serial"
    assert not warnings


@pytest.mark.usefixtures("payload")
@pytest.mark.parametrize("offset", [1, 12, 35, 107, 108, 0xFFFFFFFF])
def test_optional_offset_must_be_in_string_data_not_the_header(offset: int) -> None:
    native = sys.modules["legacy_community_windows_disk_facts_native"]
    raw = bytearray(_virtio_descriptor())
    struct.pack_into("<II", raw, 20, offset, 0)
    warnings: list[str] = []
    device = native._device_descriptor(bytes(raw), "owned-disk", warnings)
    assert device["manufacturer"] == "Red Hat" and device["model"] == "VirtIO"
    assert device["firmware_version"] is None and device["serial_number"] is None
    assert len(warnings) == 1 and "firmware_version" in warnings[0]


@pytest.mark.usefixtures("payload")
def test_string_terminator_cannot_come_from_outside_declared_size() -> None:
    native = sys.modules["legacy_community_windows_disk_facts_native"]
    raw = bytearray(_virtio_descriptor())
    struct.pack_into("<I", raw, 4, 106)
    struct.pack_into("<I", raw, 24, 0)
    warnings: list[str] = []
    device = native._device_descriptor(bytes(raw), "owned-disk", warnings)
    assert device["manufacturer"] == "Red Hat" and device["model"] == "VirtIO"
    assert device["firmware_version"] is None
    assert len(warnings) == 1 and "unterminated string" in warnings[0]


@pytest.mark.usefixtures("payload")
def test_string_terminator_cannot_come_from_unreturned_padding() -> None:
    native = sys.modules["legacy_community_windows_disk_facts_native"]
    warnings: list[str] = []
    device = native._device_descriptor(
        _virtio_descriptor()[:-1], "owned-disk", warnings
    )
    assert device["manufacturer"] == "Red Hat" and device["model"] == "VirtIO"
    assert device["firmware_version"] is None
    assert len(warnings) == 2
    assert any(
        "firmware_version" in warning and "unterminated" in warning
        for warning in warnings
    )


@pytest.mark.usefixtures("payload")
def test_offset_cannot_address_bytes_beyond_declared_size() -> None:
    native = sys.modules["legacy_community_windows_disk_facts_native"]
    raw = bytearray(_virtio_descriptor())
    struct.pack_into("<I", raw, 4, 85)
    struct.pack_into("<I", raw, 24, 0)
    warnings: list[str] = []
    device = native._device_descriptor(bytes(raw), "owned-disk", warnings)
    assert device["manufacturer"] == "Red Hat"
    assert device["model"] is None and device["firmware_version"] is None
    assert len(warnings) == 2


@pytest.mark.usefixtures("payload")
def test_absent_optional_strings_are_null_without_malformed_data_warnings() -> None:
    native = sys.modules["legacy_community_windows_disk_facts_native"]
    raw = bytearray(36)
    struct.pack_into("<II", raw, 0, 40, len(raw))
    warnings: list[str] = []
    device = native._device_descriptor(bytes(raw), "owned-disk", warnings)
    assert device == {
        "bus_type": 0,
        "manufacturer": None,
        "model": None,
        "firmware_version": None,
        "serial_number": None,
    }
    assert not warnings


@pytest.mark.usefixtures("payload")
@pytest.mark.parametrize("length", [0, 8, 35])
def test_truncated_fixed_descriptor_header_remains_fatal(length: int) -> None:
    native = sys.modules["legacy_community_windows_disk_facts_native"]
    with pytest.raises(ValueError, match="truncated storage descriptor"):
        native._device_descriptor(bytes(length), "owned-disk", [])


@pytest.mark.usefixtures("payload")
@pytest.mark.parametrize("size", [0, 8, 35])
def test_invalid_declared_fixed_descriptor_size_remains_fatal(size: int) -> None:
    native = sys.modules["legacy_community_windows_disk_facts_native"]
    raw = bytearray(_virtio_descriptor())
    struct.pack_into("<I", raw, 4, size)
    with pytest.raises(ValueError, match="invalid storage descriptor size"):
        native._device_descriptor(bytes(raw), "owned-disk", [])


@pytest.mark.parametrize(
    "filters",
    [
        None,
        [],
        ["physical_disk"],
        ["virtual_disk"],
        ["win32_disk_drive"],
        ["partitions"],
        ["volumes"],
    ],
)
@pytest.mark.parametrize("fallback_serial", [None, "", " \t", "wmi-serial"])
def test_legacy_facts_use_real_descriptor_decoder_under_every_filter(
    payload: ModuleType,
    monkeypatch: pytest.MonkeyPatch,
    filters: list[str] | None,
    fallback_serial: str | None,
) -> None:
    native, disk_handle = _native_disk(monkeypatch, _virtio_descriptor())
    monkeypatch.setattr(payload, "describe_disk", native.describe_disk)
    missing = OSError("missing namespace")
    setattr(missing, "hresult", 0x8004100E)
    modern = _connection({})
    modern.__enter__.side_effect = missing
    legacy = _connection(
        {
            "Win32_DiskDrive": [
                {
                    "Index": 0,
                    "DeviceID": "owned-disk",
                    "Size": "67108864",
                    "Model": "WMI model",
                    "Manufacturer": "WMI manufacturer",
                    "FirmwareRevision": "WMI revision",
                    "SerialNumber": fallback_serial,
                    "BytesPerSector": 512,
                }
            ]
        }
    )
    monkeypatch.setattr(payload, "FactsConnection", Mock(side_effect=[modern, legacy]))
    arguments = {} if filters is None else {"filter": filters}
    result = payload.collect_facts(arguments)
    assert result["changed"] is False
    fact = result["ansible_facts"]["ansible_disks"][0]
    assert fact["number"] == 0 and fact["size"] == 67108864
    assert fact["partition_style"] == "MBR" and fact["partition_count"] == 1
    assert fact["manufacturer"] == "Red Hat" and fact["model"] == "VirtIO"
    assert fact["firmware_version"] == "0001"
    assert fact["serial_number"] == (
        fallback_serial if fallback_serial and fallback_serial.strip() else None
    )
    assert fact["sector_size"] == 4096
    assert any(
        "owned-disk" in warning and "serial_number" in warning
        for warning in result["warnings"]
    )
    selected = payload._DEFAULT_FILTERS if filters is None else filters
    assert ("physical_disk" in fact) == ("physical_disk" in selected)
    assert ("win32_disk_drive" in fact) == ("win32_disk_drive" in selected)
    assert ("partitions" in fact) == bool(
        set(selected).intersection(("partitions", "volumes"))
    )
    disk_handle.__exit__.assert_called_once()


@pytest.mark.parametrize(
    "field",
    [
        ("manufacturer", "Manufacturer", 12),
        ("model", "Model", 16),
        ("firmware_version", "FirmwareRevision", 20),
        ("serial_number", "SerialNumber", 24),
    ],
)
@pytest.mark.parametrize("fallback", [None, "", " \t", "WMI field value"])
def test_each_unavailable_native_string_uses_real_wmi_value_or_null(
    payload: ModuleType,
    monkeypatch: pytest.MonkeyPatch,
    field: tuple[str, str, int],
    fallback: str | None,
) -> None:
    name, property_name, position = field
    descriptor = bytearray(_virtio_descriptor())
    struct.pack_into("<I", descriptor, position, 0xFFFFFFFF)
    native, _disk = _native_disk(monkeypatch, bytes(descriptor))
    monkeypatch.setattr(payload, "describe_disk", native.describe_disk)
    connection = _connection(
        {
            "Win32_DiskDrive": [
                {
                    "Index": 0,
                    "DeviceID": "owned-disk",
                    "Size": "67108864",
                    "Manufacturer": None,
                    "Model": None,
                    "FirmwareRevision": None,
                    "SerialNumber": None,
                    "BytesPerSector": 512,
                    property_name: fallback,
                }
            ]
        }
    )
    warnings: list[str] = []
    disk = payload._legacy_disks(connection, [], warnings)[0]
    assert disk[name] == (fallback if fallback and fallback.strip() else None)
    assert any(name in warning and "owned-disk" in warning for warning in warnings)


@pytest.mark.usefixtures("payload")
@pytest.mark.parametrize("status", [5, 87])
@pytest.mark.parametrize("stage", [0, 1, 2])
def test_required_device_access_errors_remain_fatal(
    monkeypatch: pytest.MonkeyPatch, status: int, stage: int
) -> None:
    native, disk = _native_disk(monkeypatch, _virtio_descriptor())
    error = OSError("device access failed")
    setattr(error, "winerror", status)
    responses = list(disk._control.side_effect)
    responses[stage] = error
    disk._control.side_effect = responses
    with pytest.raises(OSError, match="device access failed"):
        native.describe_disk("owned-disk")
    disk.__exit__.assert_called_once()


@pytest.mark.parametrize("status", [1, 50, 87])
def test_unsupported_alignment_keeps_metadata_and_uses_logical_sector_size(
    payload: ModuleType, monkeypatch: pytest.MonkeyPatch, status: int
) -> None:
    native, disk = _native_disk(monkeypatch, _virtio_descriptor())
    error = OSError("alignment property unavailable")
    setattr(error, "winerror", status)
    responses = list(disk._control.side_effect)
    responses[3] = error
    disk._control.side_effect = responses
    monkeypatch.setattr(payload, "describe_disk", native.describe_disk)
    row = {
        "Index": 0,
        "DeviceID": "owned-disk",
        "Size": "67108864",
        "Manufacturer": None,
        "Model": "WMI model",
        "FirmwareRevision": None,
        "SerialNumber": None,
        "BytesPerSector": 512,
    }
    warnings: list[str] = []
    facts = payload._legacy_disks(_connection({"Win32_DiskDrive": [row]}), [], warnings)
    assert facts[0]["sector_size"] == 512
    assert facts[0]["model"] == "VirtIO" and facts[0]["partition_count"] == 1
    assert any(
        "alignment" in warning and "owned-disk" in warning for warning in warnings
    )


@pytest.mark.usefixtures("payload")
def test_alignment_access_denial_is_not_an_unsupported_property(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    native, disk = _native_disk(monkeypatch, _virtio_descriptor())
    error = OSError("alignment access denied")
    setattr(error, "winerror", 5)
    responses = list(disk._control.side_effect)
    responses[3] = error
    disk._control.side_effect = responses
    with pytest.raises(OSError, match="alignment access denied"):
        native.describe_disk("owned-disk")


@pytest.mark.usefixtures("payload")
def test_partition_consumer_reads_real_layout_despite_optional_descriptor_warning(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    native, _disk = _native_disk(monkeypatch, _virtio_descriptor())
    legacy = __import__("legacy_community_windows_partition_legacy")
    monkeypatch.setattr(legacy, "describe_disk", native.describe_disk)
    monkeypatch.setattr(legacy, "_volumes", Mock(return_value=[]))
    monkeypatch.setattr(legacy, "_volume_state", Mock(return_value={}))
    provider = legacy.LegacyPartitions()
    provider._disks = Mock(return_value=[{"Index": 0, "DeviceID": "owned-disk"}])
    part = provider.partitions()[0]
    assert part["disk_number"] == 0 and part["number"] == 1
    assert part["offset"] == 1048576 and part["size"] == 65000000
