"""Exercise legacy setup metadata without substituting modern Windows layouts."""

# SPDX-License-Identifier: GPL-3.0-or-later
# The fault tests inspect the concrete private Windows ABI boundaries.
# pylint: disable=protected-access

import ctypes
import importlib
import struct
import sys
from pathlib import Path
from types import ModuleType, SimpleNamespace
from typing import Any
from unittest.mock import Mock

import pytest


@pytest.fixture(name="native")
def native_helper(monkeypatch: pytest.MonkeyPatch) -> ModuleType:
    """Load setup's native helpers from the maintained source tree.

    :param monkeypatch: Scoped import path and module isolation.
    :returns: Native collector module.
    """
    monkeypatch.syspath_prepend(
        str(Path(__file__).resolve().parents[2] / "plugins/module_utils")
    )
    for name in (
        "legacy_windows_setup_native",
        "legacy_windows_setup_network",
        "legacy_windows_setup_date",
    ):
        monkeypatch.delitem(sys.modules, name, raising=False)
    return importlib.import_module("legacy_windows_setup_native")


def test_legacy_prefixes_match_networks_not_linked_list_positions(
    native: ModuleType, monkeypatch: pytest.MonkeyPatch
) -> None:
    network = native.network
    entries = (network._Prefix * 3)()
    for index, prefix in enumerate((64, 25, 24)):
        entries[index].prefix_length = prefix
        entries[index].address.pointer = index + 1
        if index < 2:
            entries[index].next = ctypes.addressof(entries[index + 1])
    values = {1: (23, "fe80::%7"), 2: (2, "192.0.2.128"), 3: (2, "192.0.2.0")}
    monkeypatch.setattr(
        network, "_socket_text", lambda address: values[address.pointer]
    )
    addresses = [
        (2, "192.0.2.129", None),
        (23, "fe80::1%7", None),
        (2, "192.0.2.1", None),
        (2, "198.51.100.1", None),
    ]
    assert network._legacy_prefixes(ctypes.addressof(entries), addresses) == [
        (2, "192.0.2.129", "25"),
        (23, "fe80::1%7", "64"),
        (2, "192.0.2.1", "24"),
        (2, "198.51.100.1", None),
    ]


def test_legacy_gateways_retry_size_and_preserve_null_gateway(
    native: ModuleType,
) -> None:
    network = native.network
    entries = (network._LegacyAdapter * 2)()
    entries[0].next = ctypes.addressof(entries[1])
    entries[0].index, entries[1].index = 7, 8
    entries[0].gateways.address = b"192.0.2.254"
    entries[1].gateways.address = b"0.0.0.0"

    def _read(buffer: Any, size: Any) -> int:
        ctypes.cast(size, ctypes.POINTER(ctypes.c_uint32)).contents.value = 32768
        if read.call_count == 1:
            return 111
        ctypes.memmove(buffer, entries, ctypes.sizeof(entries))
        return 0

    read = Mock(side_effect=_read)
    assert network._legacy_gateways(SimpleNamespace(GetAdaptersInfo=read)) == {
        7: "192.0.2.254",
        8: None,
    }
    assert read.call_count == 2


def test_legacy_adapter_does_not_treat_padding_as_vista_prefix(
    native: ModuleType, monkeypatch: pytest.MonkeyPatch
) -> None:
    network = native.network
    adapter = network._Adapter(length=network._Adapter.transmit_speed.offset, index=7)

    def _read(
        _family: int, _flags: int, _reserved: object, buffer: Any, _size: object
    ) -> int:
        ctypes.memmove(buffer, ctypes.byref(adapter), ctypes.sizeof(adapter))
        return 0

    monkeypatch.setattr(
        network.ctypes,
        "WinDLL",
        Mock(
            return_value=SimpleNamespace(GetAdaptersAddresses=Mock(side_effect=_read))
        ),
        raising=False,
    )
    monkeypatch.setattr(
        network.sys,
        "getwindowsversion",
        lambda: SimpleNamespace(major=5),
        raising=False,
    )
    monkeypatch.setattr(network, "_unicast", lambda _pointer: [(2, "192.0.2.1", "67")])
    prefixes = Mock(return_value=[(2, "192.0.2.1", "24")])
    monkeypatch.setattr(network, "_legacy_prefixes", prefixes)
    assert network._adapters()[0]["addresses"] == [(2, "192.0.2.1", "24")]
    prefixes.assert_called_once_with(None, [(2, "192.0.2.1", None)])


@pytest.mark.parametrize("speed, expected", [(1000000000, 1000), (1234567, 1.234567)])
def test_legacy_speed_uses_fixed_width_mib_row_and_requested_index(
    native: ModuleType, speed: int, expected: int | float
) -> None:
    network = native.network

    def _read(pointer: Any) -> int:
        row = ctypes.cast(pointer, ctypes.POINTER(network._InterfaceRow)).contents
        assert row.index == 7
        row.speed = speed
        return 0

    assert ctypes.sizeof(network._InterfaceRow) == 860
    assert network._InterfaceRow.speed.offset == 524
    assert (
        network._legacy_speed(SimpleNamespace(GetIfEntry=Mock(side_effect=_read)), 7)
        == expected
    )


def test_legacy_interface_projection_keeps_order_and_available_fields(
    native: ModuleType, monkeypatch: pytest.MonkeyPatch
) -> None:
    network = native.network
    adapters = [
        {"kind": 24, "modern": False, "interface_index": 1},
        {
            "kind": 6,
            "modern": False,
            "interface_index": 7,
            "addresses": [(2, "192.0.2.1", "24")],
            "connection_name": "Legacy 雪",
            "speed": None,
            "default_gateway": None,
        },
    ]
    monkeypatch.setattr(network, "_adapters", lambda: adapters)
    monkeypatch.setattr(
        network.ctypes, "WinDLL", Mock(return_value=object()), raising=False
    )
    monkeypatch.setattr(
        network, "_legacy_gateways", lambda _library: {7: "192.0.2.254"}
    )
    monkeypatch.setattr(
        network, "_legacy_speed", lambda _library, index: 100 if index == 7 else 0
    )
    assert network.read_interfaces() == [
        {
            "interface_index": 7,
            "connection_name": "Legacy 雪",
            "speed": 100,
            "default_gateway": "192.0.2.254",
            "ipv4": {"address": "192.0.2.1", "prefix": "24"},
            "ipv6": None,
        }
    ]


def test_missing_legacy_prefix_does_not_fabricate_network_metadata(
    native: ModuleType, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(
        native.network,
        "_adapters",
        lambda: [
            {
                "kind": 6,
                "modern": False,
                "interface_index": 7,
                "addresses": [(2, "192.0.2.1", None)],
            }
        ],
    )
    with pytest.raises(OSError, match="without a matching prefix"):
        native.network.read_interfaces()


@pytest.mark.parametrize("architecture, expected", [(0, "32-bit"), (9, "64-bit")])
def test_legacy_platform_does_not_query_missing_os_architecture(
    native: ModuleType,
    monkeypatch: pytest.MonkeyPatch,
    architecture: int,
    expected: str,
) -> None:
    monkeypatch.setattr(native, "_bios", lambda: {})
    monkeypatch.setattr(native, "_domain", lambda: {"member": False})
    monkeypatch.setattr(
        native,
        "_system_info",
        lambda: (SimpleNamespace(architecture=architecture), "LEGACY"),
    )
    monkeypatch.setattr(native.network, "host_information", lambda: ("legacy", ""))
    monkeypatch.setattr(
        native,
        "windows_version",
        lambda: SimpleNamespace(
            major=5,
            minor=2,
            build=3790,
            service_pack_major=2,
            service_pack_minor=0,
        ),
    )
    monkeypatch.setattr(native.account, "sid_to_name", lambda _sid: "Administrators")
    monkeypatch.setattr(native.group, "member_sids", lambda _group: [])
    monkeypatch.setattr(native, "_registry", lambda _path, _name: None)
    monkeypatch.setattr(native, "_key_exists", lambda _path: False)
    monkeypatch.setattr(native, "_administrator", lambda: True)
    read = Mock(return_value={"PrimaryOwnerContact": "Legacy owner"})
    monkeypatch.setattr(native, "_one", read)
    facts: dict[str, object] = {}
    native._platform(facts, [])
    assert facts["ansible_architecture"] == expected
    assert facts["ansible_owner_contact"] == "Legacy owner"
    read.assert_called_once_with("Win32_ComputerSystem", ["PrimaryOwnerContact"])


def test_modern_timezone_id_does_not_enumerate_legacy_catalogue(
    native: ModuleType, monkeypatch: pytest.MonkeyPatch
) -> None:
    native = native.date_time
    monkeypatch.setattr(native, "_value", lambda _path, _name: "Modern Time")
    read = Mock(side_effect=AssertionError("Native fallback must not run"))
    monkeypatch.setattr(native.ctypes, "WinDLL", read, raising=False)
    assert native._timezone_id() == "Modern Time"
    read.assert_not_called()


@pytest.mark.parametrize("valid", [True, False])
def test_legacy_timezone_matches_native_name_and_signed_bias(
    native: ModuleType, monkeypatch: pytest.MonkeyPatch, valid: bool
) -> None:
    native = native.date_time
    zone_type = native._TimeZoneInformation

    def _read(pointer: Any) -> int:
        zone = ctypes.cast(pointer, ctypes.POINTER(zone_type)).contents
        zone.bias = -180
        text = "Legacy 雪".encode("utf-16-le").ljust(64, b"\0")
        zone.standard_name = (ctypes.c_uint16 * 32).from_buffer_copy(text)
        return 1

    monkeypatch.setattr(
        native.ctypes,
        "WinDLL",
        Mock(
            return_value=SimpleNamespace(GetTimeZoneInformation=Mock(side_effect=_read))
        ),
        raising=False,
    )
    registry = Mock()
    registry.OpenKey.return_value.__enter__ = Mock(return_value=object())
    registry.OpenKey.return_value.__exit__ = Mock(return_value=False)
    registry.QueryInfoKey.return_value = (2, 0, 0)
    registry.EnumKey.side_effect = ["Wrong bias", "Legacy ID"]
    monkeypatch.setattr(native, "winreg", registry)

    def _value(path: str, name: str) -> object:
        if name == "TimeZoneKeyName":
            return None
        if name == "Std":
            return "Legacy 雪"
        bias = 0 if path.endswith("Wrong bias") else -180
        return struct.pack("<l", bias).ljust(44 if valid else 4, b"\0")

    monkeypatch.setattr(native, "_value", _value)
    if valid:
        assert native._timezone_id() == "Legacy ID"
    else:
        with pytest.raises(ValueError, match="44 binary bytes"):
            native._timezone_id()
