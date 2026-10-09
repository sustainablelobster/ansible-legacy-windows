"""Verify DNS registry reads and native/WMI write boundaries offline."""

# SPDX-License-Identifier: GPL-3.0-or-later
# Native substitutes do not establish Windows execution compatibility.
# pylint: disable=protected-access

import ctypes
import ipaddress
from types import ModuleType, SimpleNamespace
from typing import Any
from unittest.mock import MagicMock, Mock

import pytest

from tests.unit.payload_support import ROOT, load_module


@pytest.fixture(name="helper")
def dns_helper(monkeypatch: pytest.MonkeyPatch) -> ModuleType:
    """Load the native DNS helper with only its import path staged.

    :param monkeypatch: Scoped sibling import path.
    :returns: Native module without opening Windows resources.
    """
    monkeypatch.syspath_prepend(str(ROOT / "plugins/module_utils"))
    return load_module(
        ROOT / "plugins/module_utils/legacy_windows_dns_client.py",
        "tested_dns_client_native",
    )


def _connection(helper: ModuleType, monkeypatch: pytest.MonkeyPatch) -> Mock:
    context = MagicMock()
    connection = Mock()
    context.__enter__.return_value = connection
    monkeypatch.setattr(helper, "WmiConnection", Mock(return_value=context))
    return connection


def test_reads_adapter_caption_index_identity_and_order(
    helper: ModuleType, monkeypatch: pytest.MonkeyPatch
) -> None:
    connection = _connection(helper, monkeypatch)
    connection.query.side_effect = [
        [
            {"DeviceID": "8", "NetConnectionID": "Local Area Connection"},
            {"DeviceID": "9", "NetConnectionID": None},
        ],
        [{"Index": 8, "SettingID": "owned-guid", "__PATH": "owned-path"}],
    ]
    monkeypatch.setattr(helper, "_families", Mock(return_value=[{"version": 4}]))
    assert helper.read_adapters(["LOCAL AREA*", "absent*"]) == [
        {
            "name": "Local Area Connection",
            "guid": "owned-guid",
            "path": "owned-path",
            "families": [{"version": 4}],
        }
    ]
    helper._families.assert_called_once_with("owned-guid")


def test_exact_missing_adapter_is_actionable(
    helper: ModuleType, monkeypatch: pytest.MonkeyPatch
) -> None:
    connection = _connection(helper, monkeypatch)
    connection.query.side_effect = [[], []]
    with pytest.raises(ValueError, match="IP enabled with the name 'Absent'"):
        helper.read_adapters(["Absent"])


def test_per_family_registry_static_precedence_and_bad_format(
    helper: ModuleType, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(
        helper,
        "_values",
        Mock(
            side_effect=[
                {
                    "NameServer": "192.0.2.53;192.0.2.54\0",
                    "DhcpNameServer": "192.0.2.1",
                    "EnableDHCP": 1,
                },
                {
                    "NameServer": None,
                    "Dhcpv6DNSServers": ipaddress.ip_address("2001:db8::53").packed,
                    "EnableDHCP": 1,
                },
            ]
        ),
    )
    assert helper._families("guid") == [
        {
            "version": 4,
            "servers": ["192.0.2.53", "192.0.2.54"],
            "dhcp": False,
            "bad_format": True,
        },
        {"version": 6, "servers": ["2001:db8::53"], "dhcp": True, "bad_format": False},
    ]


@pytest.mark.parametrize("servers", [[], ["192.0.2.53", "192.0.2.54"]])
def test_legacy_setter_uses_array_or_omits_reset_parameter(
    helper: ModuleType, monkeypatch: pytest.MonkeyPatch, servers: list[str]
) -> None:
    monkeypatch.setattr(helper, "os", SimpleNamespace(name="nt"))
    monkeypatch.setattr(helper, "_set_interface", Mock(return_value=False))
    connection = _connection(helper, monkeypatch)
    connection.call_method.return_value = {"ReturnValue": 0}
    helper.write_servers({"guid": "guid", "path": "path", "families": []}, servers)
    connection.call_method.assert_called_once_with(
        "path",
        "SetDNSServerSearchOrder",
        ["ReturnValue"],
        {"DNSServerSearchOrder": servers} if servers else {},
    )


def test_provider_failure_is_not_reported_as_success(
    helper: ModuleType, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(helper, "os", SimpleNamespace(name="nt"))
    monkeypatch.setattr(helper, "_set_interface", Mock(return_value=False))
    connection = _connection(helper, monkeypatch)
    connection.call_method.return_value = {"ReturnValue": 70}
    with pytest.raises(OSError, match="SetDNSServerSearchOrder, code 70"):
        helper.write_servers(
            {"guid": "guid", "path": "path", "families": []}, ["192.0.2.53"]
        )


def test_unavailable_ipv6_fails_before_any_legacy_provider_write(
    helper: ModuleType, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(helper, "os", SimpleNamespace(name="nt"))
    monkeypatch.setattr(helper, "_set_interface", Mock(return_value=False))
    connection = _connection(helper, monkeypatch)
    with pytest.raises(ValueError, match="no IPv6 DNS configuration"):
        helper.write_servers(
            {"guid": "guid", "path": "path", "families": []}, ["2001:db8::53"]
        )
    connection.call_method.assert_not_called()


@pytest.mark.parametrize(
    ("servers", "expected_ipv6", "expected_ipv4"),
    [
        (["2001:db8::53"], ["2001:db8::53"], None),
        (["192.0.2.53"], None, {"DNSServerSearchOrder": ["192.0.2.53"]}),
        ([], [], {}),
        (
            ["2001:db8::53", "192.0.2.53"],
            ["2001:db8::53"],
            {"DNSServerSearchOrder": ["192.0.2.53"]},
        ),
    ],
)
def test_older_setter_preserves_omitted_families_and_resets_both(
    helper: ModuleType,
    monkeypatch: pytest.MonkeyPatch,
    servers: list[str],
    expected_ipv6: list[str] | None,
    expected_ipv4: dict[str, Any] | None,
) -> None:
    monkeypatch.setattr(helper, "os", SimpleNamespace(name="nt"))
    monkeypatch.setattr(helper, "_set_interface", Mock(return_value=False))
    monkeypatch.setattr(helper, "_set_ipv6_servers", Mock())
    connection = _connection(helper, monkeypatch)
    connection.call_method.return_value = {"ReturnValue": 0}
    adapter = {"guid": "guid", "path": "path", "families": [{"version": 6}]}
    helper.write_servers(adapter, servers)
    if expected_ipv6 is None:
        helper._set_ipv6_servers.assert_not_called()
    else:
        helper._set_ipv6_servers.assert_called_once_with(adapter, expected_ipv6)
    if expected_ipv4 is None:
        connection.call_method.assert_not_called()
    else:
        assert connection.call_method.call_args.args[-1] == expected_ipv4


def test_ipv6_command_failure_precedes_mixed_request_ipv4_write(
    helper: ModuleType, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(helper, "os", SimpleNamespace(name="nt"))
    monkeypatch.setattr(helper, "_set_interface", Mock(return_value=False))
    monkeypatch.setattr(
        helper, "_set_ipv6_servers", Mock(side_effect=OSError("IPv6 command absent"))
    )
    connection = _connection(helper, monkeypatch)
    with pytest.raises(OSError, match="IPv6 command absent"):
        helper.write_servers(
            {"guid": "guid", "families": [{"version": 6}]},
            ["192.0.2.53", "2001:db8::53"],
        )
    connection.call_method.assert_not_called()


@pytest.mark.parametrize("servers", [[], ["2001:db8::53", "2001:db8::54"]])
def test_ipv6_tool_receives_ordered_addresses_without_shell_or_dns_validation(
    helper: ModuleType, monkeypatch: pytest.MonkeyPatch, servers: list[str]
) -> None:
    monkeypatch.setenv("SystemRoot", "Windows")
    process = MagicMock(returncode=0)
    process.communicate.return_value = [Mock(decode=Mock(return_value=""))]
    context = MagicMock()
    context.__enter__.return_value = process
    launch = Mock(return_value=context)
    monkeypatch.setattr(helper.subprocess, "Popen", launch)
    helper._set_ipv6_servers({"name": "Local Area Connection"}, servers)
    commands = [call.args[0][1:] for call in launch.call_args_list]
    if servers:
        assert commands == [
            [
                "interface",
                "ipv6",
                "set",
                "dnsservers",
                "name=Local Area Connection",
                "source=static",
                "address=2001:db8::53",
                "validate=no",
            ],
            [
                "interface",
                "ipv6",
                "add",
                "dnsservers",
                "name=Local Area Connection",
                "address=2001:db8::54",
                "index=2",
                "validate=no",
            ],
        ]
    else:
        assert commands == [
            [
                "interface",
                "ipv6",
                "set",
                "dnsservers",
                "name=Local Area Connection",
                "source=dhcp",
            ]
        ]
    assert all("shell" not in call.kwargs for call in launch.call_args_list)


def test_ipv6_tool_reports_native_failure_and_stops_adding_addresses(
    helper: ModuleType, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv("SystemRoot", "Windows")
    process = MagicMock(returncode=1)
    process.communicate.return_value = [
        Mock(decode=Mock(return_value="IPv6 command unavailable"))
    ]
    context = MagicMock()
    context.__enter__.return_value = process
    launch = Mock(return_value=context)
    monkeypatch.setattr(helper.subprocess, "Popen", launch)
    with pytest.raises(OSError, match="IPv6 DNS configuration failed"):
        helper._set_ipv6_servers(
            {"name": "Local Area Connection"}, ["2001:db8::53", "2001:db8::54"]
        )
    launch.assert_called_once()


@pytest.mark.parametrize(
    ("servers", "expected"),
    [
        (
            ["192.0.2.53", "2001:db8::53", "192.0.2.54"],
            [
                (1, 2, "192.0.2.53,192.0.2.54", None, None),
                (1, 3, "2001:db8::53", None, None),
            ],
        ),
        (["192.0.2.53"], [(1, 2, "192.0.2.53", None, None)]),
        (["2001:db8::53"], [(1, 3, "2001:db8::53", None, None)]),
        ([], [(1, 2, "", None, None), (1, 3, "", None, None)]),
    ],
)
def test_modern_native_setter_updates_supplied_families_or_resets_both(
    helper: ModuleType,
    monkeypatch: pytest.MonkeyPatch,
    servers: list[str],
    expected: list[tuple[object, ...]],
) -> None:
    observed = []

    def _set_dns(unused_guid: Any, pointer: Any) -> int:
        settings = ctypes.cast(
            pointer, ctypes.POINTER(helper._InterfaceSettings)
        ).contents
        observed.append(
            (
                settings.version,
                settings.flags,
                settings.servers,
                settings.domain,
                settings.search_list,
            )
        )
        return 0

    setter = Mock(side_effect=_set_dns)
    monkeypatch.setattr(
        helper.ctypes,
        "WinDLL",
        Mock(return_value=Mock(SetInterfaceDnsSettings=setter)),
        raising=False,
    )
    assert helper._set_interface(
        "{00112233-4455-6677-8899-AABBCCDDEEFF}",
        servers,
    )
    assert observed == expected


def test_suffix_write_calls_global_class_with_ordered_array(
    helper: ModuleType, monkeypatch: pytest.MonkeyPatch
) -> None:
    connection = _connection(helper, monkeypatch)
    connection.call_method.return_value = {"ReturnValue": 0}
    helper.write_suffixes(["one.invalid", "two.invalid"])
    connection.call_method.assert_called_once_with(
        "Win32_NetworkAdapterConfiguration",
        "SetDNSSuffixSearchOrder",
        ["ReturnValue"],
        {"DNSDomainSuffixSearchOrder": ["one.invalid", "two.invalid"]},
    )
