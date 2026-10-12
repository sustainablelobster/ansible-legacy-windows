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


def _netsh_tool(
    helper: ModuleType,
    monkeypatch: pytest.MonkeyPatch,
    spelling: str,
    validation: tuple[bool, bool],
    write_error: str | None = None,
) -> tuple[Mock, list[list[str]]]:
    writes: list[list[str]] = []

    def _launch(arguments: list[str], **_keywords: Any) -> MagicMock:
        command = arguments[3:]
        operation = command[0]
        valid = validation[operation == "add"]
        status = 0
        if command == [operation, "/?"]:
            output = (
                f"Available commands:\r\n{operation} {spelling} - DNS settings.\r\n"
            )
        elif command == [operation, spelling, "/?"]:
            output = f"Usage: {operation} {spelling} [name=]connection "
            output += "[[validate=]yes|no]" if valid else "[address=]address"
        elif command[1] != spelling or (not valid and "validate=no" in command):
            status, output = 1, "The following command was not found."
        else:
            writes.append(command)
            status, output = (1, write_error) if write_error else (0, "")
        process = MagicMock(returncode=status)
        process.communicate.return_value = [Mock(decode=Mock(return_value=output))]
        context = MagicMock()
        context.__enter__.return_value = process
        return context

    launch_mock = Mock(side_effect=_launch)
    monkeypatch.setattr(helper.subprocess, "Popen", launch_mock)
    monkeypatch.setenv("SystemRoot", "Windows")
    return launch_mock, writes


@pytest.mark.parametrize(
    ("spelling", "validation"),
    [
        ("dnsserver", (False, False)),
        ("dnsservers", (True, True)),
        ("dnsserver", (False, True)),
    ],
)
@pytest.mark.parametrize("servers", [[], ["2001:db8::53", "2001:db8::54"]])
def test_ipv6_tool_uses_advertised_syntax_and_ordered_addresses_without_shell(
    helper: ModuleType,
    monkeypatch: pytest.MonkeyPatch,
    servers: list[str],
    spelling: str,
    validation: tuple[bool, bool],
) -> None:
    launch, commands = _netsh_tool(helper, monkeypatch, spelling, validation)
    helper._set_ipv6_servers({"name": "Local Area Connection"}, servers)
    if servers:
        assert commands == [
            [
                "set",
                spelling,
                "name=Local Area Connection",
                "source=static",
                "address=2001:db8::53",
            ]
            + (["validate=no"] if validation[0] else []),
            [
                "add",
                spelling,
                "name=Local Area Connection",
                "address=2001:db8::54",
                "index=2",
            ]
            + (["validate=no"] if validation[1] else []),
        ]
    else:
        assert commands == [
            [
                "set",
                spelling,
                "name=Local Area Connection",
                "source=dhcp",
            ]
        ]
    assert all("shell" not in call.kwargs for call in launch.call_args_list)


def test_ipv6_tool_reports_native_failure_and_stops_adding_addresses(
    helper: ModuleType, monkeypatch: pytest.MonkeyPatch
) -> None:
    unused_launch, commands = _netsh_tool(
        helper, monkeypatch, "dnsserver", (False, False), "provider denied settings"
    )
    with pytest.raises(OSError, match="IPv6 DNS configuration failed.*provider denied"):
        helper._set_ipv6_servers(
            {"name": "Local Area Connection"}, ["2001:db8::53", "2001:db8::54"]
        )
    assert len(commands) == 1
    assert commands[0][:2] == ["set", "dnsserver"]


def test_singular_only_ipv6_reset_reaches_ipv4_reset(
    helper: ModuleType, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(
        helper,
        "os",
        SimpleNamespace(name="nt", path=helper.os.path, environ=helper.os.environ),
    )
    monkeypatch.setattr(helper, "_set_interface", Mock(return_value=False))
    connection = _connection(helper, monkeypatch)
    connection.call_method.return_value = {"ReturnValue": 0}
    unused_launch, commands = _netsh_tool(
        helper, monkeypatch, "dnsserver", (False, False)
    )
    helper.write_servers(
        {
            "name": "Local Area Connection",
            "guid": "guid",
            "path": "path",
            "families": [{"version": 4}, {"version": 6}],
        },
        [],
    )
    assert commands == [
        ["set", "dnsserver", "name=Local Area Connection", "source=dhcp"]
    ]
    connection.call_method.assert_called_once_with(
        "path", "SetDNSServerSearchOrder", ["ReturnValue"], {}
    )


@pytest.mark.parametrize("missing_operation", ["set", "add"])
def test_missing_installed_ipv6_dns_command_fails_before_changing_either_family(
    helper: ModuleType, monkeypatch: pytest.MonkeyPatch, missing_operation: str
) -> None:
    monkeypatch.setenv("SystemRoot", "Windows")
    monkeypatch.setattr(
        helper,
        "os",
        SimpleNamespace(name="nt", path=helper.os.path, environ=helper.os.environ),
    )
    monkeypatch.setattr(helper, "_set_interface", Mock(return_value=False))
    connection = _connection(helper, monkeypatch)
    commands: list[list[str]] = []

    def _run(unused_executable: str, command: list[str]) -> str:
        commands.append(command)
        if command == [missing_operation, "/?"]:
            return missing_operation + " address - Address settings."
        return "set dnsserver - DNS settings."

    monkeypatch.setattr(helper, "_run_ipv6_netsh", Mock(side_effect=_run))
    with pytest.raises(OSError, match="no IPv6 DNS '" + missing_operation + "'"):
        helper.write_servers(
            {
                "name": "Local Area Connection",
                "guid": "guid",
                "path": "path",
                "families": [{"version": 4}, {"version": 6}],
            },
            ["192.0.2.53", "2001:db8::53", "2001:db8::54"],
        )
    assert all(command[-1] == "/?" for command in commands)
    connection.call_method.assert_not_called()


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
