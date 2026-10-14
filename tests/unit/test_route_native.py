"""Check native route selection, exact tool arguments and WMI filtering offline."""

# SPDX-License-Identifier: GPL-3.0-or-later

import ctypes
import ipaddress
import sys
from types import ModuleType, SimpleNamespace
from typing import Any
from unittest.mock import MagicMock, Mock

import pytest

from tests.unit.payload_support import ROOT, load_module

# These boundary tests intentionally inspect native argument buffers and tool calls.
# pylint: disable=protected-access


@pytest.fixture(name="route")
def native_route(monkeypatch: pytest.MonkeyPatch) -> ModuleType:
    """Load the maintained native helper without opening Windows libraries.

    :param monkeypatch: Scoped helper import path.
    :returns: Native route helper.
    """
    monkeypatch.syspath_prepend(str(ROOT / "legacy_windows/plugins/module_utils"))
    monkeypatch.setattr(
        sys,
        "getwindowsversion",
        lambda: SimpleNamespace(major=10),
        raising=False,
    )
    return load_module(
        ROOT / "legacy_windows/plugins/module_utils/legacy_windows_route.py",
        "route_tested",
    )


def connection(
    monkeypatch: pytest.MonkeyPatch, route: ModuleType, rows: list[dict[str, Any]]
) -> Mock:
    """Replace the helper's WMI boundary with recorded provider rows.

    :param monkeypatch: Scoped WMI replacement.
    :param route: Maintained native helper.
    :param rows: Provider observations returned by the test boundary.
    :returns: Query recorder.
    """
    provider = Mock()
    provider.query.return_value = rows
    context = MagicMock()
    context.__enter__.return_value = provider
    monkeypatch.setattr(route, "WmiConnection", Mock(return_value=context))
    return provider


def test_persistent_lookup_is_destination_only_without_wql_injection(
    route: ModuleType, monkeypatch: pytest.MonkeyPatch
) -> None:
    rows = [
        {"Destination": "192.0.2.73", "Mask": "255.255.255.0"},
        {"Destination": "192.0.2.74"},
    ]
    provider = connection(monkeypatch, route, rows)
    assert route.persistent_routes("192.0.2.73") == rows[:1]
    assert route.persistent_routes("' OR TRUE") == []
    assert all(
        "' OR TRUE" not in call.args[0] for call in provider.query.call_args_list
    )


def test_legacy_persistence_reads_os_boot_store_including_metric_zero(
    route: ModuleType, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(
        route.sys, "getwindowsversion", lambda: SimpleNamespace(major=5)
    )
    registry = MagicMock(HKEY_LOCAL_MACHINE=1, REG_SZ=1)
    values = [
        ("192.0.2.73,255.255.255.255,192.168.0.1,0", "", 1),
        ("192.0.2.74,255.255.255.255,192.168.0.1,1", "", 1),
        ("192.0.2.73,255.255.255.255,192.168.0.2,1", "", 1),
        ("192.0.2.73,255.255.255.255,invalid,0", "", 1),
        ("192.0.2.73,invalid,192.168.0.1,0", "", 1),
        ("192.0.2.73,255.255.255.255,192.168.0.1,-1", "", 1),
        ("192.0.2.73,255.255.255.255,192.168.0.1,no", "", 1),
        ("192.0.2.73,255.255.255.255,192.168.0.1,0", b"", 3),
        ("192.0.2.73", "", 1),
    ]
    registry.QueryInfoKey.return_value = (0, len(values), 0)
    registry.EnumValue.side_effect = lambda unused, index: values[index]
    monkeypatch.setattr(route, "winreg", registry)
    provider = connection(monkeypatch, route, [])
    assert route.persistent_routes("192.0.2.73") == [
        {
            "Destination": "192.0.2.73",
            "Mask": "255.255.255.255",
            "NextHop": "192.168.0.1",
            "Metric1": 0,
        },
        {
            "Destination": "192.0.2.73",
            "Mask": "255.255.255.255",
            "NextHop": "192.168.0.2",
            "Metric1": 1,
        },
    ]
    assert route.persistent_routes("' OR TRUE") == []
    provider.query.assert_not_called()


def test_absent_legacy_persistence_store_is_an_empty_observation(
    route: ModuleType, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(
        route.sys, "getwindowsversion", lambda: SimpleNamespace(major=5)
    )
    registry = MagicMock()
    registry.OpenKey.side_effect = FileNotFoundError()
    monkeypatch.setattr(route, "winreg", registry)
    assert route.persistent_routes("192.0.2.73") == []


def test_legacy_persistence_access_error_is_not_silently_absent(
    route: ModuleType, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(
        route.sys, "getwindowsversion", lambda: SimpleNamespace(major=5)
    )
    registry = MagicMock()
    registry.OpenKey.side_effect = PermissionError("denied")
    monkeypatch.setattr(route, "winreg", registry)
    with pytest.raises(PermissionError, match="denied"):
        route.persistent_routes("192.0.2.73")


@pytest.mark.parametrize("gateway", ["192.168.0.1", "2001:db8::1"])
@pytest.mark.parametrize("status", [0, 1231])
def test_best_interface_sockaddr_layout_and_status(
    route: ModuleType, monkeypatch: pytest.MonkeyPatch, gateway: str, status: int
) -> None:
    captured = []

    def _choose(address: Any, index: Any) -> int:
        captured.append(address.raw)
        index._obj.value = 11
        return status

    function = Mock(side_effect=_choose)
    monkeypatch.setattr(
        route.ctypes,
        "WinDLL",
        Mock(return_value=SimpleNamespace(GetBestInterfaceEx=function)),
        raising=False,
    )
    monkeypatch.setattr(
        route.ctypes,
        "WinError",
        lambda code: OSError(code, "unreachable"),
        raising=False,
    )
    address = ipaddress.ip_address(gateway)
    if status:
        with pytest.raises(OSError, match="unreachable"):
            route._interface(address)
    else:
        assert route._interface(address) == 11
    raw = captured[0]
    offset = 4 if address.version == 4 else 8
    assert raw[offset : offset + len(address.packed)] == address.packed
    assert ctypes.c_ushort.from_buffer_copy(raw).value == (
        route.socket.AF_INET if address.version == 4 else route.socket.AF_INET6
    )
    assert function.restype is ctypes.c_uint32


@pytest.mark.parametrize("major", [5, 6, 10])
def test_native_creation_uses_pinned_metric_zero_and_persistence(
    route: ModuleType, monkeypatch: pytest.MonkeyPatch, major: int
) -> None:
    monkeypatch.setattr(
        route.sys,
        "getwindowsversion",
        lambda: SimpleNamespace(major=major),
        raising=False,
    )
    command = Mock()
    monkeypatch.setattr(route, "_command", command)
    legacy = Mock()
    monkeypatch.setattr(route, "_legacy_add", legacy)
    route.add_route(("192.0.2.73/32", ipaddress.ip_address("192.168.0.1"), 11))
    if major == 5:
        command.assert_not_called()
        legacy.assert_called_once_with(
            ipaddress.ip_network("192.0.2.73/32"),
            ipaddress.ip_address("192.168.0.1"),
            11,
        )
    else:
        legacy.assert_not_called()
        tool, arguments = command.call_args.args
        assert tool == "netsh"
        assert arguments == [
            "interface",
            "ipv4",
            "add",
            "route",
            "prefix=192.0.2.73/32",
            "interface=11",
            "nexthop=192.168.0.1",
            "metric=0",
            "store=persistent",
        ]


def test_host_bit_prefix_preparation_preserves_text_but_actual_write_rejects_it(
    route: ModuleType, monkeypatch: pytest.MonkeyPatch
) -> None:
    choose = Mock(return_value=11)
    monkeypatch.setattr(route, "_interface", choose)
    command, legacy = Mock(), Mock()
    monkeypatch.setattr(route, "_command", command)
    monkeypatch.setattr(route, "_legacy_add", legacy)
    prepared = route.prepare_add("192.0.2.193/24", "192.168.0.1")
    assert prepared == ("192.0.2.193/24", ipaddress.ip_address("192.168.0.1"), 11)
    choose.assert_called_once_with(ipaddress.ip_address("192.168.0.1"))
    with pytest.raises(ValueError, match="host bits"):
        route.add_route(prepared)
    command.assert_not_called()
    legacy.assert_not_called()


@pytest.mark.parametrize("suffix", ["255.255.255.0", "0.0.0.255"])
def test_dotted_masks_are_not_windows_prefix_lengths(
    route: ModuleType, monkeypatch: pytest.MonkeyPatch, suffix: str
) -> None:
    choose = Mock()
    monkeypatch.setattr(route, "_interface", choose)
    with pytest.raises(ValueError, match="prefix length"):
        route.prepare_add("192.0.2.0/" + suffix, "192.168.0.1")
    with pytest.raises(ValueError, match="prefix length"):
        route.prepare_remove("192.0.2.0/" + suffix)
    choose.assert_not_called()


@pytest.mark.parametrize(
    "create_status,persist_error,recovery_status",
    [(0, False, 0), (87, False, 0), (0, True, 0), (0, True, 5)],
)
def test_legacy_native_metric_zero_abi_persistence_and_owned_failure_recovery(
    route: ModuleType,
    monkeypatch: pytest.MonkeyPatch,
    create_status: int,
    persist_error: bool,
    recovery_status: int,
) -> None:
    rows = []

    def _create(pointer: Any) -> int:
        rows.append(ctypes.string_at(pointer, ctypes.sizeof(route._ForwardRow)))
        return create_status

    create = Mock(side_effect=_create)
    delete = Mock(return_value=recovery_status)
    monkeypatch.setattr(
        route.ctypes,
        "WinDLL",
        Mock(
            return_value=SimpleNamespace(
                CreateIpForwardEntry=create, DeleteIpForwardEntry=delete
            )
        ),
        raising=False,
    )
    monkeypatch.setattr(
        route.ctypes,
        "WinError",
        lambda code: OSError(code, "native create rejected"),
        raising=False,
    )
    registry = MagicMock(HKEY_LOCAL_MACHINE=1, KEY_SET_VALUE=2, REG_SZ=1)
    if persist_error:
        registry.SetValueEx.side_effect = OSError("persistence denied")
    monkeypatch.setattr(route, "winreg", registry)
    arguments = (
        ipaddress.ip_network("192.0.2.73/32"),
        ipaddress.ip_address("192.168.0.1"),
        11,
    )
    if create_status or persist_error:
        with pytest.raises(
            OSError,
            match="native create rejected" if create_status else "persistence denied",
        ):
            route._legacy_add(*arguments)
    else:
        route._legacy_add(*arguments)
    raw = rows[0]
    assert len(raw) == 56 and raw[:4] == arguments[0].network_address.packed
    row = route._ForwardRow.from_buffer_copy(raw)
    assert row.interface == 11 and row.protocol == 3 and row.metric1 == 0
    assert row.metric2 == row.metric5 == 0xFFFFFFFF
    if create_status:
        registry.CreateKeyEx.assert_not_called()
        delete.assert_not_called()
    else:
        assert registry.SetValueEx.call_args.args[1:] == (
            "192.0.2.73,255.255.255.255,192.168.0.1,0",
            0,
            1,
            "",
        )
        assert delete.call_count == int(persist_error)


def test_removal_selects_every_exact_prefix_and_ignores_other_masks(
    route: ModuleType, monkeypatch: pytest.MonkeyPatch
) -> None:
    rows = [
        {
            "Destination": "192.0.2.73",
            "Mask": mask,
            "NextHop": gateway,
            "InterfaceIndex": index,
        }
        for mask, gateway, index in [
            ("255.255.255.255", "192.168.0.1", 11),
            ("255.255.255.255", "192.168.0.2", 12),
            ("255.255.255.0", "192.168.0.3", 13),
        ]
    ]
    connection(monkeypatch, route, rows)
    prepared = route.prepare_remove("192.0.2.73/32")
    assert prepared[1] == rows[:2]
    monkeypatch.setattr(
        route.sys, "getwindowsversion", lambda: SimpleNamespace(major=10), raising=False
    )
    command = Mock()
    monkeypatch.setattr(route, "_command", command)
    route.remove_route(prepared)
    assert command.call_count == 2
    assert command.call_args_list[0].args[1][-3:] == [
        "interface=11",
        "nexthop=192.168.0.1",
        "store=persistent",
    ]
    with pytest.raises(OSError, match="No routes"):
        route.prepare_remove("192.0.2.74/32")


@pytest.mark.parametrize(
    "destination,gateway",
    [("invalid", "192.168.0.1"), ("192.0.2.73/32", "invalid"), ("192.0.2.73/32", "::")],
)
def test_invalid_new_route_fails_before_interface_selection(
    route: ModuleType, monkeypatch: pytest.MonkeyPatch, destination: str, gateway: str
) -> None:
    choose = Mock()
    monkeypatch.setattr(route, "_interface", choose)
    with pytest.raises(ValueError):
        route.prepare_add(destination, gateway)
    choose.assert_not_called()


@pytest.mark.parametrize("index", [1, 5])
def test_legacy_ipv6_uses_installed_native_selection_and_persistent_tool(
    route: ModuleType, monkeypatch: pytest.MonkeyPatch, index: int
) -> None:
    monkeypatch.setattr(
        route.sys, "getwindowsversion", lambda: SimpleNamespace(major=5), raising=False
    )
    choose = Mock(return_value=index)
    monkeypatch.setattr(route, "_interface", choose)
    command, legacy = Mock(return_value="No entries found."), Mock()
    monkeypatch.setattr(route, "_command", command)
    monkeypatch.setattr(route, "_legacy_add", legacy)
    prepared = route.prepare_add("2001:db8::73/128", "fe80::2")
    choose.assert_called_once_with(ipaddress.ip_address("fe80::2"))
    route.add_route(prepared)
    assert command.call_count == 2
    assert command.call_args_list[0].args == (
        "netsh",
        ["interface", "ipv6", "show", "routes", "store=persistent"],
    )
    command.assert_called_with(
        "netsh",
        [
            "interface",
            "ipv6",
            "add",
            "route",
            "prefix=2001:db8::73/128",
            "interface=" + str(index),
            "nexthop=fe80::2",
            "metric=0",
            "store=persistent",
        ],
    )
    legacy.assert_not_called()


@pytest.mark.parametrize("prefix", ["2001:db8::73/128", "2001:0DB8:0:0:0:0:0:73/128"])
def test_legacy_ipv6_duplicate_prefix_fails_before_any_setter(
    route: ModuleType, monkeypatch: pytest.MonkeyPatch, prefix: str
) -> None:
    monkeypatch.setattr(
        route.sys, "getwindowsversion", lambda: SimpleNamespace(major=5)
    )
    command = Mock(
        side_effect=[
            "no Manual 0 " + prefix + " 0 fd51::2",
            "no Manual 0 " + prefix + " 5 fd51::2",
        ]
    )
    monkeypatch.setattr(route, "_command", command)
    with pytest.raises(OSError, match="already exists"):
        route.add_route(("2001:db8::73/128", ipaddress.ip_address("fd51::2"), 5))
    assert [call.args[1] for call in command.call_args_list] == [
        ["interface", "ipv6", "show", "routes", "store=persistent"],
        ["interface", "ipv6", "show", "routes", "store=active"],
    ]


@pytest.mark.parametrize("prefix", ["2001:db8::730/128", "2001:db8::/64"])
def test_legacy_ipv6_duplicate_lookup_matches_the_exact_network(
    route: ModuleType, monkeypatch: pytest.MonkeyPatch, prefix: str
) -> None:
    monkeypatch.setattr(
        route.sys, "getwindowsversion", lambda: SimpleNamespace(major=5)
    )
    command = Mock(return_value="no Manual 0 " + prefix + " 0 fd51::2")
    monkeypatch.setattr(route, "_command", command)
    route.add_route(("2001:db8::73/128", ipaddress.ip_address("fd51::2"), 5))
    assert command.call_count == 2
    assert command.call_args.args[1][2:4] == ["add", "route"]


def test_legacy_ipv6_persistent_read_failure_cannot_start_a_write(
    route: ModuleType, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(
        route.sys, "getwindowsversion", lambda: SimpleNamespace(major=5)
    )
    command = Mock(side_effect=OSError("native access denied"))
    monkeypatch.setattr(route, "_command", command)
    with pytest.raises(OSError, match="native access denied"):
        route.add_route(("2001:db8::73/128", ipaddress.ip_address("fd51::2"), 5))
    assert command.call_count == 1


@pytest.mark.parametrize("gateway,index", [("fd51::3", 5), ("fd51::2", 7)])
def test_legacy_ipv6_duplicate_identity_includes_gateway_and_active_interface(
    route: ModuleType, monkeypatch: pytest.MonkeyPatch, gateway: str, index: int
) -> None:
    monkeypatch.setattr(
        route.sys, "getwindowsversion", lambda: SimpleNamespace(major=5)
    )
    command = Mock(return_value="no Manual 0 2001:db8::73/128 5 fd51::2")
    monkeypatch.setattr(route, "_command", command)
    route.add_route(("2001:db8::73/128", ipaddress.ip_address(gateway), index))
    assert command.call_args.args[1][2:4] == ["add", "route"]


def test_plain_gateway_column_cannot_become_a_duplicate_host_prefix(
    route: ModuleType, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(
        route.sys, "getwindowsversion", lambda: SimpleNamespace(major=5)
    )
    command = Mock(return_value="no Manual 0 2001:db8:1::/64 0 fd51::2")
    monkeypatch.setattr(route, "_command", command)
    route.add_route(("fd51::2/128", ipaddress.ip_address("fd51::3"), 5))
    assert command.call_count == 2
    assert command.call_args.args[1][2:4] == ["add", "route"]


def test_absent_legacy_ipv6_stack_returns_the_native_selection_failure(
    route: ModuleType, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(
        route.sys, "getwindowsversion", lambda: SimpleNamespace(major=5), raising=False
    )
    monkeypatch.setattr(
        route, "_interface", Mock(side_effect=OSError(50, "not supported"))
    )
    with pytest.raises(OSError, match="not supported"):
        route.prepare_add("2001:db8::73/128", "fe80::2")


@pytest.mark.parametrize("status", [0, 1])
def test_tools_use_system_path_no_shell_and_return_actionable_failure(
    route: ModuleType, monkeypatch: pytest.MonkeyPatch, status: int
) -> None:
    monkeypatch.setenv("SystemRoot", "C:\\Windows")
    process = MagicMock(returncode=status)
    process.__enter__.return_value = process
    output = Mock()
    output.decode.return_value = " denied "
    process.communicate.return_value = (output, None)
    launch = Mock(return_value=process)
    monkeypatch.setattr(route.subprocess, "Popen", launch)
    if status:
        with pytest.raises(OSError, match=r"netsh failed \(1\): denied"):
            route._command("netsh", ["interface", "ipv4"])
    else:
        route._command("netsh", ["interface", "ipv4"])
    assert launch.call_args.args[0] == [
        route.os.path.join("C:\\Windows", "System32", "netsh.exe"),
        "interface",
        "ipv4",
    ]
    assert "shell" not in launch.call_args.kwargs
