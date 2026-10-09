"""Exercise endpoint native boundaries without contacting Windows hosts."""

# SPDX-License-Identifier: GPL-3.0-or-later
# Native substitutes establish contracts, not Windows execution evidence.
# pylint: disable=protected-access

import ctypes
import socket
import struct
from types import ModuleType, SimpleNamespace
from typing import Any
from unittest.mock import MagicMock, Mock, call

import pytest

from tests.unit.payload_support import ROOT, load_module, native_error


@pytest.fixture(name="helper")
def ports_helper(monkeypatch: pytest.MonkeyPatch) -> ModuleType:
    """Load the endpoint helper with portable native-error substitution.

    :param monkeypatch: Scoped Windows-only ctypes substitutions.
    :returns: Helper module without executing a Windows operation.
    """
    monkeypatch.syspath_prepend(str(ROOT / "plugins/module_utils"))
    module = load_module(
        ROOT / "plugins/module_utils/legacy_windows_ports.py", "tested_ports_native"
    )
    monkeypatch.setattr(module.ctypes, "WinError", native_error, raising=False)
    monkeypatch.setattr(module, "os", SimpleNamespace(name="nt"))
    monkeypatch.setattr(
        module, "WmiConnection", Mock(side_effect=_wmi_error(0x8004100E))
    )
    return module


def _wmi_error(result: int) -> OSError:
    error = OSError("WMI call failed")
    setattr(error, "hresult", result)
    return error


# This workflow keeps an independent fixture and expected-result oracle.
# pylint: disable=duplicate-code
def _table(rows: list[Any]) -> bytes:
    return struct.pack("<I", len(rows)) + b"".join(bytes(row) for row in rows)


# pylint: enable=duplicate-code


# This workflow keeps an independent fixture and expected-result oracle.
# pylint: disable=duplicate-code
def _table_call(content: bytes) -> Mock:
    def _read(buffer: Any, pointer: Any, *_arguments: Any) -> int:
        size = ctypes.cast(pointer, ctypes.POINTER(ctypes.c_uint32)).contents
        previous_size = size.value
        size.value = len(content)
        if buffer is None or previous_size < len(content):
            return 122
        ctypes.memmove(buffer, content, len(content))
        return 0

    return Mock(side_effect=_read)


# pylint: enable=duplicate-code


# This workflow keeps an independent fixture and expected-result oracle.
# pylint: disable=duplicate-code
def test_fixed_native_record_layouts(helper: ModuleType) -> None:
    assert ctypes.sizeof(helper._TcpRow) == 24
    assert helper._TcpRow.process_id.offset == 20
    assert ctypes.sizeof(helper._Tcp6Row) == 56
    assert helper._Tcp6Row.local_scope.offset == 16
    assert helper._Tcp6Row.local_port.offset == 20
    assert helper._Tcp6Row.remote_scope.offset == 40
    assert helper._Tcp6Row.state.offset == 48
    assert helper._Tcp6Row.process_id.offset == 52
    assert ctypes.sizeof(helper._UdpRow) == 12
    assert helper._UdpRow.process_id.offset == 8
    assert ctypes.sizeof(helper._Udp6Row) == 28
    assert helper._Udp6Row.local_scope.offset == 16
    assert helper._Udp6Row.process_id.offset == 24
    assert ctypes.sizeof(helper._SocketAddress6) == 28
    assert helper._SocketAddress6.address.offset == 8
    assert helper._SocketAddress6.scope.offset == 24
    for row_type in (helper._TcpRow, helper._Tcp6Row, helper._UdpRow, helper._Udp6Row):
        assert ctypes.alignment(row_type) == 4


# pylint: enable=duplicate-code


@pytest.mark.parametrize("reader", ["tcp_endpoints", "udp_endpoints"])
def test_non_windows_inspection_is_rejected(
    helper: ModuleType, monkeypatch: pytest.MonkeyPatch, reader: str
) -> None:
    monkeypatch.setattr(helper, "os", SimpleNamespace(name="posix"))
    with pytest.raises(ValueError, match="requires a Windows target"):
        getattr(helper, reader)(*([2], []) if reader == "tcp_endpoints" else ())


# This workflow keeps an independent fixture and expected-result oracle.
# pylint: disable=duplicate-code
def test_native_api_signatures(
    helper: ModuleType, monkeypatch: pytest.MonkeyPatch
) -> None:
    library = Mock()
    loader = Mock(return_value=library)
    monkeypatch.setattr(helper, "os", SimpleNamespace(name="nt"))
    monkeypatch.setattr(helper.ctypes, "WinDLL", loader, raising=False)
    assert helper._ip_helper() is library
    loader.assert_called_once_with("iphlpapi", use_last_error=True)
    for function in (library.GetExtendedTcpTable, library.GetExtendedUdpTable):
        assert function.restype is ctypes.c_uint32
        assert function.argtypes == [
            ctypes.c_void_p,
            ctypes.POINTER(ctypes.c_uint32),
            ctypes.c_int,
            ctypes.c_uint32,
            ctypes.c_int,
            ctypes.c_uint32,
        ]


# pylint: enable=duplicate-code


# This workflow keeps an independent fixture and expected-result oracle.
# pylint: disable=duplicate-code
def test_family_probe_closes_its_unbound_socket(
    helper: ModuleType, monkeypatch: pytest.MonkeyPatch
) -> None:
    probe = Mock()
    factory = Mock(return_value=probe)
    monkeypatch.setattr(helper.socket, "socket", factory)
    assert helper._supports_family(socket.AF_INET6) is True
    factory.assert_called_once_with(socket.AF_INET6, socket.SOCK_DGRAM)
    probe.close.assert_called_once_with()
    probe.bind.assert_not_called()
    probe.connect.assert_not_called()


# pylint: enable=duplicate-code


# This workflow keeps an independent fixture and expected-result oracle.
# pylint: disable=duplicate-code
@pytest.mark.parametrize("error_code", [10047, 10013, 10055])
def test_only_uninstalled_family_is_omitted(
    helper: ModuleType, monkeypatch: pytest.MonkeyPatch, error_code: int
) -> None:
    monkeypatch.setattr(
        helper.socket, "socket", Mock(side_effect=native_error(error_code))
    )
    if error_code == 10047:
        assert helper._supports_family(socket.AF_INET6) is False
    else:
        with pytest.raises(OSError) as failure:
            helper._supports_family(socket.AF_INET6)
        assert failure.value.errno == error_code


# pylint: enable=duplicate-code


# This workflow keeps an independent fixture and expected-result oracle.
# pylint: disable=duplicate-code
def test_tcp_states_ports_pids_and_duplicates_retain_native_order(
    helper: ModuleType, monkeypatch: pytest.MonkeyPatch
) -> None:
    states = [12, 11, 10, 9, 8, 7, 6, 5, 4, 3, 2, 1, 2]
    rows = [
        helper._TcpRow(
            state,
            struct.unpack("<I", socket.inet_aton("192.0.2.7"))[0],
            socket.htons(8080) | 0xFFFF0000,
            0,
            0,
            index,
        )
        for index, state in enumerate(states)
    ]
    library = Mock()
    library.GetExtendedTcpTable = _table_call(_table(rows))
    monkeypatch.setattr(helper, "_ip_helper", lambda: library)
    families = Mock(side_effect=lambda family: family == socket.AF_INET)
    monkeypatch.setattr(helper, "_supports_family", families)

    warnings: list[str] = []
    assert helper.tcp_endpoints(range(1, 13), warnings) == [
        {"address": "192.0.2.7", "port": 8080, "pid": index, "state": state}
        for index, state in enumerate(states)
    ]
    assert not warnings
    assert library.GetExtendedTcpTable.call_count == 2
    assert all(
        item.args[2:] == (False, 2, 5, 0)
        for item in library.GetExtendedTcpTable.call_args_list
    )
    library.GetExtendedUdpTable.assert_not_called()
    assert families.call_args_list == [call(socket.AF_INET), call(socket.AF_INET6)]


# pylint: enable=duplicate-code


def test_tcp_legacy_filter_keeps_selected_rows_and_warns_for_bound(
    helper: ModuleType, monkeypatch: pytest.MonkeyPatch
) -> None:
    library = Mock()
    library.GetExtendedTcpTable = _table_call(
        _table([helper._TcpRow(state=state) for state in (5, 2, 999, 2)])
    )
    monkeypatch.setattr(helper, "_ip_helper", lambda: library)
    monkeypatch.setattr(
        helper, "_supports_family", lambda family: family == socket.AF_INET
    )
    warnings: list[str] = []
    assert helper.tcp_endpoints([2, 100], warnings) == [
        {"address": "0.0.0.0", "port": 0, "pid": 0, "state": 2},
        {"address": "0.0.0.0", "port": 0, "pid": 0, "state": 2},
    ]
    assert len(warnings) == 1
    assert "Bound TCP endpoints cannot be reported" in warnings[0]


def test_empty_tcp_selection_never_queries_a_provider(
    helper: ModuleType, monkeypatch: pytest.MonkeyPatch
) -> None:
    tables = Mock()
    monkeypatch.setattr(helper, "_ip_helper", tables)
    warnings: list[str] = []
    assert helper.tcp_endpoints([], warnings) == []
    assert not warnings
    helper.WmiConnection.assert_not_called()
    tables.assert_not_called()


@pytest.mark.parametrize("protocol", ["tcp", "udp"])
def test_modern_provider_preserves_addresses_order_duplicates_and_bound(
    helper: ModuleType, monkeypatch: pytest.MonkeyPatch, protocol: str
) -> None:
    rows = [
        {"LocalAddress": "fe80::1%19", "LocalPort": 65535, "OwningProcess": 400},
        {"LocalAddress": "0.0.0.0", "LocalPort": 9000, "OwningProcess": 0},
        {"LocalAddress": "0.0.0.0", "LocalPort": 9000, "OwningProcess": 0},
    ]
    if protocol == "tcp":
        for row in rows:
            row["State"] = 100
    connection = MagicMock()
    connection.__enter__.return_value = connection
    connection.query.return_value = rows
    factory = Mock(return_value=connection)
    tables = Mock()
    monkeypatch.setattr(helper, "WmiConnection", factory)
    monkeypatch.setattr(helper, "_ip_helper", tables)
    warnings: list[str] = []
    arguments = ([100, 2], warnings) if protocol == "tcp" else ()
    result = getattr(helper, protocol + "_endpoints")(*arguments)
    expected = [
        {"address": "fe80::1%19", "port": 65535, "pid": 400},
        {"address": "0.0.0.0", "port": 9000, "pid": 0},
        {"address": "0.0.0.0", "port": 9000, "pid": 0},
    ]
    if protocol == "tcp":
        for endpoint in expected:
            endpoint["state"] = 100
    assert result == expected
    assert not warnings
    factory.assert_called_once_with(namespace="ROOT\\StandardCimv2")
    fields = ["LocalAddress", "LocalPort", "OwningProcess"]
    if protocol == "tcp":
        fields.append("State")
        expected_query = (
            "SELECT LocalAddress, LocalPort, OwningProcess, State "
            "FROM MSFT_NetTCPConnection WHERE State = 100 OR State = 2"
        )
    else:
        expected_query = (
            "SELECT LocalAddress, LocalPort, OwningProcess FROM MSFT_NetUDPEndpoint"
        )
    connection.query.assert_called_once_with(expected_query, fields)
    connection.__exit__.assert_called_once_with(None, None, None)
    tables.assert_not_called()


@pytest.mark.parametrize("protocol", ["tcp", "udp"])
def test_empty_modern_provider_does_not_fall_back(
    helper: ModuleType, monkeypatch: pytest.MonkeyPatch, protocol: str
) -> None:
    connection = MagicMock()
    connection.__enter__.return_value = connection
    connection.query.return_value = []
    tables = Mock()
    monkeypatch.setattr(helper, "WmiConnection", Mock(return_value=connection))
    monkeypatch.setattr(helper, "_ip_helper", tables)
    warnings: list[str] = []
    arguments = ([100], warnings) if protocol == "tcp" else ()
    assert getattr(helper, protocol + "_endpoints")(*arguments) == []
    assert not warnings
    tables.assert_not_called()


@pytest.mark.parametrize("result", [0x8004100E, 0x80041010, 0x80041003, 0x80004005])
@pytest.mark.parametrize("operation", ["connect", "query"])
def test_only_absent_namespace_or_class_allows_legacy_fallback(
    helper: ModuleType, monkeypatch: pytest.MonkeyPatch, result: int, operation: str
) -> None:
    error = _wmi_error(result)
    connection = MagicMock()
    connection.__enter__.return_value = connection
    factory = Mock(return_value=connection)
    if operation == "connect":
        factory.side_effect = error
    else:
        connection.query.side_effect = error
    monkeypatch.setattr(helper, "WmiConnection", factory)
    if result in (0x8004100E, 0x80041010):
        assert helper._provider_endpoints("udp") is None
    else:
        with pytest.raises(OSError) as failure:
            helper._provider_endpoints("udp")
        assert failure.value is error


@pytest.mark.parametrize("protocol", ["tcp", "udp"])
def test_ipv6_endpoints_keep_scope_port_and_unsigned_pid(
    helper: ModuleType, monkeypatch: pytest.MonkeyPatch, protocol: str
) -> None:
    address = (ctypes.c_ubyte * 16)(*range(16))
    row_type = helper._Tcp6Row if protocol == "tcp" else helper._Udp6Row
    rows = [
        row_type(
            local_address=address,
            local_scope=19,
            local_port=socket.htons(65535),
            process_id=0xFFFFFFFF,
        )
    ]
    if protocol == "tcp":
        rows[0].state = 2
    library = Mock()
    function = _table_call(_table(rows))
    setattr(library, "GetExtended" + protocol.title() + "Table", function)
    formatter = Mock(return_value="fe80::1%19")
    monkeypatch.setattr(helper, "_ip_helper", lambda: library)
    monkeypatch.setattr(
        helper, "_supports_family", lambda family: family == socket.AF_INET6
    )
    monkeypatch.setattr(helper, "_ipv6_text", formatter)
    expected = {"address": "fe80::1%19", "port": 65535, "pid": 0xFFFFFFFF}
    if protocol == "tcp":
        expected["state"] = 2
    arguments = ([2], []) if protocol == "tcp" else ()
    assert getattr(helper, protocol + "_endpoints")(*arguments) == [expected]
    assert formatter.call_count == 1
    assert bytes(formatter.call_args.args[0]) == bytes(address)
    assert formatter.call_args.args[1] == 19
    assert all(
        item.args[2:] == (False, 23, 5 if protocol == "tcp" else 1, 0)
        for item in function.call_args_list
    )


def test_udp_ipv4_then_ipv6_keep_duplicates_and_zero_pid(
    helper: ModuleType, monkeypatch: pytest.MonkeyPatch
) -> None:
    functions = {
        2: _table_call(_table([helper._UdpRow(0, socket.htons(53), 0)] * 2)),
        23: _table_call(_table([helper._Udp6Row(local_port=socket.htons(443))])),
    }
    library = Mock()
    library.GetExtendedUdpTable.side_effect = lambda *args: functions[args[3]](*args)
    monkeypatch.setattr(helper, "_ip_helper", lambda: library)
    monkeypatch.setattr(helper, "_supports_family", lambda _family: True)
    monkeypatch.setattr(helper, "_ipv6_text", lambda _address, _scope: "::")
    assert helper.udp_endpoints() == [
        {"address": "0.0.0.0", "port": 53, "pid": 0},
        {"address": "0.0.0.0", "port": 53, "pid": 0},
        {"address": "::", "port": 443, "pid": 0},
    ]
    assert all(
        item.args[2] is False and item.args[4:] == (1, 0)
        for item in library.GetExtendedUdpTable.call_args_list
    )
    library.GetExtendedTcpTable.assert_not_called()


@pytest.mark.parametrize("status", [0, 232, 5, 50, 87, 10055])
def test_table_errors_are_not_misreported_as_empty(
    helper: ModuleType, status: int
) -> None:
    function = Mock(return_value=status)
    if status in (0, 232):
        assert helper._table_rows(function, helper._TcpRow, 2, 5) == []
    else:
        with pytest.raises(OSError) as failure:
            helper._table_rows(function, helper._TcpRow, 2, 5)
        assert failure.value.errno == status


def test_empty_allocated_table(helper: ModuleType) -> None:
    assert helper._table_rows(_table_call(_table([])), helper._UdpRow, 2, 1) == []


# This workflow keeps an independent fixture and expected-result oracle.
# pylint: disable=duplicate-code
def test_table_resize_retries_and_rows_own_their_memory(helper: ModuleType) -> None:
    content = _table([helper._TcpRow(state=2, process_id=400)])
    buffers = []

    def _growing(buffer: Any, pointer: Any, *arguments: Any) -> int:
        assert arguments == (False, 2, 5, 0)
        buffers.append(buffer)
        size = ctypes.cast(pointer, ctypes.POINTER(ctypes.c_uint32)).contents
        if len(buffers) < 3:
            size.value = 4 if len(buffers) == 1 else len(content)
            return 122
        ctypes.memmove(buffer, content, len(content))
        return 0

    rows = helper._table_rows(_growing, helper._TcpRow, 2, 5)
    assert len(buffers) == 3
    assert buffers[0] is None
    assert len(buffers[1]) == 4
    assert len(buffers[2]) == len(content)
    ctypes.memset(buffers[2], 0, len(content))
    assert len(rows) == 1
    assert rows[0].state == 2
    assert rows[0].process_id == 400


# pylint: enable=duplicate-code


# This workflow keeps an independent fixture and expected-result oracle.
# pylint: disable=duplicate-code
@pytest.mark.parametrize("scope", [0, 19, 0x12345678])
def test_ipv6_formatter_uses_native_address_and_scope(
    helper: ModuleType, monkeypatch: pytest.MonkeyPatch, scope: int
) -> None:
    library = Mock()
    address = (ctypes.c_ubyte * 16)(*range(16))

    def _format_address(
        pointer: Any, size: int, protocol: Any, output: Any, length: Any
    ) -> int:
        native = ctypes.cast(pointer, ctypes.POINTER(helper._SocketAddress6)).contents
        assert size == 28
        assert native.family == 23
        assert native.port == native.flow == 0
        assert native.scope == scope
        assert bytes(native.address) == bytes(address)
        assert protocol is None
        assert (
            ctypes.cast(length, ctypes.POINTER(ctypes.c_uint32)).contents.value == 256
        )
        output.value = "fe80::1%" + str(scope) if scope else "::1"
        return 0

    library.WSAAddressToStringW.side_effect = _format_address
    monkeypatch.setattr(
        helper.ctypes, "WinDLL", Mock(return_value=library), raising=False
    )
    assert helper._ipv6_text(address, scope) == (
        "fe80::1%" + str(scope) if scope else "::1"
    )
    assert library.WSAAddressToStringW.restype is ctypes.c_int
    library.WSAGetLastError.assert_not_called()


# pylint: enable=duplicate-code


# This workflow keeps an independent fixture and expected-result oracle.
# pylint: disable=duplicate-code
def test_ipv6_formatter_preserves_winsock_failure(
    helper: ModuleType, monkeypatch: pytest.MonkeyPatch
) -> None:
    library = Mock()
    library.WSAAddressToStringW.return_value = -1
    library.WSAGetLastError.return_value = 10022
    monkeypatch.setattr(
        helper.ctypes, "WinDLL", Mock(return_value=library), raising=False
    )
    with pytest.raises(OSError) as failure:
        helper._ipv6_text((ctypes.c_ubyte * 16)(), 0)
    assert failure.value.errno == 10022


# pylint: enable=duplicate-code
