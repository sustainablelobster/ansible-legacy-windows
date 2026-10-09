"""Exercise wait probes without contacting Windows or external services."""

# SPDX-License-Identifier: GPL-3.0-or-later
# Native substitutes establish contracts, not Windows execution evidence.
# pylint: disable=protected-access

import ctypes
import io
import socket
import struct
import threading
from types import ModuleType, SimpleNamespace
from typing import Any
from unittest.mock import Mock, call

import pytest

from tests.unit.payload_support import ROOT, load_module, native_error


@pytest.fixture(name="helper")
def wait_helper(monkeypatch: pytest.MonkeyPatch) -> ModuleType:
    """Import the target helper with portable substitutes for native errors.

    :param monkeypatch: Scoped Windows-only ctypes substitutions.
    :returns: Loaded helper without executing Windows operations.
    """
    monkeypatch.syspath_prepend(str(ROOT / "plugins/module_utils"))
    module = load_module(
        ROOT / "plugins/module_utils/legacy_windows_wait.py", "tested_wait_native"
    )
    monkeypatch.setattr(module.ctypes, "WinError", native_error, raising=False)
    return module


def _table(rows: list[Any]) -> bytes:
    return struct.pack("<I", len(rows)) + b"".join(bytes(row) for row in rows)


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


def test_fixed_native_record_layouts(helper: ModuleType) -> None:
    assert ctypes.sizeof(helper._TcpRow) == 20
    assert ctypes.sizeof(helper._Tcp6Row) == 56
    assert ctypes.sizeof(helper._SocketAddress6) == 28
    assert helper._Tcp6Row.local_scope.offset == 16
    assert helper._Tcp6Row.remote_scope.offset == 40
    assert helper._Tcp6Row.state.offset == 48
    assert helper._SocketAddress6.address.offset == 8
    assert helper._SocketAddress6.scope.offset == 24


def test_non_windows_inspection_is_rejected(
    helper: ModuleType, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(helper, "os", SimpleNamespace(name="posix"))
    with pytest.raises(ValueError, match="requires a Windows target"):
        helper.active_connections()


def test_native_api_signatures(
    helper: ModuleType, monkeypatch: pytest.MonkeyPatch
) -> None:
    library = Mock()
    loader = Mock(return_value=library)
    monkeypatch.setattr(helper, "os", SimpleNamespace(name="nt"))
    monkeypatch.setattr(helper.ctypes, "WinDLL", loader, raising=False)
    assert helper._ip_helper() is library
    loader.assert_called_once_with("iphlpapi", use_last_error=True)
    assert library.GetTcpTable.restype is ctypes.c_uint32
    assert library.GetTcpTable.argtypes == [
        ctypes.c_void_p,
        ctypes.POINTER(ctypes.c_uint32),
        ctypes.c_int,
    ]
    assert library.GetExtendedTcpTable.restype is ctypes.c_uint32
    assert library.GetExtendedTcpTable.argtypes == [
        ctypes.c_void_p,
        ctypes.POINTER(ctypes.c_uint32),
        ctypes.c_int,
        ctypes.c_uint32,
        ctypes.c_int,
        ctypes.c_uint32,
    ]


def test_family_detection_closes_the_unbound_socket(
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


def test_ipv4_connections_exclude_only_listen_and_keep_endpoint_duplicates(
    helper: ModuleType, monkeypatch: pytest.MonkeyPatch
) -> None:
    rows = [
        helper._TcpRow(
            state,
            struct.unpack("<I", socket.inet_aton("192.0.2.7"))[0],
            socket.htons(8080) | 0xFFFF0000,
            struct.unpack("<I", socket.inet_aton("198.51.100.9"))[0],
            socket.htons(30100),
        )
        for state in range(1, 13)
    ]
    library = Mock()
    library.GetTcpTable = _table_call(_table(rows))
    monkeypatch.setattr(helper, "_ip_helper", lambda: library)
    families = Mock(side_effect=lambda family: family == socket.AF_INET)
    monkeypatch.setattr(helper, "_supports_family", families)

    assert helper.active_connections() == [("192.0.2.7", 8080, "198.51.100.9")] * 11

    assert library.GetTcpTable.call_count == 2
    assert all(item.args[2] is True for item in library.GetTcpTable.call_args_list)
    library.GetExtendedTcpTable.assert_not_called()
    assert families.call_args_list == [call(socket.AF_INET), call(socket.AF_INET6)]


def test_ipv6_connections_keep_scopes_and_do_not_format_listeners(
    helper: ModuleType, monkeypatch: pytest.MonkeyPatch
) -> None:
    local = (ctypes.c_ubyte * 16)(*range(16))
    remote = (ctypes.c_ubyte * 16)(*range(16, 32))
    rows = [
        helper._Tcp6Row(local, 9, socket.htons(445), remote, 19, 0, state, 200)
        for state in (2, 5, 11)
    ]
    library = Mock()
    library.GetTcpTable = _table_call(_table([]))
    library.GetExtendedTcpTable = _table_call(_table(rows))
    formatter = Mock(side_effect=lambda address, scope: f"{address[0]}%{scope}")
    monkeypatch.setattr(helper, "_ip_helper", lambda: library)
    monkeypatch.setattr(helper, "_supports_family", lambda _family: True)
    monkeypatch.setattr(helper, "_ipv6_text", formatter)

    assert helper.active_connections() == [("0%9", 445, "16%19")] * 2

    assert formatter.call_count == 4
    assert library.GetExtendedTcpTable.call_count == 2
    assert all(
        item.args[2:] == (True, 23, 5, 0)
        for item in library.GetExtendedTcpTable.call_args_list
    )


def test_ipv4_rows_precede_ipv6_rows(
    helper: ModuleType, monkeypatch: pytest.MonkeyPatch
) -> None:
    library = Mock()
    library.GetTcpTable = _table_call(_table([helper._TcpRow(5, 0, 0, 0, 0)]))
    library.GetExtendedTcpTable = _table_call(
        _table([helper._Tcp6Row(state=5, local_port=socket.htons(443))])
    )
    monkeypatch.setattr(helper, "_ip_helper", lambda: library)
    monkeypatch.setattr(helper, "_supports_family", lambda _family: True)
    monkeypatch.setattr(helper, "_ipv6_text", lambda _address, _scope: "::")
    assert helper.active_connections() == [
        ("0.0.0.0", 0, "0.0.0.0"),
        ("::", 443, "::"),
    ]


@pytest.mark.parametrize("status", [0, 232, 5, 50, 87, 10055])
def test_native_table_status_is_not_misreported_as_drained(
    helper: ModuleType, status: int
) -> None:
    function = Mock(return_value=status)
    if status in (0, 232):
        assert helper._tcp_rows(function, helper._TcpRow) == []
    else:
        with pytest.raises(OSError) as failure:
            helper._tcp_rows(function, helper._TcpRow)
        assert failure.value.errno == status


def test_growing_table_is_read_again_without_retaining_borrowed_memory(
    helper: ModuleType,
) -> None:
    content = _table([helper._TcpRow(5, 0, 0, 0, 0)])
    buffers = []

    def _growing(buffer: Any, pointer: Any, ordered: bool) -> int:
        assert ordered is True
        buffers.append(buffer)
        size = ctypes.cast(pointer, ctypes.POINTER(ctypes.c_uint32)).contents
        if len(buffers) < 3:
            size.value = 4 if len(buffers) == 1 else len(content)
            return 122
        ctypes.memmove(buffer, content, len(content))
        return 0

    rows = helper._tcp_rows(_growing, helper._TcpRow)
    assert len(buffers) == 3
    assert buffers[0] is None
    assert len(buffers[1]) == 4
    assert len(buffers[2]) == len(content)
    ctypes.memset(buffers[2], 0, len(content))
    assert len(rows) == 1
    assert rows[0].state == 5


@pytest.mark.parametrize("scope", [0, 19, 0x12345678])
def test_ipv6_formatter_preserves_native_scope_without_byte_swap(
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
        output.value = f"fe80::1%{scope}"
        return 0

    library.WSAAddressToStringW.side_effect = _format_address
    monkeypatch.setattr(
        helper.ctypes, "WinDLL", Mock(return_value=library), raising=False
    )
    assert helper._ipv6_text(address, scope) == f"fe80::1%{scope}"
    library.WSAGetLastError.assert_not_called()


def test_ipv6_formatting_failure_keeps_winsock_error(
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


@pytest.mark.parametrize(
    ("host", "expected"),
    [
        ("127.0.0.1", "127.0.0.1"),
        ("127.1", "127.0.0.1"),
        ("1", "0.0.0.1"),
        ("0x7f000001", "127.0.0.1"),
        ("::1", "::1"),
        ("[::1]", "::1"),
        ("fe80::1%19", "fe80::1%19"),
    ],
)
def test_literal_resolution_does_not_use_dns(
    helper: ModuleType, monkeypatch: pytest.MonkeyPatch, host: str, expected: str
) -> None:
    resolver = Mock()
    monkeypatch.setattr(helper.socket, "getaddrinfo", resolver)
    monkeypatch.setattr(helper, "_supports_family", lambda _family: False)
    assert helper.resolve_addresses(host) == [expected]
    resolver.assert_not_called()


@pytest.mark.parametrize("host", ["0.0.0.0", "0", "::", "[::]"])
def test_unspecified_addresses_are_not_resolved(helper: ModuleType, host: str) -> None:
    with pytest.raises(ValueError, match="unspecified"):
        helper.resolve_addresses(host)


@pytest.mark.parametrize("host", [None, 1, True, ["127.0.0.1"]])
def test_resolver_requires_frontend_string_conversion(
    helper: ModuleType, host: Any
) -> None:
    with pytest.raises(TypeError, match="must be a string"):
        helper.resolve_addresses(host)


def test_literal_ipv6_uses_native_mapped_address_and_scope_format(
    helper: ModuleType, monkeypatch: pytest.MonkeyPatch
) -> None:
    formatter = Mock(return_value="::ffff:127.0.0.1%19")
    monkeypatch.setattr(helper, "_supports_family", lambda _family: True)
    monkeypatch.setattr(helper, "_ipv6_text", formatter)
    assert helper.resolve_addresses("[::ffff:7f00:1%19]") == ["::ffff:127.0.0.1%19"]
    packed, scope = formatter.call_args.args
    assert bytes(packed) == b"\0" * 10 + b"\xff\xff\x7f\0\0\1"
    assert scope == 19


@pytest.mark.parametrize("host", ["service.example", ""])
def test_dns_resolution_keeps_family_order_and_scope(
    helper: ModuleType, monkeypatch: pytest.MonkeyPatch, host: str
) -> None:
    resolver = Mock(
        return_value=[
            (socket.AF_INET6, socket.SOCK_STREAM, 6, "", ("fe80::1", 0, 0, 19)),
            (socket.AF_INET, socket.SOCK_STREAM, 6, "", ("192.0.2.1", 0)),
            (socket.AF_INET6, socket.SOCK_STREAM, 6, "", ("fe80::1%19", 0, 0, 19)),
        ]
    )
    monkeypatch.setattr(helper.socket, "getaddrinfo", resolver)
    monkeypatch.setattr(helper.socket, "gethostname", lambda: "local.example")
    assert helper.resolve_addresses(host) == ["fe80::1%19", "192.0.2.1", "fe80::1%19"]
    resolver.assert_called_once_with(
        host or "local.example", None, socket.AF_UNSPEC, socket.SOCK_STREAM
    )


def test_dns_failure_remains_available_to_exclusion_warning(
    helper: ModuleType, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(
        helper.socket,
        "getaddrinfo",
        Mock(side_effect=socket.gaierror(11001, "missing")),
    )
    with pytest.raises(OSError) as failure:
        helper.resolve_addresses("missing.example")
    assert failure.value.errno == 11001


@pytest.mark.parametrize(
    ("left", "right", "expected"),
    [
        ("127.0.0.1", "127.1", True),
        ("127.0.0.1", "2130706433", True),
        ("127.0.0.1", "0x7f000001", True),
        ("127.0.0.1", "0177.0.0.1", True),
        ("127.0.0.1", "127.0.0.2", False),
        ("0.0.0.0", "0", True),
        ("::1", "[0:0:0:0:0:0:0:1]", True),
        ("fe80::1%19", "[FE80:0:0:0:0:0:0:1%019]", True),
        ("fe80::1", "fe80::1%0", True),
        ("fe80::1%4294967295", "FE80::1%4294967295", True),
        ("fe80::1%19", "fe80::1%20", False),
        ("fe80::1%19", "fe80::1", False),
        ("fe80::1", "fe80::1%-1", False),
        ("fe80::1", "fe80::1%4294967296", False),
        ("fe80::1", "fe80::1%adapter", False),
        ("fe80::1", "fe80::1%", False),
        ("fe80::1", "fe80::1%1%2", False),
        ("::ffff:127.0.0.1", "::FFFF:7F00:1", True),
        ("127.0.0.1", "::ffff:127.0.0.1", False),
        ("127.0.0.1", " 127.0.0.1", False),
        ("127.0.0.1", "127.0.0.1\t", False),
        ("::1", "::1\n", False),
        ("127.0.0.1", "localhost", False),
        ("127.0.0.1", "127.0.0.1\0", False),
        ("127.0.0.1", "bad\0host", False),
        ("::1", "::1\0", False),
        ("localhost", "localhost", False),
        ("", "", False),
    ],
)
def test_address_identity_is_numeric_family_and_scope_sensitive(
    helper: ModuleType,
    monkeypatch: pytest.MonkeyPatch,
    left: str,
    right: str,
    expected: bool,
) -> None:
    resolver = Mock(side_effect=AssertionError("Address comparison must not use DNS."))
    factory = Mock(side_effect=AssertionError("Address comparison needs no socket."))
    monkeypatch.setattr(helper.socket, "getaddrinfo", resolver)
    monkeypatch.setattr(helper.socket, "socket", factory)

    assert helper.address_matches(left, right) is expected
    assert helper.address_matches(right, left) is expected

    resolver.assert_not_called()
    factory.assert_not_called()


@pytest.mark.parametrize("value", [None, 1, True, b"127.0.0.1", ["127.0.0.1"]])
def test_address_identity_does_not_coerce_non_strings(
    helper: ModuleType, value: Any
) -> None:
    assert helper.address_matches("127.0.0.1", value) is False
    assert helper.address_matches(value, "127.0.0.1") is False


@pytest.mark.parametrize(
    ("host", "port", "message"),
    [
        (None, 1, "must not be null"),
        ("127.0.0.1", -1, "between 0 and 65535"),
        ("127.0.0.1", 65536, "between 0 and 65535"),
        ("0.0.0.0", 1, "unspecified"),
        ("::", 1, "unspecified"),
        ("::1", 1, "IPv4 socket address family"),
        ("[::1]", 1, "IPv4 socket address family"),
        ("::ffff:127.0.0.1", 1, "IPv4 socket address family"),
    ],
)
def test_connect_rejects_invalid_endpoints_before_opening_sockets(
    helper: ModuleType,
    monkeypatch: pytest.MonkeyPatch,
    host: Any,
    port: int,
    message: str,
) -> None:
    factory = Mock()
    monkeypatch.setattr(helper.socket, "socket", factory)
    with pytest.raises(ValueError, match=message):
        helper.port_open(host, port, 1)
    factory.assert_not_called()


@pytest.mark.parametrize(
    ("status", "socket_error", "ready", "expected"),
    [
        (0, 0, True, True),
        (10035, 0, True, True),
        (10035, 10061, True, False),
        (10035, 0, False, False),
    ],
)
# Separate result fields keep each native outcome visible in the case table.
# pylint: disable-next=too-many-arguments,too-many-positional-arguments
def test_connect_results_close_the_socket(
    helper: ModuleType,
    monkeypatch: pytest.MonkeyPatch,
    status: int,
    socket_error: int,
    ready: bool,
    expected: bool,
) -> None:
    client = Mock()
    client.connect_ex.return_value = status
    client.getsockopt.return_value = socket_error
    factory = Mock(return_value=client)
    poll = Mock(return_value=([], [client] if ready else [], []))
    monkeypatch.setattr(helper.socket, "socket", factory)
    monkeypatch.setattr(helper.select, "select", poll)
    monkeypatch.setattr(helper.time, "monotonic", lambda: 10)

    assert helper.port_open("127.0.0.1", 8080, 3) is expected

    factory.assert_called_once_with(socket.AF_INET, socket.SOCK_STREAM)
    client.setblocking.assert_called_once_with(False)
    client.connect_ex.assert_called_once_with(("127.0.0.1", 8080))
    client.close.assert_called_once_with()
    if status:
        poll.assert_called_once_with([], [client], [client], 3)
    else:
        poll.assert_not_called()


def test_exceptional_select_result_uses_socket_error(
    helper: ModuleType, monkeypatch: pytest.MonkeyPatch
) -> None:
    client = Mock()
    client.connect_ex.return_value = 10035
    client.getsockopt.return_value = 10061
    monkeypatch.setattr(helper.socket, "socket", Mock(return_value=client))
    monkeypatch.setattr(helper.select, "select", lambda *_args: ([], [], [client]))
    assert helper.port_open("127.0.0.1", 8080, 3) is False
    client.close.assert_called_once_with()


@pytest.mark.parametrize("timeout", [-1, 2147484])
def test_timeout_validation_follows_connect_and_still_closes_socket(
    helper: ModuleType, monkeypatch: pytest.MonkeyPatch, timeout: int
) -> None:
    client = Mock()
    client.connect_ex.return_value = 10035
    monkeypatch.setattr(helper.socket, "socket", Mock(return_value=client))
    with pytest.raises(ValueError, match="connect_timeout"):
        helper.port_open("127.0.0.1", 8080, timeout)
    client.connect_ex.assert_called_once()
    client.close.assert_called_once()


def test_immediate_connect_error_precedes_invalid_timeout(
    helper: ModuleType, monkeypatch: pytest.MonkeyPatch
) -> None:
    client = Mock()
    client.connect_ex.return_value = 10049
    monkeypatch.setattr(helper.socket, "socket", Mock(return_value=client))
    with pytest.raises(OSError) as failure:
        helper.port_open("127.0.0.1", 0, -1)
    assert failure.value.errno == 10049
    client.close.assert_called_once_with()


def test_socket_is_closed_when_polling_fails(
    helper: ModuleType, monkeypatch: pytest.MonkeyPatch
) -> None:
    client = Mock()
    client.connect_ex.return_value = 10035
    monkeypatch.setattr(helper.socket, "socket", Mock(return_value=client))
    monkeypatch.setattr(helper.select, "select", Mock(side_effect=native_error(10038)))
    with pytest.raises(OSError) as failure:
        helper.port_open("127.0.0.1", 8080, 1)
    assert failure.value.errno == 10038
    client.close.assert_called_once_with()


@pytest.mark.parametrize("operation", ["setblocking", "connect_ex", "getsockopt"])
def test_socket_is_closed_when_a_socket_operation_fails(
    helper: ModuleType, monkeypatch: pytest.MonkeyPatch, operation: str
) -> None:
    client = Mock()
    client.connect_ex.return_value = 10035
    error = native_error(10038)
    getattr(client, operation).side_effect = error
    monkeypatch.setattr(helper.socket, "socket", Mock(return_value=client))
    monkeypatch.setattr(helper.select, "select", lambda *_args: ([], [client], []))

    with pytest.raises(OSError) as failure:
        helper.port_open("127.0.0.1", 8080, 1)

    assert failure.value is error
    client.close.assert_called_once_with()


def test_socket_creation_failure_is_not_reported_as_a_closed_port(
    helper: ModuleType, monkeypatch: pytest.MonkeyPatch
) -> None:
    error = native_error(10055)
    factory = Mock(side_effect=error)
    monkeypatch.setattr(helper.socket, "socket", factory)
    with pytest.raises(OSError) as failure:
        helper.port_open("127.0.0.1", 8080, 1)
    assert failure.value is error
    factory.assert_called_once_with(socket.AF_INET, socket.SOCK_STREAM)


def test_dns_connect_uses_only_ipv4_and_one_remaining_deadline(
    helper: ModuleType, monkeypatch: pytest.MonkeyPatch
) -> None:
    client = Mock()
    client.connect_ex.return_value = 10035
    client.getsockopt.return_value = 0
    monkeypatch.setattr(helper.socket, "socket", Mock(return_value=client))
    monkeypatch.setattr(helper, "resolve_addresses", lambda _host: ["::1", "127.0.0.1"])
    monkeypatch.setattr(helper.time, "monotonic", Mock(side_effect=[10, 12]))
    poll = Mock(return_value=([], [client], []))
    monkeypatch.setattr(helper.select, "select", poll)
    assert helper.port_open("localhost", 8080, 5) is True
    client.connect_ex.assert_called_once_with(("127.0.0.1", 8080))
    poll.assert_called_once_with([], [client], [client], 3)
    client.close.assert_called_once_with()


@pytest.mark.parametrize(
    ("clock", "expected"),
    [([10, 11, 12, 13], True), ([10, 11, 15], False)],
    ids=["second-address-before-deadline", "deadline-after-first-address"],
)
def test_all_resolved_addresses_share_one_connect_deadline(
    helper: ModuleType,
    monkeypatch: pytest.MonkeyPatch,
    clock: list[int],
    expected: bool,
) -> None:
    first = Mock()
    first.connect_ex.return_value = 10035
    first.getsockopt.return_value = 10061
    second = Mock()
    second.connect_ex.return_value = 10035
    second.getsockopt.return_value = 0
    factory = Mock(side_effect=[first, second])
    poll = Mock(side_effect=[([], [first], []), ([], [second], [])])
    monkeypatch.setattr(helper.socket, "socket", factory)
    monkeypatch.setattr(helper.select, "select", poll)
    monkeypatch.setattr(helper.time, "monotonic", Mock(side_effect=clock))
    monkeypatch.setattr(
        helper, "resolve_addresses", lambda _host: ["192.0.2.1", "192.0.2.2"]
    )

    assert helper.port_open("service.example", 8080, 5) is expected

    first.connect_ex.assert_called_once_with(("192.0.2.1", 8080))
    first.close.assert_called_once_with()
    assert poll.call_args_list[0] == call([], [first], [first], 4)
    if expected:
        second.connect_ex.assert_called_once_with(("192.0.2.2", 8080))
        second.close.assert_called_once_with()
        assert poll.call_args_list[1] == call([], [second], [second], 2)
        assert factory.call_count == 2
    else:
        second.connect_ex.assert_not_called()
        assert factory.call_count == 1
        assert poll.call_count == 1


def test_ipv6_only_dns_result_does_not_allocate_an_ipv4_socket(
    helper: ModuleType, monkeypatch: pytest.MonkeyPatch
) -> None:
    factory = Mock()
    monkeypatch.setattr(helper.socket, "socket", factory)
    monkeypatch.setattr(helper, "resolve_addresses", lambda _host: ["::1", "fe80::1%2"])
    assert helper.port_open("ipv6.example", 8080, 1) is False
    factory.assert_not_called()


def test_dns_failure_is_a_closed_port_without_allocating_a_socket(
    helper: ModuleType, monkeypatch: pytest.MonkeyPatch
) -> None:
    factory = Mock()
    monkeypatch.setattr(helper.socket, "socket", factory)
    monkeypatch.setattr(
        helper, "resolve_addresses", Mock(side_effect=socket.gaierror(11001, "missing"))
    )
    assert helper.port_open("missing.example", 8080, 1) is False
    factory.assert_not_called()


@pytest.mark.parametrize("timeout", [0, -1, 2147484])
def test_expired_or_invalid_timeout_cannot_open_a_late_dns_connection(
    helper: ModuleType, monkeypatch: pytest.MonkeyPatch, timeout: int
) -> None:
    entered = threading.Event()
    release = threading.Event()
    exited = threading.Event()

    def _blocked_resolver(_host: str) -> list[str]:
        entered.set()
        try:
            assert release.wait(5)
            return ["127.0.0.1"]
        finally:
            exited.set()

    factory = Mock()
    monkeypatch.setattr(helper.socket, "socket", factory)
    monkeypatch.setattr(helper, "resolve_addresses", _blocked_resolver)
    try:
        if timeout == 0:
            assert helper.port_open("blocked.example", 8080, timeout) is False
        else:
            with pytest.raises(ValueError, match="connect_timeout"):
                helper.port_open("blocked.example", 8080, timeout)
        assert entered.wait(5)
        factory.assert_not_called()
    finally:
        release.set()
        assert exited.wait(5)
    factory.assert_not_called()


def test_dns_worker_is_daemon_and_deferred_resolution_cannot_connect(
    helper: ModuleType, monkeypatch: pytest.MonkeyPatch
) -> None:
    worker = Mock()
    threads = Mock(return_value=worker)
    finished = Mock()
    finished.wait.return_value = False
    resolver = Mock(return_value=["127.0.0.1"])
    factory = Mock()
    monkeypatch.setattr(helper.threading, "Thread", threads)
    monkeypatch.setattr(helper.threading, "Event", Mock(return_value=finished))
    monkeypatch.setattr(helper, "resolve_addresses", resolver)
    monkeypatch.setattr(helper.socket, "socket", factory)

    assert helper.port_open("deferred.example", 8080, 2) is False

    assert worker.daemon is True
    worker.start.assert_called_once_with()
    finished.wait.assert_called_once_with(2)
    resolver.assert_not_called()
    factory.assert_not_called()
    threads.call_args.kwargs["target"]()
    resolver.assert_called_once_with("deferred.example")
    finished.set.assert_called_once_with()
    factory.assert_not_called()


@pytest.mark.parametrize("code", [2, 3, 5, 32, 123])
def test_path_existence_does_not_hide_access_or_name_errors(
    helper: ModuleType, monkeypatch: pytest.MonkeyPatch, code: int
) -> None:
    library = Mock()
    library.GetFileAttributesW.return_value = 0xFFFFFFFF
    monkeypatch.setattr(
        helper.ctypes, "WinDLL", Mock(return_value=library), raising=False
    )
    monkeypatch.setattr(helper.ctypes, "get_last_error", lambda: code, raising=False)
    if code in (2, 3):
        assert helper.path_exists(r"C:\owned\file") is False
    else:
        with pytest.raises(OSError) as failure:
            helper.path_exists(r"C:\owned\file")
        assert failure.value.errno == code
    library.GetFileAttributesW.assert_called_once_with(r"C:\owned\file")


@pytest.mark.parametrize(
    ("path", "attributes"),
    [
        (r"C:\owned\plain-file", 0x80),
        (r"C:\owned\directory", 0x10),
        (r"C:\owned\broken-directory-junction", 0x410),
        (r"C:\owned\broken-file-link", 0x400),
        (r"C:\owned\%literal%\[brackets]", 0),
    ],
)
def test_path_existence_reads_literal_final_entry_without_following_reparse_targets(
    helper: ModuleType,
    monkeypatch: pytest.MonkeyPatch,
    path: str,
    attributes: int,
) -> None:
    library = Mock()
    library.GetFileAttributesW.return_value = attributes
    loader = Mock(return_value=library)
    last_error = Mock(
        side_effect=AssertionError("Successful attributes have no error.")
    )
    follow_target = Mock(side_effect=AssertionError("Do not follow a reparse target."))
    monkeypatch.setattr(helper.ctypes, "WinDLL", loader, raising=False)
    monkeypatch.setattr(helper.ctypes, "get_last_error", last_error, raising=False)
    monkeypatch.setattr(helper.os, "stat", follow_target)

    assert helper.path_exists(path) is True

    loader.assert_called_once_with("kernel32", use_last_error=True)
    library.GetFileAttributesW.assert_called_once_with(path)
    assert library.GetFileAttributesW.argtypes == [ctypes.c_wchar_p]
    assert library.GetFileAttributesW.restype is ctypes.c_uint32
    last_error.assert_not_called()
    follow_target.assert_not_called()


@pytest.mark.parametrize(
    ("content", "expected"),
    [
        (b"", None),
        (b"\xef\xbb\xbf", None),
        (b"\xff\xfe", None),
        (b"\xfe\xff", None),
        (b"\xff\xfe\0\0", None),
        (b"\0\0\xfe\xff", None),
        (b"a\r\n\x80\x81\0", "a\r\n\u20ac\x81\0"),
        (b"\xef\xbb\xbf\xe0\x80\x80\xed\xa0\x80", "\ufffd" * 4),
        ("ready\r\n\u00e9".encode("utf-16"), "ready\r\n\u00e9"),
    ],
)
def test_text_reads_keep_boms_replacement_and_empty_stream_behavior(
    helper: ModuleType,
    monkeypatch: pytest.MonkeyPatch,
    content: bytes,
    expected: str | None,
) -> None:
    stream = io.BytesIO(content)
    opener = Mock(return_value=stream)
    decoder = helper.decode_bytes

    def _decode(raw: bytes, encoding: str) -> str:
        assert encoding == "mbcs"
        return str(decoder(raw, "cp1252"))

    monkeypatch.setattr(helper, "open", opener, raising=False)
    monkeypatch.setattr(helper, "decode_bytes", _decode)
    assert helper.read_text(r"C:\owned\log.txt") == expected
    opener.assert_called_once_with(r"C:\owned\log.txt", "rb")
    assert stream.closed
