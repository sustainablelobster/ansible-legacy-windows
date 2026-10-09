# -*- coding: utf-8 -*-
# Copyright 2026 Joe Lustri
# SPDX-License-Identifier: GPL-3.0-or-later

"""Inspect TCP connections using the network interfaces available on Windows XP."""

import ctypes
import ipaddress
import os
import select
import socket
import struct
import threading
import time

# The action stages this Python 3.4-compatible sibling helper beside the payload.
from legacy_windows_text import decode_bytes  # pylint: disable=import-error


# These records describe the fixed Windows ABI and do not need methods.
class _TcpRow(ctypes.Structure):  # pylint: disable=too-few-public-methods
    _fields_ = [
        ("state", ctypes.c_uint32),
        ("local_address", ctypes.c_uint32),
        ("local_port", ctypes.c_uint32),
        ("remote_address", ctypes.c_uint32),
        ("remote_port", ctypes.c_uint32),
    ]


class _Tcp6Row(ctypes.Structure):  # pylint: disable=too-few-public-methods
    _fields_ = [
        ("local_address", ctypes.c_ubyte * 16),
        ("local_scope", ctypes.c_uint32),
        ("local_port", ctypes.c_uint32),
        ("remote_address", ctypes.c_ubyte * 16),
        ("remote_scope", ctypes.c_uint32),
        ("remote_port", ctypes.c_uint32),
        ("state", ctypes.c_uint32),
        ("process_id", ctypes.c_uint32),
    ]


class _SocketAddress6(ctypes.Structure):  # pylint: disable=too-few-public-methods
    _fields_ = [
        ("family", ctypes.c_uint16),
        ("port", ctypes.c_uint16),
        ("flow", ctypes.c_uint32),
        ("address", ctypes.c_ubyte * 16),
        ("scope", ctypes.c_uint32),
    ]


def _ip_helper():
    if os.name != "nt":
        raise ValueError("TCP connection inspection requires a Windows target.")
    library = ctypes.WinDLL("iphlpapi", use_last_error=True)
    library.GetTcpTable.argtypes = [
        ctypes.c_void_p,
        ctypes.POINTER(ctypes.c_uint32),
        ctypes.c_int,
    ]
    library.GetTcpTable.restype = ctypes.c_uint32
    library.GetExtendedTcpTable.argtypes = [
        ctypes.c_void_p,
        ctypes.POINTER(ctypes.c_uint32),
        ctypes.c_int,
        ctypes.c_uint32,
        ctypes.c_int,
        ctypes.c_uint32,
    ]
    library.GetExtendedTcpTable.restype = ctypes.c_uint32
    return library


def _supports_family(family):
    try:
        probe = socket.socket(family, socket.SOCK_DGRAM)
    except OSError as error:
        if error.errno == 10047:  # WSAEAFNOSUPPORT: the family is not installed.
            return False
        raise
    probe.close()
    return True


def _tcp_rows(function, row_type, *arguments):
    size = ctypes.c_uint32()
    buffer = None
    while True:
        status = function(buffer, ctypes.byref(size), True, *arguments)
        if status == 122:  # Connections may change between the sizing and read calls.
            buffer = ctypes.create_string_buffer(size.value)
            continue
        if status == 232:  # ERROR_NO_DATA also represents an empty table upstream.
            return []
        if status:
            raise ctypes.WinError(status)
        if buffer is None:
            return []
        count = ctypes.c_uint32.from_buffer(buffer).value
        stride = ctypes.sizeof(row_type)
        return [
            row_type.from_buffer_copy(buffer, 4 + index * stride)
            for index in range(count)
        ]


def _ipv6_text(address, scope):
    winsock = ctypes.WinDLL("ws2_32", use_last_error=True)
    winsock.WSAAddressToStringW.argtypes = [
        ctypes.POINTER(_SocketAddress6),
        ctypes.c_uint32,
        ctypes.c_void_p,
        ctypes.c_wchar_p,
        ctypes.POINTER(ctypes.c_uint32),
    ]
    winsock.WSAAddressToStringW.restype = ctypes.c_int
    winsock.WSAGetLastError.argtypes = []
    winsock.WSAGetLastError.restype = ctypes.c_int
    native = _SocketAddress6(23, 0, 0, address, scope)
    text = ctypes.create_unicode_buffer(256)
    size = ctypes.c_uint32(len(text))
    if winsock.WSAAddressToStringW(
        ctypes.byref(native), ctypes.sizeof(native), None, text, ctypes.byref(size)
    ):
        raise ctypes.WinError(winsock.WSAGetLastError())
    return text.value


def active_connections():
    """Read local TCP connections in every state except LISTEN.

    :returns: A list of ``(local_address, local_port, remote_address)`` tuples.
        Addresses are Windows' canonical strings, including IPv6 scope IDs.
        IPv4 rows precede IPv6 rows; each native table is sorted by endpoint.
    :rtype: list
    :raises ValueError: If the target is not Windows.
    :raises OSError: If Windows cannot query an installed address family or
        format an address. An unavailable family and an empty table are omitted.
    """
    library = _ip_helper()
    result = []
    if _supports_family(socket.AF_INET):
        for row in _tcp_rows(library.GetTcpTable, _TcpRow):
            if row.state != 2:
                result.append(
                    (
                        socket.inet_ntoa(struct.pack("<I", row.local_address)),
                        socket.ntohs(row.local_port & 0xFFFF),
                        socket.inet_ntoa(struct.pack("<I", row.remote_address)),
                    )
                )
    if _supports_family(socket.AF_INET6):
        # AF_INET6 is 23 in the Windows ABI; OWNER_PID_ALL is the IPv6 table
        # used upstream because the BASIC table classes support only IPv4.
        for row in _tcp_rows(library.GetExtendedTcpTable, _Tcp6Row, 23, 5, 0):
            if row.state != 2:
                result.append(
                    (
                        _ipv6_text(row.local_address, row.local_scope),
                        socket.ntohs(row.local_port & 0xFFFF),
                        _ipv6_text(row.remote_address, row.remote_scope),
                    )
                )
    return result


def _literal_address(host):
    if "\0" in host or host != host.strip():
        return None
    try:
        packed = socket.inet_aton(host)
    except OSError:
        pass
    else:
        return socket.AF_INET, socket.inet_ntoa(packed)
    candidate = host[1:-1] if host.startswith("[") and host.endswith("]") else host
    pieces = candidate.split("%", 1)
    try:
        address = ipaddress.IPv6Address(pieces[0])
        scope = int(pieces[1]) if len(pieces) == 2 else 0
        if not 0 <= scope <= 0xFFFFFFFF:
            return None
    except ValueError:
        return None
    # Formatting a literal does not require an installed IPv6 stack. A real
    # IPv6 table, in contrast, always uses the native provider's formatter.
    text = str(address)
    if scope:
        text += "%" + str(scope)
    return socket.AF_INET6, text


def address_matches(left, right):
    """Compare numeric IP identities without resolving hostnames.

    :param left: Numeric IPv4 or IPv6 address.
    :type left: str
    :param right: Address spelling to compare, including IPv4 short forms.
    :type right: str
    :returns: Whether both values parse to the same family, address, and scope.
        Non-addresses, whitespace-padded strings, and non-strings return False.
    :rtype: bool
    """
    if not isinstance(left, str) or not isinstance(right, str):
        return False
    first = _literal_address(left)
    return first is not None and first == _literal_address(right)


def resolve_addresses(host):
    """Resolve an exclusion hostname without performing a reverse lookup.

    :param host: Hostname or numeric address; an empty string names this host.
    :type host: str
    :returns: IPv4 and IPv6 address strings, retaining IPv6 numeric scope IDs.
    :rtype: list
    :raises TypeError: If host is not a string.
    :raises ValueError: If host is an unspecified address.
    :raises OSError: If Windows cannot resolve the name or format an address.
    """
    if not isinstance(host, str):
        raise TypeError("The hostname must be a string.")
    literal = _literal_address(host)
    if literal is not None:
        if literal[1] in ("0.0.0.0", "::"):
            raise ValueError("An unspecified IP address cannot be used as a hostname.")
        if literal[0] == socket.AF_INET6 and _supports_family(socket.AF_INET6):
            address, _, scope = literal[1].partition("%")
            packed = ipaddress.IPv6Address(address).packed
            return [_ipv6_text((ctypes.c_ubyte * 16)(*packed), int(scope or "0"))]
        return [literal[1]]
    addresses = socket.getaddrinfo(
        host or socket.gethostname(), None, socket.AF_UNSPEC, socket.SOCK_STREAM
    )
    result = []
    for family, _kind, _protocol, _canonical_name, address in addresses:
        text = address[0]
        if family == socket.AF_INET6 and address[3] and "%" not in text:
            text += "%" + str(address[3])
        result.append(text)
    return result


def _validate_connect_timeout(timeout):
    if timeout < 0 or timeout * 1000 > 2147483647:
        raise ValueError("connect_timeout must be between 0 and 2147483 seconds.")


def _resolve_before(host, timeout):
    finished = threading.Event()
    result = []

    def _resolve():
        try:
            result.append(resolve_addresses(host))
        except (OSError, ValueError, TypeError) as error:
            result.append(error)
        finally:
            finished.set()

    # DNS can outlast a socket timeout. The daemon owns no sockets and cannot
    # initiate a late connection after this attempt has timed out or failed.
    worker = threading.Thread(target=_resolve)
    worker.daemon = True
    worker.start()
    _validate_connect_timeout(timeout)
    if not finished.wait(timeout):
        return []
    if isinstance(result[0], Exception):
        return []
    return result[0]


def _connect_address(client, address, port, deadline, timeout):
    status = client.connect_ex((address, port))
    if status not in (0, 10035):  # WSAEWOULDBLOCK is the ordinary pending result.
        raise ctypes.WinError(status)
    _validate_connect_timeout(timeout)
    if status == 0:
        return True
    remaining = max(0, deadline - time.monotonic())
    _readable, writable, failed = select.select([], [client], [client], remaining)
    return (
        bool(writable or failed)
        and client.getsockopt(socket.SOL_SOCKET, socket.SO_ERROR) == 0
    )


def port_open(host, port, connect_timeout):
    """Try an IPv4 TCP connection within one DNS-and-connect timeout.

    The upstream client uses an IPv4 socket, including for DNS names. Listening
    checks therefore reject IPv6 literals even though drain checks inspect IPv6.

    :param host: Hostname, numeric IPv4 address, or an empty local-host name.
    :type host: str
    :param port: TCP port from zero through 65535.
    :type port: int
    :param connect_timeout: Maximum seconds for DNS resolution and connection.
    :type connect_timeout: int
    :returns: Whether a connection succeeded. DNS failures, connection refusals,
        and expiry of the timeout return False.
    :rtype: bool
    :raises ValueError: For an invalid host, port, address family, or timeout.
    :raises OSError: For a socket creation or immediate connect error.
    """
    if host is None:
        raise ValueError("The host must not be null.")
    if not 0 <= port <= 65535:
        raise ValueError("The port must be between 0 and 65535.")
    literal = _literal_address(host)
    if literal is not None:
        if literal[1] in ("0.0.0.0", "::"):
            raise ValueError("An unspecified IP address cannot be used as a hostname.")
        if literal[0] != socket.AF_INET:
            raise ValueError(
                "The address does not match the IPv4 socket address family."
            )
    deadline = time.monotonic() + connect_timeout
    addresses = [literal[1]] if literal else _resolve_before(host, connect_timeout)
    for address in addresses:
        if ":" in address:
            continue
        client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        try:
            client.setblocking(False)
            if _connect_address(client, address, port, deadline, connect_timeout):
                return True
        finally:
            client.close()
        if time.monotonic() >= deadline:
            break
    return False


def path_exists(path):
    """Check for a literal file or directory while retaining access failures.

    :param path: Validated literal Windows path; final reparse entries are read
        without following their targets.
    :type path: str
    :returns: False only when the file or a parent cannot be found.
    :rtype: bool
    :raises OSError: If metadata cannot be read for another reason.
    """
    kernel = ctypes.WinDLL("kernel32", use_last_error=True)
    kernel.GetFileAttributesW.argtypes = [ctypes.c_wchar_p]
    kernel.GetFileAttributesW.restype = ctypes.c_uint32
    if kernel.GetFileAttributesW(path) == 0xFFFFFFFF:
        error = ctypes.get_last_error()
        if error in (2, 3):
            return False
        raise ctypes.WinError(error)
    return True


def read_text(path):
    """Read a log as BOM-detected text without translating line endings.

    :param path: Literal Windows file path; readers and writers may share it.
    :type path: str
    :returns: Text using the active ANSI code page when no BOM is present.
        An empty decoded stream returns None, like upstream raw Get-Content.
    :rtype: str or None
    :raises OSError: If the file cannot be opened or read.
    """
    with open(path, "rb") as source:
        raw = source.read()
    return decode_bytes(raw, "mbcs") or None
