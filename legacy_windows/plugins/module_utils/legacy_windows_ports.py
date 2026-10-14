# -*- coding: utf-8 -*-
# Copyright 2026 sustainablelobster
# SPDX-License-Identifier: GPL-3.0-or-later

"""Read local endpoints through the native network provider or IP Helper."""

import ctypes
import os
import socket
import struct

# The action stages this Python 3.4-compatible sibling helper beside the payload.
from legacy_windows_wmi import WmiConnection  # pylint: disable=import-error


# These fixed-width records describe Windows ABI layouts, not Python objects.
class _TcpRow(ctypes.Structure):  # pylint: disable=too-few-public-methods
    # Repeat the fixed Windows record layout without adding a staging dependency.
    # pylint: disable=duplicate-code
    _fields_ = [
        ("state", ctypes.c_uint32),
        ("local_address", ctypes.c_uint32),
        ("local_port", ctypes.c_uint32),
        ("remote_address", ctypes.c_uint32),
        ("remote_port", ctypes.c_uint32),
        ("process_id", ctypes.c_uint32),
    ]
    # pylint: enable=duplicate-code


class _Tcp6Row(ctypes.Structure):  # pylint: disable=too-few-public-methods
    # Repeat the fixed Windows record layout without adding a staging dependency.
    # pylint: disable=duplicate-code
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
    # pylint: enable=duplicate-code


class _UdpRow(ctypes.Structure):  # pylint: disable=too-few-public-methods
    _fields_ = [
        ("local_address", ctypes.c_uint32),
        ("local_port", ctypes.c_uint32),
        ("process_id", ctypes.c_uint32),
    ]


class _Udp6Row(ctypes.Structure):  # pylint: disable=too-few-public-methods
    _fields_ = [
        ("local_address", ctypes.c_ubyte * 16),
        ("local_scope", ctypes.c_uint32),
        ("local_port", ctypes.c_uint32),
        ("process_id", ctypes.c_uint32),
    ]


class _SocketAddress6(ctypes.Structure):  # pylint: disable=too-few-public-methods
    # Repeat the fixed Windows record layout without adding a staging dependency.
    # pylint: disable=duplicate-code
    _fields_ = [
        ("family", ctypes.c_uint16),
        ("port", ctypes.c_uint16),
        ("flow", ctypes.c_uint32),
        ("address", ctypes.c_ubyte * 16),
        ("scope", ctypes.c_uint32),
    ]
    # pylint: enable=duplicate-code


def _ip_helper():
    if os.name != "nt":
        raise ValueError("Endpoint inspection requires a Windows target.")
    library = ctypes.WinDLL("iphlpapi", use_last_error=True)
    for function in (library.GetExtendedTcpTable, library.GetExtendedUdpTable):
        # Keep this independently staged wrapper's native ABI declarations local.
        # pylint: disable=duplicate-code
        function.argtypes = [
            ctypes.c_void_p,
            ctypes.POINTER(ctypes.c_uint32),
            ctypes.c_int,
            ctypes.c_uint32,
            ctypes.c_int,
            ctypes.c_uint32,
        ]
        function.restype = ctypes.c_uint32
        # pylint: enable=duplicate-code
    return library


def _supports_family(family):
    # Probe installed address families within this independently staged provider.
    # pylint: disable=duplicate-code
    try:
        probe = socket.socket(family, socket.SOCK_DGRAM)
    except OSError as error:
        if error.errno == 10047:  # WSAEAFNOSUPPORT: the family is not installed.
            return False
        raise
    probe.close()
    return True
    # pylint: enable=duplicate-code


def _table_rows(function, row_type, family, table_class):
    # This endpoint table owns its buffer, table class and unsorted native query.
    # pylint: disable=duplicate-code
    size = ctypes.c_uint32()
    buffer = None
    while True:
        status = function(buffer, ctypes.byref(size), False, family, table_class, 0)
        if status == 122:  # Endpoints can change between sizing and reading.
            buffer = ctypes.create_string_buffer(size.value)
            continue
        if status == 232:  # ERROR_NO_DATA denotes an empty table.
            return []
        if status:
            raise ctypes.WinError(status)
        if buffer is None:
            return []
        count = ctypes.c_uint32.from_buffer(buffer).value
        # All owner-PID rows contain only BYTE and DWORD fields. Their DWORD
        # alignment puts the first row directly after the count on x86 and x64.
        stride = ctypes.sizeof(row_type)
        return [
            row_type.from_buffer_copy(buffer, 4 + index * stride)
            for index in range(count)
        ]
    # pylint: enable=duplicate-code


def _ipv6_text(address, scope):
    # Keep Winsock's scoped-address conversion within this endpoint provider.
    # pylint: disable=duplicate-code
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
    # pylint: enable=duplicate-code


def _endpoint(row, family):
    if family == socket.AF_INET:
        address = socket.inet_ntoa(struct.pack("<I", row.local_address))
    else:
        address = _ipv6_text(row.local_address, row.local_scope)
    return {
        "address": address,
        "port": socket.ntohs(row.local_port & 0xFFFF),
        "pid": row.process_id,
    }


def _provider_endpoints(protocol, states=None):
    if os.name != "nt":
        raise ValueError("Endpoint inspection requires a Windows target.")
    properties = ["LocalAddress", "LocalPort", "OwningProcess"]
    if protocol == "tcp":
        properties.append("State")
        class_name = "MSFT_NetTCPConnection"
    else:
        class_name = "MSFT_NetUDPEndpoint"
    query = "SELECT {0} FROM {1}".format(", ".join(properties), class_name)
    if states is not None:
        query += " WHERE " + " OR ".join(
            "State = {0}".format(state) for state in states
        )
    try:
        with WmiConnection(namespace="ROOT\\StandardCimv2") as connection:
            rows = connection.query(query, properties)
    except OSError as error:
        # Older Windows has neither the modern namespace nor its network classes.
        if getattr(error, "hresult", None) in (0x8004100E, 0x80041010):
            return None
        raise
    result = []
    for row in rows:
        endpoint = {
            "address": row["LocalAddress"],
            "port": row["LocalPort"],
            "pid": row["OwningProcess"],
        }
        if protocol == "tcp":
            endpoint["state"] = row["State"]
        result.append(endpoint)
    return result


def tcp_endpoints(states, warnings):
    """Read selected local TCP endpoints and their owning process IDs.

    :param states: Iterable of validated numeric TCP states to select.
    :type states: iterable
    :param warnings: List receiving a warning when legacy Windows cannot expose
        requested Bound endpoints. Other requested states remain available.
    :type warnings: list
    :returns: Dictionaries containing ``address``, ``port``, ``pid``, and
        numeric ``state`` in native provider order, including Bound on modern
        Windows. The legacy fallback keeps IPv4 rows before IPv6 and preserves
        each family's unsorted native table order. Addresses retain native
        IPv6 formatting and scope IDs. Empty selections return an empty list.
    :rtype: list
    :raises ValueError: If the target is not Windows.
    :raises OSError: If the network provider fails, an installed family cannot
        be read, or an IPv6 address cannot be formatted. Uninstalled families
        and empty tables are omitted.
    """
    states = list(states)
    if not states:
        return []
    result = _provider_endpoints("tcp", states)
    if result is not None:
        return result
    if 100 in states:
        warnings.append(
            "Bound TCP endpoints cannot be reported by the legacy Windows "
            "IP Helper API; other requested TCP states remain available."
        )
    library = _ip_helper()
    result = []
    for family, native_family, row_type in (
        (socket.AF_INET, 2, _TcpRow),
        (socket.AF_INET6, 23, _Tcp6Row),
    ):
        if not _supports_family(family):
            continue
        # TCP_TABLE_OWNER_PID_ALL includes every state exposed by IP Helper.
        for row in _table_rows(library.GetExtendedTcpTable, row_type, native_family, 5):
            if row.state in states:
                endpoint = _endpoint(row, family)
                endpoint["state"] = row.state
                result.append(endpoint)
    return result


def udp_endpoints():
    """Read local UDP endpoints and their owning process IDs.

    :returns: Dictionaries containing ``address``, ``port``, and ``pid``.
        Native provider order is retained. On legacy Windows, IPv4 rows precede
        IPv6 rows and each family retains its unsorted native table order.
        Address strings retain native IPv6 formatting and scope IDs.
    :rtype: list
    :raises ValueError: If the target is not Windows.
    :raises OSError: If the network provider fails, an installed family cannot
        be read, or an IPv6 address cannot be formatted. Uninstalled families
        and empty tables are omitted.
    """
    result = _provider_endpoints("udp")
    if result is not None:
        return result
    library = _ip_helper()
    result = []
    for family, native_family, row_type in (
        (socket.AF_INET, 2, _UdpRow),
        (socket.AF_INET6, 23, _Udp6Row),
    ):
        if _supports_family(family):
            # UDP_TABLE_OWNER_PID supplies all local endpoints, including PID 0.
            for row in _table_rows(
                library.GetExtendedUdpTable, row_type, native_family, 1
            ):
                result.append(_endpoint(row, family))
    return result
