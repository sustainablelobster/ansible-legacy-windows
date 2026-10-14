# -*- coding: utf-8 -*-
# Copyright 2026 sustainablelobster
# SPDX-License-Identifier: GPL-3.0-or-later

"""Read setup network facts directly from the Windows IP Helper API."""

import ctypes
import ipaddress
import socket
import struct
import sys


# Native SOCKET_ADDRESS includes pointer-alignment padding after its length.
class _SocketAddress(ctypes.Structure):  # pylint: disable=too-few-public-methods
    _fields_ = [("pointer", ctypes.c_void_p), ("length", ctypes.c_int32)]


class _Address(ctypes.Structure):  # pylint: disable=too-few-public-methods
    _fields_ = [
        ("length", ctypes.c_uint32),
        ("flags", ctypes.c_uint32),
        ("next", ctypes.c_void_p),
        ("address", _SocketAddress),
    ]


class _UnicastAddress(ctypes.Structure):  # pylint: disable=too-few-public-methods
    # ctypes fields are the documented public structure declaration protocol.
    _fields_ = _Address._fields_ + [  # pylint: disable=protected-access
        ("prefix_origin", ctypes.c_int32),
        ("suffix_origin", ctypes.c_int32),
        ("dad_state", ctypes.c_int32),
        ("valid_lifetime", ctypes.c_uint32),
        ("preferred_lifetime", ctypes.c_uint32),
        ("lease_lifetime", ctypes.c_uint32),
        ("prefix_length", ctypes.c_uint8),
    ]


class _Prefix(ctypes.Structure):  # pylint: disable=too-few-public-methods
    # IP_ADAPTER_PREFIX uses the same linked SOCKET_ADDRESS header.
    _fields_ = _Address._fields_ + [  # pylint: disable=protected-access
        ("prefix_length", ctypes.c_uint32)
    ]


# The Vista layout ends after gateways for the fields needed by this module.
# Length gates access to extensions that are absent from the XP layout.
class _Adapter(ctypes.Structure):  # pylint: disable=too-few-public-methods
    _fields_ = [
        ("length", ctypes.c_uint32),
        ("index", ctypes.c_uint32),
        ("next", ctypes.c_void_p),
        ("name", ctypes.c_char_p),
        ("unicast", ctypes.c_void_p),
        ("anycast", ctypes.c_void_p),
        ("multicast", ctypes.c_void_p),
        ("dns_servers", ctypes.c_void_p),
        ("dns_suffix", ctypes.c_wchar_p),
        ("description", ctypes.c_wchar_p),
        ("friendly_name", ctypes.c_wchar_p),
        ("physical", ctypes.c_uint8 * 8),
        ("physical_length", ctypes.c_uint32),
        ("flags", ctypes.c_uint32),
        ("mtu", ctypes.c_uint32),
        ("kind", ctypes.c_uint32),
        ("status", ctypes.c_int32),
        ("ipv6_index", ctypes.c_uint32),
        ("zones", ctypes.c_uint32 * 16),
        ("prefixes", ctypes.c_void_p),
        ("transmit_speed", ctypes.c_uint64),
        ("receive_speed", ctypes.c_uint64),
        ("wins", ctypes.c_void_p),
        ("gateways", ctypes.c_void_p),
    ]


class _IpAddressString(ctypes.Structure):  # pylint: disable=too-few-public-methods
    _fields_ = [
        ("next", ctypes.c_void_p),
        ("address", ctypes.c_char * 16),
        ("mask", ctypes.c_char * 16),
        ("context", ctypes.c_uint32),
    ]


class _LegacyAdapter(ctypes.Structure):  # pylint: disable=too-few-public-methods
    # Only this fixed prefix is read; the trailing lease time_t differs by ABI.
    _fields_ = [
        ("next", ctypes.c_void_p),
        ("combo_index", ctypes.c_uint32),
        ("name", ctypes.c_char * 260),
        ("description", ctypes.c_char * 132),
        ("physical_length", ctypes.c_uint32),
        ("physical", ctypes.c_uint8 * 8),
        ("index", ctypes.c_uint32),
        ("kind", ctypes.c_uint32),
        ("dhcp", ctypes.c_uint32),
        ("current_address", ctypes.c_void_p),
        ("addresses", _IpAddressString),
        ("gateways", _IpAddressString),
    ]


class _InterfaceRow(ctypes.Structure):  # pylint: disable=too-few-public-methods
    _fields_ = (
        [
            ("name", ctypes.c_uint16 * 256),
            ("index", ctypes.c_uint32),
            ("kind", ctypes.c_uint32),
            ("mtu", ctypes.c_uint32),
            ("speed", ctypes.c_uint32),
            ("physical_length", ctypes.c_uint32),
            ("physical", ctypes.c_uint8 * 8),
        ]
        + [
            (name, ctypes.c_uint32)
            for name in (
                "admin_status",
                "status",
                "last_change",
                "in_octets",
                "in_unicast",
                "in_non_unicast",
                "in_discards",
                "in_errors",
                "in_unknown",
                "out_octets",
                "out_unicast",
                "out_non_unicast",
                "out_discards",
                "out_errors",
                "out_queue_length",
                "description_length",
            )
        ]
        + [("description", ctypes.c_uint8 * 256)]
    )


class _FixedInfo(ctypes.Structure):  # pylint: disable=too-few-public-methods
    _fields_ = [
        ("hostname", ctypes.c_char * 132),
        ("domain", ctypes.c_char * 132),
        ("current_dns", ctypes.c_void_p),
        ("dns", _IpAddressString),
        ("node_type", ctypes.c_uint32),
        ("scope", ctypes.c_char * 260),
        ("routing", ctypes.c_uint32),
        ("proxy", ctypes.c_uint32),
        ("dns_enabled", ctypes.c_uint32),
    ]


def _socket_text(address):
    raw = ctypes.string_at(address.pointer, address.length)
    family = struct.unpack_from("<H", raw)[0]
    if family == 2:
        return family, socket.inet_ntop(socket.AF_INET, raw[4:8])
    if family == 23:
        text = socket.inet_ntop(socket.AF_INET6, raw[8:24])
        scope = struct.unpack_from("<I", raw, 24)[0]
        if scope:
            text += "%" + str(scope)
        return family, text
    raise OSError("IP Helper returned an unsupported socket address family.")


def _unicast(pointer):
    values = []
    while pointer:
        entry = ctypes.cast(pointer, ctypes.POINTER(_UnicastAddress)).contents
        family, text = _socket_text(entry.address)
        prefix = None
        if entry.length > _UnicastAddress.prefix_length.offset:
            prefix = str(entry.prefix_length)
        values.append((family, text, prefix))
        pointer = entry.next
    return values


def _legacy_prefixes(pointer, addresses):
    networks = []
    while pointer:
        entry = ctypes.cast(pointer, ctypes.POINTER(_Prefix)).contents
        family, text = _socket_text(entry.address)
        networks.append(
            (
                family,
                ipaddress.ip_network(
                    text.split("%", 1)[0] + "/" + str(entry.prefix_length), strict=False
                ),
            )
        )
        pointer = entry.next
    result = []
    # Prefix and unicast lists are independent; never associate them by position.
    for family, text, prefix in addresses:
        if prefix is None:
            address = ipaddress.ip_address(text.split("%", 1)[0])
            matches = [
                network.prefixlen
                for kind, network in networks
                if kind == family and address in network
            ]
            if matches:
                prefix = str(max(matches))
        result.append((family, text, prefix))
    return result


def _legacy_gateways(library):
    read = library.GetAdaptersInfo
    read.argtypes = [ctypes.c_void_p, ctypes.POINTER(ctypes.c_uint32)]
    read.restype = ctypes.c_uint32
    size = ctypes.c_uint32(16384)
    while True:
        buffer = ctypes.create_string_buffer(size.value)
        code = read(buffer, ctypes.byref(size))
        if code == 111:
            continue
        if code == 232:
            return {}
        if code:
            raise ctypes.WinError(code)
        break
    gateways = {}
    pointer = ctypes.addressof(buffer)
    while pointer:
        adapter = ctypes.cast(pointer, ctypes.POINTER(_LegacyAdapter)).contents
        address = adapter.gateways.address.decode("ascii")
        gateways[adapter.index] = address if address not in ("", "0.0.0.0") else None
        pointer = adapter.next
    return gateways


def _legacy_speed(library, index):
    read = library.GetIfEntry
    read.argtypes = [ctypes.POINTER(_InterfaceRow)]
    read.restype = ctypes.c_uint32
    row = _InterfaceRow(index=index)
    code = read(ctypes.byref(row))
    if code:
        raise ctypes.WinError(code)
    return row.speed // 1000000 if row.speed % 1000000 == 0 else row.speed / 1000000


def _adapters():
    library = ctypes.WinDLL("iphlpapi", use_last_error=True)
    read = library.GetAdaptersAddresses
    read.argtypes = [
        ctypes.c_uint32,
        ctypes.c_uint32,
        ctypes.c_void_p,
        ctypes.c_void_p,
        ctypes.POINTER(ctypes.c_uint32),
    ]
    read.restype = ctypes.c_uint32
    version = sys.getwindowsversion()  # pylint: disable=no-member
    flags = 2 | 4 | 8 | 16
    if version.major >= 6:
        flags |= 128
    size = ctypes.c_uint32(16384)
    while True:
        buffer = ctypes.create_string_buffer(size.value)
        code = read(0, flags, None, buffer, ctypes.byref(size))
        if code == 111:
            continue
        if code == 232:
            return []
        if code:
            raise ctypes.WinError(code)
        break
    pointer = ctypes.addressof(buffer)
    rows = []
    while pointer:
        adapter = ctypes.cast(pointer, ctypes.POINTER(_Adapter)).contents
        gateway = None
        modern = adapter.length >= _Adapter.gateways.offset + ctypes.sizeof(
            ctypes.c_void_p
        )
        if modern and adapter.gateways:
            gateway_entry = ctypes.cast(
                adapter.gateways, ctypes.POINTER(_Address)
            ).contents
            _, gateway = _socket_text(gateway_entry.address)
        addresses = _unicast(adapter.unicast)
        if not modern:
            # Legacy records can include padding at Vista's prefix byte offset.
            # Only the separate XP prefix list supplies meaningful prefix data.
            addresses = _legacy_prefixes(
                adapter.prefixes,
                [(family, text, None) for family, text, _ in addresses],
            )
        rows.append(
            {
                "connection_name": adapter.friendly_name,
                "interface_name": adapter.description,
                "interface_index": adapter.index or adapter.ipv6_index,
                "dns_domain": adapter.dns_suffix or None,
                "default_gateway": gateway,
                "macaddress": ":".join(
                    "{0:02X}".format(value)
                    for value in adapter.physical[: adapter.physical_length]
                ),
                "mtu": adapter.mtu if adapter.index else None,
                "speed": (
                    adapter.transmit_speed // 1000000
                    if modern and adapter.transmit_speed % 1000000 == 0
                    else adapter.transmit_speed / 1000000 if modern else None
                ),
                "kind": adapter.kind,
                "modern": modern,
                "addresses": addresses,
            }
        )
        pointer = adapter.next
    return rows


def _pipeline(values):
    return values[0] if len(values) == 1 else values or None


def read_addresses():
    """Read all interface unicast addresses in native enumeration order.

    :returns: Ordered address strings, excluding the two loopback addresses.
    :rtype: list[str]
    :raises OSError: IP Helper enumeration fails.
    """
    return [
        text
        for adapter in _adapters()
        for _, text, _ in adapter["addresses"]
        if text not in ("127.0.0.1", "::1")
    ]


def read_interfaces():
    """Read released setup interface fields with scalar-or-array IP projections.

    :returns: Ordered interface dictionaries, excluding loopback/tunnel interfaces.
    :rtype: list[dict]
    :raises OSError: IP Helper enumeration fails or an address has no native prefix.
    """
    result = []
    library, gateways = None, None
    for adapter in _adapters():
        if adapter["kind"] in (24, 131) or not adapter["interface_index"]:
            continue
        if any(prefix is None for _, _, prefix in adapter["addresses"]):
            raise OSError(
                "Windows returned a unicast address without a matching prefix."
            )
        row = {
            key: value
            for key, value in adapter.items()
            if key not in ("kind", "modern", "addresses")
        }
        if not adapter["modern"]:
            if library is None:
                library = ctypes.WinDLL("iphlpapi", use_last_error=True)
                gateways = _legacy_gateways(library)
            row["default_gateway"] = gateways.get(adapter["interface_index"])
            row["speed"] = _legacy_speed(library, adapter["interface_index"])
        for family, field in ((2, "ipv4"), (23, "ipv6")):
            row[field] = _pipeline(
                [
                    {"address": text, "prefix": prefix}
                    for kind, text, prefix in adapter["addresses"]
                    if kind == family
                ]
            )
        result.append(row)
    return result


def host_information():
    """Read IPGlobalProperties-compatible hostname and DNS suffix.

    :returns: Native hostname and domain strings, retaining their spelling.
    :rtype: tuple[str, str]
    :raises OSError: Windows cannot read its network parameters.
    """
    library = ctypes.WinDLL("iphlpapi", use_last_error=True)
    read = library.GetNetworkParams
    read.argtypes = [ctypes.c_void_p, ctypes.POINTER(ctypes.c_uint32)]
    read.restype = ctypes.c_uint32
    size = ctypes.c_uint32(ctypes.sizeof(_FixedInfo))
    while True:
        buffer = ctypes.create_string_buffer(size.value)
        code = read(buffer, ctypes.byref(size))
        if code == 111:
            continue
        if code:
            raise ctypes.WinError(code)
        info = _FixedInfo.from_buffer(buffer)
        return info.hostname.decode("mbcs"), info.domain.decode("mbcs")
