# Copyright 2026 Joe Lustri
# SPDX-License-Identifier: GPL-3.0-or-later
"""Read persistent routes and use native IP Helper and Windows route tools."""

import ctypes
import ipaddress
import os
import socket
import subprocess
import sys

try:
    import winreg
except ImportError:
    winreg = None

from legacy_windows_wmi import WmiConnection  # pylint: disable=import-error

_PERSISTENT_ROUTES = (
    r"SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\PersistentRoutes"
)


# This record follows the native IPv4 ABI, not an application object model.
class _ForwardRow(ctypes.Structure):  # pylint: disable=too-few-public-methods
    _fields_ = [
        ("destination", ctypes.c_uint32),
        ("mask", ctypes.c_uint32),
        ("policy", ctypes.c_uint32),
        ("gateway", ctypes.c_uint32),
        ("interface", ctypes.c_uint32),
        ("kind", ctypes.c_uint32),
        ("protocol", ctypes.c_uint32),
        ("age", ctypes.c_uint32),
        ("next_hop_as", ctypes.c_uint32),
        ("metric1", ctypes.c_uint32),
        ("metric2", ctypes.c_uint32),
        ("metric3", ctypes.c_uint32),
        ("metric4", ctypes.c_uint32),
        ("metric5", ctypes.c_uint32),
    ]


def _legacy_add(network, gateway, index):
    # Legacy route.exe rejects zero, but the IP Helper API accepts DWORD metrics.
    row = _ForwardRow(
        destination=ctypes.c_uint32.from_buffer_copy(
            network.network_address.packed
        ).value,
        mask=ctypes.c_uint32.from_buffer_copy(network.netmask.packed).value,
        gateway=ctypes.c_uint32.from_buffer_copy(gateway.packed).value,
        interface=index,
        protocol=3,  # MIB_IPPROTO_NETMGMT
        kind=4 if int(gateway) else 3,
        age=0xFFFFFFFF,
        metric2=0xFFFFFFFF,
        metric3=0xFFFFFFFF,
        metric4=0xFFFFFFFF,
        metric5=0xFFFFFFFF,
    )
    library = ctypes.WinDLL("iphlpapi", use_last_error=True)
    create = library.CreateIpForwardEntry
    create.argtypes, create.restype = [ctypes.POINTER(_ForwardRow)], ctypes.c_uint32
    status = create(ctypes.byref(row))
    if status:
        raise ctypes.WinError(status)
    try:
        name = "{0},{1},{2},0".format(network.network_address, network.netmask, gateway)
        with winreg.CreateKeyEx(
            winreg.HKEY_LOCAL_MACHINE, _PERSISTENT_ROUTES, 0, winreg.KEY_SET_VALUE
        ) as key:
            winreg.SetValueEx(key, name, 0, winreg.REG_SZ, "")
    except OSError as error:
        # Do not leave a newly created active route when its persistence write fails.
        delete = library.DeleteIpForwardEntry
        delete.argtypes, delete.restype = [ctypes.POINTER(_ForwardRow)], ctypes.c_uint32
        status = delete(ctypes.byref(row))
        if status:
            raise OSError(
                "Persistence failed ({0}); active route recovery failed ({1})".format(
                    error, status
                )
            ) from error
        raise


def persistent_routes(destination):
    """Read IPv4 persistent routes matching the original destination string.

    :param str destination: Text before the request's first slash.
    :returns: Matching persistent IPv4 route dictionaries.
    :rtype: list
    :raises OSError: Windows cannot read its persistent routes.
    """
    if getattr(sys, "getwindowsversion")().major < 6:
        # XP/2003 load metric-zero entries at boot but omit them from WMI.
        return _legacy_persistent_routes(destination)
    # Reading all rows avoids interpolating caller-controlled text into WQL.
    with WmiConnection() as connection:
        return [
            row
            for row in connection.query(
                "SELECT * FROM Win32_IP4PersistedRouteTable",
                ["Destination", "Mask", "NextHop", "Metric1"],
            )
            if row["Destination"].lower() == destination.lower()
        ]


def _legacy_persistent_routes(destination):
    try:
        key = winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, _PERSISTENT_ROUTES)
    except FileNotFoundError:
        return []
    rows = []
    with key:
        for index in range(winreg.QueryInfoKey(key)[1]):
            name, _data, kind = winreg.EnumValue(key, index)
            fields = name.split(",")
            if kind != winreg.REG_SZ or len(fields) != 4:
                continue
            address, mask, gateway, metric = fields
            if address.lower() != destination.lower():
                continue
            try:
                ipaddress.IPv4Network(address + "/" + mask)
                ipaddress.IPv4Address(gateway)
                number = int(metric)
                if not 0 <= number <= 0xFFFFFFFF:
                    continue
            except ValueError:
                continue
            rows.append(
                {
                    "Destination": address,
                    "Mask": mask,
                    "NextHop": gateway,
                    "Metric1": number,
                }
            )
    return rows


def _prefix(destination, strict=True):
    if "/" not in destination or not destination.rsplit("/", 1)[1].isdigit():
        raise ValueError("destination must contain an IP address and prefix length")
    return ipaddress.ip_network(destination, strict=strict)


def _interface(gateway):
    family = socket.AF_INET if gateway.version == 4 else socket.AF_INET6
    # sockaddr_in and sockaddr_in6 have a native-endian family and network-endian address.
    size, offset = (16, 4) if gateway.version == 4 else (28, 8)
    address = ctypes.create_string_buffer(size)
    ctypes.c_ushort.from_buffer(address).value = family
    address[offset : offset + len(gateway.packed)] = gateway.packed
    index = ctypes.c_uint32()
    function = ctypes.WinDLL("iphlpapi", use_last_error=True).GetBestInterfaceEx
    function.argtypes = [ctypes.c_void_p, ctypes.POINTER(ctypes.c_uint32)]
    function.restype = ctypes.c_uint32
    status = function(address, ctypes.byref(index))
    if status:
        raise ctypes.WinError(status)
    return index.value


def _command(tool, arguments):
    executable = os.path.join(os.environ["SystemRoot"], "System32", tool + ".exe")
    with subprocess.Popen(
        [executable] + arguments, stdout=subprocess.PIPE, stderr=subprocess.STDOUT
    ) as process:
        output = process.communicate()[0].decode("mbcs", errors="replace").strip()
    if process.returncode:
        raise OSError("{0} failed ({1}): {2}".format(tool, process.returncode, output))
    return output


def prepare_add(destination, gateway):
    """Validate a new route and select the best existing interface to its gateway.

    :param str destination: IPv4 or IPv6 address and decimal prefix length.
    :param str gateway: IP address used to select the interface and next hop.
    :returns: Original prefix text, validated gateway and interface index.
    :rtype: tuple
    :raises ValueError: The prefix or next hop is invalid or has a different family.
    :raises OSError: Windows cannot select an interface through its installed IP stack.
    """
    # New-NetRoute's WhatIf validates syntax but accepts a prefix with host bits.
    network = _prefix(destination, strict=False)
    address = ipaddress.ip_address(gateway)
    if network.version != address.version:
        raise ValueError("destination and gateway must use the same address family")
    return destination, address, _interface(address)


def _legacy_ipv6_duplicate(network, gateway, index):
    # The persistent table reports index zero; the active table establishes the
    # actual interface. Read the prefix and next-hop columns, never other tokens.
    for store in ("persistent", "active"):
        output = _command(
            "netsh", ["interface", "ipv6", "show", "routes", "store=" + store]
        )
        found = False
        for line in output.splitlines():
            fields = line.split()
            if len(fields) < 6:
                continue
            try:
                prefix = ipaddress.ip_network(fields[3])
                next_hop = ipaddress.ip_address(fields[5])
                interface = int(fields[4])
            except ValueError:
                continue
            if (
                prefix == network
                and next_hop == gateway
                and (store == "persistent" or interface == index)
            ):
                found = True
                break
        if not found:
            return False
    return True


def add_route(prepared):
    """Create an active and persistent route using the pinned effective metric zero.

    :param tuple prepared: Original prefix text, validated gateway and interface index.
    :raises OSError: A native interface rejects the active or persistent write.
    :raises ValueError: The actual creation request has host bits in its prefix.
    """
    destination, gateway, index = prepared
    # Unlike WhatIf, the measured setter rejects host bits without writing.
    network = _prefix(destination)
    major = getattr(sys, "getwindowsversion")().major
    if network.version == 6 and major < 6:
        # The older netsh setter silently accepts an identical route. Preserve
        # New-NetRoute's duplicate failure before that setter can update it.
        if _legacy_ipv6_duplicate(network, gateway, index):
            raise OSError("The IPv6 route already exists")
    # The shipped IPv6 netsh backend supports persistence on the older stack,
    # too. Keep only IPv4's distinct legacy metric-zero IP Helper path.
    if network.version == 6 or major >= 6:
        _command(
            "netsh",
            [
                "interface",
                "ipv" + str(network.version),
                "add",
                "route",
                "prefix=" + str(network),
                "interface=" + str(index),
                "nexthop=" + str(gateway),
                "metric=0",
                "store=persistent",
            ],
        )
    else:
        _legacy_add(network, gateway, index)


def prepare_remove(destination):
    """Validate a prefix and find all active IPv4 routes removed by that prefix.

    :param str destination: Canonical prefix from a request with a persistent destination.
    :returns: Validated network and its active IPv4 routes.
    :rtype: tuple
    :raises ValueError: The requested prefix is invalid.
    :raises OSError: Windows cannot read routes or the exact prefix has no active route.
    """
    network = _prefix(destination)
    with WmiConnection() as connection:
        rows = connection.query(
            "SELECT * FROM Win32_IP4RouteTable",
            ["Destination", "Mask", "NextHop", "InterfaceIndex"],
        )
    matching = [
        row
        for row in rows
        if row["Destination"] == str(network.network_address)
        and row["Mask"] == str(network.netmask)
    ]
    if not matching:
        raise OSError("No routes match the requested destination prefix")
    return network, matching


def remove_route(prepared):
    """Remove all routes for the exact prefix, independently of the supplied gateway.

    :param tuple prepared: Validated network and active route identities.
    :raises OSError: The shipped native tool cannot remove a route.
    """
    network, rows = prepared
    if getattr(sys, "getwindowsversion")().major >= 6:
        for row in rows:
            _command(
                "netsh",
                [
                    "interface",
                    "ipv4",
                    "delete",
                    "route",
                    "prefix=" + str(network),
                    "interface=" + str(row["InterfaceIndex"]),
                    "nexthop=" + row["NextHop"],
                    "store=persistent",
                ],
            )
    else:
        _command(
            "route",
            ["delete", str(network.network_address), "mask", str(network.netmask)],
        )
