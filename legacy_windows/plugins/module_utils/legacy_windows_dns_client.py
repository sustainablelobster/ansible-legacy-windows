# -*- coding: utf-8 -*-
# Copyright 2026 sustainablelobster
# SPDX-License-Identifier: GPL-3.0-or-later

"""Read DNS settings and change them through native Windows interfaces."""

import ctypes
import fnmatch
import ipaddress
import os
import re
import subprocess
import uuid

try:
    import winreg
except ImportError:
    winreg = None

from legacy_windows_wmi import WmiConnection  # pylint: disable=import-error

TCPIP = r"SYSTEM\CurrentControlSet\Services\Tcpip\Parameters"
_POLICY = r"SOFTWARE\Policies\Microsoft\Windows NT\DNSClient"


# Native records describe the Windows ABI rather than application objects.
# pylint: disable=too-few-public-methods
class _Guid(ctypes.Structure):
    # Only the opaque UUID bytes are used; GUID's native alignment is four.
    _fields_ = [("parts", ctypes.c_uint32 * 4)]


class _InterfaceSettings(ctypes.Structure):
    _fields_ = [
        ("version", ctypes.c_uint32),
        ("flags", ctypes.c_uint64),
        ("domain", ctypes.c_wchar_p),
        ("servers", ctypes.c_wchar_p),
        ("search_list", ctypes.c_wchar_p),
        ("registration", ctypes.c_uint32),
        ("register_name", ctypes.c_uint32),
        ("llmnr", ctypes.c_uint32),
        ("query_name", ctypes.c_uint32),
        ("profile_servers", ctypes.c_wchar_p),
    ]


# pylint: enable=too-few-public-methods


def _values(path, names):
    if winreg is None:
        raise OSError("DNS client operations require a Windows target.")
    try:
        key = winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, path)
    except FileNotFoundError:
        return None
    with key:
        result = {}
        for name in names:
            try:
                result[name] = winreg.QueryValueEx(key, name)[0]
            except FileNotFoundError:
                result[name] = None
    return result


def _addresses(value, binary=False):
    if not value:
        return []
    if binary:
        return [
            str(ipaddress.ip_address(value[index : index + 16]))
            for index in range(0, len(value), 16)
        ]
    texts = value.strip("\0").replace(";", ",").replace(" ", ",").split(",")
    return [str(ipaddress.ip_address(text)) for text in texts if text]


def _families(guid):
    families = []
    for version, service, dhcp_name in (
        (4, "Tcpip", "DhcpNameServer"),
        (6, "Tcpip6", "Dhcpv6DNSServers"),
    ):
        path = r"SYSTEM\CurrentControlSet\Services\{0}\Parameters\Interfaces\{1}"
        values = _values(
            path.format(service, guid), ("NameServer", dhcp_name, "EnableDHCP")
        )
        if values is None:
            continue
        static = values["NameServer"]
        servers = _addresses(static or values[dhcp_name], not static and version == 6)
        families.append(
            {
                "version": version,
                "servers": servers,
                "dhcp": bool(values["EnableDHCP"]) and not bool(static),
                "bad_format": bool(static and (";" in static or " " in static)),
            }
        )
    return families


def read_adapters(names):
    """Find named IP-enabled adapters and read each address family's DNS state.

    :param list names: Adapter captions or wildcard patterns, in request order.
    :returns: Adapter dictionaries with identity and per-family DNS settings.
    :rtype: list
    :raises OSError: WMI or the DNS registry configuration is inaccessible.
    :raises ValueError: A requested exact adapter is absent or a server is invalid.
    """
    with WmiConnection() as connection:
        adapters = connection.query(
            "SELECT DeviceID, NetConnectionID FROM Win32_NetworkAdapter",
            ["DeviceID", "NetConnectionID"],
        )
        configurations = connection.query(
            "SELECT Index, SettingID FROM Win32_NetworkAdapterConfiguration WHERE IPEnabled=TRUE",
            ["Index", "SettingID", "__PATH"],
        )
    configurations = {str(row["Index"]): row for row in configurations}
    selected = []
    for pattern in names:
        matched = []
        for adapter in adapters:
            caption = adapter["NetConnectionID"]
            configuration = configurations.get(adapter["DeviceID"])
            if caption is None or configuration is None:
                continue
            if fnmatch.fnmatchcase(caption.lower(), pattern.lower()):
                matched.append(
                    {
                        "name": caption,
                        "guid": configuration["SettingID"],
                        "path": configuration["__PATH"],
                        "families": _families(configuration["SettingID"]),
                    }
                )
        if not matched and "*" not in pattern:
            raise ValueError(
                "Get-NetAdapterInfo: Failed to find network adapter(s) that are IP enabled "
                "with the name '{0}'".format(pattern)
            )
        selected.extend(matched)
    return selected


def read_suffixes():
    """Read the ordered global suffix search list, respecting policy precedence.

    :returns: Configured DNS suffix strings in stored order.
    :rtype: list
    :raises OSError: The DNS configuration is inaccessible.
    """
    policy = _values(_POLICY, ("SearchList",))
    values = (
        policy
        if policy and policy["SearchList"] is not None
        else _values(TCPIP, ("SearchList",))
    )
    text = values["SearchList"] if values else None
    return text.split(",") if text else []


def _set_interface(guid, servers):
    library = ctypes.WinDLL("iphlpapi")
    setter = getattr(library, "SetInterfaceDnsSettings", None)
    if setter is None:
        return False
    setter.restype = ctypes.c_uint32
    setter.argtypes = [_Guid, ctypes.POINTER(_InterfaceSettings)]
    identity = _Guid.from_buffer_copy(uuid.UUID(guid).bytes_le)
    for version in (4, 6):
        text = ",".join(
            value for value in servers if ipaddress.ip_address(value).version == version
        )
        # The pinned cmdlet only updates supplied families unless resetting all DNS.
        if servers and not text:
            continue
        settings = _InterfaceSettings(version=1, flags=2 | (version == 6), servers=text)
        status = setter(identity, ctypes.byref(settings))
        if status:
            raise OSError(
                "SetInterfaceDnsSettings failed (Win32 error {0}).".format(status)
            )
    return True


def _run_ipv6_netsh(executable, command):
    with subprocess.Popen(
        [executable, "interface", "ipv6"] + command,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
    ) as process:
        output = process.communicate()[0].decode("mbcs", errors="replace").strip()
    if process.returncode:
        raise OSError(
            "netsh IPv6 DNS configuration failed ({0}): {1}".format(
                process.returncode, output
            )
        )
    return output


def _ipv6_dns_command(executable, operation):
    # Command and parameter names stay invariant in localized netsh help.
    listing = _run_ipv6_netsh(executable, [operation, "/?"])
    for line in listing.splitlines():
        words = line.lower().split()
        if (
            len(words) > 1
            and words[0] == operation
            and words[1] in ("dnsserver", "dnsservers")
        ):
            command = words[1]
            details = _run_ipv6_netsh(executable, [operation, command, "/?"])
            validation = re.search(r"(?:\[|\s)validate(?:=|\])", details, re.I)
            return command, bool(validation)
    raise OSError("Installed netsh has no IPv6 DNS '{0}' command.".format(operation))


def _set_ipv6_servers(adapter, servers):
    executable = os.path.join(os.environ["SystemRoot"], "System32", "netsh.exe")
    set_command, validate_set = _ipv6_dns_command(executable, "set")
    add_command, validate_add = (
        _ipv6_dns_command(executable, "add") if len(servers) > 1 else (None, False)
    )
    commands = [
        (
            ["set", set_command, "name=" + adapter["name"], "source=dhcp"]
            if not servers
            else [
                "set",
                set_command,
                "name=" + adapter["name"],
                "source=static",
                "address=" + servers[0],
            ]
            + (["validate=no"] if validate_set else [])
        )
    ]
    commands.extend(
        [
            "add",
            add_command,
            "name=" + adapter["name"],
            "address=" + address,
            "index=" + str(index),
        ]
        + (["validate=no"] if validate_add else [])
        for index, address in enumerate(servers[1:], 2)
    )
    for command in commands:
        _run_ipv6_netsh(executable, command)


def write_servers(adapter, servers):
    """Set ordered DNS addresses, or reset the adapter's static configuration.

    :param dict adapter: Adapter identity returned by read_adapters.
    :param list servers: IP address strings; an empty list resets static DNS.
        Nonempty requests leave omitted address families unchanged.
    :raises OSError: The native API, IPv6 network tool, or WMI setter fails.
    :raises ValueError: IPv6 is requested on an adapter without IPv6 settings.
    """
    if os.name != "nt":
        raise OSError("DNS client operations require a Windows target.")
    if _set_interface(adapter["guid"], servers):
        return
    ipv4 = [value for value in servers if ipaddress.ip_address(value).version == 4]
    ipv6 = [value for value in servers if ipaddress.ip_address(value).version == 6]
    has_ipv6 = any(family["version"] == 6 for family in adapter["families"])
    if ipv6 and not has_ipv6:
        raise ValueError("The selected adapter has no IPv6 DNS configuration.")
    # Apply IPv6 first so an unavailable legacy command cannot alter IPv4.
    if ipv6 or (not servers and has_ipv6):
        _set_ipv6_servers(adapter, ipv6)
    if servers and not ipv4:
        return
    with WmiConnection() as connection:
        result = connection.call_method(
            adapter["path"],
            "SetDNSServerSearchOrder",
            ["ReturnValue"],
            {"DNSServerSearchOrder": ipv4} if ipv4 else {},
        )
    if result["ReturnValue"] != 0:
        raise OSError(
            "Set-DnsClientServerAddressLegacy: Error calling SetDNSServerSearchOrder, "
            "code {0})".format(result["ReturnValue"])
        )


def write_suffixes(suffixes):
    """Set the machine-wide ordered DNS suffix search list.

    :param list suffixes: Ordered suffix strings; an empty list clears the list.
    :raises OSError: The WMI provider cannot apply the setting.
    """
    with WmiConnection() as connection:
        result = connection.call_method(
            "Win32_NetworkAdapterConfiguration",
            "SetDNSSuffixSearchOrder",
            ["ReturnValue"],
            {"DNSDomainSuffixSearchOrder": suffixes},
        )
    if result["ReturnValue"] != 0:
        raise OSError(
            "SetDNSSuffixSearchOrder failed (code {0}).".format(result["ReturnValue"])
        )
