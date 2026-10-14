# Copyright 2026 sustainablelobster
# SPDX-License-Identifier: GPL-3.0-or-later
"""Initialize and observe Windows routing for a GUID-owned fixture forest trust."""

import ctypes
import json
import sys
import uuid

# The integration fixture stages these exact installed helpers beside this file.
from legacy_ad_ldap import (  # pylint: disable=import-error
    SCOPE_SUBTREE,
    LDAPConnection,
    escape_filter,
)
from legacy_ad_trust_native import (  # pylint: disable=import-error
    TrustPolicy,
    _unicode,
    _UnicodeString,
)


# These structures describe SDK buffers, not objects with application methods.
# pylint: disable=too-few-public-methods
class _ChannelInformation(ctypes.Structure):
    _fields_ = [
        ("flags", ctypes.c_uint32),
        ("verification_status", ctypes.c_uint32),
        ("trusted_dc", ctypes.c_wchar_p),
        ("channel_status", ctypes.c_uint32),
    ]


class _ForestDomain(ctypes.Structure):
    _fields_ = [
        ("sid", ctypes.c_void_p),
        ("dns_name", _UnicodeString),
        ("flat_name", _UnicodeString),
    ]


class _ForestData(ctypes.Union):
    _fields_ = [("name", _UnicodeString), ("domain", _ForestDomain)]


class _ForestRecord(ctypes.Structure):
    _fields_ = [
        ("flags", ctypes.c_uint32),
        ("kind", ctypes.c_uint32),
        ("time", ctypes.c_int64),
        ("data", _ForestData),
    ]


class _ForestInformation(ctypes.Structure):
    _fields_ = [
        ("count", ctypes.c_uint32),
        ("entries", ctypes.POINTER(ctypes.POINTER(_ForestRecord))),
    ]


# pylint: enable=too-few-public-methods


def _network():
    network = ctypes.WinDLL("netapi32", use_last_error=True)
    network.I_NetLogonControl2.argtypes = [
        ctypes.c_wchar_p,
        ctypes.c_uint32,
        ctypes.c_uint32,
        ctypes.c_void_p,
        ctypes.POINTER(ctypes.c_void_p),
    ]
    network.I_NetLogonControl2.restype = ctypes.c_uint32
    network.DsGetForestTrustInformationW.argtypes = [
        ctypes.c_wchar_p,
        ctypes.c_wchar_p,
        ctypes.c_uint32,
        ctypes.POINTER(ctypes.c_void_p),
    ]
    network.DsGetForestTrustInformationW.restype = ctypes.c_uint32
    network.NetApiBufferFree.argtypes = [ctypes.c_void_p]
    network.NetApiBufferFree.restype = ctypes.c_uint32
    return network


def _verify(network, server, partner):
    target = ctypes.c_wchar_p(partner)
    buffer = ctypes.c_void_p()
    result = {}
    try:
        result["winerror"] = network.I_NetLogonControl2(
            server, 10, 2, ctypes.byref(target), ctypes.byref(buffer)
        )
        if result["winerror"] == 0 and buffer:
            information = ctypes.cast(
                buffer, ctypes.POINTER(_ChannelInformation)
            ).contents
            result.update(
                flags=information.flags,
                verification_status=information.verification_status,
                channel_status=information.channel_status,
                trusted_dc=information.trusted_dc,
            )
    finally:
        if buffer:
            network.NetApiBufferFree(buffer)
    return result


def _refresh(network, server, partner):
    buffer = ctypes.c_void_p()
    try:
        # UPDATE_TDO asks Windows to discover/store the real partner topology.
        status = network.DsGetForestTrustInformationW(
            server, partner, 1, ctypes.byref(buffer)
        )
        return {"winerror": status}
    finally:
        if buffer:
            network.NetApiBufferFree(buffer)


def _text(value):
    return ctypes.wstring_at(value.buffer, value.length // 2) if value.buffer else None


def _routing(server, partner):
    with TrustPolicy(server) as policy:
        query = policy.security.LsaQueryForestTrustInformation
        query.argtypes = [
            ctypes.c_void_p,
            ctypes.POINTER(_UnicodeString),
            ctypes.POINTER(ctypes.c_void_p),
        ]
        query.restype = ctypes.c_int32
        name, backing = _unicode(partner)
        buffer = ctypes.c_void_p()
        result = {"records": []}
        try:
            status = query(policy.handle, ctypes.byref(name), ctypes.byref(buffer))
            result["status"] = status & 0xFFFFFFFF
            if status == 0 and buffer:
                information = ctypes.cast(
                    buffer, ctypes.POINTER(_ForestInformation)
                ).contents
                for index in range(information.count):
                    record = information.entries[index].contents
                    item = {"kind": record.kind, "flags": record.flags}
                    if record.kind in (0, 1):
                        item["name"] = _text(record.data.name)
                    elif record.kind == 2:
                        item["name"] = _text(record.data.domain.dns_name)
                    result["records"].append(item)
        finally:
            if buffer:
                policy.security.LsaFreeMemory(buffer)
            del backing
        return result


def _owned_guid(server, partner, object_guid, username, password):
    with LDAPConnection(server, username, password) as connection:
        rows = connection.search(
            connection.naming_context(),
            SCOPE_SUBTREE,
            "(&(objectClass=trustedDomain)(trustPartner="
            + escape_filter(partner)
            + "))",
            ["objectGUID", "trustDirection", "trustType", "trustAttributes"],
        )
        if len(rows) != 1:
            raise ValueError("Expected exactly one acquired local trusted domain.")
        attributes = rows[0]["attributes"]
        observed_guid = str(uuid.UUID(bytes_le=attributes["objectGUID"][0]))
        if observed_guid.lower() != object_guid.lower() or any(
            attributes.get(name) != [value]
            for name, value in (
                ("trustDirection", b"3"),
                ("trustType", b"2"),
                ("trustAttributes", b"8"),
            )
        ):
            raise ValueError("Refuse to prepare an unowned or changed forest trust.")
    return observed_guid


def prepare(server, partner, object_guid, username, password):
    """Verify/refresh only a fixture-owned paired bidirectional forest trust.

    :param str server: Local forest-root PDC DNS name.
    :param str partner: Opposite forest's DNS name.
    :param str object_guid: Independently journaled local TDO GUID.
    :param str username: Credential for the local ownership read.
    :param str password: Credential supplied privately on standard input.
    :returns: Native statuses and enabled root routing readiness, not an
        authentication success claim. No credential is returned.
    :rtype: dict
    :raises ValueError: The observed TDO does not match the acquired GUID/state.
    :raises OSError: Native ownership or security-policy access fails.
    """
    observed_guid = _owned_guid(server, partner, object_guid, username, password)
    network = _network()
    channel = _verify(network, server, partner)
    refresh = _refresh(network, server, partner)
    routing = _routing(server, partner)
    enabled = {
        item["kind"]
        for item in routing["records"]
        if (item.get("name") or "").lower() == partner.lower() and item["flags"] == 0
    }
    ready = (
        channel.get("winerror") == 0
        and channel.get("flags", 0) & 0x80 != 0
        and channel.get("verification_status") == 0
        and channel.get("channel_status") == 0
        and bool(channel.get("trusted_dc"))
        and refresh["winerror"] == 0
        and routing["status"] == 0
        and {0, 2}.issubset(enabled)
    )
    return {
        "server": server,
        "partner": partner,
        "object_guid": observed_guid,
        "channel": channel,
        "refresh": refresh,
        "routing": routing,
        "ready": ready,
    }


if __name__ == "__main__":
    print(json.dumps(prepare(**json.load(sys.stdin))))
