# Copyright 2026 sustainablelobster
# SPDX-License-Identifier: GPL-3.0-or-later

"""Manage directory-owned KDS root keys through signed and sealed WinLDAP."""

import datetime
import os
import re
import struct
import uuid

from legacy_ad_arguments import as_int32  # pylint: disable=import-error
from legacy_ad_ldap import (  # pylint: disable=import-error
    SCOPE_BASE,
    SCOPE_SUBTREE,
    LDAPConnection,
    LDAPError,
    escape_filter,
)
from legacy_windows_module import as_bool, as_string  # pylint: disable=import-error

EMPTY_GUID = "00000000-0000-0000-0000-000000000000"
_EPOCH = datetime.datetime(1601, 1, 1)
_TICKS_PER_HOUR = 36000000000
_METADATA = ("cn", "msKds-CreateTime", "msKds-UseStartTime", "msKds-Version")
_CONFIGURATION = (
    "msKds-Version",
    "msKds-KDFAlgorithmID",
    "msKds-KDFParam",
    "msKds-SecretAgreementAlgorithmID",
    "msKds-SecretAgreementParam",
    "msKds-PublicKeyLength",
    "msKds-PrivateKeyLength",
)

# These are the public group parameters, not secret keys or a DH implementation.
# MS-GKDI 3.1.4.1.1 specifies RFC 5114 section 2.3 as the default group.
_DH_PRIME = bytes.fromhex(
    "87A8E61D B4B6663C FFBBD19C 65195999 8CEEF608 660DD0F2 "
    "5D2CEED4 435E3B00 E00DF8F1 D61957D4 FAF7DF45 61B2AA30 "
    "16C3D911 34096FAA 3BF4296D 830E9A7C 209E0C64 97517ABD "
    "5A8A9D30 6BCF67ED 91F9E672 5B4758C0 22E0B1EF 4275BF7B "
    "6C5BFC11 D45F9088 B941F54E B1E59BB8 BC39A0BF 12307F5C "
    "4FDB70C5 81B23F76 B63ACAE1 CAA6B790 2D525267 35488A0E "
    "F13C6D9A 51BFA4AB 3AD83477 96524D8E F6A167B5 A41825D9 "
    "67E144E5 14056425 1CCACB83 E6B486F6 B3CA3F79 71506026 "
    "C0B857F6 89962856 DED4010A BD0BE621 C3A3960A 54E710C3 "
    "75F26375 D7014103 A4B54330 C198AF12 6116D227 6E11715F "
    "693877FA D7EF09CA DB094AE9 1E1A1597"
)
_DH_GENERATOR = bytes.fromhex(
    "3FB32C9B 73134D0B 2E775066 60EDBD48 4CA7B18F 21EF2054 "
    "07F4793A 1A0BA125 10DBC150 77BE463F FF4FED4A AC0BB555 "
    "BE3A6C1B 0C6B47B1 BC3773BF 7E8C6F62 901228F8 C28CBB18 "
    "A55AE313 41000A65 0196F931 C77A57F2 DDF463E5 E9EC144B "
    "777DE62A AAB8A862 8AC376D2 82D6ED38 64E67982 428EBC83 "
    "1D14348F 6F2F9193 B5045AF2 767164E1 DFC967C1 FB3F2E55 "
    "A4BD1BFF E83B9C80 D052B985 D182EA0A DB2A3B73 13D3FE14 "
    "C8484B1E 052588B9 B7D2BBD2 DF016199 ECD06E15 57CD0915 "
    "B3353BBB 64E0EC37 7FD02837 0DF92B52 C7891428 CDC67EB6 "
    "184B523D 1DB246C3 2F630784 90F00EF8 D647D148 D4795451 "
    "5E2327CF EF98C582 664B4C0F 6CC41659"
)


def kds_arguments(raw, information=False):
    """Validate the released KDS interfaces without adding connection options.

    :param raw: Arguments from the public JSON payload.
    :type raw: dict
    :param information: Whether the read-only information interface is selected.
    :type information: bool
    :returns: Normalized KDS options and check-mode flag.
    :rtype: dict
    :raises ValueError: If option values or required combinations are invalid.
    """
    arguments = {
        "key_id": as_string(raw.get("key_id"), "key_id"),
        "check_mode": as_bool(raw.get("_ansible_check_mode", False), "check_mode"),
    }
    if information:
        return arguments
    for name, default, choices in (
        ("state", "present", ("present", "absent")),
        ("match_by", "any", ("any", "key_id", "never")),
    ):
        value = as_string(raw.get(name, default), name)
        value = value.lower() if value is not None else None
        if value not in choices:
            raise ValueError(name + " must be one of: " + ", ".join(choices) + ".")
        arguments[name] = value
    arguments["effective_time_hours"] = as_int32(
        raw.get("effective_time_hours", 10), "effective_time_hours"
    )
    if (
        arguments["state"] == "absent" or arguments["match_by"] == "key_id"
    ) and arguments["key_id"] is None:
        raise ValueError("key_id is required for state=absent or match_by=key_id.")
    return arguments


def _raw(entry):
    return {name.lower(): values for name, values in entry["attributes"].items()}


def _value(entry, attribute):
    values = _raw(entry).get(attribute.lower(), [])
    if len(values) != 1:
        raise ValueError("The directory did not return readable " + attribute + ".")
    return values[0]


def _root_container(connection):
    service = (
        "CN=Group Key Distribution Service,CN=Services,"
        + connection.naming_context("configurationNamingContext")
    )
    container = "CN=Master Root Keys," + service
    try:
        rows = connection.search(
            container, SCOPE_BASE, "(objectClass=container)", ["cn"]
        )
    except LDAPError as error:
        if error.errno != 32:
            raise
        rows = []
    if len(rows) != 1:
        raise ValueError("The directory does not provide the KDS root-key container.")
    return container, service


def _keys(connection, container, key_id=None):
    predicate = "(objectClass=msKds-ProvRootKey)"
    if key_id is not None:
        predicate = "(&" + predicate + "(cn=" + escape_filter(key_id) + "))"
    return connection.search(container, SCOPE_SUBTREE, predicate, list(_METADATA))


def _filetime_now():
    delta = datetime.datetime.utcnow() - _EPOCH
    return (delta.days * 86400 + delta.seconds) * 10000000 + delta.microseconds * 10


def _filetime_text(value):
    ticks = int(value)
    seconds, fraction = divmod(ticks, 10000000)
    try:
        instant = _EPOCH + datetime.timedelta(seconds=seconds)
    except OverflowError:
        raise ValueError(
            "The KDS time is outside the supported Windows date range."
        ) from None
    # Keep the small UTC formatter local instead of staging account/schema APIs.
    # pylint: disable=duplicate-code
    return "{0:04d}-{1:02d}-{2:02d}T{3:02d}:{4:02d}:{5:02d}.{6:07d}Z".format(
        instant.year,
        instant.month,
        instant.day,
        instant.hour,
        instant.minute,
        instant.second,
        fraction,
    )
    # pylint: enable=duplicate-code


def read_root_keys(arguments, result):
    """Return root-key metadata using the current Windows domain credentials.

    :param arguments: Validated information options.
    :type arguments: dict
    :param result: Mutable result with the read-only changed flag.
    :type result: dict
    :raises OSError: If the native directory operation fails.
    :raises ValueError: If required capabilities or readable metadata are absent.
    """
    with LDAPConnection() as connection:
        container, _service = _root_container(connection)
        key_id = arguments["key_id"]
        key_id = key_id if key_id and key_id.strip() else None
        for entry in _keys(connection, container, key_id):
            result["kds_root_keys"].append(
                {
                    "key_id": str(uuid.UUID(_value(entry, "cn").decode("utf-8"))),
                    "creation_time": _filetime_text(_value(entry, "msKds-CreateTime")),
                    "effective_time": _filetime_text(
                        _value(entry, "msKds-UseStartTime")
                    ),
                    "version_number": int(_value(entry, "msKds-Version")),
                }
            )


def _configuration(connection, service):
    rows = connection.search(
        "CN=Server Configuration," + service,
        SCOPE_SUBTREE,
        "(objectClass=msKds-ProvServerConfiguration)",
        list(_CONFIGURATION),
    )
    if len(rows) != 1:
        raise ValueError("The directory does not provide one KDS server configuration.")
    source = _raw(rows[0])
    values = {"msKds-Version": [_value(rows[0], "msKds-Version")]}
    for algorithm, attributes in (
        ("msKds-KDFAlgorithmID", ("msKds-KDFAlgorithmID", "msKds-KDFParam")),
        (
            "msKds-SecretAgreementAlgorithmID",
            (
                "msKds-SecretAgreementAlgorithmID",
                "msKds-SecretAgreementParam",
                "msKds-PublicKeyLength",
                "msKds-PrivateKeyLength",
            ),
        ),
    ):
        if source.get(algorithm.lower()):
            for name in attributes:
                if source.get(name.lower()):
                    values[name] = list(source[name.lower()])
        elif algorithm == "msKds-KDFAlgorithmID":
            # MS-GKDI 2.2.1: reserved, version, UTF-16 byte length, reserved.
            hash_name = "SHA512\0".encode("utf-16-le")
            values.update(
                {
                    algorithm: [b"SP800_108_CTR_HMAC"],
                    "msKds-KDFParam": [
                        struct.pack("<IIII", 0, 1, len(hash_name), 0) + hash_name
                    ],
                }
            )
        else:
            # MS-GKDI 2.2.2 encodes the public prime/generator as big endian.
            parameters = (
                struct.pack("<I4sI", 524, b"DHPM", 256) + _DH_PRIME + _DH_GENERATOR
            )
            values.update(
                {
                    algorithm: [b"DH"],
                    "msKds-SecretAgreementParam": [parameters],
                    "msKds-PublicKeyLength": [b"2048"],
                    "msKds-PrivateKeyLength": [b"256"],
                }
            )
    return values


def _selected_dc_computer(connection):
    root = connection.search("", SCOPE_BASE, "(objectClass=*)", ["serverName"])
    if len(root) != 1:
        raise ValueError("The selected directory server did not return one RootDSE.")
    server_dn = _value(root[0], "serverName").decode("utf-8")
    server = connection.search(
        server_dn, SCOPE_BASE, "(objectClass=server)", ["serverReference"]
    )
    if len(server) != 1:
        raise ValueError("The selected DC's directory server object is unavailable.")
    # The vendor's root-key creator links the actual DC computer, not its domain
    # or the execution host. RootDSE and serverReference provide that exact link.
    return _value(server[0], "serverReference")


def _guid_match_id(value):
    candidate = value.strip()
    hexadecimal = re.fullmatch(
        r"\{0x([0-9a-f]{1,8}),0x([0-9a-f]{1,4}),0x([0-9a-f]{1,4}),"
        r"\{0x([0-9a-f]{1,2}),0x([0-9a-f]{1,2}),0x([0-9a-f]{1,2}),"
        r"0x([0-9a-f]{1,2}),0x([0-9a-f]{1,2}),0x([0-9a-f]{1,2}),"
        r"0x([0-9a-f]{1,2}),0x([0-9a-f]{1,2})\}\}",
        re.sub(r"\s+", "", candidate),
        re.I,
    )
    if hexadecimal:
        data = struct.pack(">IHH8B", *[int(part, 16) for part in hexadecimal.groups()])
        return str(uuid.UUID(bytes=data))
    wrapped = (candidate.startswith("{") and candidate.endswith("}")) or (
        candidate.startswith("(") and candidate.endswith(")")
    )
    if wrapped:
        candidate = candidate[1:-1]
    dashed = r"[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}"
    pattern = dashed if wrapped else r"(?:[0-9a-f]{32}|" + dashed + ")"
    if re.fullmatch(pattern, candidate, re.I):
        return str(uuid.UUID(candidate))
    # An unparsable identifier matches no existing Guid upstream.
    return value


def manage_root_key(arguments, result):
    """Reconcile one KDS key without deriving group or managed-account passwords.

    :param arguments: Validated management options.
    :type arguments: dict
    :param result: Mutable result retaining identifiers after successful writes.
    :type result: dict
    :raises OSError: If a native directory operation fails.
    :raises ValueError: If directory capabilities or configuration are unavailable.
    """
    with LDAPConnection() as connection:
        container, service = _root_container(connection)
        match_id = arguments["key_id"] if arguments["match_by"] == "key_id" else None
        if arguments["state"] == "absent":
            match_id = arguments["key_id"]
        elif match_id is not None:
            match_id = _guid_match_id(match_id)
        existing = _keys(connection, container, match_id)
        if arguments["state"] == "absent":
            result["key_id"] = arguments["key_id"]
            if existing:
                if not arguments["check_mode"]:
                    for entry in existing:
                        connection.delete(entry["dn"])
                        result["changed"] = True
                result["changed"] = True
            return
        if existing and arguments["match_by"] != "never":
            # Released upstream reads .Guid on its string parameter: null.
            result["key_id"] = None if match_id is not None else EMPTY_GUID
            return
        if arguments["check_mode"]:
            result.update({"changed": True, "key_id": EMPTY_GUID})
            return
        attributes = _configuration(connection, service)
        created = _filetime_now()
        # Released microsoft.ad 1.12.1 passes EffectiveTime=(now + hours - 10).
        effective = created + (arguments["effective_time_hours"] - 10) * _TICKS_PER_HOUR
        _filetime_text(effective)
        key_id = str(uuid.uuid4())
        attributes.update(
            {
                "objectClass": [b"msKds-ProvRootKey"],
                "cn": [key_id.encode("ascii")],
                "msKds-RootKeyData": [os.urandom(64)],
                "msKds-CreateTime": [str(created).encode("ascii")],
                "msKds-UseStartTime": [str(effective).encode("ascii")],
                "msKds-DomainID": [_selected_dc_computer(connection)],
            }
        )
        connection.add("CN=" + key_id + "," + container, attributes)
        result.update({"changed": True, "key_id": key_id})
