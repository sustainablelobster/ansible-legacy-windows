# Copyright 2026 sustainablelobster
# Attribute lists and flag mappings derived from microsoft.ad, Copyright 2026 Ansible Project.
# SPDX-License-Identifier: GPL-3.0-or-later

"""Clone, update and publish certificate templates with authenticated WinLDAP."""

import random
import struct
import uuid

from legacy_ad_arguments import as_int32  # pylint: disable=import-error
from legacy_ad_ldap import (  # pylint: disable=import-error
    SCOPE_ONE_LEVEL,
    LDAPConnection,
    escape_filter,
)
from legacy_ad_object import escape_rdn  # pylint: disable=import-error
from legacy_windows_module import (  # pylint: disable=import-error
    as_bool,
    as_string,
    as_string_list,
    read_arguments,
)

PARAMETERS = (
    "name",
    "display_name",
    "state",
    "source_template",
    "key_size",
    "extended_key_usages",
    "key_usage",
    "validity_period_days",
    "renewal_period_days",
    "enrollment_flag",
    "private_key_flag",
    "certificate_name_flag",
    "schema_version",
    "publish_to_ca",
    "domain_server",
)
_EKUS = {
    "server_authentication": "1.3.6.1.5.5.7.3.1",
    "client_authentication": "1.3.6.1.5.5.7.3.2",
    "code_signing": "1.3.6.1.5.5.7.3.3",
    "secure_email": "1.3.6.1.5.5.7.3.4",
    "ip_security_end_system": "1.3.6.1.5.5.7.3.5",
    "ip_security_tunnel": "1.3.6.1.5.5.7.3.6",
    "ip_security_user": "1.3.6.1.5.5.7.3.7",
    "time_stamping": "1.3.6.1.5.5.7.3.8",
    "ocsp_signing": "1.3.6.1.5.5.7.3.9",
    "smart_card_logon": "1.3.6.1.4.1.311.20.2.2",
    "certificate_request_agent": "1.3.6.1.4.1.311.20.2.1",
    "encrypting_file_system": "1.3.6.1.4.1.311.10.3.4",
    "file_recovery": "1.3.6.1.4.1.311.10.3.4.1",
    "key_recovery": "1.3.6.1.4.1.311.10.3.11",
    "key_recovery_agent": "1.3.6.1.4.1.311.21.6",
    "document_signing": "1.3.6.1.4.1.311.10.3.12",
    "remote_desktop": "1.3.6.1.4.1.311.54.1.2",
    "kdc_authentication": "1.3.6.1.5.2.3.5",
}
_ENROLLMENT_FLAGS = {
    "include_symmetric_algorithms": 1,
    "pend_all_requests": 2,
    "publish_to_kra_container": 4,
    "publish_to_ds": 8,
    "auto_enrollment_check_user_ds_certificate": 16,
    "auto_enrollment": 32,
    "previous_approval_validate_reenrollment": 64,
}
_PRIVATE_FLAGS = {
    "require_private_key_archival": 1,
    "exportable_key": 16,
    "strong_key_protection_required": 32,
    "require_alternate_signature_algorithm": 64,
    "require_same_key_renewal": 128,
    "use_legacy_provider": 256,
    "ek_trust_on_use": 512,
    "ek_validate_cert": 1024,
    "ek_validate_key": 2048,
    "attest_preferred": 4096,
    "attest_required": 8192,
    "attestation_without_policy": 16384,
    "hello_logon_key": 2097152,
}
_NAME_FLAGS = {
    "enrollee_supplies_subject": 1,
    "enrollee_supplies_subject_alt_name": 65536,
    "subject_alt_require_domain_dns": 4194304,
    "subject_alt_require_spn": 8388608,
    "subject_alt_require_directory_guid": 16777216,
    "subject_alt_require_upn": 33554432,
    "subject_alt_require_email": 67108864,
    "subject_alt_require_dns": 134217728,
    "subject_require_dns_as_cn": 268435456,
    "subject_require_email": 536870912,
    "subject_require_common_name": 1073741824,
    "subject_require_directory_path": -2147483648,
}
_KEY_USAGES = {
    "digital_signature": (0, 128),
    "non_repudiation": (0, 64),
    "key_encipherment": (0, 32),
    "data_encipherment": (0, 16),
    "key_agreement": (0, 8),
    "key_cert_sign": (0, 4),
    "crl_sign": (0, 2),
    "encipher_only": (0, 1),
    "decipher_only": (1, 128),
}
_INTEGERS = (
    "flags",
    "revision",
    "pKIDefaultKeySpec",
    "pKIMaxIssuingDepth",
    "msPKI-RA-Signature",
    "msPKI-Enrollment-Flag",
    "msPKI-Private-Key-Flag",
    "msPKI-Certificate-Name-Flag",
    "msPKI-Minimal-Key-Size",
    "msPKI-Template-Schema-Version",
    "msPKI-Template-Minor-Revision",
)
_COLLECTIONS = (
    "pKIExtendedKeyUsage",
    "pKICriticalExtensions",
    "pKIDefaultCSPs",
    "msPKI-Certificate-Application-Policy",
    "msPKI-RA-Application-Policies",
)
_BYTES = ("pKIExpirationPeriod", "pKIOverlapPeriod", "pKIKeyUsage")
_ATTRIBUTES = (
    _INTEGERS + _COLLECTIONS + _BYTES + ("displayName", "msPKI-Cert-Template-OID")
)


def _int32(value, name):
    try:
        text = str(value).strip()
        number = int(text, 16 if "0x" in text.lower() else 10)
    except (ValueError, TypeError) as error:
        raise ValueError(name + " must contain an integer.") from error
    if text.lower().lstrip("+").startswith("0x") and 2147483648 <= number <= 4294967295:
        number -= 4294967296
    if not -2147483648 <= number <= 2147483647:
        raise ValueError(name + " must fit a signed 32-bit integer.")
    return number


def template_arguments():
    """Read the released template interface without adding credential options.

    :returns: Normalized public arguments and check-mode flag.
    :rtype: dict
    :raises ValueError: If a required option, state or type is invalid.
    """
    values = read_arguments(PARAMETERS, "sustainablelobster.legacy_ad.cs_template")
    arguments = dict(values)
    for name in ("name", "display_name", "state", "source_template", "domain_server"):
        arguments[name] = as_string(values.get(name), name)
    if arguments["name"] is None:
        raise ValueError("name is required.")
    arguments["state"] = (
        "present" if arguments["state"] is None else arguments["state"].lower()
    )
    if arguments["state"] not in ("present", "absent"):
        raise ValueError("state must be present or absent.")
    for name in (
        "key_size",
        "validity_period_days",
        "renewal_period_days",
        "schema_version",
    ):
        arguments[name] = (
            None if values.get(name) is None else as_int32(values[name], name)
        )
    if arguments["schema_version"] not in (None, 2, 3, 4):
        raise ValueError("schema_version must be 2, 3 or 4.")
    for name in (
        "extended_key_usages",
        "key_usage",
        "enrollment_flag",
        "private_key_flag",
        "certificate_name_flag",
        "publish_to_ca",
    ):
        arguments[name] = (
            None if values.get(name) is None else as_string_list(values[name], name)
        )
    arguments["check_mode"] = as_bool(
        values.get("_ansible_check_mode", False), "_ansible_check_mode"
    )
    return arguments


def _raw(entry):
    return {name.lower(): values for name, values in entry["attributes"].items()}


def _text(entry, attribute):
    return _raw(entry).get(attribute.lower(), [b""])[0].decode("utf-8") or None


def _template(connection, parent, attribute, name):
    rows = connection.search(
        parent,
        SCOPE_ONE_LEVEL,
        "(&(objectClass=pKICertificateTemplate)("
        + attribute
        + "="
        + escape_filter(name)
        + "))",
        list(_ATTRIBUTES),
    )
    if len(rows) > 1:
        raise ValueError("The certificate template identity is ambiguous: " + name)
    return rows[0] if rows else None


def _flags(values, mapping, name):
    result = 0
    for value in values:
        result |= (
            mapping[value.lower()] if value.lower() in mapping else _int32(value, name)
        )
    return str(result).encode("ascii")


def _overrides(arguments):
    values = {}
    for name, attribute in (
        ("key_size", "msPKI-Minimal-Key-Size"),
        ("schema_version", "msPKI-Template-Schema-Version"),
    ):
        if arguments[name] is not None:
            values[attribute] = [str(arguments[name]).encode("ascii")]
    for name, attribute, mapping in (
        ("enrollment_flag", "msPKI-Enrollment-Flag", _ENROLLMENT_FLAGS),
        ("private_key_flag", "msPKI-Private-Key-Flag", _PRIVATE_FLAGS),
        ("certificate_name_flag", "msPKI-Certificate-Name-Flag", _NAME_FLAGS),
    ):
        if arguments[name] is not None:
            values[attribute] = [_flags(arguments[name], mapping, name)]
    if arguments["extended_key_usages"] is not None:
        values["pKIExtendedKeyUsage"] = [
            _EKUS.get(value.lower(), value).encode("utf-8")
            for value in arguments["extended_key_usages"]
        ]
    for name, attribute in (
        ("validity_period_days", "pKIExpirationPeriod"),
        ("renewal_period_days", "pKIOverlapPeriod"),
    ):
        if arguments[name] is not None:
            try:
                values[attribute] = [struct.pack("<q", -arguments[name] * 864000000000)]
            except struct.error as error:
                raise ValueError(name + " is too large for an AD interval.") from error
    if arguments["key_usage"] is not None:
        data = bytearray(2)
        for value in arguments["key_usage"]:
            if value.lower() not in _KEY_USAGES:
                raise ValueError("Invalid key_usage value: " + value)
            index, bit = _KEY_USAGES[value.lower()]
            data[index] |= bit
        values["pKIKeyUsage"] = [bytes(data)]
    return values


def _new_oid(connection, parent):
    rows = connection.search(parent, 0, "(objectClass=*)", ["msPKI-Cert-Template-OID"])
    base = _text(rows[0], "msPKI-Cert-Template-OID") if rows else None
    if not base:
        raise ValueError(
            "The forest OID container has no msPKI-Cert-Template-OID base."
        )
    generator = random.SystemRandom()
    while True:
        first, second = generator.randrange(10000000, 99999999), generator.randrange(
            10000000, 99999999
        )
        oid = base + ".{0}.{1}".format(first, second)
        name = str(second) + "." + uuid.uuid4().hex.upper()
        if not connection.search(
            parent,
            SCOPE_ONE_LEVEL,
            "(|(cn="
            + escape_filter(name)
            + ")(msPKI-Cert-Template-OID="
            + escape_filter(oid)
            + "))",
            ["cn"],
        ):
            return name, oid


def _different(attribute, current, desired):
    if attribute == "pKIKeyUsage":
        return not current or current[0][:2].ljust(2, b"\0") != desired[0]
    if attribute in ("pKIExpirationPeriod", "pKIOverlapPeriod"):
        return (
            not current
            or len(current[0]) != 8
            or round(-struct.unpack("<q", current[0])[0] / 864000000000)
            != -struct.unpack("<q", desired[0])[0] / 864000000000
        )
    if attribute == "pKIExtendedKeyUsage":
        return sorted(value.lower() for value in current) != sorted(
            value.lower() for value in desired
        )
    return current != desired


def _publish(connection, parent, arguments, desired, result):
    name = arguments["name"]
    authorities = connection.search(
        parent, SCOPE_ONE_LEVEL, "(objectClass=*)", ["name", "certificateTemplates"]
    )
    wanted = {value.lower() for value in desired}
    known = set()
    for entry in authorities:
        ca_name = _text(entry, "name")
        known.add(ca_name.lower())
        published = [
            _value.decode("utf-8")
            for _value in _raw(entry).get("certificatetemplates", [])
        ]
        current = next(
            (value for value in published if value.lower() == name.lower()), None
        )
        if (ca_name.lower() in wanted) != (current is not None):
            result["changed"] = True
            if not arguments["check_mode"]:
                connection.modify(
                    entry["dn"],
                    [
                        (
                            0 if current is None else 1,
                            "certificateTemplates",
                            [(name if current is None else current).encode("utf-8")],
                        )
                    ],
                )
    for value in desired:
        if value.lower() not in known:
            result.setdefault("warnings", []).append(
                "Certificate Authority '"
                + value
                + "' was not found in Enrollment Services."
            )


def _create(connection, arguments, services, source, result):
    parent, oid_parent = "CN=Certificate Templates," + services, "CN=OID," + services
    values = {
        name: _raw(source)[name.lower()]
        for name in _INTEGERS + _COLLECTIONS + _BYTES
        if _raw(source).get(name.lower())
    }
    values.update(_overrides(arguments))
    result["changed"] = True
    if arguments["check_mode"]:
        return
    display = arguments["display_name"] or arguments["name"]
    oid_name, oid = _new_oid(connection, oid_parent)
    connection.add(
        "CN=" + escape_rdn(oid_name) + "," + oid_parent,
        {
            "objectClass": [b"msPKI-Enterprise-Oid"],
            "cn": [oid_name.encode("utf-8")],
            "displayName": [display.encode("utf-8")],
            "flags": [b"1"],
            "msPKI-Cert-Template-OID": [oid.encode("ascii")],
        },
    )
    values.update(
        {
            "objectClass": [b"pKICertificateTemplate"],
            "cn": [arguments["name"].encode("utf-8")],
            "displayName": [display.encode("utf-8")],
            "msPKI-Cert-Template-OID": [oid.encode("ascii")],
        }
    )
    dn = "CN=" + escape_rdn(arguments["name"]) + "," + parent
    connection.add(dn, {name: data for name, data in values.items() if data})
    result.update({"distinguished_name": dn, "template_oid": oid})


def _remove(connection, arguments, services, entry, result):
    result["changed"] = True
    if arguments["check_mode"]:
        return
    _publish(connection, "CN=Enrollment Services," + services, arguments, [], result)
    connection.delete(entry["dn"])
    if result["template_oid"]:
        try:
            for registration in connection.search(
                "CN=OID," + services,
                SCOPE_ONE_LEVEL,
                "(msPKI-Cert-Template-OID="
                + escape_filter(result["template_oid"])
                + ")",
                ["cn"],
            ):
                connection.delete(registration["dn"])
        except OSError as error:
            result.setdefault("warnings", []).append(
                "Failed to remove OID object for template '"
                + arguments["name"]
                + "': "
                + str(error)
            )


def _update(connection, arguments, entry, result):
    desired = _overrides(arguments)
    if (
        arguments["display_name"]
        and arguments["display_name"].lower()
        != (_text(entry, "displayName") or "").lower()
    ):
        desired["displayName"] = [arguments["display_name"].encode("utf-8")]
    changes = [
        (2 if values else 1, name, values)
        for name, values in desired.items()
        if _different(name, _raw(entry).get(name.lower(), []), values)
    ]
    if changes:
        result["changed"] = True
        if not arguments["check_mode"]:
            connection.modify(entry["dn"], changes)


def manage_template(arguments, result):
    """Manage a certificate template and its Enterprise CA publication state.

    :param arguments: Validated public template options.
    :type arguments: dict
    :param result: Mutable JSON result retaining partial changes and identities.
    :type result: dict
    :raises ValueError: If creation lacks a source or a requested value is invalid.
    :raises OSError: If the directory rejects a read or write.
    """
    with LDAPConnection(arguments["domain_server"]) as connection:
        services = "CN=Public Key Services,CN=Services," + connection.naming_context(
            "configurationNamingContext"
        )
        parent, enrollment = (
            "CN=Certificate Templates," + services,
            "CN=Enrollment Services," + services,
        )
        entry = _template(connection, parent, "cn", arguments["name"])
        if entry:
            result.update(
                {
                    "distinguished_name": entry["dn"],
                    "template_oid": _text(entry, "msPKI-Cert-Template-OID"),
                }
            )
        if arguments["state"] == "absent":
            if entry:
                _remove(connection, arguments, services, entry, result)
            return
        if entry is None:
            if not arguments["source_template"]:
                raise ValueError(
                    "source_template is required when creating a new certificate template."
                )
            source = _template(
                connection, parent, "displayName", arguments["source_template"]
            )
            if source is None:
                raise ValueError(
                    "Source template '"
                    + arguments["source_template"]
                    + "' was not found in "
                    + parent
                    + "."
                )
            _create(connection, arguments, services, source, result)
        else:
            _update(connection, arguments, entry, result)
        if arguments["publish_to_ca"] is not None:
            _publish(
                connection,
                enrollment,
                arguments,
                arguments["publish_to_ca"],
                result,
            )
