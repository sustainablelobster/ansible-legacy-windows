#!/usr/bin/python
# -*- coding: utf-8 -*-
# Copyright 2026 sustainablelobster
# Interface documentation derived from microsoft.ad, Copyright 2022 Ansible Project.
# SPDX-License-Identifier: GPL-3.0-or-later

"""Gather Active Directory object information with native WinLDAP."""

# WANT_JSON

import binascii
import traceback
import uuid

import legacy_ad_ldap as ldap  # pylint: disable=import-error
import legacy_ad_schema as schema  # pylint: disable=import-error
from legacy_ad_filter import ALIASES, expression_to_ldap  # pylint: disable=import-error
from legacy_ad_result import sanitize_result  # pylint: disable=import-error
from legacy_windows_module import (  # pylint: disable=import-error
    as_bool,
    as_string,
    as_string_list,
    read_arguments,
    run_module,
)

DOCUMENTATION = r"""
---
module: object_info
short_description: Gather information about Active Directory objects
version_added: '1.0.0'
description:
  - Gather information about one or more Active Directory objects using native Windows LDAP APIs.
options:
  domain_password:
    description: Password paired with O(domain_username).
    type: str
  domain_server:
    description:
      - Domain Services instance to connect to, as a DNS or NetBIOS name, optionally followed by a port.
      - Defaults to a domain controller for the execution host's domain.
    type: str
  domain_username:
    description:
      - Domain account or UPN used for authenticated directory access.
      - If omitted, uses the target process's Windows logon credentials.
      - A remote connection may need credential delegation or become for that logon to access the directory.
      - Must be supplied together with O(domain_password).
    type: str
  filter:
    description:
      - AD expression filter using comparison operators, Boolean joins and parentheses.
      - Variable substitution and expression execution are not supported.
      - Exactly one of O(filter), O(identity), and O(ldap_filter) is required.
    type: str
  identity:
    description:
      - Distinguished name or object GUID of one object.
      - Cannot be combined with O(search_base) or O(search_scope).
    type: str
  include_deleted:
    description: Include deleted objects using the directory's show-deleted control.
    type: bool
    default: false
  ldap_filter:
    description: Traditional LDAP query string, mutually exclusive with O(filter) and O(identity).
    type: str
  properties:
    description:
      - AD property names or LDAP attributes to return.
      - C(*) includes all populated attributes and supported extended AD properties.
      - Explicit valid but unset properties return null for single-valued attributes and an empty list for multivalued attributes.
      - DistinguishedName, Name, ObjectClass and ObjectGUID are always returned.
      - Invalid properties produce a warning for each matching object, which is omitted from the result.
    type: list
    elements: str
  search_base:
    description:
      - Distinguished name at which to search; defaults to the directory's default naming context.
      - An explicit empty string is preserved for global catalog searches.
    type: str
  search_scope:
    description: Search only the base object, its immediate children, or its complete subtree.
    type: str
    choices: [base, one_level, subtree]
attributes:
  check_mode:
    support: full
    description: Reads the directory without mutation in normal and check mode.
  diff_mode:
    support: none
  platform:
    platforms: [windows]
notes:
  - Uses SSPI Negotiate with LDAP signing and encryption; no simple-bind fallback is used.
  - Flag attributes requested in O(properties) also return an C(_AnsibleFlags) property.
  - Security descriptors include their readable owner, group and DACL; SACL access is not requested.
author:
  - sustainablelobster
  - Jordan Borean (@jborean93)
"""

EXAMPLES = r"""
- name: Read one account
  sustainablelobster.legacy_ad.object_info:
    identity: CN=Username,CN=Users,DC=domain,DC=com
    properties: ['objectSid', 'memberOf']

- name: Find disabled user accounts
  sustainablelobster.legacy_ad.object_info:
    filter: objectClass -eq 'user' -and userAccountControl -band 2
    properties: ['sAMAccountName', 'userAccountControl']

- name: Find objects within one OU
  sustainablelobster.legacy_ad.object_info:
    ldap_filter: (objectClass=*)
    search_base: OU=Deployment,DC=domain,DC=com
    search_scope: one_level
"""

RETURN = r"""
objects:
  description:
    - Objects found, with the requested properties and four default properties.
    - Date properties use ISO 8601 in UTC; binary properties use base64 strings.
    - SIDs use a dictionary with C(Sid) and the resolved C(Name), or null when unmapped.
    - Security descriptors use SDDL strings.
  returned: always
  type: list
  elements: dict
"""

_PARAMETERS = (
    "domain_password",
    "domain_server",
    "domain_username",
    "filter",
    "identity",
    "include_deleted",
    "ldap_filter",
    "properties",
    "search_base",
    "search_scope",
)
_DEFAULT_PROPERTIES = ("DistinguishedName", "Name", "ObjectClass", "ObjectGUID")
_FLAGS = {
    "grouptype": (
        (1, "GROUP_TYPE_BUILTIN_LOCAL_GROUP"),
        (2, "GROUP_TYPE_ACCOUNT_GROUP"),
        (4, "GROUP_TYPE_RESOURCE_GROUP"),
        (8, "GROUP_TYPE_UNIVERSAL_GROUP"),
        (16, "GROUP_TYPE_APP_BASIC_GROUP"),
        (32, "GROUP_TYPE_APP_QUERY_GROUP"),
        (0x80000000, "GROUP_TYPE_SECURITY_ENABLED"),
    ),
    "msds-supportedencryptiontypes": (
        (1, "DES_CBC_CRC"),
        (2, "DES_CBC_MD5"),
        (4, "RC4_HMAC"),
        (8, "AES128_CTS_HMAC_SHA1_96"),
        (16, "AES256_CTS_HMAC_SHA1_96"),
    ),
    "useraccountcontrol": (
        (1, "ADS_UF_SCRIPT"),
        (2, "ADS_UF_ACCOUNTDISABLE"),
        (8, "ADS_UF_HOMEDIR_REQUIRED"),
        (16, "ADS_UF_LOCKOUT"),
        (32, "ADS_UF_PASSWD_NOTREQD"),
        (64, "ADS_UF_PASSWD_CANT_CHANGE"),
        (128, "ADS_UF_ENCRYPTED_TEXT_PASSWORD_ALLOWED"),
        (256, "ADS_UF_TEMP_DUPLICATE_ACCOUNT"),
        (512, "ADS_UF_NORMAL_ACCOUNT"),
        (2048, "ADS_UF_INTERDOMAIN_TRUST_ACCOUNT"),
        (4096, "ADS_UF_WORKSTATION_TRUST_ACCOUNT"),
        (8192, "ADS_UF_SERVER_TRUST_ACCOUNT"),
        (65536, "ADS_UF_DONT_EXPIRE_PASSWD"),
        (131072, "ADS_UF_MNS_LOGON_ACCOUNT"),
        (262144, "ADS_UF_SMARTCARD_REQUIRED"),
        (524288, "ADS_UF_TRUSTED_FOR_DELEGATION"),
        (1048576, "ADS_UF_NOT_DELEGATED"),
        (2097152, "ADS_UF_USE_DES_KEY_ONLY"),
        (4194304, "ADS_UF_DONT_REQUIRE_PREAUTH"),
        (8388608, "ADS_UF_PASSWORD_EXPIRED"),
        (16777216, "ADS_UF_TRUSTED_TO_AUTHENTICATE_FOR_DELEGATION"),
    ),
}
_ACCOUNT_TYPES = {
    0: "SAM_DOMAIN_OBJECT",
    0x10000000: "SAM_GROUP_OBJECT",
    0x10000001: "SAM_NON_SECURITY_GROUP_OBJECT",
    0x20000000: "SAM_ALIAS_OBJECT",
    0x20000001: "SAM_NON_SECURITY_ALIAS_OBJECT",
    0x30000000: "SAM_USER_OBJECT",
    0x30000001: "SAM_MACHINE_ACCOUNT",
    0x30000002: "SAM_TRUST_ACCOUNT",
    0x40000000: "SAM_APP_BASIC_GROUP",
    0x40000001: "SAM_APP_QUERY_GROUP",
    0x7FFFFFFF: "SAM_ACCOUNT_TYPE_MAX",
}


def _arguments():
    values = read_arguments(_PARAMETERS, "sustainablelobster.legacy_ad.object_info")
    arguments = {
        name: as_string(values.get(name), name)
        for name in _PARAMETERS
        if name not in ("properties", "include_deleted")
    }
    arguments["properties"] = (
        as_string_list(values.get("properties"), "properties") or []
    )
    arguments["include_deleted"] = as_bool(
        values.get("include_deleted", False), "include_deleted"
    )
    specified = [
        name
        for name in ("filter", "identity", "ldap_filter")
        if arguments[name] is not None
    ]
    if len(specified) != 1:
        raise ValueError("Exactly one of filter, identity, ldap_filter is required.")
    if arguments["identity"] is not None and any(
        arguments[name] is not None for name in ("search_base", "search_scope")
    ):
        raise ValueError(
            "identity is mutually exclusive with search_base and search_scope."
        )
    if arguments["search_scope"] is not None:
        arguments["search_scope"] = arguments["search_scope"].lower()
    if arguments["search_scope"] not in (None, "base", "one_level", "subtree"):
        raise ValueError("search_scope must be base, one_level, or subtree.")
    if (arguments["domain_username"] is None) != (arguments["domain_password"] is None):
        raise ValueError(
            "domain_username and domain_password must be supplied together."
        )
    for name in specified:
        if not arguments[name]:
            raise ValueError(name + " must not be empty.")
    return arguments


def _query(connection, arguments):
    base = arguments["search_base"]
    base = connection.naming_context() if base is None else base
    scope = {
        None: ldap.SCOPE_SUBTREE,
        "base": ldap.SCOPE_BASE,
        "one_level": ldap.SCOPE_ONE_LEVEL,
        "subtree": ldap.SCOPE_SUBTREE,
    }[arguments["search_scope"]]
    identity = arguments["identity"]
    if identity is not None:
        try:
            identity = uuid.UUID(identity).bytes_le
        except ValueError:
            base, scope, ldap_filter = identity, ldap.SCOPE_BASE, "(objectClass=*)"
        else:
            # A GUID can identify configuration/schema objects outside the domain.
            base = "<GUID=" + binascii.hexlify(identity).decode("ascii") + ">"
            scope, ldap_filter = ldap.SCOPE_BASE, "(objectClass=*)"
    elif arguments["filter"] is not None:
        ldap_filter = expression_to_ldap(arguments["filter"])
    else:
        ldap_filter = arguments["ldap_filter"]
    try:
        return connection.search(
            base,
            scope,
            ldap_filter,
            ["objectGUID", "distinguishedName"],
            include_deleted=arguments["include_deleted"],
        )
    except ldap.LDAPError as error:
        if arguments["identity"] is not None and error.errno == 32:
            return []
        raise


def _flag_names(name, value):
    lower = name.lower()
    if lower == "samaccounttype":
        return [_ACCOUNT_TYPES.get(value, str(value))]
    if value is None:
        value = 0
    number = value & 0xFFFFFFFF if lower == "grouptype" else value
    known = _FLAGS[lower]
    selected = [(mask, text) for mask, text in known if number & mask == mask]
    if sum(mask for mask, _text in selected) != number:
        return [str(number)]
    if not selected:
        return ["None" if lower == "msds-supportedencryptiontypes" else "0"]
    return [text for _mask, text in selected]


def _requested_attributes(directory_schema, properties):
    wildcard = "*" in properties
    requested = list(_DEFAULT_PROPERTIES)
    requested.extend(name for name in properties if name != "*")
    attributes = ["*"] if wildcard else []
    need_descriptor = wildcard
    if wildcard:
        # LDAP '*' does not include constructed attributes such as
        # canonicalName. Get-ADObject -Properties * requests these extended
        # properties explicitly; only ask for aliases this schema exposes.
        for _property_name, attribute_name in ALIASES.values():
            attribute = directory_schema.attribute_name(attribute_name)
            if attribute is not None and attribute not in attributes:
                attributes.append(attribute)
        descriptor = directory_schema.attribute_name("nTSecurityDescriptor")
        if descriptor is not None:
            attributes.append(descriptor)
    for name in requested:
        if name.lower() == "protectedfromaccidentaldeletion":
            attribute = "nTSecurityDescriptor"
        else:
            attribute = directory_schema.attribute_name(name)
        if attribute is None:
            raise ValueError("Invalid property: " + name)
        if attribute.lower() == "ntsecuritydescriptor":
            need_descriptor = True
        if attribute.lower() not in [value.lower() for value in attributes]:
            attributes.append(attribute)
    return requested, attributes, need_descriptor


def _object(connection, directory_schema, found, properties, include_deleted):
    requested, attributes, need_descriptor = _requested_attributes(
        directory_schema, properties
    )
    # Rebind by the copied GUID so a rename between the listing and property
    # read does not make an otherwise live object disappear from the result.
    listed = {key.lower(): data for key, data in found["attributes"].items()}
    guid = listed.get("objectguid", [])
    base = (
        "<GUID=" + binascii.hexlify(guid[0]).decode("ascii") + ">"
        if guid
        else found["dn"]
    )
    rows = connection.search(
        base,
        ldap.SCOPE_BASE,
        "(objectClass=*)",
        attributes,
        include_deleted=include_deleted,
        security_descriptor=need_descriptor,
    )
    if len(rows) != 1:
        raise ValueError("Object no longer exists.")
    return _serialize_object(directory_schema, rows[0], requested, "*" in properties)


def _property_value(directory_schema, row, raw, name):
    lower = name.lower()
    if lower == "protectedfromaccidentaldeletion":
        value = directory_schema.cast(
            "nTSecurityDescriptor", raw.get("ntsecuritydescriptor", (None, []))[1]
        )
        return schema.protected_from_deletion(value) if value is not None else False
    attribute = directory_schema.attribute_name(name)
    if attribute is None:
        raise ValueError("Invalid property: " + name)
    value = directory_schema.cast(attribute, raw.get(attribute.lower(), (None, []))[1])
    if lower == "distinguishedname":
        return row["dn"]
    if lower == "objectclass":
        return value[-1] if value else None
    if lower == "description" and isinstance(value, list):
        # ADObject.Description is a mapped scalar even though the LDAP schema
        # permits multiple descriptions on non-SAM objects such as OUs.
        return value[0] if value else None
    return value


def _serialize_object(directory_schema, row, requested, wildcard):
    raw = {key.lower(): (key, data) for key, data in row["attributes"].items()}
    if wildcard:
        requested.extend(key for key, _values in raw.values())
        for property_name, attribute_name in ALIASES.values():
            if attribute_name.lower() in raw:
                requested.append(property_name)
        if "ntsecuritydescriptor" in raw:
            requested.append("ProtectedFromAccidentalDeletion")
    result = {}
    seen = set()
    for name in requested:
        lower = name.lower()
        if lower in seen:
            continue
        seen.add(lower)
        value = _property_value(directory_schema, row, raw, name)
        output_name = (
            "ProtectedFromAccidentalDeletion"
            if lower == "protectedfromaccidentaldeletion"
            else ALIASES.get(lower, (name, None))[0]
        )
        result[output_name] = value
        if lower in _FLAGS or lower == "samaccounttype":
            result[output_name + "_AnsibleFlags"] = _flag_names(lower, value)
    return result


def execute():
    """Read matching objects and retain the always-returned objects contract.

    :returns: Ansible result including objects, warnings and any failure.
    :rtype: dict
    """
    result = {"changed": False, "objects": []}
    raw, arguments = {}, None
    try:
        raw = read_arguments(
            _PARAMETERS,
            "sustainablelobster.legacy_ad.object_info",
            allow_unknown=True,
        )
        arguments = _arguments()
        with ldap.LDAPConnection(
            arguments["domain_server"],
            arguments["domain_username"],
            arguments["domain_password"],
        ) as connection:
            found = _query(connection, arguments)
            if not found:
                return sanitize_result(result, raw, arguments)
            directory_schema = schema.DirectorySchema(connection)
            for entry in found:
                try:
                    value = _object(
                        connection,
                        directory_schema,
                        entry,
                        arguments["properties"],
                        arguments["include_deleted"],
                    )
                except (OSError, ValueError, UnicodeError) as error:
                    warning = (
                        "Failed to retrieve properties for AD Object '{0}': {1}".format(
                            entry["dn"], error
                        )
                    )
                    result.setdefault("warnings", []).append(warning)
                else:
                    result["objects"].append(value)
    except (OSError, ValueError, UnicodeError) as error:
        result.update({"failed": True, "msg": str(error)})
    # Unexpected boundary errors must also pass through credential redaction.
    # Each payload keeps this secret-safe error envelope beside its operation.
    # pylint: disable=duplicate-code
    except Exception as error:  # pylint: disable=broad-exception-caught
        result.update(
            failed=True,
            msg="Unhandled exception while executing module: " + str(error),
            exception=traceback.format_exc(),
        )
    return sanitize_result(result, raw, arguments)
    # pylint: enable=duplicate-code


def main():
    """Return native directory results through the Ansible JSON protocol."""
    run_module(execute)


if __name__ == "__main__":
    main()
