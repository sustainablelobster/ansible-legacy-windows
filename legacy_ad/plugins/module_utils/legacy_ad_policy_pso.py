# Copyright 2026 sustainablelobster
# SPDX-License-Identifier: GPL-3.0-or-later

"""Manage native password settings objects and their explicit subject links."""

import re
import uuid

from legacy_ad_account import (  # pylint: disable=import-error
    apply_changes,
    integer_attribute,
    raw_attributes,
    remove_account,
    require_attributes,
)
from legacy_ad_arguments import as_int32  # pylint: disable=import-error
from legacy_ad_ldap import SCOPE_BASE  # pylint: disable=import-error
from legacy_ad_object import (  # pylint: disable=import-error
    DEFAULT_PATH,
    DirectorySession,
    ensure_present,
    escape_rdn,
    find_object,
)
from legacy_windows_module import (  # pylint: disable=import-error
    as_bool,
    as_string_list,
)

PARAMETERS = (
    "precedence",
    "min_password_length",
    "complexity_enabled",
    "lockout_threshold",
    "subjects",
)
_PROPERTIES = {"description": "description", "display_name": "displayName"}
_SETTINGS = {
    "precedence": "msDS-PasswordSettingsPrecedence",
    "min_password_length": "msDS-MinimumPasswordLength",
    "complexity_enabled": "msDS-PasswordComplexityEnabled",
    "lockout_threshold": "msDS-LockoutThreshold",
}
# Name-and-precedence-only New-ADFineGrainedPasswordPolicy was measured on the
# isolated Server 2008 R2 reference with both normal and changed domain policy.
# These defaults stayed fixed, including reversible encryption being enabled.
_DEFAULTS = {
    "msDS-PasswordReversibleEncryptionEnabled": True,
    "msDS-PasswordHistoryLength": 24,
    "msDS-PasswordComplexityEnabled": True,
    "msDS-MinimumPasswordLength": 7,
    "msDS-MinimumPasswordAge": -864000000000,
    "msDS-MaximumPasswordAge": -36288000000000,
    "msDS-LockoutThreshold": 0,
    "msDS-LockoutObservationWindow": -18000000000,
    "msDS-LockoutDuration": -18000000000,
}
_SUBJECT_ATTRIBUTE = "msDS-PSOAppliesTo"


def _options(arguments):
    for name in ("precedence", "min_password_length", "lockout_threshold"):
        value = arguments[name]
        if value is None:
            continue
        arguments[name] = as_int32(value, name)
    if arguments["complexity_enabled"] is not None:
        arguments["complexity_enabled"] = as_bool(
            arguments["complexity_enabled"], "complexity_enabled"
        )
    arguments["subjects"] = as_string_list(arguments["subjects"], "subjects")


def _capabilities(connection):
    require_attributes(
        connection, list(_DEFAULTS) + [_SETTINGS["precedence"], _SUBJECT_ATTRIBUTE]
    )
    root = connection.search("", SCOPE_BASE, "(objectClass=*)", ["domainFunctionality"])
    values = raw_attributes(root[0] if len(root) == 1 else None).get(
        "domainfunctionality", []
    )
    if len(values) != 1 or int(values[0]) < 3:
        raise ValueError(
            "Password Settings Objects require Windows Server 2008 domain "
            "functional level or later; no directory objects were changed."
        )


def _entry(session, arguments, result):
    connection = session.connection()
    default_path = (
        "CN=Password Settings Container,CN=System," + connection.naming_context()
    )
    if arguments["path"] in (None, "", DEFAULT_PATH):
        arguments["path"] = default_path
    if (
        arguments["state"] == "present"
        and arguments["path"].lower() != default_path.lower()
    ):
        raise ValueError(
            "Password Settings Objects cannot be created or moved outside "
            "the domain's Password Settings Container."
        )
    identity = arguments["identity"]
    if identity:
        try:
            uuid.UUID(identity)
        except ValueError:
            # Unlike accounts, a PSO's bare identity is its policy name.
            if "=" not in identity and not identity.upper().startswith("S-1-"):
                identity = "CN=" + escape_rdn(identity) + "," + default_path
    else:
        identity = "CN=" + escape_rdn(arguments["name"]) + "," + arguments["path"]
    # PSOs query the common lifecycle fields alongside their policy-specific fields.
    # pylint: disable=duplicate-code
    attributes = [
        "objectGUID",
        "objectClass",
        "name",
        "nTSecurityDescriptor",
        _SUBJECT_ATTRIBUTE,
    ]
    # pylint: enable=duplicate-code
    attributes.extend(_PROPERTIES.values())
    attributes.extend(_SETTINGS.values())
    attributes.extend(
        name for values in arguments["attributes"].values() for name in values
    )
    entry = find_object(
        connection, identity, attributes, expected_class="msDS-PasswordSettings"
    )
    if entry:
        result.update(
            distinguished_name=entry["dn"],
            object_guid=str(uuid.UUID(bytes_le=raw_attributes(entry)["objectguid"][0])),
        )
    return entry


def _validate_subject(subject):
    raw = raw_attributes(subject)
    classes = [value.decode("utf-8").lower() for value in raw.get("objectclass", [])]
    if "group" in classes:
        group_type = integer_attribute(subject, "groupType") & 14
        if group_type != 2:
            scope = (
                "DomainLocal"
                if group_type == 4
                else "Universal" if group_type == 8 else "Unknown"
            )
            name = raw.get("name", [subject["dn"].encode("utf-8")])[0].decode("utf-8")
            raise ValueError(
                "PSO subjects must be global security groups or users. "
                "'{0}' is a {1} group.".format(name, scope)
            )
    elif "user" not in classes:
        raise ValueError(
            "PSO subject '"
            + subject["dn"]
            + "' must be a global security group or user."
        )


def _subjects(connection, arguments, entry):
    requested = arguments["subjects"]
    if requested is None:
        return [], None, None
    desired = {}
    for identity in requested:
        subject = find_object(
            connection, identity, ["objectClass", "groupType", "name"]
        )
        if subject is None:
            raise ValueError("Unable to resolve subjects AD identity: " + identity)
        _validate_subject(subject)
        desired.setdefault(subject["dn"].lower(), subject["dn"])
    existing = {
        value.decode("utf-8").lower(): value.decode("utf-8")
        for value in raw_attributes(entry).get(_SUBJECT_ATTRIBUTE.lower(), [])
    }
    added = [
        desired[key].encode("utf-8") for key in sorted(set(desired) - set(existing))
    ]
    removed = [
        existing[key].encode("utf-8") for key in sorted(set(existing) - set(desired))
    ]
    changes = ([(0, _SUBJECT_ATTRIBUTE, added)] if added else []) + (
        [(1, _SUBJECT_ATTRIBUTE, removed)] if removed else []
    )
    return changes, list(existing.values()), requested


def _settings(arguments, entry):
    generated = set()
    requested_attributes = arguments["attributes"]["set"]
    if entry is None:
        for attribute, value in _DEFAULTS.items():
            if not any(
                name.lower() == attribute.lower() for name in requested_attributes
            ):
                generated.add(attribute)
                requested_attributes[attribute] = {
                    "type": "bool" if isinstance(value, bool) else "int",
                    "value": value,
                }
    for name, attribute in _SETTINGS.items():
        value = arguments[name]
        if value is None:
            continue
        if not any(key.lower() == attribute.lower() for key in requested_attributes):
            generated.add(attribute)
        requested_attributes[attribute] = {
            "type": "bool" if name == "complexity_enabled" else "int",
            "value": value,
        }
    return generated


def _diff(arguments, entry, result, generated, subjects):
    before, after = result["diff"]["before"], result["diff"]["after"]
    for attribute in generated:
        after["attributes"].pop(attribute, None)
        if before:
            before["attributes"].pop(attribute, None)
    for name, attribute in _SETTINGS.items():
        if arguments[name] is not None:
            after[name] = arguments[name]
            if before:
                stored = raw_attributes(entry).get(attribute.lower(), [])
                before[name] = (
                    (
                        stored[0] == b"TRUE"
                        if name == "complexity_enabled"
                        else int(stored[0])
                    )
                    if stored
                    else None
                )
    existing, requested = subjects
    if requested is not None:
        after["subjects"] = sorted(requested)
        if before:
            names = []
            for dn in existing:
                match = re.match(r"^CN=([^,]+),", dn, flags=re.IGNORECASE)
                names.append(match.group(1) if match else dn)
            before["subjects"] = sorted(names)


def manage_pso(arguments, result):
    """Apply PSO lifecycle, settings and exact-subject assignment requests.

    :param dict arguments: Common object arguments plus PSO options.
    :param dict result: Result retaining identifiers and completed partial writes.
    :raises ValueError: Inputs, identities or directory capabilities are invalid.
    :raises OSError: Native directory access or mutation fails.
    """
    _options(arguments)
    with DirectorySession(arguments) as session:
        connection = session.connection()
        _capabilities(connection)
        entry = _entry(session, arguments, result)
        if arguments["state"] == "absent":
            remove_account(connection, arguments, entry, result)
            return
        if entry is None and arguments["precedence"] is None:
            raise ValueError(
                "precedence must be set when state=present and the PSO does not exist"
            )
        changes, existing_subjects, requested_subjects = _subjects(
            connection, arguments, entry
        )
        generated = _settings(arguments, entry)
        ensure_present(
            session, arguments, "msDS-PasswordSettings", _PROPERTIES, result, entry
        )
        if arguments["diff_mode"]:
            _diff(
                arguments,
                entry,
                result,
                generated,
                (existing_subjects, requested_subjects),
            )
        # Upstream adds new subjects before removing old ones. Keep the writes
        # separate so a failed removal reports any successful additions.
        for change in changes:
            apply_changes(
                connection, result["distinguished_name"], [change], arguments, result
            )
