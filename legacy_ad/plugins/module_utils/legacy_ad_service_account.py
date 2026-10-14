# Copyright 2026 sustainablelobster
# SPDX-License-Identifier: GPL-3.0-or-later

"""Manage group managed service accounts through sealed native LDAP."""

import re

import legacy_windows_account as accounts  # pylint: disable=import-error
from legacy_ad_account import (  # pylint: disable=import-error
    account_flags,
    apply_changes,
    apply_spn,
    compare_list,
    delegation_changes,
    encryption_changes,
    encryption_request,
    find_account,
    finish_identifiers,
    list_request,
    raw_attributes,
    record_account_flags,
    remove_account,
    require_attributes,
    resolve_lists,
)
from legacy_ad_object import (  # pylint: disable=import-error
    DirectorySession,
    ensure_present,
    find_object,
    object_arguments,
)
from legacy_ad_schema import (  # pylint: disable=import-error
    security_descriptor_bytes,
    security_descriptor_text,
    sid_text,
)
from legacy_windows_module import as_bool, as_string  # pylint: disable=import-error

MANAGED_SERVICE_ACCOUNTS_CONTAINER = "1EB93889E40C45DF9F0C64D23BBB6237"
PROPERTIES = {
    "description": "description",
    "display_name": "displayName",
    "dns_hostname": "dNSHostName",
    "sam_account_name": "sAMAccountName",
    "upn": "userPrincipalName",
}
# Public option names and read attributes remain visible at each account module.
# pylint: disable=duplicate-code
PARAMETERS = (
    "allowed_to_retrieve_password",
    "delegates",
    "principals_allowed_to_delegate",
    "dns_hostname",
    "do_not_append_dollar_to_sam",
    "enabled",
    "kerberos_encryption_types",
    "outbound_auth_only",
    "sam_account_name",
    "spn",
    "spns",
    "trusted_for_delegation",
    "upn",
)
_EXTRA_ATTRIBUTES = (
    "servicePrincipalName",
    "msDS-SupportedEncryptionTypes",
    "msDS-AllowedToActOnBehalfOfOtherIdentity",
    "msDS-GroupMSAMembership",
    "msDS-ManagedPasswordInterval",
)
# pylint: enable=duplicate-code
_WORKSTATION_ACCOUNT = 4096


def service_account_arguments():
    """Normalize the released service-account options and aliases.

    :returns: Validated common and gMSA-specific module arguments.
    :rtype: dict
    :raises ValueError: If an alias, Boolean or string option is invalid.
    """
    arguments = object_arguments(
        "sustainablelobster.legacy_ad.service_account",
        PARAMETERS,
        aliases=(("spn", "spns"), ("delegates", "principals_allowed_to_delegate")),
    )
    for name in ("enabled", "trusted_for_delegation"):
        arguments[name] = (
            as_bool(arguments[name], name) if arguments[name] is not None else None
        )
    for name in ("do_not_append_dollar_to_sam", "outbound_auth_only"):
        arguments[name] = as_bool(
            False if arguments[name] is None else arguments[name], name
        )
    for name in PROPERTIES:
        arguments[name] = as_string(arguments[name], name)
    sam = arguments["sam_account_name"]
    if sam and not sam.endswith("$") and not arguments["do_not_append_dollar_to_sam"]:
        arguments["sam_account_name"] = sam + "$"
    if arguments["outbound_auth_only"] and arguments["dns_hostname"]:
        raise ValueError("dns_hostname can not be set when outbound_auth_only=true.")
    return arguments


def _stage_defaults(arguments, entry, value):
    if entry is not None:
        return
    attributes = arguments["attributes"]["set"]
    existing = {name.lower(): name for name in attributes}
    for name, default in (
        ("userAccountControl", value),
        ("msDS-ManagedPasswordInterval", 30),
    ):
        if name.lower() not in existing:
            attributes[name] = {"type": "int", "value": default}
            arguments.setdefault("_generated_attributes", []).append(name)
        elif name == "userAccountControl":
            attributes[existing[name.lower()]] = {"type": "int", "value": value}
    if arguments["sam_account_name"] in (None, ""):
        arguments["sam_account_name"] = (
            arguments["name"] or arguments["identity"]
        ) + "$"


def _flag_diff(arguments, result, entry, previous, value):
    after = result["diff"]["after"]
    for name in arguments.get("_generated_attributes", []):
        after["attributes"].pop(name, None)
    record_account_flags(arguments, result, entry, previous, value)
    if arguments["outbound_auth_only"]:
        after.pop("dns_hostname", None)


def _allowed_sid(ace):
    fields = ace.split(";")
    if len(fields) != 6 or fields[0] != "A":
        return None
    return sid_text(accounts.sid_bytes(fields[5]))


def retrieval_changes(entry, request):
    """Reconcile the vendor-projected principals and replacement membership ACL.

    Existing allow ACEs contribute SIDs regardless of their access mask, matching
    the directory cmdlet getter. An unchanged principal list retains the existing
    descriptor. A changed list replaces it with the vendor's full-control allow
    ACEs and owner, or clears the attribute when the list becomes empty.

    :param entry: Observed gMSA or None for creation.
    :type entry: dict or None
    :param request: Resolved SID add/remove/set request.
    :type request: dict
    :returns: LDAP change and existing/desired projected principal SIDs.
    :rtype: tuple[list, list, list]
    :raises ValueError: The existing membership descriptor is unreadable.
    """
    attribute = "msDS-GroupMSAMembership"
    values = raw_attributes(entry).get(attribute.lower(), [])
    descriptor = security_descriptor_text(values[0]) if values else "O:BAD:"
    dacl = re.search(r"D:([^()]*)", descriptor)
    if dacl is None or "NO_ACCESS_CONTROL" in dacl.group(1):
        raise ValueError("The password-retrieval descriptor has no readable DACL.")
    principals = [
        principal
        for ace in re.findall(r"\(([^()]*)\)", descriptor)
        for principal in [_allowed_sid(ace)]
        if principal is not None
    ]
    desired, added, removed = compare_list(principals, request)
    if not added and not removed:
        return [], principals, desired
    if not desired:
        return [(1, attribute, [])], principals, desired
    descriptor = "O:BAD:" + "".join(
        "(A;;CCDCLCSWRPWPDTLOCRSDRCWDWO;;;" + sid + ")" for sid in desired
    )
    return (
        [(2, attribute, [security_descriptor_bytes(descriptor)])],
        principals,
        desired,
    )


def _principal_names(session, values, connections):
    names = []
    for sid in values:
        connection = connections.get(sid.lower()) or session.connection()
        principal = find_object(connection, sid, ["distinguishedName"])
        names.append(principal["dn"] if principal is not None else sid)
    return sorted(names)


# Keep the option and mutable partial-effect result explicit instead of a plan.
def _principal_changes(  # pylint: disable=too-many-arguments,too-many-positional-arguments
    session, arguments, entry, request, name, result
):
    if request is None:
        return
    resolved, connections = request
    changes, existing, desired = (
        retrieval_changes(entry, resolved)
        if name == "allowed_to_retrieve_password"
        else delegation_changes(entry, resolved)
    )
    if arguments["diff_mode"]:
        result["diff"]["after"][name] = _principal_names(session, desired, connections)
        if result["diff"]["before"]:
            result["diff"]["before"][name] = _principal_names(
                session, existing, connections
            )
    apply_changes(
        session.connection(), result["distinguished_name"], changes, arguments, result
    )


# Each stage represents a separate native effect whose partial success is public.
# pylint: disable=too-many-locals,too-many-statements
def manage_service_account(arguments, result):
    """Apply the gMSA lifecycle without generating or returning its password.

    :param arguments: Validated common and gMSA-specific options.
    :type arguments: dict
    :param result: Mutable result retaining identifiers and partial changes.
    :type result: dict
    :raises ValueError: If identities, options or schema capabilities are invalid.
    :raises OSError: If a native directory operation fails.
    """
    spn = list_request(arguments["spn"], "spn")
    encryption = encryption_request(arguments["kerberos_encryption_types"])
    allowed = list_request(
        arguments["allowed_to_retrieve_password"],
        "allowed_to_retrieve_password",
        identities=True,
    )
    delegates = list_request(arguments["delegates"], "delegates", identities=True)
    with DirectorySession(arguments) as session:
        connection = session.connection()
        entry = find_account(
            session,
            arguments,
            MANAGED_SERVICE_ACCOUNTS_CONTAINER,
            list(PROPERTIES.values()) + list(_EXTRA_ATTRIBUTES),
            result,
            object_type="msDS-GroupManagedServiceAccount",
            computer=True,
            container_attribute="otherWellKnownObjects",
        )
        if arguments["state"] == "absent":
            remove_account(connection, arguments, entry, result)
            return
        if (
            entry is None
            and not arguments["outbound_auth_only"]
            and not arguments["dns_hostname"]
        ):
            raise ValueError(
                "dns_hostname is required when creating a new service account."
            )
        require_attributes(
            connection, ["msDS-ManagedPasswordInterval", "msDS-GroupMSAMembership"]
        )
        if encryption is not None:
            require_attributes(connection, ["msDS-SupportedEncryptionTypes"])
        if delegates is not None:
            require_attributes(connection, ["msDS-AllowedToActOnBehalfOfOtherIdentity"])
        delegated = (
            resolve_lists(session, delegates, "delegates", result, sids=True)
            if delegates is not None
            else None
        )
        permitted = (
            resolve_lists(
                session, allowed, "allowed_to_retrieve_password", result, sids=True
            )
            if allowed is not None
            else None
        )
        previous, value = account_flags(arguments, entry, _WORKSTATION_ACCOUNT)
        _stage_defaults(arguments, entry, value)
        if arguments["outbound_auth_only"]:
            arguments["dns_hostname"] = ""
        managed = ensure_present(
            session,
            arguments,
            "msDS-GroupManagedServiceAccount",
            PROPERTIES,
            result,
            entry,
        )
        finish_identifiers(connection, managed, result)
        if arguments["diff_mode"]:
            _flag_diff(arguments, result, entry, previous, value)
        flags = (
            [(2, "userAccountControl", [str(value).encode("ascii")])]
            if entry is not None and previous != value
            else []
        )
        apply_changes(
            connection, result["distinguished_name"], flags, arguments, result
        )
        apply_spn(connection, arguments, entry, spn, result)
        if encryption is not None:
            changes, existing, desired = encryption_changes(entry, encryption)
            apply_changes(
                connection, result["distinguished_name"], changes, arguments, result
            )
            if arguments["diff_mode"]:
                result["diff"]["after"]["kerberos_encryption_types"] = desired
                if result["diff"]["before"]:
                    result["diff"]["before"]["kerberos_encryption_types"] = existing
        _principal_changes(
            session, arguments, entry, permitted, "allowed_to_retrieve_password", result
        )
        _principal_changes(
            session,
            arguments,
            entry,
            delegated,
            "delegates",
            result,
        )


# pylint: enable=too-many-locals,too-many-statements
