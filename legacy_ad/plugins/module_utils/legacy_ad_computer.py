# Copyright 2026 sustainablelobster
# SPDX-License-Identifier: GPL-3.0-or-later

"""Manage AD computer accounts through sealed native LDAP operations."""

import random
import string

from legacy_ad_account import (  # pylint: disable=import-error
    COMPUTERS_CONTAINER,
    account_control,
    account_flags,
    apply_changes,
    apply_spn,
    delegation_changes,
    encryption_changes,
    encryption_request,
    find_account,
    finish_identifiers,
    list_request,
    record_account_flags,
    remove_account,
    require_attributes,
    resolve_delegates,
)
from legacy_ad_object import (  # pylint: disable=import-error
    DirectorySession,
    ensure_present,
    object_arguments,
)
from legacy_windows_module import as_bool, as_string  # pylint: disable=import-error

PROPERTIES = {
    "description": "description",
    "display_name": "displayName",
    "dns_hostname": "dNSHostName",
    "location": "location",
    "managed_by": "managedBy",
    "sam_account_name": "sAMAccountName",
    "upn": "userPrincipalName",
}
PARAMETERS = (
    "delegates",
    "principals_allowed_to_delegate",
    "dns_hostname",
    "do_not_append_dollar_to_sam",
    "enabled",
    "kerberos_encryption_types",
    "location",
    "managed_by",
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
)
_DISABLED_COMPUTER = 4098


def computer_arguments():
    """Normalize the upstream computer options and aliases.

    :returns: Common and computer-specific validated module arguments.
    :rtype: dict
    :raises ValueError: If Boolean values or aliases are invalid.
    """
    arguments = object_arguments(
        "sustainablelobster.legacy_ad.computer",
        PARAMETERS,
        aliases=(("spn", "spns"), ("delegates", "principals_allowed_to_delegate")),
    )
    for name in ("enabled", "trusted_for_delegation"):
        value = arguments[name]
        arguments[name] = None if value is None else as_bool(value, name)
    value = arguments["do_not_append_dollar_to_sam"]
    arguments["do_not_append_dollar_to_sam"] = as_bool(
        False if value is None else value, "do_not_append_dollar_to_sam"
    )
    for name in PROPERTIES:
        if name != "managed_by":
            arguments[name] = as_string(arguments[name], name)
    sam = arguments["sam_account_name"]
    if sam and not sam.endswith("$") and not arguments["do_not_append_dollar_to_sam"]:
        arguments["sam_account_name"] = sam + "$"
    return arguments


def random_computer_password():
    """Generate the secure 240-character default computer password.

    :returns: A cryptographically generated secret, never placed in result data.
    :rtype: str
    """
    generator = random.SystemRandom()
    groups = (
        string.ascii_uppercase,
        string.ascii_lowercase,
        string.digits,
        string.punctuation,
    )
    characters = [generator.choice(group) for group in groups]
    alphabet = "".join(groups)
    characters.extend(generator.choice(alphabet) for _index in range(236))
    generator.shuffle(characters)
    return "".join(characters)


def _computer_diff(arguments, result, entry, previous, value):
    after = result["diff"]["after"]
    if arguments.get("_generated_uac"):
        after["attributes"].pop("userAccountControl", None)
    elif arguments.get("_uac_attribute"):
        after["attributes"][arguments["_uac_attribute"]] = value
    record_account_flags(arguments, result, entry, previous, value)


# The account lifecycle has separate validated options, LDAP writes and diff
# values; keep their native effects explicit rather than hiding them in a plan.
# pylint: disable=too-many-locals,too-many-statements,too-many-branches
def manage_computer(arguments, result):
    """Apply the computer lifecycle while preserving successful partial writes.

    :param arguments: Validated common and computer-specific module arguments.
    :type arguments: dict
    :param result: Mutable result retaining actual or predicted identifiers.
    :type result: dict
    :raises ValueError: If identities or schema capabilities are invalid.
    :raises OSError: If a native directory operation fails.
    """
    spn = list_request(arguments["spn"], "spn")
    encryption = encryption_request(arguments["kerberos_encryption_types"])
    # Class-specific account lookup deliberately shares this small session setup;
    # the actual user and computer workflows remain separately readable below.
    # pylint: disable=duplicate-code
    delegates = list_request(arguments["delegates"], "delegates", identities=True)
    with DirectorySession(arguments) as session:
        connection = session.connection()
        entry = find_account(
            session,
            arguments,
            COMPUTERS_CONTAINER,
            list(PROPERTIES.values()) + list(_EXTRA_ATTRIBUTES),
            result,
            object_type="computer",
            computer=True,
        )
        # pylint: enable=duplicate-code
        if arguments["state"] == "absent":
            remove_account(connection, arguments, entry, result)
            return
        if encryption is not None:
            require_attributes(connection, ["msDS-SupportedEncryptionTypes"])
        delegated = resolve_delegates(session, delegates, result)
        previous, value = account_flags(arguments, entry, _DISABLED_COMPUTER)
        staged_flags = account_control(arguments, entry, _DISABLED_COMPUTER)
        password = None
        if entry is None:
            requested_flags = next(
                (
                    name
                    for name in arguments["attributes"]["set"]
                    if name.lower() == "useraccountcontrol"
                ),
                None,
            )
            arguments["_generated_uac"] = requested_flags is None
            arguments["_uac_attribute"] = requested_flags
            staged_flags = value | 2
            arguments["attributes"]["set"][requested_flags or "userAccountControl"] = {
                "type": "int",
                "value": staged_flags,
            }
            if arguments["sam_account_name"] in (None, ""):
                arguments["sam_account_name"] = (
                    arguments["name"] or arguments["identity"]
                ) + "$"
            if not arguments["check_mode"]:
                password = random_computer_password()
        managed = ensure_present(
            session, arguments, "computer", PROPERTIES, result, entry
        )
        dn = result["distinguished_name"]
        finish_identifiers(connection, managed, result)
        if arguments["diff_mode"]:
            _computer_diff(arguments, result, entry, previous, value)
        if password is not None:
            # unicodePwd resets require a quoted UTF-16LE secret; DirectorySession
            # uses a bind with signing and sealing before any password is sent.
            apply_changes(
                connection,
                dn,
                [(2, "unicodePwd", [('"' + password + '"').encode("utf-16-le")])],
                arguments,
                result,
            )
        flags = (
            [(2, "userAccountControl", [str(value).encode("ascii")])]
            if staged_flags != value
            else []
        )
        apply_changes(connection, dn, flags, arguments, result)
        apply_spn(connection, arguments, entry, spn, result)
        if encryption is not None:
            changes, existing, desired = encryption_changes(entry, encryption)
            apply_changes(connection, dn, changes, arguments, result)
            if arguments["diff_mode"]:
                result["diff"]["after"]["kerberos_encryption_types"] = desired
                if result["diff"]["before"]:
                    result["diff"]["before"]["kerberos_encryption_types"] = existing
        if delegated is not None:
            changes, existing, desired = delegation_changes(entry, delegated)
            apply_changes(connection, dn, changes, arguments, result)
            if arguments["diff_mode"]:
                result["diff"]["after"]["delegates"] = sorted(desired)
                if result["diff"]["before"]:
                    result["diff"]["before"]["delegates"] = sorted(existing)
