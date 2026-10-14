# Copyright 2026 sustainablelobster
# SPDX-License-Identifier: GPL-3.0-or-later

"""Manage AD security/distribution groups and their explicit member links."""

from legacy_ad_account import (  # pylint: disable=import-error
    USERS_CONTAINER,
    apply_changes,
    compare_list,
    find_account,
    finish_identifiers,
    integer_attribute,
    list_request,
    raw_attributes,
    remove_account,
    require_attributes,
    resolve_lists,
)
from legacy_ad_object import (  # pylint: disable=import-error
    DirectorySession,
    ensure_present,
)
from legacy_windows_module import as_string  # pylint: disable=import-error

PROPERTIES = {
    "description": "description",
    "display_name": "displayName",
    "homepage": "wWWHomePage",
    "managed_by": "managedBy",
    "sam_account_name": "sAMAccountName",
}
PARAMETERS = (
    "category",
    "homepage",
    "managed_by",
    "members",
    "sam_account_name",
    "scope",
)
_SCOPES = {"global": 2, "domainlocal": 4, "universal": 8}


def _group_type(arguments, entry):
    if entry is None and arguments["scope"] is None:
        raise ValueError(
            "scope must be set when state=present and the group does not exist"
        )
    previous = integer_attribute(entry, "groupType")
    if (
        entry is not None
        and arguments["scope"] is None
        and arguments["category"] is None
    ):
        # Without named group options, leave generic groupType requests to the
        # ordinary attribute writer rather than overwriting them with old flags.
        return previous, False
    value = previous if entry else 0x80000000
    if arguments["scope"] is not None:
        value = (value & ~14) | _SCOPES[arguments["scope"]]
    if arguments["category"] is not None:
        value = (
            value | 0x80000000
            if arguments["category"] == "security"
            else value & ~0x80000000
        )
    value &= 0xFFFFFFFF
    value = value - 0x100000000 if value & 0x80000000 else value
    raw_type_keys = [
        name for name in arguments["attributes"]["set"] if name.lower() == "grouptype"
    ]
    generated = not raw_type_keys
    # LDAP attribute names are case-insensitive; a named override must replace
    # every spelling instead of submitting duplicate logical modifications.
    for name in raw_type_keys:
        del arguments["attributes"]["set"][name]
    arguments["attributes"]["set"]["groupType"] = {"type": "int", "value": value}
    return previous, generated


def _member_changes(session, arguments, entry, result):
    request = list_request(arguments["members"], "members", identities=True)
    if request is None:
        return [], None, None
    require_attributes(session.connection(), ["member"])
    resolved, _connections = resolve_lists(session, request, "members", result)
    existing = [
        value.decode("utf-8") for value in raw_attributes(entry).get("member", [])
    ]
    desired, added, removed = compare_list(existing if entry else None, resolved)
    # Builtin groups reject a member replace; delta operations also avoid
    # touching unchanged links in ordinary groups.
    changes = []
    if removed:
        changes.append((1, "member", [value.encode("utf-8") for value in removed]))
    if added:
        changes.append((0, "member", [value.encode("utf-8") for value in added]))
    return changes, existing, desired


def _group_diff(arguments, result, previous, generated, members):
    before, after = result["diff"]["before"], result["diff"]["after"]
    if generated:
        after["attributes"].pop("groupType", None)
        if before:
            before["attributes"].pop("groupType", None)
    if arguments["scope"] is not None:
        after["scope"] = arguments["scope"]
        if before:
            before["scope"] = next(
                (name for name, bit in _SCOPES.items() if previous & bit), None
            )
    if arguments["category"] is not None:
        after["category"] = arguments["category"]
        if before:
            before["category"] = "security" if previous & 0x80000000 else "distribution"
    existing, desired = members
    if desired is not None:
        after["members"] = sorted(desired)
        if before:
            before["members"] = sorted(existing)


def manage_group(arguments, result):
    """Apply the upstream group interface through native LDAP operations.

    :param arguments: Common arguments plus group-specific options.
    :type arguments: dict
    :param result: Mutable result preserving completed writes on failure.
    :type result: dict
    :raises ValueError: If scope, category, identities or schema are invalid.
    :raises OSError: If an authenticated directory operation fails.
    """
    for name, choices in (
        ("scope", _SCOPES),
        ("category", ("security", "distribution")),
    ):
        value = as_string(arguments.get(name), name)
        if value is not None:
            value = value.lower()
        if value is not None and value not in choices:
            raise ValueError(name + " must be one of " + ", ".join(choices) + ".")
        arguments[name] = value
    # Each account module keeps its directory session and explicit read set local.
    # pylint: disable=duplicate-code
    with DirectorySession(arguments) as session:
        connection = session.connection()
        entry = find_account(
            session,
            arguments,
            USERS_CONTAINER,
            list(PROPERTIES.values()) + ["groupType", "member"],
            result,
            object_type="group",
        )
        # pylint: enable=duplicate-code
        if arguments["state"] == "absent":
            remove_account(connection, arguments, entry, result)
            return
        previous, generated = _group_type(arguments, entry)
        if entry is None and arguments["sam_account_name"] is None:
            arguments["sam_account_name"] = arguments["name"] or arguments["identity"]
        changes, existing, desired = _member_changes(session, arguments, entry, result)
        created = ensure_present(session, arguments, "group", PROPERTIES, result, entry)
        finish_identifiers(connection, created, result)
        apply_changes(
            connection, result["distinguished_name"], changes, arguments, result
        )
        if arguments["diff_mode"]:
            _group_diff(arguments, result, previous, generated, (existing, desired))
