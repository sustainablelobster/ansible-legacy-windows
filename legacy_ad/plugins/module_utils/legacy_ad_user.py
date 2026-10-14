# Copyright 2026 sustainablelobster
# SPDX-License-Identifier: GPL-3.0-or-later

"""Manage AD user flags, encrypted password resets and group membership."""

import ctypes
import re

from legacy_ad_account import (  # pylint: disable=import-error
    NO_LOG,
    USERS_CONTAINER,
    account_control,
    apply_changes,
    apply_spn,
    compare_list,
    delegation_changes,
    find_account,
    finish_identifiers,
    integer_attribute,
    list_request,
    raw_attributes,
    remove_account,
    resolve_delegates,
    resolve_lists,
    text_attribute,
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

PROPERTIES = {
    "description": "description",
    "display_name": "displayName",
    "city": "l",
    "company": "company",
    "country": "c",
    "email": "mail",
    "firstname": "givenName",
    "postal_code": "postalCode",
    "sam_account_name": "sAMAccountName",
    "state_province": "st",
    "street": "streetAddress",
    "surname": "sn",
    "upn": "userPrincipalName",
}
PARAMETERS = (
    "account_locked",
    "city",
    "company",
    "country",
    "delegates",
    "email",
    "enabled",
    "firstname",
    "groups",
    "password",
    "password_expired",
    "password_never_expires",
    "postal_code",
    "sam_account_name",
    "spn",
    "state_province",
    "street",
    "surname",
    "update_password",
    "upn",
    "user_cannot_change_password",
    "lastname",
    "spns",
    "principals_allowed_to_delegate",
)
_CHANGE_PASSWORD = "ab721a53-1e2f-11d0-9819-00aa0040529b"
_EXTRA_ATTRIBUTES = (
    "lockoutTime",
    "pwdLastSet",
    "msDS-User-Account-Control-Computed",
    "msDS-PrincipalName",
    "memberOf",
    "primaryGroupID",
    "servicePrincipalName",
    "msDS-AllowedToActOnBehalfOfOtherIdentity",
)


def user_arguments():
    """Read and normalize the user module's interface, including aliases.

    :returns: Validated common and user-specific arguments.
    :rtype: dict
    :raises ValueError: If aliases or Boolean/password options are invalid.
    """
    arguments = object_arguments(
        "sustainablelobster.legacy_ad.user",
        PARAMETERS,
        aliases=(
            ("surname", "lastname"),
            ("spn", "spns"),
            ("delegates", "principals_allowed_to_delegate"),
        ),
    )
    for name in (
        "account_locked",
        "enabled",
        "password_expired",
        "password_never_expires",
        "user_cannot_change_password",
    ):
        value = arguments[name]
        arguments[name] = None if value is None else as_bool(value, name)
    if arguments["account_locked"] is True:
        raise ValueError(
            "account_locked only accepts false; administrators may unlock, not lock, an account."
        )
    if arguments["password_expired"] and arguments["password_never_expires"]:
        raise ValueError(
            "password_expired and password_never_expires cannot both be true."
        )
    arguments["password"] = as_string(arguments["password"], "password")
    password_policy = as_string(arguments["update_password"], "update_password")
    arguments["update_password"] = (
        "always" if password_policy is None else password_policy.lower()
    )
    if arguments["update_password"] not in ("always", "on_create", "when_changed"):
        raise ValueError("update_password must be always, on_create or when_changed.")
    return arguments


def password_matches(username, password):
    """Check a domain password using the same network logon semantics as upstream.

    :param username: UPN or DOMAIN\\account identity.
    :type username: str
    :param password: Supplied secret; never included in errors or return data.
    :type password: str
    :returns: Whether the password is valid under the upstream error rules.
    :rtype: bool
    :raises OSError: If the logon or token cleanup fails unexpectedly.
    """
    domain = None
    if "\\" in username and "@" not in username:
        domain, username = username.split("\\", 1)
    # The fixed logon ABI repeats local-account declarations, not their error rules.
    # pylint: disable=duplicate-code
    security = ctypes.WinDLL("advapi32", use_last_error=True)
    security.LogonUserW.argtypes = [
        ctypes.c_wchar_p,
        ctypes.c_wchar_p,
        ctypes.c_wchar_p,
        ctypes.c_uint32,
        ctypes.c_uint32,
        ctypes.POINTER(ctypes.c_void_p),
    ]
    security.LogonUserW.restype = ctypes.c_int
    kernel = ctypes.WinDLL("kernel32", use_last_error=True)
    kernel.CloseHandle.argtypes = [ctypes.c_void_p]
    kernel.CloseHandle.restype = ctypes.c_int
    token = ctypes.c_void_p()
    # pylint: enable=duplicate-code
    if security.LogonUserW(username, domain, password, 3, 0, ctypes.byref(token)):
        if not kernel.CloseHandle(token):
            raise ctypes.WinError(ctypes.get_last_error())
        return True
    error = ctypes.get_last_error()
    if error in (1327, 1328, 1329, 1385):
        return True
    if error in (1326, 1330, 1793, 1907, 1331):
        return False
    raise ctypes.WinError(error)


def _password_change(arguments, entry, connection):
    password = arguments["password"]
    if password is None:
        return False
    if entry is None:
        return bool(password.strip())
    if arguments["update_password"] == "always":
        return True
    if arguments["update_password"] == "on_create":
        return False
    username = text_attribute(entry, "userPrincipalName") or text_attribute(
        entry, "msDS-PrincipalName"
    )
    if not username:
        domain = ".".join(
            part[3:]
            for part in connection.naming_context().split(",")
            if part.lower().startswith("dc=")
        )
        username = text_attribute(entry, "sAMAccountName") + "@" + domain
    return not password_matches(username, password)


def _password_denial(fields):
    if len(fields) != 6 or fields[0] != "OD" or fields[3].lower() != _CHANGE_PASSWORD:
        return False
    if fields[5] not in ("WD", "PS", "S-1-1-0", "S-1-5-10"):
        return False
    return (
        bool(int(fields[2], 16) & 256)
        if fields[2].lower().startswith("0x")
        else "CR" in fields[2]
    )


def _cannot_change_password(entry):
    descriptor = security_descriptor_text(
        raw_attributes(entry)["ntsecuritydescriptor"][0]
    )
    for ace in re.findall(r"\(([^()]*)\)", descriptor):
        fields = ace.split(";")
        if _password_denial(fields):
            return True
    return False


def _password_permission(entry, enabled):
    descriptor = security_descriptor_text(
        raw_attributes(entry)["ntsecuritydescriptor"][0]
    )
    if enabled == _cannot_change_password(entry):
        return []

    def _strip_ace(match):
        fields = match.group(1).split(";")
        if _password_denial(fields):
            if "ID" in fields[1]:
                raise ValueError(
                    "Change inherited password restrictions on the parent object's ACL."
                )
            if fields[2].lower().startswith("0x"):
                remainder = int(fields[2], 16) & ~256
                if not remainder:
                    return ""
                fields[2] = "0x{0:x}".format(remainder)
            else:
                fields[2] = fields[2].replace("CR", "")
                if not fields[2]:
                    return ""
            return "(" + ";".join(fields) + ")"
        return match.group(0)

    updated = re.sub(r"\(([^()]*)\)", _strip_ace, descriptor)
    if enabled:
        match = re.search(r"D:([^()]*)", updated)
        if match is None:
            raise ValueError(
                "Cannot manage password-change permissions without a readable DACL."
            )
        deny = "".join(
            "(OD;;CR;" + _CHANGE_PASSWORD + ";;" + sid + ")" for sid in ("WD", "PS")
        )
        updated = updated[: match.end()] + deny + updated[match.end() :]
    return [(2, "nTSecurityDescriptor", [security_descriptor_bytes(updated)])]


def _account_flags(arguments, entry):
    previous = integer_attribute(entry, "userAccountControl", 514)
    value = account_control(arguments, entry, 514)
    enabled = arguments["enabled"]
    if entry is None and enabled is None:
        enabled = bool(arguments["password"] and arguments["password"].strip())
    if enabled is not None:
        value = value & ~2 if enabled else value | 2
    if arguments["password_never_expires"] is not None:
        value = value | 65536 if arguments["password_never_expires"] else value & ~65536
    changes = (
        []
        if value == previous
        else [(2, "userAccountControl", [str(value).encode("ascii")])]
    )
    if (
        arguments["account_locked"] is False
        and integer_attribute(entry, "msDS-User-Account-Control-Computed") & 16
    ):
        changes.append((2, "lockoutTime", [b"0"]))
    return changes, previous, value, enabled


def _password_expired(entry):
    computed = integer_attribute(entry, "msDS-User-Account-Control-Computed")
    return bool(computed & 0x800000) or integer_attribute(entry, "pwdLastSet") == 0


# These inputs separate foreign-group credentials, desired links and the
# account's owned execution result; keep native link writes visible here.
# pylint: disable=too-many-arguments,too-many-positional-arguments,too-many-locals
def _group_membership(session, entry, request, resolved, servers, arguments, result):
    existing = [
        value.decode("utf-8") for value in raw_attributes(entry).get("memberof", [])
    ]
    primary = None
    if entry:
        sid = sid_text(raw_attributes(entry)["objectsid"][0])
        primary_sid = (
            sid.rsplit("-", 1)[0]
            + "-"
            + str(integer_attribute(entry, "primaryGroupID", 513))
        )
        group = find_object(session.connection(), primary_sid, ["objectClass"])
        if group:
            primary = group["dn"]
            existing.append(primary)
    desired, added, removed = compare_list(existing if entry else None, resolved)
    policy = request["permissions_failure_action"]
    for operation, groups in ((0, added), (1, removed)):
        for group in groups:
            if primary and group.lower() == primary.lower() and operation == 1:
                if request.get("set") != []:
                    result.setdefault("warnings", []).append(
                        "Cannot remove group '"
                        + group
                        + "' because it is the user's primary group."
                    )
                result["changed"] = True
                continue
            connection = servers.get(group.lower()) or session.connection()
            try:
                apply_changes(
                    connection,
                    group,
                    [
                        (
                            operation,
                            "member",
                            [result["distinguished_name"].encode("utf-8")],
                        )
                    ],
                    arguments,
                    result,
                )
            except OSError as error:
                if policy == "fail":
                    raise
                if policy == "warn":
                    result.setdefault("warnings", []).append(
                        "Cannot update membership of group '"
                        + group
                        + "': "
                        + str(error)
                    )
                result["changed"] = True
    return existing, desired


# pylint: enable=too-many-arguments,too-many-positional-arguments,too-many-locals


# Explicit old/new account flags keep the password-redacted diff independent
# of the post-write account snapshot.
# pylint: disable=too-many-arguments,too-many-positional-arguments
def _user_diff(
    arguments, result, entry, previous_uac, desired_uac, enabled, password_changed
):
    before, after = result["diff"]["before"], result["diff"]["after"]
    if "userAccountControl" not in arguments.get("_original_set", {}):
        after["attributes"].pop("userAccountControl", None)
        if before:
            before["attributes"].pop("userAccountControl", None)
    fields = {
        "enabled": (not bool(previous_uac & 2), enabled),
        "password_never_expires": (
            bool(previous_uac & 65536),
            bool(desired_uac & 65536),
        ),
        "account_locked": (
            bool(integer_attribute(entry, "msDS-User-Account-Control-Computed") & 16),
            False,
        ),
        "password_expired": (
            _password_expired(entry),
            arguments["password_expired"],
        ),
    }
    for name, (old, new) in fields.items():
        if arguments[name] is not None or name == "enabled" and entry is None:
            after[name] = new
            if before:
                before[name] = old
    if arguments["password"] is not None and (entry or arguments["password"].strip()):
        after["password"] = NO_LOG + (
            " - changed" if entry and password_changed else ""
        )
        if before:
            before["password"] = NO_LOG


# pylint: enable=too-many-arguments,too-many-positional-arguments


# Keep this module workflow linear: validation and reads, shared lifecycle,
# encrypted password reset, flags, then the separately-owned group links.
# pylint: disable=too-many-locals,too-many-statements,too-many-branches
def manage_user(arguments, result):
    """Apply the upstream user interface without exposing password values.

    :param arguments: Common arguments plus normalized user-specific options.
    :type arguments: dict
    :param result: Mutable result preserving successful partial changes.
    :type result: dict
    :raises ValueError: If identities or required schema capabilities are invalid.
    :raises OSError: If native authentication or a directory mutation fails.
    """
    spn = list_request(arguments["spn"], "spn")
    groups = list_request(
        arguments["groups"], "groups", identities=True, permissions=True
    )
    # Class-specific account lookup deliberately shares this small session setup;
    # the actual user and computer workflows remain separately readable below.
    # pylint: disable=duplicate-code
    delegates = list_request(arguments["delegates"], "delegates", identities=True)
    with DirectorySession(arguments) as session:
        connection = session.connection()
        entry = find_account(
            session,
            arguments,
            USERS_CONTAINER,
            list(PROPERTIES.values()) + list(_EXTRA_ATTRIBUTES),
            result,
            object_type="user",
        )
        # pylint: enable=duplicate-code
        if arguments["state"] == "absent":
            remove_account(connection, arguments, entry, result)
            return
        original = entry
        delegated = resolve_delegates(session, delegates, result)
        resolved, servers = (
            resolve_lists(session, groups, "groups", result)
            if groups is not None
            else (None, None)
        )
        password_changed = _password_change(arguments, entry, connection)
        flags, previous_uac, desired_uac, enabled = _account_flags(arguments, entry)
        arguments["_original_set"] = dict(arguments["attributes"]["set"])
        if entry is None:
            initial_uac = account_control(arguments, entry, 514) | 2
            for name in list(arguments["attributes"]["set"]):
                if name.lower() == "useraccountcontrol":
                    del arguments["attributes"]["set"][name]
            arguments["attributes"]["set"]["userAccountControl"] = {
                "type": "int",
                "value": initial_uac,
            }
            if arguments["sam_account_name"] is None:
                arguments["sam_account_name"] = (
                    arguments["name"] or arguments["identity"]
                )
        managed = ensure_present(session, arguments, "user", PROPERTIES, result, entry)
        finish_identifiers(connection, managed, result)
        dn = result["distinguished_name"]
        if password_changed:
            # AD's unicodePwd reset is a quoted UTF-16LE value sent exclusively
            # through the LDAP session whose bind requires signing and sealing.
            apply_changes(
                connection,
                dn,
                [
                    (
                        2,
                        "unicodePwd",
                        [('"' + arguments["password"] + '"').encode("utf-16-le")],
                    )
                ],
                arguments,
                result,
            )
        apply_changes(connection, dn, flags, arguments, result)
        if arguments["password_expired"] is not None:
            old = _password_expired(entry)
            if (
                entry is None
                or old != arguments["password_expired"]
                or password_changed
                and arguments["password_expired"]
            ):
                apply_changes(
                    connection,
                    dn,
                    [
                        (
                            2,
                            "pwdLastSet",
                            [b"0" if arguments["password_expired"] else b"-1"],
                        )
                    ],
                    arguments,
                    result,
                )
        if arguments["user_cannot_change_password"] is not None:
            current = (
                find_object(connection, dn, ["nTSecurityDescriptor"], True)
                if not arguments["check_mode"]
                else entry
            )
            old = _cannot_change_password(current) if current else False
            changes = (
                _password_permission(current, arguments["user_cannot_change_password"])
                if current
                else []
            )
            if current is None and arguments["user_cannot_change_password"]:
                result["changed"] = True
            apply_changes(connection, dn, changes, arguments, result)
            if arguments["diff_mode"]:
                result["diff"]["after"]["user_cannot_change_password"] = arguments[
                    "user_cannot_change_password"
                ]
                if result["diff"]["before"]:
                    result["diff"]["before"]["user_cannot_change_password"] = old
        apply_spn(connection, arguments, entry, spn, result)
        if delegated is not None:
            changes, previous, desired = delegation_changes(entry, delegated)
            apply_changes(connection, dn, changes, arguments, result)
            if arguments["diff_mode"]:
                result["diff"]["after"]["delegates"] = sorted(desired)
                if result["diff"]["before"]:
                    result["diff"]["before"]["delegates"] = sorted(previous)
        if groups is not None:
            group_entry = (
                original
                if arguments["check_mode"]
                else (
                    find_object(
                        connection,
                        dn,
                        ["objectSid", "memberOf", "primaryGroupID"],
                        True,
                    )
                    if managed
                    else None
                )
            )
            before_groups, after_groups = _group_membership(
                session, group_entry, groups, resolved, servers, arguments, result
            )
            if arguments["diff_mode"]:
                result["diff"]["after"]["groups"] = sorted(after_groups)
                if result["diff"]["before"]:
                    result["diff"]["before"]["groups"] = sorted(before_groups)
        if arguments["diff_mode"]:
            _user_diff(
                arguments,
                result,
                original,
                previous_uac,
                desired_uac,
                enabled,
                password_changed,
            )
