# Copyright 2026 sustainablelobster
# SPDX-License-Identifier: GPL-3.0-or-later

"""Share concrete AD account identity, list and result handling."""

import re
import uuid

import legacy_windows_account as accounts  # pylint: disable=import-error
from legacy_ad_object import (  # pylint: disable=import-error
    DEFAULT_PATH,
    escape_rdn,
    find_object,
    remove_tree,
    split_dn,
)
from legacy_ad_schema import (  # pylint: disable=import-error
    DirectorySchema,
    security_descriptor_bytes,
    security_descriptor_text,
    sid_text,
)
from legacy_windows_module import (  # pylint: disable=import-error
    as_dictionary,
    as_string,
    as_string_list,
)

USERS_CONTAINER = "A9D1CA15768811D1ADED00C04FD8D5CD"
COMPUTERS_CONTAINER = "AA312825768811D1ADED00C04FD8D5CD"
ACCOUNT_ATTRIBUTES = (
    "objectGUID",
    "objectSid",
    "objectClass",
    "name",
    "nTSecurityDescriptor",
    "sAMAccountName",
    "userAccountControl",
)
NO_LOG = "VALUE_SPECIFIED_IN_NO_LOG_PARAMETER"
_KERBEROS_TYPES = {"des": 3, "rc4": 4, "aes128": 8, "aes256": 16}


def raw_attributes(entry):
    """Read copied LDAP values with case-insensitive attribute names.

    :param entry: LDAP entry, or None for a predicted new account.
    :type entry: dict or None
    :returns: Lowercase LDAP names mapped to byte-value lists.
    :rtype: dict
    """
    return (
        {name.lower(): values for name, values in entry["attributes"].items()}
        if entry
        else {}
    )


def text_attribute(entry, name, default=None):
    """Read one UTF-8 directory value or the supplied default.

    :param entry: LDAP entry, or None.
    :type entry: dict or None
    :param name: LDAP attribute name.
    :type name: str
    :param default: Missing-value fallback.
    :type default: str or None
    :returns: Decoded directory value or the fallback.
    :rtype: str or None
    """
    values = raw_attributes(entry).get(name.lower(), [])
    return values[0].decode("utf-8") if values else default


def integer_attribute(entry, name, default=0):
    """Read one integer directory value or the supplied default.

    :param entry: LDAP entry, or None.
    :type entry: dict or None
    :param name: LDAP attribute name.
    :type name: str
    :param default: Missing-value fallback.
    :type default: int
    :returns: Parsed directory integer.
    :rtype: int
    """
    return int(text_attribute(entry, name, str(default)))


def default_container(connection, container, attribute="wellKnownObjects"):
    """Find the domain's possibly redirected well-known account container.

    :param connection: Authenticated native LDAP connection.
    :type connection: LDAPConnection
    :param container: Well-known account container GUID text.
    :type container: str
    :param attribute: Directory attribute advertising the well-known container.
    :type attribute: str
    :returns: The advertised distinguished name.
    :rtype: str
    :raises ValueError: If the directory does not advertise the container.
    """
    domain = find_object(connection, connection.naming_context(), [attribute], True)
    for value in raw_attributes(domain).get(attribute.lower(), []):
        fields = value.decode("utf-8").split(":", 3)
        if (
            len(fields) == 4
            and fields[:2] == ["B", "32"]
            and fields[2].upper() == container
        ):
            return fields[3]
    raise ValueError(
        "The directory does not advertise the default account container "
        + container
        + "."
    )


# Container, selected values, requested class and result ownership are distinct
# parts of account lookup; keep them named instead of bundling hidden state.
def find_account(  # pylint: disable=too-many-arguments
    session,
    arguments,
    container,
    attributes,
    result,
    *,
    object_type,
    computer=False,
    container_attribute="wellKnownObjects"
):
    """Resolve an account and initialize identifiers without mutating AD.

    :param session: Owned credential-aware directory session.
    :type session: DirectorySession
    :param arguments: Validated account module options.
    :type arguments: dict
    :param container: Default well-known account container GUID.
    :type container: str
    :param attributes: Additional attributes to read.
    :type attributes: list[str]
    :param result: Mutable module result retaining observed identifiers.
    :type result: dict
    :param object_type: Requested account's structural LDAP class.
    :type object_type: str
    :param computer: Whether a bare identity has the upstream dollar fallback.
    :type computer: bool
    :param container_attribute: Attribute advertising the default account container.
    :type container_attribute: str
    :returns: The observed account or None.
    :rtype: dict or None
    :raises ValueError: If the directory's default container is unavailable.
    """
    connection = session.connection()
    identity = arguments["identity"]
    if arguments["path"] == DEFAULT_PATH or (
        not identity and arguments["path"] in (None, "")
    ):
        arguments["path"] = default_container(
            connection, container, container_attribute
        )
    if not identity:
        identity = "CN=" + escape_rdn(arguments["name"]) + "," + arguments["path"]
    requested = list(ACCOUNT_ATTRIBUTES) + list(attributes)
    requested.extend(
        name for values in arguments["attributes"].values() for name in values
    )
    entry = find_object(
        connection,
        identity,
        requested,
        not bool(arguments["identity"]),
        expected_class=object_type,
    )
    bare_computer = computer and arguments["identity"] and not identity.endswith("$")
    if (
        entry is None
        and bare_computer
        and "=" not in identity
        and not identity.upper().startswith("S-1-")
    ):
        try:
            uuid.UUID(identity)
        except ValueError:
            entry = find_object(
                connection, identity + "$", requested, expected_class=object_type
            )
    if entry:
        raw = raw_attributes(entry)
        result.update(
            {
                "distinguished_name": entry["dn"],
                "object_guid": str(uuid.UUID(bytes_le=raw["objectguid"][0])),
                "sid": sid_text(raw["objectsid"][0]),
            }
        )
    elif arguments["state"] == "present" and arguments["path"] in (
        None,
        "",
        DEFAULT_PATH,
    ):
        arguments["path"] = default_container(
            connection, container, container_attribute
        )
    return entry


def remove_account(connection, arguments, entry, result):
    """Remove an account through the shared protected-object lifecycle.

    :param connection: Authenticated native LDAP connection.
    :type connection: LDAPConnection
    :param arguments: Validated account options.
    :type arguments: dict
    :param entry: The observed account, or None.
    :type entry: dict or None
    :param result: Mutable result retaining identifiers and partial changes.
    :type result: dict
    """
    # Account diffs allow an unavailable name, unlike the strict object projection.
    # pylint: disable=duplicate-code
    if entry:
        remove_tree(connection, entry, arguments, result)
    if arguments["diff_mode"]:
        result["diff"] = {
            "before": (
                {
                    "name": text_attribute(entry, "name"),
                    "path": split_dn(entry["dn"])[1],
                    "attributes": None,
                }
                if entry
                else None
            ),
            "after": None,
        }
    # pylint: enable=duplicate-code


def _list_policies(value, name, identities, permissions):
    result = {}
    policies = []
    if identities:
        policies.append("lookup_failure_action")
    if permissions:
        policies.append("permissions_failure_action")
    for policy in policies:
        choice = (
            value["missing_behaviour"]
            if policy == "lookup_failure_action" and "missing_behaviour" in value
            else value.get(policy, "fail")
        )
        choice = as_string(choice, name + "." + policy)
        choice = choice.lower() if choice is not None else None
        if choice not in ("fail", "ignore", "warn"):
            raise ValueError(name + "." + policy + " must be fail, ignore or warn.")
        result[policy] = choice
    return result


def list_request(value, name, identities=False, permissions=False):
    """Validate an upstream add/remove/set list option and its failure policy.

    :param value: User-supplied option value.
    :type value: object
    :param name: Parameter name used in actionable validation failures.
    :type name: str
    :param identities: Whether elements may be DN-lookup dictionaries.
    :type identities: bool
    :param permissions: Whether group-write failure policy is accepted.
    :type permissions: bool
    :returns: Normalized request or None when the option was omitted.
    :rtype: dict or None
    :raises ValueError: If keys, policies or list elements are invalid.
    """
    value = as_dictionary(value, name)
    if value is None:
        return None
    allowed = {"add", "remove", "set"}
    if identities:
        allowed.add("lookup_failure_action")
    if permissions:
        allowed.update(("permissions_failure_action", "missing_behaviour"))
    if set(value) - allowed:
        raise ValueError(
            name
            + " has unsupported keys: "
            + ", ".join(sorted(set(value) - allowed))
            + "."
        )
    result = {}
    for action in ("add", "remove", "set"):
        items = value.get(action)
        if items is None:
            continue
        if identities:
            items = [items] if not isinstance(items, list) else items
            for item in items:
                if not isinstance(item, (str, dict)):
                    raise ValueError(
                        name
                        + "."
                        + action
                        + " requires identity strings or name/server dictionaries."
                    )
            result[action] = items
        else:
            result[action] = as_string_list(items, name + "." + action)
    result.update(_list_policies(value, name, identities, permissions))
    return result


def compare_list(existing, request):
    """Reconcile case-insensitive AD list values in upstream precedence order.

    :param existing: Existing string list.
    :type existing: list[str] or None
    :param request: Normalized add/remove/set option.
    :type request: dict
    :returns: Desired values, additions and removals.
    :rtype: tuple[list, list, list]
    """
    if existing is None:
        existing = []
        desired = list(request.get("add", [])) + list(request.get("set", []))
    elif "set" in request:
        desired = list(request["set"])
    else:
        remove = {value.lower() for value in request.get("remove", [])}
        desired = [value for value in existing if value.lower() not in remove]
        old = {value.lower() for value in existing}
        desired.extend(
            value for value in request.get("add", []) if value.lower() not in old
        )
    unique = set()
    ordered = []
    for value in desired:
        key = value.lower()
        if key not in unique:
            unique.add(key)
            ordered.append(value)
    desired = ordered
    old, new = {value.lower() for value in existing}, unique
    return (
        desired,
        [value for value in desired if value.lower() not in old],
        [value for value in existing if value.lower() not in new],
    )


def resolve_lists(session, request, name, result, sids=False):
    """Resolve requested principal identities using their directory credentials.

    :param session: Owned credential-aware directory session.
    :type session: DirectorySession
    :param request: Normalized DN-lookup list request.
    :type request: dict
    :param name: Parameter name used in warnings and failures.
    :type name: str
    :param result: Mutable result receiving warnings.
    :type result: dict
    :param sids: Whether resolved SID strings rather than DNs are required.
    :type sids: bool
    :returns: Resolved list request and DN-to-connection mapping.
    :rtype: tuple[dict, dict]
    :raises ValueError: If an identity cannot be resolved under fail policy.
    """
    resolved, connections = {}, {}
    for action in ("add", "remove", "set"):
        if action not in request:
            continue
        resolved[action] = []
        for identity in request[action]:
            server = None
            if isinstance(identity, dict):
                if set(identity) - {"name", "server"} or "name" not in identity:
                    raise ValueError(
                        name
                        + " identity dictionaries require name and optionally server."
                    )
                server, identity = identity.get("server"), identity["name"]
            identity = as_string(identity, name)
            server = as_string(server, name + ".server")
            if identity is None or not identity.strip():
                continue
            server = server if server and server.strip() else None
            connection = session.connection(server)
            entry = find_object(connection, identity, ["objectSid", "objectClass"])
            if entry is None:
                message = "Unable to resolve " + name + " AD identity: " + identity
                policy = request["lookup_failure_action"]
                if policy == "fail":
                    raise ValueError(message)
                if policy == "warn":
                    result.setdefault("warnings", []).append(message)
                continue
            if sids and not raw_attributes(entry).get("objectsid"):
                raise ValueError(
                    "The " + name + " identity is not a security principal: " + identity
                )
            value = (
                sid_text(raw_attributes(entry)["objectsid"][0]) if sids else entry["dn"]
            )
            resolved[action].append(value)
            connections[value.lower()] = connection
    return resolved, connections


def require_attributes(connection, names):
    """Reject unsupported schema capabilities before any account mutation.

    :param connection: Authenticated native LDAP connection.
    :type connection: LDAPConnection
    :param names: LDAP names required by the requested options.
    :type names: list[str]
    :raises ValueError: If the directory schema lacks a required attribute.
    """
    schema = DirectorySchema(connection)
    for name in names:
        if name.lower() not in schema.attributes:
            raise ValueError("The directory schema does not support " + name + ".")


def apply_changes(connection, dn, changes, arguments, result):
    """Apply known account differences, retaining successful partial writes.

    :param connection: Authenticated native LDAP connection.
    :type connection: LDAPConnection
    :param dn: Distinguished name of the account or membership group.
    :type dn: str
    :param changes: Nonempty LDAP modification list, or an empty list.
    :type changes: list[tuple]
    :param arguments: Validated options with check_mode.
    :type arguments: dict
    :param result: Mutable result receiving the changed flag.
    :type result: dict
    """
    if not changes:
        return
    if not arguments["check_mode"]:
        connection.modify(dn, changes)
    result["changed"] = True


def resolve_delegates(session, request, result):
    """Resolve RBCD principals only when the schema supports delegation.

    :param session: Owned credential-aware directory session.
    :type session: DirectorySession
    :param request: Normalized delegation request, or None when omitted.
    :type request: dict or None
    :param result: Mutable result receiving lookup warnings.
    :type result: dict
    :returns: Resolved principal SID request, or None.
    :rtype: dict or None
    :raises ValueError: If the schema or requested principals are unavailable.
    """
    if request is None:
        return None
    require_attributes(
        session.connection(), ["msDS-AllowedToActOnBehalfOfOtherIdentity"]
    )
    return resolve_lists(session, request, "delegates", result, sids=True)[0]


def apply_spn(connection, arguments, entry, request, result):
    """Reconcile account service principals and expose the requested diff.

    :param connection: Authenticated native LDAP connection.
    :type connection: LDAPConnection
    :param arguments: Validated options containing check_mode and diff_mode.
    :type arguments: dict
    :param entry: Original account, or None for creation.
    :type entry: dict or None
    :param request: Normalized SPN add/remove/set request, or None.
    :type request: dict or None
    :param result: Mutable lifecycle result with the current account DN.
    :type result: dict
    """
    if request is None:
        return
    existing = [
        value.decode("utf-8")
        for value in raw_attributes(entry).get("serviceprincipalname", [])
    ]
    desired, added, removed = compare_list(existing if entry else None, request)
    changes = (
        [(1, "servicePrincipalName", [value.encode("utf-8") for value in removed])]
        if removed
        else []
    )
    if added:
        changes.append(
            (0, "servicePrincipalName", [value.encode("utf-8") for value in added])
        )
    apply_changes(connection, result["distinguished_name"], changes, arguments, result)
    if arguments["diff_mode"]:
        result["diff"]["after"]["spn"] = sorted(desired)
        if result["diff"]["before"]:
            result["diff"]["before"]["spn"] = sorted(existing)


def delegation_changes(entry, request):
    """Build an RBCD descriptor change while preserving non-principal ACEs.

    :param entry: Existing account or None for creation.
    :type entry: dict or None
    :param request: Resolved SID add/remove/set request.
    :type request: dict
    :returns: Modification list and old/new principal SID lists.
    :rtype: tuple[list, list, list]
    :raises ValueError: If an existing delegation descriptor has no readable DACL.
    """
    attribute = "msDS-AllowedToActOnBehalfOfOtherIdentity"
    values = raw_attributes(entry).get(attribute.lower(), [])
    descriptor = security_descriptor_text(values[0]) if values else "O:BAG:BAD:"
    if "D:" not in descriptor:
        raise ValueError("The delegation security descriptor has no readable DACL.")
    principals = []
    for ace in re.findall(r"\(([^()]*)\)", descriptor):
        fields = ace.split(";")
        if len(fields) == 6 and fields[0] == "A":
            principals.append(sid_text(accounts.sid_bytes(fields[5])))
    desired, added, removed = compare_list(principals, request)
    if not added and not removed:
        return [], principals, desired
    removed = {sid.lower() for sid in removed}

    def _keep_ace(match):
        fields = match.group(1).split(";")
        principal = (
            sid_text(accounts.sid_bytes(fields[5])).lower()
            if len(fields) == 6 and fields[0] == "A"
            else None
        )
        return "" if principal in removed else match.group(0)

    updated = re.sub(r"\(([^()]*)\)", _keep_ace, descriptor)
    insertion = re.search(r"D:([^()]*)", updated).end()
    aces = "".join("(A;;CCDCLCSWRPWPDTLOCRSDRCWDWO;;;" + sid + ")" for sid in added)
    updated = updated[:insertion] + aces + updated[insertion:]
    return [(2, attribute, [security_descriptor_bytes(updated)])], principals, desired


def encryption_request(value):
    """Validate the shared computer/gMSA Kerberos encryption option.

    :param value: Public add/remove/set request, or None when omitted.
    :type value: dict or None
    :returns: Validated request, or None.
    :rtype: dict or None
    :raises ValueError: A requested encryption type is unknown.
    """
    request = list_request(value, "kerberos_encryption_types")
    if not request:
        return None
    for action in ("add", "remove", "set"):
        for name in request.get(action, []):
            if name.lower() not in _KERBEROS_TYPES:
                raise ValueError(
                    "kerberos_encryption_types."
                    + action
                    + " must contain aes128, aes256, des or rc4."
                )
    return request


def encryption_changes(entry, request):
    """Build the existing Kerberos bitmask update and its before/after values.

    :param entry: Existing account, or None for creation.
    :type entry: dict or None
    :param request: Validated encryption request.
    :type request: dict
    :returns: LDAP modifications and existing/desired encryption names.
    :rtype: tuple[list, list, list]
    """
    previous = integer_attribute(entry, "msDS-SupportedEncryptionTypes")
    existing = [
        name.upper()
        for name in ("des", "rc4", "aes128", "aes256")
        if previous & _KERBEROS_TYPES[name]
    ]
    desired, added, removed = compare_list(existing if entry else None, request)
    mask = sum(_KERBEROS_TYPES[name.lower()] for name in desired)
    changes = (
        [(2, "msDS-SupportedEncryptionTypes", [str(mask).encode("ascii")])]
        if entry is None or added or removed
        else []
    )
    return changes, existing, desired


def finish_identifiers(connection, entry, result):
    """Return the account SID, including upstream's predicted-creation marker.

    :param connection: Authenticated native LDAP connection.
    :type connection: LDAPConnection
    :param entry: Observed final account, or None for predicted creation.
    :type entry: dict or None
    :param result: Mutable result receiving sid.
    :type result: dict
    :raises ValueError: If an observed account disappears during readback.
    """
    if entry and "objectsid" not in raw_attributes(entry):
        entry = find_object(connection, entry["dn"], ["objectSid"], True)
        if entry is None:
            raise ValueError("The managed account disappeared during SID readback.")
    result["sid"] = (
        sid_text(raw_attributes(entry)["objectsid"][0]) if entry else "S-1-5-0000"
    )


def account_control(arguments, entry, default):
    """Read requested raw account flags before applying named Boolean options.

    :param arguments: Common account options with raw attributes.
    :type arguments: dict
    :param entry: Existing account, or None for creation.
    :type entry: dict or None
    :param default: New-account flag value.
    :type default: int
    :returns: Requested or existing userAccountControl bits.
    :rtype: int
    :raises ValueError: If the raw flags are not one integer value.
    """
    value = next(
        (
            value
            for name, value in arguments["attributes"]["set"].items()
            if name.lower() == "useraccountcontrol"
        ),
        None,
    )
    if value is None:
        return integer_attribute(entry, "userAccountControl", default)
    if isinstance(value, list):
        if len(value) != 1:
            raise ValueError("userAccountControl must contain one integer value.")
        value = value[0]
    if isinstance(value, dict):
        if value.get("type") not in ("int", "raw") or set(value) != {"type", "value"}:
            raise ValueError(
                "userAccountControl requires a raw or int attribute value."
            )
        value = value["value"]
    return int(value)


def account_flags(arguments, entry, default):
    """Apply the shared computer/gMSA enabled and delegation flags.

    :param arguments: Validated Boolean options and raw account attributes.
    :type arguments: dict
    :param entry: Existing LDAP account, or None for creation.
    :type entry: dict or None
    :param default: Initial userAccountControl bits for this account class.
    :type default: int
    :returns: Existing and desired userAccountControl integers.
    :rtype: tuple[int, int]
    :raises ValueError: A requested raw flag value is invalid.
    """
    previous = integer_attribute(entry, "userAccountControl", default)
    value = account_control(arguments, entry, default)
    enabled = arguments["enabled"]
    if entry is None and enabled is None:
        enabled = True
    if enabled is not None:
        value = value & ~2 if enabled else value | 2
    if arguments["trusted_for_delegation"] is not None:
        value = (
            value | 524288 if arguments["trusted_for_delegation"] else value & ~524288
        )
    return previous, value


def record_account_flags(arguments, result, entry, previous, value):
    """Record the two shared named account flags in the public diff.

    :param arguments: Validated Boolean account options.
    :type arguments: dict
    :param result: Mutable result containing before/after diff dictionaries.
    :type result: dict
    :param entry: Existing LDAP account, or None for creation.
    :type entry: dict or None
    :param previous: Previously observed userAccountControl integer.
    :type previous: int
    :param value: Desired userAccountControl integer.
    :type value: int
    """
    before, after = result["diff"]["before"], result["diff"]["after"]
    for name, old, new in (
        ("enabled", not bool(previous & 2), not bool(value & 2)),
        ("trusted_for_delegation", bool(previous & 524288), bool(value & 524288)),
    ):
        if arguments[name] is not None or name == "enabled" and entry is None:
            after[name] = new
            if before:
                before[name] = old
