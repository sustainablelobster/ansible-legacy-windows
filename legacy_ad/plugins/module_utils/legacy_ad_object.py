# Copyright 2026 sustainablelobster
# SPDX-License-Identifier: GPL-3.0-or-later

"""Manage native directory object lifecycles and their requested attributes."""

import base64
import binascii
import datetime
import re
import uuid

import legacy_windows_account as accounts  # pylint: disable=import-error
from legacy_ad_ldap import (  # pylint: disable=import-error
    SCOPE_BASE,
    SCOPE_SUBTREE,
    LDAPConnection,
    LDAPError,
    escape_filter,
)
from legacy_ad_schema import (  # pylint: disable=import-error
    DirectorySchema,
    is_explicit_everyone_deny,
    protected_from_deletion,
    security_descriptor_bytes,
    security_descriptor_text,
)
from legacy_windows_module import (  # pylint: disable=import-error
    as_bool,
    as_dictionary,
    as_string,
    read_arguments,
)

COMMON_PARAMETERS = (
    "attributes",
    "description",
    "display_name",
    "domain_credentials",
    "domain_password",
    "domain_server",
    "domain_username",
    "identity",
    "name",
    "path",
    "protect_from_deletion",
    "state",
)
DEFAULT_PATH = "microsoft.ad.default_path"
_ZERO_GUID = "00000000-0000-0000-0000-000000000000"
_SDDL_RIGHTS = {
    "CC": 1,
    "DC": 2,
    "LC": 4,
    "SW": 8,
    "RP": 16,
    "WP": 32,
    "DT": 64,
    "LO": 128,
    "CR": 256,
    "SD": 65536,
    "RC": 131072,
    "WD": 262144,
    "WO": 524288,
    "GA": 0x10000000,
    "GX": 0x20000000,
    "GW": 0x40000000,
    "GR": 0x80000000,
}


def _credentials(value):
    if value is None:
        return []
    if not isinstance(value, list):
        raise ValueError(
            "domain_credentials must be a list of credential dictionaries."
        )
    result = []
    for entry in value:
        entry = as_dictionary(entry, "domain_credentials")
        if not entry or set(entry) - {"name", "username", "password"}:
            raise ValueError(
                "domain_credentials entries allow name, username and password."
            )
        if entry.get("username") is None or entry.get("password") is None:
            raise ValueError(
                "domain_credentials entries require username and password."
            )
        result.append(
            {
                name: as_string(entry.get(name), "domain_credentials." + name)
                for name in ("name", "username", "password")
            }
        )
    return result


def object_arguments(module_name, property_names, aliases=()):
    """Read common object arguments and validate their public interface.

    :param module_name: Fully qualified module name for error messages.
    :type module_name: str
    :param property_names: Additional module-specific argument names.
    :type property_names: tuple[str]
    :param aliases: Canonical name/alias pairs, in upstream precedence order.
    :type aliases: tuple[tuple[str, str]]
    :returns: Normalized object-management arguments.
    :rtype: dict
    :raises ValueError: If input violates the module's argument contract.
    """
    values = read_arguments(COMMON_PARAMETERS + property_names, module_name)
    # Upstream applies supplied aliases before type checks, including explicit nulls.
    for canonical, alias in aliases:
        if alias in values:
            values[canonical] = values[alias]
    arguments = {
        name: as_string(values.get(name), name)
        for name in COMMON_PARAMETERS
        if name not in ("attributes", "domain_credentials", "protect_from_deletion")
    }
    for name in property_names:
        arguments[name] = values.get(name)
    arguments["state"] = (
        "present" if arguments["state"] is None else arguments["state"].lower()
    )
    if arguments["state"] not in ("absent", "present"):
        raise ValueError("state must be absent or present.")
    if not arguments["identity"] and not arguments["name"]:
        raise ValueError("At least one of identity or name is required.")
    if (arguments["domain_username"] is None) != (arguments["domain_password"] is None):
        raise ValueError(
            "domain_username and domain_password must be supplied together."
        )
    arguments["protect_from_deletion"] = (
        None
        if values.get("protect_from_deletion") is None
        else as_bool(values["protect_from_deletion"], "protect_from_deletion")
    )
    attributes = as_dictionary(values.get("attributes", {}), "attributes") or {}
    if set(attributes) - {"add", "remove", "set"}:
        raise ValueError("attributes only supports add, remove and set.")
    arguments["attributes"] = {
        action: as_dictionary(attributes.get(action), "attributes." + action) or {}
        for action in ("add", "remove", "set")
    }
    arguments["domain_credentials"] = _credentials(values.get("domain_credentials"))
    defaults = [entry for entry in arguments["domain_credentials"] if not entry["name"]]
    if len(defaults) > 1:
        raise ValueError("Only one default domain_credentials entry may be supplied.")
    if defaults and arguments["domain_username"] is not None:
        raise ValueError(
            "Cannot combine default domain_credentials with domain_username/domain_password."
        )
    arguments["check_mode"] = as_bool(
        values.get("_ansible_check_mode", False), "_ansible_check_mode"
    )
    arguments["diff_mode"] = as_bool(
        values.get("_ansible_diff", False), "_ansible_diff"
    )
    return arguments


class DirectorySession:
    """Own the default and explicitly requested credentialed LDAP connections.

    :param arguments: Validated module arguments with domain credentials.
    :type arguments: dict
    """

    def __init__(self, arguments):
        self.arguments = arguments
        self.connections = {}

    def connection(self, server=None):
        """Open or reuse the connection for a requested directory server.

        :param server: Optional foreign server name; omission means the default.
        :type server: str or None
        :returns: An authenticated, signed and encrypted native connection.
        :rtype: LDAPConnection
        """
        key = server.lower() if server else None
        if key not in self.connections:
            credentials = (
                self.arguments["domain_username"],
                self.arguments["domain_password"],
            )
            for entry in self.arguments["domain_credentials"]:
                if key is None and not entry["name"]:
                    credentials = (entry["username"], entry["password"])
            if key is not None:
                for entry in self.arguments["domain_credentials"]:
                    if entry["name"] and entry["name"].lower() == key:
                        credentials = (entry["username"], entry["password"])
            host = server if server is not None else self.arguments["domain_server"]
            self.connections[key] = LDAPConnection(host, *credentials)
        return self.connections[key]

    def __enter__(self):
        return self

    def __exit__(self, _kind, _value, _traceback):
        for connection in self.connections.values():
            connection.close()


def escape_rdn(value):
    """Escape one relative-DN value without treating input as a whole DN.

    :param value: The literal object name.
    :type value: str
    :returns: RFC 4514 escaped RDN value.
    :rtype: str
    """
    return "".join(
        (
            "\\00"
            if character == "\0"
            else (
                "\\" + character
                if character in ',+"\\<>;='
                or (position == 0 and character in " #")
                or (position == len(value) - 1 and character == " ")
                else character
            )
        )
        for position, character in enumerate(value)
    )


def split_dn(dn):
    """Separate an object's RDN from its parent without splitting escapes.

    :param dn: The object distinguished name.
    :type dn: str
    :returns: Relative distinguished name and parent distinguished name.
    :rtype: tuple[str, str]
    :raises ValueError: If no parent component exists.
    """
    escaped = False
    for index, character in enumerate(dn):
        if escaped:
            escaped = False
        elif character == "\\":
            escaped = True
        elif character == ",":
            return dn[:index], dn[index + 1 :]
    raise ValueError("An object distinguished name must contain a parent: " + dn)


def _raw(entry):
    return {name.lower(): values for name, values in entry["attributes"].items()}


def find_object(
    connection, identity, attributes, distinguished_name=False, *, expected_class=None
):
    """Resolve a supported AD identity into one object with requested values.

    :param connection: Native LDAP connection for the identity's directory.
    :type connection: LDAPConnection
    :param identity: DN, GUID, SID, account name or user principal name.
    :type identity: str
    :param attributes: LDAP attributes required by the caller.
    :type attributes: list[str]
    :param distinguished_name: Treat the supplied value solely as a DN.
    :type distinguished_name: bool
    :param expected_class: Optional required structural class, excluding other identities.
    :type expected_class: str or None
    :returns: One copied entry, or None if the identity does not exist.
    :rtype: dict or None
    :raises ValueError: If a name resolves to multiple objects.
    :raises LDAPError: If the directory lookup fails.
    """
    if expected_class is not None:
        attributes = list(attributes)
        if "objectclass" not in [name.lower() for name in attributes]:
            attributes.append("objectClass")
    base, scope, ldap_filter = identity, SCOPE_BASE, "(objectClass=*)"
    if not distinguished_name:
        try:
            guid = uuid.UUID(identity)
        except ValueError:
            if identity.upper().startswith("S-1-"):
                base, scope = connection.naming_context(), SCOPE_SUBTREE
                ldap_filter = (
                    "(objectSid=" + escape_filter(accounts.sid_bytes(identity)) + ")"
                )
            elif not re.match(r"^[^=]+=", identity):
                base, scope = connection.naming_context(), SCOPE_SUBTREE
                value = escape_filter(identity)
                ldap_filter = "(|(sAMAccountName={0})(userPrincipalName={0}))".format(
                    value
                )
        else:
            base = "<GUID=" + binascii.hexlify(guid.bytes_le).decode("ascii") + ">"
    try:
        rows = connection.search(
            base,
            scope,
            ldap_filter,
            attributes,
            security_descriptor="ntsecuritydescriptor"
            in [name.lower() for name in attributes],
        )
    except LDAPError as error:
        if error.errno == 32:
            return None
        raise
    if len(rows) > 1:
        raise ValueError("The AD identity resolves to multiple objects: " + identity)
    entry = rows[0] if rows else None
    if entry is not None and expected_class is not None:
        classes = _raw(entry).get("objectclass", [])
        if not classes or classes[-1].decode("utf-8").lower() != expected_class.lower():
            return None
    return entry


def _date_time(value):
    match = re.match(
        r"^(\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2})(?:\.(\d{1,7}))?(Z|[+-]\d{2}:\d{2})?$",
        value,
    )
    if not match:
        raise ValueError("date_time attributes require an ISO 8601 timestamp.")
    instant = datetime.datetime.strptime(match.group(1), "%Y-%m-%dT%H:%M:%S")
    zone = match.group(3) or "Z"
    if zone != "Z":
        hours, minute = int(zone[1:3]), int(zone[4:])
        if minute > 59 or hours > 14 or (hours == 14 and minute):
            raise ValueError("date_time offsets must be within fourteen hours of UTC.")
        minutes = hours * 60 + minute
        instant -= datetime.timedelta(minutes=minutes if zone[0] == "+" else -minutes)
    delta = instant - datetime.datetime(1601, 1, 1)
    if delta.days < 0:
        raise ValueError("FILETIME attributes cannot precede 1601-01-01 UTC.")
    return (delta.days * 86400 + delta.seconds) * 10000000 + int(
        ((match.group(2) or "") + "0000000")[:7]
    )


def _encoded_value(value):
    kind = "raw"
    if isinstance(value, dict):
        if (
            set(value) - {"type", "value"}
            or "type" not in value
            or "value" not in value
        ):
            raise ValueError("Typed attribute entries require only type and value.")
        kind, value = value["type"], value["value"]
    if kind == "bytes":
        return base64.b64decode(value, validate=True)
    if kind == "date_time":
        value = _date_time(value)
    elif kind == "security_descriptor":
        return security_descriptor_bytes(value)
    elif kind == "int":
        value = int(value)
    elif kind == "bool":
        value = as_bool(value, "attribute value")
    elif kind != "raw":
        raise ValueError(
            "Attribute type must be bytes, date_time, int, bool, security_descriptor or raw."
        )
    if not isinstance(value, (str, int, bool)):
        raise ValueError("Raw attribute values must be strings, integers or Booleans.")
    return (
        "TRUE" if value is True else "FALSE" if value is False else str(value)
    ).encode("utf-8")


def _attribute_values(value):
    if value is None:
        return []
    values = value if isinstance(value, list) else [value]
    result = []
    for item in values:
        encoded = _encoded_value(item)
        if encoded not in result:
            result.append(encoded)
    return result


def _diff_attribute(directory_schema, name, values):
    value = directory_schema.cast(name, values)
    return (
        sorted(value, key=str)
        if isinstance(value, list)
        else ([] if value is None else [value])
    )


def _custom_attributes(directory_schema, requests, existing):
    changes = []
    before, after = {}, {}
    working = dict(existing)
    for action in ("add", "remove", "set"):
        for name, value in requests[action].items():
            if name.lower() not in directory_schema.attributes:
                raise ValueError("Invalid LDAP attribute: " + name)
            desired = _attribute_values(value)
            present = list(working.get(name.lower(), []))
            if action == "add":
                updated = present + [item for item in desired if item not in present]
            elif action == "remove":
                updated = [item for item in present if item not in desired]
            else:
                updated = desired
            if directory_schema.attributes[name.lower()]["single"] and len(updated) > 1:
                raise ValueError("LDAP attribute " + name + " permits only one value.")
            before[name] = _diff_attribute(
                directory_schema, name, existing.get(name.lower(), [])
            )
            after[name] = _diff_attribute(directory_schema, name, updated)
            if set(present) != set(updated):
                changes.append((2 if updated else 1, name, updated))
            working[name.lower()] = updated
    return changes, before, after


def _rights_mask(rights):
    if rights.startswith("0x"):
        return int(rights, 16)
    return sum(
        _SDDL_RIGHTS[rights[index : index + 2]] for index in range(0, len(rights), 2)
    )


def _protection_descriptor(descriptor, enabled):
    if enabled:
        if protected_from_deletion(descriptor):
            return descriptor
        match = re.search(r"D:([^()]*)", descriptor)
        if not match:
            raise ValueError("Cannot protect an AD object without a readable DACL.")
        if "NO_ACCESS_CONTROL" in match.group(1):
            raise ValueError("Cannot add deletion protection to a NULL DACL.")
        return descriptor[: match.end()] + "(D;;SDDT;;;WD)" + descriptor[match.end() :]

    def _strip_delete(match):
        fields = match.group(1).split(";")
        if not is_explicit_everyone_deny(fields):
            return match.group(0)
        mask = _rights_mask(fields[2])
        remainder = mask & ~0x10040
        if remainder == mask:
            return match.group(0)
        if not remainder:
            return ""
        fields[2] = "0x{0:x}".format(remainder)
        return "(" + ";".join(fields) + ")"

    return re.sub(r"\(([^()]*)\)", _strip_delete, descriptor)


def _set_protection(connection, entry, enabled):
    value = _raw(entry).get("ntsecuritydescriptor", [])
    if not value:
        raise ValueError(
            "The directory did not return the DACL required for deletion protection."
        )
    descriptor = security_descriptor_text(value[0])
    updated = _protection_descriptor(descriptor, enabled)
    if updated == descriptor:
        return False
    encoded = security_descriptor_bytes(updated)
    connection.modify(entry["dn"], [(2, "nTSecurityDescriptor", [encoded])])
    entry["attributes"]["nTSecurityDescriptor"] = [encoded]
    return True


def _get_protected(entry):
    value = _raw(entry).get("ntsecuritydescriptor", [])
    if not value:
        raise ValueError("The directory did not return the object's DACL.")
    return protected_from_deletion(security_descriptor_text(value[0]))


def _managed_by(session, value):
    if value is None or value == "":
        return None
    server = None
    if isinstance(value, dict):
        if set(value) - {"name", "server"} or not value.get("name"):
            raise ValueError(
                "managed_by dictionaries require name and optionally server."
            )
        server, value = (
            as_string(value.get("server"), "managed_by.server"),
            value["name"],
        )
    value = as_string(value, "managed_by")
    entry = find_object(session.connection(server), value, ["distinguishedName"])
    if entry is None:
        raise ValueError("Unable to resolve the managed_by AD identity: " + value)
    return entry["dn"]


def _property_changes(session, arguments, mapping, existing):
    changes, before, after = [], {}, {}
    for name, attribute in mapping.items():
        value = arguments.get(name)
        if value is None:
            continue
        value = (
            _managed_by(session, value)
            if name == "managed_by"
            else as_string(value, name)
        )
        present = existing.get(attribute.lower(), [])
        stored = present[0].decode("utf-8") if present else None
        desired = [] if value is None or not value.strip() else [value.encode("utf-8")]
        before[name], after[name] = stored, value if desired else None
        wanted = value if desired else None
        # Upstream compares ordinary string properties case-sensitively, but
        # DN lookup properties such as managedBy use a case-insensitive match.
        changed = (
            ((stored or "").lower() != (wanted or "").lower())
            if name == "managed_by"
            else stored != wanted
        )
        if changed:
            changes.append((2 if desired else 1, attribute, desired))
    return changes, before, after


def _validate_properties(directory_schema, arguments, mapping):
    for name, attribute in mapping.items():
        if (
            arguments.get(name) is not None
            and attribute.lower() not in directory_schema.attributes
        ):
            raise ValueError(
                "The directory schema does not support "
                + name
                + " ("
                + attribute
                + ")."
            )


def remove_tree(connection, entry, arguments, result):
    """Remove an owned subtree child-first, restoring protection on failures.

    :param connection: Authenticated native connection for the directory.
    :type connection: LDAPConnection
    :param entry: Existing entry whose entire subtree should be removed.
    :type entry: dict
    :param arguments: Validated options containing check_mode.
    :type arguments: dict
    :param result: Result updated with completed or predicted changes.
    :type result: dict
    :raises LDAPError: If a directory operation fails.
    :raises OSError: If security descriptor conversion or a native call fails.
    :raises ValueError: If required security descriptors are unavailable.
    """
    rows = connection.search(
        entry["dn"],
        SCOPE_SUBTREE,
        "(objectClass=*)",
        ["nTSecurityDescriptor"],
        security_descriptor=True,
    )
    for row in sorted(rows, key=lambda value: len(value["dn"]), reverse=True):
        if not arguments["check_mode"]:
            was_protected = _get_protected(row)
            if was_protected:
                _set_protection(connection, row, False)
                result["changed"] = True
            try:
                connection.delete(row["dn"])
            except (OSError, ValueError):
                if was_protected:
                    _set_protection(connection, row, True)
                raise
        result["changed"] = True


def _move(connection, entry, desired, arguments, result):
    current_rdn, current_parent = split_dn(entry["dn"])
    prefix = current_rdn.split("=", 1)[0]
    desired_rdn = prefix + "=" + escape_rdn(desired["name"])
    desired_dn = desired_rdn + "," + desired["path"]
    if desired_rdn == current_rdn and desired["path"].lower() == current_parent.lower():
        return entry["dn"]
    if arguments["check_mode"]:
        result["changed"] = True
        return desired_dn
    protected = _get_protected(entry)
    if protected:
        _set_protection(connection, entry, False)
    moved = False
    try:
        connection.rename(entry["dn"], desired_rdn, desired["path"])
        moved = True
        result["changed"] = True
    finally:
        if protected:
            restored = dict(entry)
            restored["dn"] = desired_dn if moved else entry["dn"]
            _set_protection(connection, restored, True)
    return desired_dn


def _requested_attributes(arguments, property_mapping):
    attributes = ["objectGUID", "objectClass", "name", "nTSecurityDescriptor"] + list(
        property_mapping.values()
    )
    attributes.extend(
        name for action in arguments["attributes"].values() for name in action
    )
    return attributes


def _path(connection, arguments, entry=None):
    if entry and arguments["path"] is None:
        return split_dn(entry["dn"])[1]
    return (
        connection.naming_context()
        if arguments["path"] in (None, "", DEFAULT_PATH)
        else arguments["path"]
    )


def _prepare_changes(session, arguments, object_type, mapping, entry):
    directory_schema = DirectorySchema(session.connection())
    _validate_properties(directory_schema, arguments, mapping)
    raw = _raw(entry) if entry else {}
    changes, before, after = _custom_attributes(
        directory_schema, arguments["attributes"], raw
    )
    mapped_changes, before_properties, after_properties = _property_changes(
        session, arguments, mapping, raw
    )
    changes.extend(mapped_changes)
    before = (
        {
            "name": raw["name"][0].decode("utf-8"),
            "path": split_dn(entry["dn"])[1],
            "attributes": before,
        }
        if entry
        else None
    )
    after = {
        "name": arguments["name"]
        or (raw["name"][0].decode("utf-8") if entry else arguments["identity"]),
        "path": _path(session.connection(), arguments, entry),
        "attributes": after,
    }
    if before is not None:
        before.update(before_properties)
    after.update(after_properties)
    protection = arguments["protect_from_deletion"]
    if protection is None and not entry and object_type.lower() == "organizationalunit":
        protection = True
    if protection is not None:
        if before is not None:
            before["protect_from_deletion"] = _get_protected(entry)
        after["protect_from_deletion"] = protection
    return changes, before, after, protection


# Session, module options, class, property map, result and current entry each
# have a distinct role; keeping them explicit is clearer than an opaque bundle.
def ensure_present(
    session, arguments, object_type, mapping, result, entry
):  # pylint: disable=too-many-arguments,too-many-positional-arguments
    """Create or update a previously resolved object in an existing session.

    :param session: Session owning credentialed directory connections.
    :type session: DirectorySession
    :param arguments: Common validated options and named string properties.
    :type arguments: dict
    :param object_type: Desired structural LDAP object class.
    :type object_type: str
    :param mapping: Named string options mapped to LDAP attributes.
    :type mapping: dict
    :param result: Result retaining identities, diffs and completed changes.
    :type result: dict
    :param entry: Previously resolved directory entry, or None for creation.
    :type entry: dict or None
    :returns: The final entry, or None for predicted creation.
    :rtype: dict or None
    :raises ValueError: If a requested type, attribute or read-back is invalid.
    :raises LDAPError: If the directory rejects a read or mutation.
    """
    connection = session.connection()
    if (
        entry
        and _raw(entry)["objectclass"][-1].decode("utf-8").lower()
        != object_type.lower()
    ):
        raise ValueError(
            "Cannot change object type of existing AD object " + entry["dn"] + "."
        )
    changes, before, after, protection = _prepare_changes(
        session, arguments, object_type, mapping, entry
    )
    if arguments["diff_mode"]:
        result["diff"] = {"before": before, "after": after}
    attributes = _requested_attributes(arguments, mapping)
    if not entry:
        prefix = "OU" if object_type.lower() == "organizationalunit" else "CN"
        dn = prefix + "=" + escape_rdn(after["name"]) + "," + after["path"]
        values = {attribute: data for _operation, attribute, data in changes if data}
        values["objectClass"] = [object_type.encode("utf-8")]
        values[prefix.lower()] = [after["name"].encode("utf-8")]
        result.update({"distinguished_name": dn, "object_guid": _ZERO_GUID})
        if arguments["check_mode"]:
            result["changed"] = True
            return None
        connection.add(dn, values)
        result["changed"] = True
        entry = find_object(connection, dn, attributes, distinguished_name=True)
        if entry is None:
            raise ValueError("Created AD object could not be read back: " + dn)
        result["object_guid"] = str(uuid.UUID(bytes_le=_raw(entry)["objectguid"][0]))
    else:
        result["distinguished_name"] = _move(
            connection, entry, after, arguments, result
        )
        entry["dn"] = result["distinguished_name"]
        if changes:
            if not arguments["check_mode"]:
                connection.modify(entry["dn"], changes)
                result["changed"] = True
                entry = find_object(
                    connection, entry["dn"], attributes, distinguished_name=True
                )
                if entry is None:
                    raise ValueError(
                        "Updated AD object could not be read back: "
                        + result["distinguished_name"]
                    )
            result["changed"] = True
    if protection is not None and _get_protected(entry) != protection:
        if not arguments["check_mode"]:
            _set_protection(connection, entry, protection)
        result["changed"] = True
    return entry


def manage_object(
    arguments, object_type, property_mapping, result, *, expected_class=None
):
    """Apply one generic/OU lifecycle using authenticated native directory APIs.

    :param arguments: Validated module options.
    :type arguments: dict
    :param object_type: Object's LDAP structural class.
    :type object_type: str
    :param property_mapping: Module option names mapped to LDAP attributes.
    :type property_mapping: dict
    :param result: Mutable result retaining completed changes on failure.
    :type result: dict
    :param expected_class: Required structural class for type-specific lookup, if any.
    :type expected_class: str or None
    :raises ValueError: If a requested object class or attribute is invalid.
    :raises LDAPError: If the directory rejects a read or mutation.
    """
    with DirectorySession(arguments) as session:
        connection = session.connection()
        prefix = "OU" if object_type.lower() == "organizationalunit" else "CN"
        identity = arguments["identity"] or prefix + "=" + escape_rdn(
            arguments["name"]
        ) + "," + _path(connection, arguments)
        entry = find_object(
            connection,
            identity,
            _requested_attributes(arguments, property_mapping),
            distinguished_name=not bool(arguments["identity"]),
            expected_class=expected_class,
        )
        if entry:
            result["object_guid"] = str(
                uuid.UUID(bytes_le=_raw(entry)["objectguid"][0])
            )
            result["distinguished_name"] = entry["dn"]
        if arguments["state"] == "present":
            ensure_present(
                session, arguments, object_type, property_mapping, result, entry
            )
            return
        # Generic objects retain their name/path projection at this lifecycle boundary.
        # pylint: disable=duplicate-code
        if entry:
            remove_tree(connection, entry, arguments, result)
        if arguments["diff_mode"]:
            result["diff"] = {
                "before": (
                    {
                        "name": _raw(entry)["name"][0].decode("utf-8"),
                        "path": split_dn(entry["dn"])[1],
                        "attributes": None,
                    }
                    if entry
                    else None
                ),
                "after": None,
            }
        # pylint: enable=duplicate-code
