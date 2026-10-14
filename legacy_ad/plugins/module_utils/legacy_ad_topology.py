# Copyright 2026 sustainablelobster
# SPDX-License-Identifier: GPL-3.0-or-later

"""Manage replication sites, links and subnets through native directory writes."""

import copy
import ipaddress
import re
import uuid

from legacy_ad_arguments import as_int32  # pylint: disable=import-error
from legacy_ad_object import (  # pylint: disable=import-error
    DEFAULT_PATH,
    DirectorySession,
    ensure_present,
    escape_rdn,
    find_object,
    object_arguments,
    remove_tree,
    split_dn,
)
from legacy_windows_module import (  # pylint: disable=import-error
    as_bool,
    as_string,
    as_string_list,
)

SITE_PARAMETERS = (
    "managed_by",
    "automatic_inter_site_topology_generation_enabled",
    "automatic_topology_generation_enabled",
    "universal_group_caching_enabled",
)
LINK_PARAMETERS = (
    "cost",
    "replication_frequency",
    "sites_included",
    "intersite_transport_protocol",
)
SUBNET_PARAMETERS = ("site", "location")
_SITE_FLAGS = (
    ("automatic_topology_generation_enabled", 0x1, True),
    ("automatic_inter_site_topology_generation_enabled", 0x10, True),
    ("universal_group_caching_enabled", 0x20, False),
)


def topology_arguments(kind):
    """Read and normalize one topology module's public arguments.

    :param kind: Module basename: site, site_link or site_subnet.
    :type kind: str
    :returns: Common lifecycle arguments and normalized topology properties.
    :rtype: dict
    :raises ValueError: If options do not satisfy their documented types.
    """
    parameters = (
        SITE_PARAMETERS
        if kind == "site"
        else LINK_PARAMETERS if kind == "site_link" else SUBNET_PARAMETERS
    )
    arguments = object_arguments("sustainablelobster.legacy_ad." + kind, parameters)
    if kind == "site":
        for name, _mask, _inverted in _SITE_FLAGS:
            if arguments[name] is not None:
                arguments[name] = as_bool(arguments[name], name)
    elif kind == "site_link":
        protocol = as_string(
            arguments["intersite_transport_protocol"],
            "intersite_transport_protocol",
        )
        protocol = "IP" if protocol is None else protocol.upper()
        if protocol not in ("IP", "SMTP"):
            raise ValueError("intersite_transport_protocol must be IP or SMTP.")
        arguments["intersite_transport_protocol"] = protocol
        for name in ("cost", "replication_frequency"):
            if arguments[name] is not None:
                arguments[name] = as_int32(arguments[name], name)
        if arguments["sites_included"] is not None:
            arguments["sites_included"] = as_string_list(
                arguments["sites_included"], "sites_included"
            )
    else:
        for name in SUBNET_PARAMETERS:
            arguments[name] = as_string(arguments[name], name)
    return arguments


def _raw(entry):
    return (
        {name.lower(): values for name, values in entry["attributes"].items()}
        if entry
        else {}
    )


def _container(connection, kind, protocol="IP"):
    sites = "CN=Sites," + connection.naming_context("configurationNamingContext")
    if kind == "site_subnet":
        return "CN=Subnets," + sites
    if kind == "site_link":
        return "CN=" + protocol + ",CN=Inter-Site Transports," + sites
    return sites


def _lookup(connection, identity, parent, attributes, object_type):
    try:
        uuid.UUID(identity)
    except ValueError:
        if not re.match(r"^[^=]+=", identity) and not identity.upper().startswith(
            "S-1-"
        ):
            identity = "CN=" + escape_rdn(identity) + "," + parent
    return find_object(connection, identity, attributes, expected_class=object_type)


def _site_dn(connection, name):
    site = _lookup(
        connection, name, _container(connection, "site"), ["objectClass"], "site"
    )
    if site is None:
        raise ValueError("The replication site could not be found: " + name)
    return site["dn"]


def _site_name(dn):
    match = re.match(r"^CN=([^,]+),", dn, re.IGNORECASE)
    return match.group(1) if match else None


def _set_attribute(arguments, attribute, value):
    # Named properties take precedence over a custom request for the same value.
    for action in arguments["attributes"].values():
        for key in list(action):
            if key.lower() == attribute.lower():
                del action[key]
    arguments["attributes"]["set"][attribute] = value


def _project_diff(result, properties, injected):
    if "diff" not in result:
        return
    for side in ("before", "after"):
        diff = result["diff"][side]
        if diff is None:
            continue
        for attribute in injected:
            diff["attributes"].pop(attribute, None)
        diff.update(properties[side])


def _has_custom_attribute(arguments, attribute):
    return any(
        key.lower() == attribute.lower()
        for action in arguments["attributes"].values()
        for key in action
    )


def _link_properties(connection, arguments, entry, result):
    raw = _raw(entry)
    before, after, injected = {}, {}, []
    for name, attribute, default in (
        ("cost", "cost", 100),
        ("replication_frequency", "replInterval", 180),
    ):
        desired = arguments[name]
        if desired is not None or (
            entry is None and not _has_custom_attribute(arguments, attribute)
        ):
            _set_attribute(
                arguments, attribute, default if desired is None else desired
            )
            injected.append(attribute)
        if desired is not None:
            before[name] = (
                int(raw[attribute.lower()][0]) if raw.get(attribute.lower()) else None
            )
            after[name] = desired
    desired = arguments["sites_included"]
    if entry is None and (
        desired is None or len(set(name.lower() for name in desired)) < 2
    ):
        raise ValueError(
            "sites_included must contain at least two different sites when creating a site link."
        )
    if desired is not None:
        wanted = [_site_dn(connection, name) for name in desired]
        current = [
            _site_name(value.decode("utf-8")) for value in raw.get("sitelist", [])
        ]
        before["sites_included"] = sorted(current, key=str.lower)
        after["sites_included"] = sorted(desired, key=str.lower)
        if {name.lower() for name in current} != {name.lower() for name in desired}:
            _set_attribute(arguments, "siteList", wanted)
            injected.append("siteList")
    current_protocol = (
        split_dn(entry["dn"])[1].split(",", 1)[0][3:].upper()
        if entry
        else arguments["intersite_transport_protocol"]
    )
    before["intersite_transport_protocol"] = current_protocol
    after["intersite_transport_protocol"] = current_protocol
    if entry and current_protocol != arguments["intersite_transport_protocol"]:
        result.setdefault("warnings", []).append(
            "intersite_transport_protocol cannot be changed after creation (current: "
            + current_protocol
            + ", requested: "
            + arguments["intersite_transport_protocol"]
            + ")"
        )
    return {"before": before, "after": after}, injected


def _subnet_properties(connection, arguments, entry):
    name = arguments["name"] or (
        _raw(entry).get("name", [b""])[0].decode("utf-8")
        if entry
        else arguments["identity"]
    )
    try:
        if "/" not in name:
            raise ValueError("A CIDR prefix length is required.")
        ipaddress.ip_network(name, strict=False)
    except ValueError as error:
        raise ValueError(
            "Subnet names must use valid IPv4 or IPv6 CIDR notation: " + name
        ) from error
    before, after, injected = {}, {}, []
    desired = arguments["site"]
    if desired is not None:
        values = _raw(entry).get("siteobject", [])
        current = _site_name(values[0].decode("utf-8")) if values else None
        before["site"], after["site"] = current, desired
        if (current or "").lower() != desired.lower():
            _set_attribute(
                arguments,
                "siteObject",
                _site_dn(connection, desired) if desired else None,
            )
            injected.append("siteObject")
    return {"before": before, "after": after}, injected


def _site_child(connection, entry, name, object_type):
    if not entry:
        return None
    child = find_object(
        connection,
        "CN=" + name + "," + entry["dn"],
        ["options", "objectClass"],
        distinguished_name=True,
    )
    if (
        child is not None
        and _raw(child).get("objectclass", [b""])[-1].decode("utf-8").lower()
        != object_type.lower()
    ):
        raise ValueError(
            "The replication site's child has an unexpected object class: "
            + child["dn"]
        )
    return child


def _site_options(old, arguments):
    new, before, after = old, {}, {}
    for name, mask, inverted in _SITE_FLAGS:
        if arguments[name] is None:
            continue
        before[name] = not bool(old & mask) if inverted else bool(old & mask)
        after[name] = arguments[name]
        enabled = not arguments[name] if inverted else arguments[name]
        new = (new | mask) if enabled else (new & ~mask)
    return new, {"before": before, "after": after}


def _site_settings(connection, arguments, entry):
    settings = _site_child(connection, entry, "NTDS Site Settings", "nTDSSiteSettings")
    servers = _site_child(connection, entry, "Servers", "serversContainer")
    old = int(_raw(settings).get("options", [b"0"])[0])
    options, properties = _site_options(old, arguments)
    changes = []
    if servers is None:
        changes.append(
            (
                "add",
                "Servers",
                {"objectClass": [b"serversContainer"], "cn": [b"Servers"]},
            )
        )
    if settings is None:
        changes.append(
            (
                "add",
                "NTDS Site Settings",
                {
                    "objectClass": [b"nTDSSiteSettings"],
                    "cn": [b"NTDS Site Settings"],
                    "options": [str(options).encode("ascii")],
                },
            )
        )
    elif old != options:
        changes.append(
            (
                "modify",
                "NTDS Site Settings",
                [(2, "options", [str(options).encode("ascii")])],
            )
        )
    return changes, properties


def _write_site_children(connection, arguments, entry, changes, result):
    for operation, name, values in changes:
        if not arguments["check_mode"]:
            dn = "CN=" + name + "," + entry["dn"]
            if operation == "add":
                connection.add(dn, values)
            else:
                connection.modify(dn, values)
        result["changed"] = True


def manage_topology(arguments, kind, result):
    """Apply a typed replication object's lifecycle in its configuration partition.

    :param arguments: Validated public module arguments.
    :type arguments: dict
    :param kind: Module basename: site, site_link or site_subnet.
    :type kind: str
    :param result: Mutable result retaining completed writes on failure.
    :type result: dict
    :raises ValueError: If an identity, site reference or option is invalid.
    :raises OSError: If the directory rejects a read or mutation.
    """
    arguments = copy.deepcopy(arguments)
    object_type = (
        "site" if kind == "site" else "siteLink" if kind == "site_link" else "subnet"
    )
    mapping = {"description": "description", "display_name": "displayName"}
    if kind == "site":
        mapping["managed_by"] = "managedBy"
    elif kind == "site_subnet":
        mapping["location"] = "location"
    # This query includes the same lifecycle fields as other typed AD objects.
    # pylint: disable=duplicate-code
    attributes = [
        "objectGUID",
        "objectClass",
        "name",
        "nTSecurityDescriptor",
        "siteList",
        "siteObject",
        "cost",
        "replInterval",
    ] + list(mapping.values())
    # pylint: enable=duplicate-code
    attributes.extend(
        name for action in arguments["attributes"].values() for name in action
    )
    with DirectorySession(arguments) as session:
        connection = session.connection()
        parent = _container(
            connection, kind, arguments.get("intersite_transport_protocol", "IP")
        )
        lookup_parent = (
            parent
            if arguments["path"] in (None, "", DEFAULT_PATH)
            else arguments["path"]
        )
        entry = _lookup(
            connection,
            arguments["identity"] or arguments["name"],
            lookup_parent,
            attributes,
            object_type,
        )
        if entry:
            result.update(
                {
                    "distinguished_name": entry["dn"],
                    "object_guid": str(
                        uuid.UUID(bytes_le=_raw(entry)["objectguid"][0])
                    ),
                }
            )
        if arguments["state"] == "absent":
            # Typed topology objects keep their local name/path diff projection.
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
            return
        if arguments["path"] in ("", DEFAULT_PATH) or (
            arguments["path"] is None and entry is None
        ):
            arguments["path"] = parent
        properties, injected = {"before": {}, "after": {}}, []
        child_changes = []
        if kind == "site_link":
            properties, injected = _link_properties(
                connection, arguments, entry, result
            )
        elif kind == "site_subnet":
            properties, injected = _subnet_properties(connection, arguments, entry)
        else:
            child_changes, properties = _site_settings(connection, arguments, entry)
        final_entry = ensure_present(
            session, arguments, object_type, mapping, result, entry
        )
        _project_diff(result, properties, injected)
        if kind == "site":
            _write_site_children(
                connection,
                arguments,
                final_entry,
                child_changes,
                result,
            )
