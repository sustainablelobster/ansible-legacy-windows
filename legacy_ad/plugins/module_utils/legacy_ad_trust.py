# Copyright 2026 sustainablelobster
# SPDX-License-Identifier: GPL-3.0-or-later

"""Preserve the domain_trust contract with LDAP reads and native LSA changes."""

import socket

from legacy_ad_ldap import (  # pylint: disable=import-error
    SCOPE_SUBTREE,
    LDAPConnection,
    escape_filter,
)
from legacy_ad_trust_native import (  # pylint: disable=import-error
    TrustPolicy,
    target_domain,
)
from legacy_windows_module import (  # pylint: disable=import-error
    as_bool,
    as_string,
    read_arguments,
)

PARAMETERS = (
    "name",
    "state",
    "direction",
    "type",
    "trust_password",
    "selective_authentication",
    "domain_server",
)
_DIRECTIONS = {
    "inbound": (1, "Inbound"),
    "outbound": (2, "Outbound"),
    "bidirectional": (3, "BiDirectional"),
}


def trust_arguments():
    """Validate the released trust module interface before directory access.

    :returns: Normalized trust parameters and Ansible execution flags.
    :rtype: dict
    :raises ValueError: Required parameters or choices are invalid.
    """
    arguments = read_arguments(PARAMETERS, "sustainablelobster.legacy_ad.domain_trust")
    for name in PARAMETERS:
        if name != "selective_authentication":
            arguments[name] = as_string(arguments.get(name), name)
    arguments["state"] = (
        "present" if arguments["state"] is None else arguments["state"].lower()
    )
    if arguments["name"] is None:
        raise ValueError("name is required")
    if arguments["state"] not in ("present", "absent"):
        raise ValueError("state must be present or absent")
    for name, choices in (("direction", _DIRECTIONS), ("type", ("external", "forest"))):
        if arguments[name] is not None:
            arguments[name] = arguments[name].lower()
        if arguments[name] is not None and arguments[name] not in choices:
            raise ValueError(name + " must be one of: " + ", ".join(choices))
    if arguments["state"] == "present":
        for name in ("direction", "type", "trust_password"):
            if arguments[name] is None:
                raise ValueError(name + " is required when state=present")
    value = arguments.get("selective_authentication")
    arguments["selective_authentication"] = (
        None if value is None else as_bool(value, "selective_authentication")
    )
    arguments["check_mode"] = as_bool(
        arguments.get("_ansible_check_mode", False), "_ansible_check_mode"
    )
    arguments["diff_mode"] = as_bool(
        arguments.get("_ansible_diff", False), "_ansible_diff"
    )
    return arguments


def _existing(connection, name):
    escaped = escape_filter(name)
    rows = connection.search(
        connection.naming_context(),
        SCOPE_SUBTREE,
        "(&(objectClass=trustedDomain)(|(name="
        + escaped
        + ")(trustPartner="
        + escaped
        + ")(flatName="
        + escaped
        + ")))",
        ["trustDirection", "trustType", "trustAttributes", "securityIdentifier"],
    )
    if len(rows) > 1:
        raise ValueError(
            "The trust identity matches more than one trusted domain: " + name
        )
    return rows[0] if rows else None


def _values(entry):
    return {name.lower(): values for name, values in entry["attributes"].items()}


def _description(name, entry):
    attributes = _values(entry)
    flags = int(attributes["trustattributes"][0])
    direction = int(attributes["trustdirection"][0])
    return {
        "name": name,
        "direction": {
            0: "Disabled",
            1: "Inbound",
            2: "Outbound",
            3: "BiDirectional",
        }.get(direction, str(direction)),
        "trust_type": "Forest" if flags & 8 else "External",
        "selective_authentication": bool(flags & 16),
    }


def _set_diff(arguments, result, before, after):
    if arguments["diff_mode"]:
        result["diff"] = {"before": before, "after": after}


def _create(connection, arguments, result, server):
    name = arguments["name"]
    result["changed"] = True
    _set_diff(
        arguments,
        result,
        {},
        {
            "name": name,
            "direction": _DIRECTIONS[arguments["direction"]][1],
            "trust_type": "Forest" if arguments["type"] == "forest" else "External",
            "selective_authentication": bool(arguments["selective_authentication"]),
        },
    )
    if arguments["check_mode"]:
        return
    try:
        socket.getaddrinfo(name, None)
    except OSError as error:
        raise ValueError(
            "DNS resolution failed for '"
            + name
            + "'. Ensure DNS conditional forwarders are configured before creating a trust: "
            + str(error)
        ) from error
    forest = arguments["type"] == "forest"
    try:
        information = target_domain(name, forest)
        with TrustPolicy(server) as policy:
            policy.create(
                information,
                _DIRECTIONS[arguments["direction"]][0],
                forest,
                arguments["trust_password"],
            )
    except (OSError, ValueError) as error:
        raise ValueError(
            "Failed to create trust '" + name + "': " + str(error)
        ) from error
    if forest and arguments["selective_authentication"]:
        try:
            with TrustPolicy(server) as policy:
                policy.set_selective(name, True)
        except (OSError, ValueError) as error:
            raise ValueError(
                "Trust created but failed to enable selective authentication on '"
                + name
                + "': "
                + str(error)
            ) from error
    try:
        observed = _existing(connection, name)
        if observed is None:
            raise ValueError("The created trust was not found in the directory.")
    except (OSError, ValueError) as error:
        raise ValueError(
            "Trust creation succeeded but validation failed for '"
            + name
            + "': "
            + str(error)
        ) from error
    result["distinguished_name"] = observed["dn"]


def _update(entry, arguments, result, server):
    name = arguments["name"]
    before = _description(name, entry)
    result["distinguished_name"] = entry["dn"]
    _set_diff(arguments, result, before, {})
    desired_direction = _DIRECTIONS[arguments["direction"]][1]
    desired_type = "Forest" if arguments["type"] == "forest" else "External"
    for field, wanted, noun in (
        ("direction", desired_direction, "Direction"),
        ("trust_type", desired_type, "Type"),
    ):
        if before[field] != wanted:
            raise ValueError(
                "Trust '"
                + name
                + "' exists with "
                + noun.lower()
                + " '"
                + before[field]
                + "' but '"
                + wanted
                + "' was requested. "
                + noun
                + " cannot be changed in-place. Remove the trust first "
                "(state=absent) and recreate it."
            )
    after = dict(before)
    selective = arguments["selective_authentication"]
    if selective is not None and selective != before["selective_authentication"]:
        if desired_type != "Forest":
            raise ValueError(
                "Selective authentication can only be set on forest trusts, not external trusts."
            )
        result["changed"] = True
        after["selective_authentication"] = selective
        if not arguments["check_mode"]:
            try:
                with TrustPolicy(server) as policy:
                    policy.set_selective(name, selective)
            except (OSError, ValueError) as error:
                raise ValueError(
                    "Failed to update selective authentication on trust '"
                    + name
                    + "': "
                    + str(error)
                ) from error
    _set_diff(arguments, result, before, after)


def manage_trust(arguments, result):
    """Read one trust and reconcile only the supported local-side changes.

    :param arguments: Normalized released trust-module parameters.
    :type arguments: dict
    :param result: Mutable result retaining partial changes and observed DN.
    :type result: dict
    :raises ValueError: An incompatible trust or directory lookup is encountered.
    :raises OSError: Native directory or LSA access fails.
    """
    name = arguments["name"]
    with LDAPConnection(arguments["domain_server"]) as connection:
        try:
            existing = _existing(connection, name)
        except (OSError, ValueError) as error:
            raise ValueError(
                "Failed to retrieve trust '" + name + "': " + str(error)
            ) from error
        if existing is None and arguments["state"] == "absent":
            return
        if (
            arguments["state"] == "present"
            and existing
            and arguments["selective_authentication"] is None
        ):
            # No policy handle is needed for an idempotent read-only request.
            _update(existing, arguments, result, None)
            return
        hosts = connection.root_dse.get("dnshostname", [])
        if not hosts:
            raise ValueError("The LDAP server does not advertise its DNS host name.")
        server = hosts[0].decode("utf-8")
        if arguments["state"] == "present":
            if existing:
                _update(existing, arguments, result, server)
            else:
                _create(connection, arguments, result, server)
            return
        result.update(changed=True, distinguished_name=existing["dn"])
        _set_diff(arguments, result, _description(name, existing), {})
        if not arguments["check_mode"]:
            try:
                attributes = _values(existing)
                if int(attributes["trusttype"][0]) != 2:
                    raise ValueError(
                        "Removing downlevel or MIT Kerberos trusts is not supported."
                    )
                with TrustPolicy(server) as policy:
                    policy.delete(attributes["securityidentifier"][0])
            except (OSError, ValueError) as error:
                raise ValueError(
                    "Failed to remove trust '" + name + "': " + str(error)
                ) from error
