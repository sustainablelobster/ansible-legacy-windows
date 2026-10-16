# -*- coding: utf-8 -*-
# Copyright 2026 sustainablelobster
# SPDX-License-Identifier: GPL-3.0-or-later

"""Apply released firewall-rule options to the installed firewall facilities."""

import os
import re

from legacy_community_windows_firewall_rule_native import (  # pylint: disable=import-error
    FirewallRules,
)
from legacy_windows_module import (  # pylint: disable=import-error
    as_bool,
    as_string,
    as_string_list,
)

_FIELDS = (
    ("Description", "description"),
    ("Grouping", "group"),
    ("ApplicationName", "program"),
    ("ServiceName", "service"),
    ("Protocol", "protocol"),
    ("LocalPorts", "localport"),
    ("RemotePorts", "remoteport"),
    ("LocalAddresses", "localip"),
    ("RemoteAddresses", "remoteip"),
    ("IcmpTypesAndCodes", "icmp_type_code"),
    ("Direction", "direction"),
    ("Action", "action"),
    ("Profiles", "profiles"),
    ("InterfaceTypes", "interfacetypes"),
    ("EdgeTraversalOptions", "edge"),
    ("SecureFlags", "security"),
    ("Enabled", "enabled"),
)
PARAMETERS = tuple(argument for _field, argument in _FIELDS) + (
    "name",
    "state",
    "enable",
    "profile",
)


def _choice(value, name, choices):
    if value is not None and value not in choices:
        raise ValueError("Unknown {0} '{1}'".format(name, value))
    return value


def _protocol(value):
    try:
        number = int(value)
    except ValueError as error:
        named = {"tcp": 6, "udp": 17, "any": 256}
        value = value.lower()
        if value.startswith("icmpv4"):
            return 1
        if value.startswith("icmpv6"):
            return 58
        if value not in named:
            raise ValueError("Unknown protocol '{0}'".format(value)) from error
        return named[value]
    if not -(2**31) <= number < 2**31:
        raise ValueError("protocol must fit a signed 32-bit integer")
    return number


def parameters(arguments):
    """Normalize released firewall arguments without accessing native policy.

    :param dict arguments: WANT_JSON module arguments.
    :returns: Typed public options and optional supplied values.
    :rtype: dict
    :raises ValueError: Required selectors, choices or option types are invalid.
    """
    options = {
        name: as_string(arguments.get(name), name)
        for name in (
            "name",
            "group",
            "description",
            "direction",
            "action",
            "localip",
            "remoteip",
            "localport",
            "remoteport",
            "program",
            "service",
            "protocol",
            "edge",
            "security",
        )
    }
    for name in (
        "localip",
        "remoteip",
        "localport",
        "remoteport",
        "program",
        "service",
        "protocol",
    ):
        if options[name] is not None and options[name].lower() == "any":
            options[name] = "any"
    options["state"] = _choice(
        as_string(arguments.get("state", "present"), "state"),
        "state",
        ("present", "absent"),
    )
    if not options["name"] and not options["group"]:
        raise ValueError("Either name or group must be specified")
    for name, choices in (
        ("direction", ("in", "out")),
        ("action", ("allow", "block")),
        ("edge", ("no", "yes", "deferapp", "deferuser")),
        (
            "security",
            ("notrequired", "authnoencap", "authenticate", "authdynenc", "authenc"),
        ),
    ):
        _choice(options[name], name, choices)
    enabled = arguments.get("enabled", arguments.get("enable"))
    options["enabled"] = None if enabled is None else as_bool(enabled, "enabled")
    for name in ("profiles", "interfacetypes", "icmp_type_code"):
        value = arguments.get(
            name, arguments.get("profile") if name == "profiles" else None
        )
        options[name] = as_string_list(value, name)
    if options["profiles"] is not None:
        for value in options["profiles"]:
            _choice(value.lower(), "profile", ("domain", "private", "public"))
    if options["interfacetypes"] is not None:
        options["interfacetypes"] = [
            value.lower() for value in options["interfacetypes"]
        ]
        for value in options["interfacetypes"]:
            _choice(value.lower(), "interface type", ("any", "wireless", "lan", "ras"))
        if "any" in options["interfacetypes"] and len(options["interfacetypes"]) > 1:
            raise ValueError(
                "interface type any cannot be combined with a specific type"
            )
    if options["program"] not in (None, "any"):
        options["program"] = os.path.expandvars(options["program"])
    if options["protocol"] is not None:
        _protocol(options["protocol"])
    return options


def _same(field, first, second):
    if first in (None, "") and second in (None, ""):
        return True
    if isinstance(first, str) and isinstance(second, str):
        first, second = first.lower(), second.lower()
        if field.endswith("Addresses"):
            return set(first.split(",")) == set(second.split(","))
    return first == second


def _converted(field, value):
    if field == "Protocol":
        return _protocol(value)
    choices = {
        "Direction": {"in": 1, "out": 2},
        "Action": {"allow": 1, "block": 0},
        "EdgeTraversalOptions": {"no": 0, "yes": 1, "deferapp": 2, "deferuser": 3},
        "SecureFlags": {
            "notrequired": 0,
            "authnoencap": 1,
            "authenticate": 2,
            "authdynenc": 3,
            "authenc": 4,
        },
    }
    if field in choices:
        return choices[field][value]
    if field == "Profiles":
        mask = sum(
            {"domain": 1, "private": 2, "public": 4}[name]
            for name in set(item.lower() for item in value)
        )
        return 0x7FFFFFFF if mask == 7 else mask
    if field == "InterfaceTypes":
        names = []
        for entry in value:
            if entry.lower() not in names:
                names.append(entry.lower())
        return ",".join(
            {"wireless": "Wireless", "lan": "Lan", "ras": "RemoteAccess"}[name]
            for name in names
        )
    if field == "IcmpTypesAndCodes":
        return ",".join(value)
    return value


def _set_requested(rule, options):
    for field, argument in _FIELDS:
        value = options[argument]
        if value is None or field not in rule.fields:
            continue
        if (
            value == "any"
            or value == ["any"]
            or (field == "IcmpTypesAndCodes" and value == ["any"])
        ):
            if rule.kind != "modern" and field == "RemoteAddresses":
                rule.put(field, "*")
            continue
        if field == "EdgeTraversalOptions" and value == "no":
            continue
        if field == "SecureFlags" and value == "notrequired":
            continue
        rule.put(field, _converted(field, value))


def _classic_profiles(options):
    values = options["profiles"]
    if values is None:
        return (0, 1)
    values = set(value.lower() for value in values)
    if not values:
        raise ValueError("profiles must select at least one installed firewall profile")
    if ("private" in values) != ("public" in values):
        raise ValueError(
            "The classic firewall combines Private/Public in Standard; select both or omit profiles"
        )
    return tuple(
        profile
        for profile, selected in ((0, "domain" in values), (1, "private" in values))
        if selected
    )


def _classic_validate(options):
    if options["group"]:
        raise ValueError("The installed classic firewall does not expose rule groups")
    for name, supported in (
        ("direction", (None, "in")),
        ("action", (None, "allow")),
        ("description", (None, "")),
        ("localip", (None, "any")),
        ("remoteport", (None, "any")),
        ("service", (None, "any")),
        ("edge", (None, "no")),
        ("security", (None, "notrequired")),
    ):
        if options[name] not in supported:
            raise ValueError(
                "The installed classic firewall cannot represent {0}={1}".format(
                    name, options[name]
                )
            )
    if options["interfacetypes"] not in (None, ["any"]):
        raise ValueError(
            "The installed classic firewall cannot restrict interface types"
        )
    if options["icmp_type_code"] is not None:
        raise ValueError(
            "The installed classic firewall cannot represent named ICMP rules"
        )
    if options["localport"] not in (None, "any") and (
        not re.match(r"^\d+$", options["localport"])
        or not 1 <= int(options["localport"]) <= 65535
    ):
        raise ValueError("Classic localport must be one integer from 1 through 65535")
    _classic_profiles(options)


def _identity(rule):
    if rule.kind == "port":
        return rule.kind, rule.get("Protocol"), rule.get("LocalPorts")
    return rule.kind, (rule.get("ApplicationName") or "").lower()


def _classic_kind(options):
    if options["program"] not in (None, "any"):
        if options["localport"] not in (None, "any") or options["protocol"] not in (
            None,
            "any",
        ):
            raise ValueError(
                "Classic application exceptions cover all protocols/ports; "
                "program and port filters cannot be combined"
            )
        return "application"
    if not options["localport"] or not re.match(r"^\d+$", options["localport"]):
        raise ValueError(
            "A new classic exception requires a program or one numeric "
            "localport with TCP/UDP protocol"
        )
    if options["protocol"] is None or _protocol(options["protocol"]) not in (6, 17):
        raise ValueError("Classic port exceptions require protocol=tcp or protocol=udp")
    return "port"


def _template(provider, options, kind="modern", profile=None, source=None):
    if kind == "port" and (
        options["program"] not in (None, "any")
        or options["localport"] == "any"
        or options["protocol"] is not None
        and _protocol(options["protocol"]) not in (6, 17)
    ):
        raise ValueError(
            "Classic port exceptions require one TCP/UDP port and cannot restrict a program"
        )
    if kind == "application" and (
        options["program"] == "any" or options["protocol"] not in (None, "any")
    ):
        raise ValueError(
            "Classic application exceptions require a program and cover all protocols"
        )
    rule = provider.new(kind, profile)
    if source is not None:
        for field in (
            "Name",
            "ApplicationName",
            "Protocol",
            "LocalPorts",
            "RemoteAddresses",
            "Enabled",
        ):
            if field in rule.fields:
                rule.put(field, source.get(field))
    else:
        if options["name"]:
            rule.put("Name", options["name"])
        rule.put("Enabled", True if options["enabled"] is None else options["enabled"])
    _set_requested(rule, options)
    if kind == "port" and rule.get("Protocol") not in (6, 17):
        raise ValueError(
            "The installed classic firewall supports only TCP/UDP port exceptions"
        )
    if kind == "application" and options["localport"] not in (None, "any"):
        raise ValueError("Classic application exceptions cannot restrict local ports")
    return rule


def _classic_plans(provider, options, selected):
    _classic_validate(options)
    if not selected:
        kind = _classic_kind(options)
        return [
            (None, _template(provider, options, kind, profile))
            for profile in _classic_profiles(options)
        ], []
    if options["profiles"] is None:
        return [
            (rule, _template(provider, options, rule.kind, rule.profile, rule))
            for rule in selected
        ], []
    plans, identities = [], set()
    profiles = _classic_profiles(options)
    for source in selected:
        identity = _identity(source)
        if identity in identities:
            continue
        identities.add(identity)
        for profile in profiles:
            existing = next(
                (
                    rule
                    for rule in selected
                    if rule.profile == profile and _identity(rule) == identity
                ),
                None,
            )
            plans.append(
                (
                    existing,
                    _template(
                        provider, options, source.kind, profile, existing or source
                    ),
                )
            )
    removed = [rule for rule in selected if rule.profile not in profiles]
    return plans, removed


def _collision_check(plans, records, selected):
    desired = set()
    for _existing, rule in plans:
        key = (rule.profile, _identity(rule))
        if key in desired:
            raise ValueError(
                "Distinct classic exceptions cannot share one native program/port key"
            )
        desired.add(key)
        if any(
            other not in selected
            and other.profile == rule.profile
            and _identity(other) == _identity(rule)
            for other in records
        ):
            raise ValueError(
                "A classic firewall exception with this native key already "
                "exists under another name"
            )


def _changes(existing, desired, options):
    return {
        field: desired.get(field)
        for field, argument in _FIELDS
        if options[argument] is not None
        and field in desired.fields
        and not _same(field, existing.get(field), desired.get(field))
    }


def _update(provider, existing, desired, changes):
    identity_fields = ("Protocol", "LocalPorts", "ApplicationName")
    if provider.classic and any(field in changes for field in identity_fields):
        provider.remove(existing)
        try:
            provider.add(desired)
        except OSError:
            provider.add(existing)
            raise
    else:
        fields = [field for field, _argument in _FIELDS if field in changes]
        if "Protocol" in changes and changes["Protocol"] not in (6, 17):
            # Live rules validate every setter. Explicit port clears must
            # precede conversion from a TCP/UDP rule to ICMP or all protocols.
            ports = ("LocalPorts", "RemotePorts")
            fields = [field for field in ports if field in changes] + [
                field for field in fields if field not in ports
            ]
        for field in fields:
            existing.put(field, changes[field])


def _remove_rules(provider, rules, result, check_mode):
    result["changed"] = result["changed"] or bool(rules)
    for rule in rules:
        if "diff" in result:
            result["diff"]["prepared"] += "-[{0}]\n".format(rule.get("Name"))
        if not check_mode:
            provider.remove(rule)


# Retain the complete native snapshot alongside its selected subset: collision
# validation must protect unrelated exceptions before the first policy write.
def _present(  # pylint: disable=too-many-arguments,too-many-positional-arguments
    provider, options, records, selected, result, check_mode
):
    if provider.classic:
        plans, removed = _classic_plans(provider, options, selected)
        _collision_check(plans, records, selected)
    else:
        desired = _template(provider, options)
        plans = (
            [(rule, desired) for rule in selected] if selected else [(None, desired)]
        )
        removed = []
    changed_names, unchanged_names = [], []
    for existing, desired in plans:
        changes = (
            _changes(existing, desired, options)
            if existing is not None
            else {"Name": desired.get("Name")}
        )
        name = existing.get("Name") if existing is not None else desired.get("Name")
        if changes:
            result["changed"] = True
            changed_names.append(name)
            if not check_mode:
                if existing is None:
                    provider.add(desired)
                else:
                    _update(provider, existing, desired, changes)
        else:
            unchanged_names.append(name)
        if "diff" in result:
            result["diff"]["prepared"] += (
                "[{0}]\n".format(name)
                + "\n".join(
                    "+{0}='{1}'".format(field, value)
                    for field, value in changes.items()
                )
                + "\n"
            )
    _remove_rules(provider, removed, result, check_mode)
    if not selected:
        result["msg"] = "Firewall rule '{0}' created.".format(options["name"])
    else:
        result["msg"] = "Firewall rule(s) changed '{0}' - unchanged '{1}'".format(
            "', '".join(changed_names), "', '".join(unchanged_names)
        )


def manage(options, check_mode=False, diff_mode=False):
    """Manage selected native rules, validating detached definitions before writes.

    :param dict options: Normalized released module arguments.
    :param bool check_mode: Predict changes without mutating firewall policy.
    :param bool diff_mode: Return a prepared summary of selected property changes.
    :returns: Released changed/message fields and optional diff/failure details.
    :rtype: dict
    """
    result = {"changed": False}
    if diff_mode:
        result["diff"] = {"prepared": ""}
    try:
        with FirewallRules() as provider:
            records = provider.records()
            field, wanted = (
                ("Name", options["name"])
                if options["name"]
                else ("Grouping", options["group"])
            )
            if provider.classic and field == "Grouping":
                raise ValueError(
                    "The installed classic firewall does not expose rule groups"
                )
            selected = [
                rule for rule in records if _same(field, rule.get(field), wanted)
            ]
            if options["state"] == "absent":
                _remove_rules(provider, selected, result, check_mode)
                result["msg"] = (
                    "Firewall rule(s) '{0}' removed.".format(
                        "', '".join(rule.get("Name") for rule in selected)
                    )
                    if selected
                    else (
                        "Firewall rule '{0}' does not exist.".format(wanted)
                        if options["name"]
                        else "No firewall rules in group '{0}' exist.".format(wanted)
                    )
                )
            elif selected or options["name"]:
                _present(provider, options, records, selected, result, check_mode)
    except (OSError, ValueError) as error:
        result.update(failed=True, msg=str(error))
    return result
