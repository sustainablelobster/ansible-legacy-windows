# -*- coding: utf-8 -*-
# Copyright 2026 sustainablelobster
# SPDX-License-Identifier: GPL-3.0-or-later

"""Manage installed Remote Desktop Gateway policies through native WMI."""

import binascii
import ctypes
import re
from contextlib import ExitStack

from legacy_windows_account import (  # pylint: disable=import-error
    name_to_sid,
    sid_to_name,
)
from legacy_windows_certificate_store import (  # pylint: disable=import-error
    matches,
    open_store,
)
from legacy_windows_module import (  # pylint: disable=import-error
    as_bool,
    as_string,
    as_string_list,
)
from legacy_windows_wmi import (  # pylint: disable=import-error
    WmiConnection,
    _check,
    _get_object,
    _method,
    _read_property,
    _release,
)

_NAMESPACE = r"ROOT\CIMV2\TerminalServices"
_CAP = "Win32_TSGatewayConnectionAuthorizationPolicy"
_RAP = "Win32_TSGatewayResourceAuthorizationPolicy"
_SETTINGS = "Win32_TSGatewayServerSettings"
_GROUP = "Win32_TSGatewayResourceGroup"
_AUTH = ("none", "password", "smartcard", "both")
_TIMEOUT_ACTIONS = ("disconnect", "reauth")
_BRIDGING = ("none", "https_http", "https_https")
_RESOURCE_TYPES = {
    "rdg_group": "RG",
    "ad_network_resource_group": "CG",
    "allow_any": "ALL",
}
_REDIRECTIONS = (
    ("redirect_clipboard", "ClipboardDisabled", "DisableClipboard"),
    ("redirect_drives", "DiskDrivesDisabled", "DisableDiskDrives"),
    ("redirect_printers", "PrintersDisabled", "DisablePrinters"),
    ("redirect_serial", "SerialPortsDisabled", "DisableSerialPorts"),
    ("redirect_pnp", "PlugAndPlayDevicesDisabled", "DisablePlugAndPlayDevices"),
)


def _choice(parameters, key, choices, default=None):
    value = parameters.get(key)
    value = default if value is None else as_string(value, key).lower()
    if value is not None and value not in choices:
        raise ValueError(
            "Invalid {0}; choose from {1}.".format(key, ", ".join(choices))
        )
    return value


def _integer(parameters, key, minimum=0):
    value = parameters.get(key)
    if value is None:
        return None
    try:
        number = int(value)
    except (ValueError, TypeError):
        raise ValueError(key + " must be an integer.") from None
    if isinstance(value, bool) or isinstance(value, float) and number != value:
        raise ValueError(key + " must be an integer.")
    if not minimum <= number <= 0x7FFFFFFF:
        raise ValueError("{0} must be between {1} and 2147483647.".format(key, minimum))
    return number


def _group_name(value):
    if value.lower().endswith("@builtin"):
        value = "BUILTIN\\" + value[:-8]
    return sid_to_name(name_to_sid(value))


def _groups(parameters, key, allow_empty=False):
    values = as_string_list(parameters.get(key), key)
    if values is None:
        return None
    if not values and not allow_empty:
        raise ValueError("Parameter '" + key + "' cannot be an empty list.")
    names, seen = [], set()
    for value in values:
        name = _group_name(value)
        if name.lower() not in seen:
            names.append(name)
            seen.add(name.lower())
    return names


def _group_list(value):
    return [_group_name(name) for name in (value or "").split(";") if name]


def _same_groups(left, right):
    return {value.lower() for value in left} == {value.lower() for value in right}


def _name(parameters):
    name = as_string(parameters.get("name"), "name")
    if not name:
        raise ValueError("Missing required argument: name")
    if re.search(r'[*/\\;:?"<>|\t\x00]', name):
        raise ValueError("Invalid character in policy name.")
    if len(name) > 64:
        raise ValueError("Gateway policy names cannot exceed 64 characters.")
    return name


def _text(value):
    if isinstance(value, bool):
        return "True" if value else "False"
    if isinstance(value, list):
        return "[" + ",".join(str(part) for part in value) + "]"
    return "" if value is None else str(value)


def _diff(field, before, after):
    return "-{0} = {1}\n+{0} = {2}\n".format(field, _text(before), _text(after))


class Gateway:
    """Own one installed native gateway provider and its capability checks."""

    def __init__(self):
        self.connection = WmiConnection(_NAMESPACE)

    def __enter__(self):
        self.connection.__enter__()
        return self

    def __exit__(self, *arguments):
        return self.connection.__exit__(*arguments)

    def records(self, class_name, properties):
        """Read gateway instances without constructing a user-controlled query.

        :param str class_name: Internal, fixed gateway WMI class name.
        :param list properties: Required installed provider properties.
        :returns: Native property records including locatable instance paths.
        :rtype: list
        :raises OSError: The installed provider cannot expose these properties.
        """
        # The gateway provider rejects a projected Order property on Server
        # 2008 R2 (WBEM_E_NOT_SUPPORTED), but returns it in full instances.
        columns = "*" if "Order" in properties else ",".join(properties)
        return self.connection.query(
            "SELECT " + columns + " FROM " + class_name, properties
        )

    def validate(self, class_name, calls):
        """Check all requested methods and argument names before any write.

        :param str class_name: Internal, fixed gateway WMI class name.
        :param list calls: Method-name and input-dictionary pairs.
        :raises OSError: The installed provider lacks a requested capability.
        """
        # This provider-specific metadata read shares the connection's COM
        # ownership; no method is invoked while inspecting its signatures.
        # pylint: disable=protected-access
        connection = self.connection
        with ExitStack() as cleanup:
            definition = _get_object(
                connection._services, connection._automation, cleanup, class_name
            )
            get_method = _method(
                definition,
                19,
                ctypes.c_int32,
                [
                    ctypes.c_wchar_p,
                    ctypes.c_int32,
                    ctypes.POINTER(ctypes.c_void_p),
                    ctypes.POINTER(ctypes.c_void_p),
                ],
            )
            for method, inputs in calls:
                signature = ctypes.c_void_p()
                cleanup.callback(_release, signature)
                _check(
                    get_method(definition, method, 0, ctypes.byref(signature), None),
                    "Installed gateway method " + method,
                )
                for name in inputs or {}:
                    _read_property(signature, connection._automation, name)
        # pylint: enable=protected-access

    def call(self, path, method, inputs=None):
        """Run one validated native method and enforce its provider status.

        :param str path: Fixed class name or locatable native instance path.
        :param str method: Native gateway method name.
        :param inputs: Native method arguments, or None for no arguments.
        :type inputs: dict or None
        :raises OSError: Invocation fails or the provider returns nonzero.
        """
        result = self.connection.call_method(path, method, ["ReturnValue"], inputs)
        code = result.get("ReturnValue")
        if code != 0:
            raise OSError("Gateway {0} failed (code: {1}).".format(method, code))


def _find(records, name):
    return next((row for row in records if row["Name"].lower() == name.lower()), None)


def _policy_result(changed, text, parameters, warnings):
    result = {"changed": changed}
    if changed and as_bool(parameters.get("_ansible_diff", False), "_ansible_diff"):
        result["diff"] = {"prepared": text}
    if warnings:
        result["warnings"] = warnings
    return result


def _ports(parameters):
    values = parameters.get("allowed_ports")
    if values is None:
        return None
    if isinstance(values, str):
        values = [value.strip() for value in values.split(",")]
    if not isinstance(values, list):
        raise ValueError("allowed_ports must be a list.")
    ports = []
    for value in values:
        if isinstance(value, str) and value.lower() == "any":
            ports.append("any")
        elif (
            isinstance(value, int)
            and not isinstance(value, bool)
            and 1 <= value <= 65535
        ):
            ports.append(str(value))
        else:
            raise ValueError("{0} is not a valid port number.".format(value))
    return ports


def _rap_resource(gateway, parameters):
    kind = _choice(parameters, "computer_group_type", tuple(_RESOURCE_TYPES))
    group = parameters.get("computer_group")
    group = as_string(group, "computer_group") if group is not None else None
    warnings = []
    if kind in ("rdg_group", "ad_network_resource_group") and not group:
        raise ValueError("computer_group is required for " + kind)
    if kind == "allow_any" and group is not None:
        warnings.append(
            "Parameter 'computer_group' ignored because the computer_group_type "
            "is set to allow_any."
        )
        group = None
    elif kind == "ad_network_resource_group":
        group = _group_name(group)
    elif kind == "rdg_group":
        if _find(gateway.records(_GROUP, ["Name"]), group) is None:
            raise ValueError(group + " is not a valid gateway managed computer group")
    return kind, group, warnings


def _rap_properties(current, parameters, users, ports):
    calls, text = _policy_enabled(current, parameters.get("state", "present"))
    if parameters.get("description") is not None:
        description = as_string(parameters["description"], "description")
        if description != current["Description"]:
            calls.append(("SetDescription", {"Description": description}))
            text += _diff("Description", current["Description"], description)
    old_ports = (
        ["any"]
        if current["PortNumbers"] == "*"
        else re.split("[;,]", current["PortNumbers"] or "")
    )
    if ports is not None and old_ports != ports:
        calls.append(
            (
                "SetPortNumbers",
                {"PortNumbers": "*" if "any" in ports else ";".join(ports)},
            )
        )
        text += _diff("AllowedPorts", old_ports, ports)
    old_users = _group_list(current["UserGroupNames"])
    if users is not None and not _same_groups(users, old_users):
        calls.append(("SetUserGroupNames", {"UserGroupNames": ";".join(users)}))
        text += _diff("UserGroups", old_users, users)
    return calls, text


def _rap_resource_change(current, kind, group):
    target_kind = _RESOURCE_TYPES[kind] if kind else current["ResourceGroupType"]
    target_group = group if group is not None else (current["ResourceGroupName"] or "")
    if target_kind == "ALL":
        target_group = ""
    old_group = current["ResourceGroupName"] or ""
    if current["ResourceGroupType"] == "CG" and old_group:
        old_group = _group_name(old_group)
    if (
        target_kind == current["ResourceGroupType"]
        and target_group.lower() == old_group.lower()
    ):
        return [], ""
    return [
        (
            "SetResourceGroup",
            {"ResourceGroupType": target_kind, "ResourceGroupName": target_group},
        )
    ], (
        _diff("ComputerGroupType", current["ResourceGroupType"], kind or target_kind)
        + _diff("ComputerGroup", old_group, target_group)
    )


# Keep the validated identity, creation record and ordered setters in one
# operation; scalar property and resource comparisons are separated above.
# pylint: disable-next=too-many-locals
def _rap(gateway, parameters, preview):
    name = _name(parameters)
    state = _choice(
        parameters, "state", ("absent", "present", "enabled", "disabled"), "present"
    )
    users = _groups(parameters, "user_groups")
    ports = _ports(parameters)
    kind, group, warnings = _rap_resource(gateway, parameters)
    current = _find(
        gateway.records(
            _RAP,
            [
                "__PATH",
                "Name",
                "Description",
                "Enabled",
                "ResourceGroupType",
                "ResourceGroupName",
                "UserGroupNames",
                "PortNumbers",
            ],
        ),
        name,
    )
    if state == "absent":
        if current is not None:
            gateway.validate(_RAP, [("Delete", None)])
            if not preview:
                gateway.call(current["__PATH"], "Delete")
        return _policy_result(
            current is not None, "-[" + name + "]", parameters, warnings
        )
    created = current is None
    if created and users is None:
        raise ValueError("User groups must be defined to create a new RAP.")
    creation = {
        "Name": name,
        "ResourceGroupType": "ALL",
        "UserGroupNames": ";".join(users or []),
        "ProtocolNames": "RDP",
        "PortNumbers": "*",
    }
    if created:
        kind = kind or "allow_any"
        current = {
            "Description": "",
            "Enabled": False,
            "ResourceGroupType": "ALL",
            "ResourceGroupName": "",
            "UserGroupNames": ";".join(users),
            "PortNumbers": "*",
        }
    calls, text = _rap_properties(current, dict(parameters, state=state), users, ports)
    resource_calls, resource_text = _rap_resource_change(current, kind, group)
    calls.extend(resource_calls)
    text = ("+" if created else "") + "[" + name + "]\n" + text + resource_text
    gateway.validate(_RAP, ([("Create", creation)] if created else []) + calls)
    if not preview:
        if created:
            gateway.call(_RAP, "Create", creation)
            current = _find(gateway.records(_RAP, ["Name", "__PATH"]), name)
        for method, arguments in calls:
            gateway.call(current["__PATH"], method, arguments)
    return _policy_result(created or bool(calls), text, parameters, warnings)


def _cap_fields(parameters):
    fields = ["__PATH", "Name", "Enabled", "UserGroupNames", "ComputerGroupNames"]
    if parameters.get("auth_method") is not None:
        fields.extend(["PasswordAllowed", "SmartcardAllowed"])
    for option, native in (
        ("order", "Order"),
        ("session_timeout", "SessionTimeout"),
        ("idle_timeout", "IdleTimeout"),
        ("allow_only_sdrts_servers", "AllowOnlySDRServers"),
    ):
        if parameters.get(option) is not None:
            fields.append(native)
    if parameters.get("session_timeout") is not None:
        fields.append("SessionTimeoutAction")
    if any(
        parameters.get(option) is not None
        for option, _field, _method_name in _REDIRECTIONS
    ):
        fields.append("DeviceRedirectionType")
        fields.extend(field for _option, field, _method_name in _REDIRECTIONS)
    return fields


def _cap_options(parameters):
    options = dict(parameters)
    options["name"] = _name(parameters)
    options["state"] = _choice(
        parameters, "state", ("absent", "present", "enabled", "disabled"), "present"
    )
    options["auth_method"] = _choice(parameters, "auth_method", _AUTH)
    options["session_timeout_action"] = _choice(
        parameters, "session_timeout_action", _TIMEOUT_ACTIONS, "disconnect"
    )
    options["user_groups"] = _groups(parameters, "user_groups")
    options["computer_groups"] = _groups(
        parameters, "computer_groups", allow_empty=True
    )
    options["order"] = _integer(parameters, "order", 1)
    for key in ("session_timeout", "idle_timeout"):
        options[key] = _integer(parameters, key)
    return options


def _cap_defaults(users):
    defaults = {
        "Enabled": False,
        "PasswordAllowed": False,
        "SmartcardAllowed": False,
        "UserGroupNames": ";".join(users),
        "ComputerGroupNames": "",
        "Order": 1,
        "SessionTimeout": 0,
        "SessionTimeoutAction": 0,
        "IdleTimeout": 0,
        "AllowOnlySDRServers": False,
        "DeviceRedirectionType": 2,
    }
    defaults.update({field: False for _option, field, _method_name in _REDIRECTIONS})
    return defaults


def _cap_authentication(parameters, current):
    auth = parameters["auth_method"]
    if auth is None:
        return [], ""
    old_auth = int(current["PasswordAllowed"]) + 2 * int(current["SmartcardAllowed"])
    target = _AUTH.index(auth)
    if target == old_auth:
        return [], ""
    calls = []
    if current["PasswordAllowed"] != bool(target & 1):
        calls.append(("SetPasswordAllowed", {"Allowed": bool(target & 1)}))
    if current["SmartcardAllowed"] != bool(target & 2):
        calls.append(("SetSmartcardAllowed", {"Allowed": bool(target & 2)}))
    # Enable the replacement method before disabling the old one so switching
    # between password and smart-card authentication has no empty interim policy.
    calls.sort(key=lambda call: not call[1]["Allowed"])
    return calls, _diff("AuthMethod", _AUTH[old_auth], auth)


def _policy_enabled(current, state):
    if state not in ("enabled", "disabled") or current["Enabled"] == (
        state == "enabled"
    ):
        return [], ""
    return [("SetEnabled", {"Enabled": state == "enabled"})], _diff(
        "State", "enabled" if current["Enabled"] else "disabled", state
    )


def _cap_timeouts(parameters, current):
    calls, text = [], ""
    timeout = parameters["session_timeout"]
    action = parameters["session_timeout_action"]
    if timeout is not None and (
        timeout != current["SessionTimeout"]
        or _TIMEOUT_ACTIONS.index(action) != current["SessionTimeoutAction"]
    ):
        calls.append(
            (
                "SetSessionTimeout",
                {
                    "SessionTimeout": timeout,
                    "SessionTimeoutAction": _TIMEOUT_ACTIONS.index(action),
                },
            )
        )
        text += _diff(
            "SessionTimeoutAction",
            _TIMEOUT_ACTIONS[current["SessionTimeoutAction"]],
            action,
        )
        text += _diff("SessionTimeout", current["SessionTimeout"], timeout)
    idle = parameters["idle_timeout"]
    if idle is not None and idle != current["IdleTimeout"]:
        calls.append(("SetIdleTimeout", {"IdleTimeout": idle}))
        text += _diff("IdleTimeout", current["IdleTimeout"], idle)
    if parameters.get("allow_only_sdrts_servers") is not None:
        allowed = as_bool(
            parameters["allow_only_sdrts_servers"], "allow_only_sdrts_servers"
        )
        if allowed != current["AllowOnlySDRServers"]:
            calls.append(
                ("EnableAllowOnlySDRServers", {"AllowOnlySDRServers": allowed})
            )
            text += _diff(
                "AllowOnlySDRTSServers", current["AllowOnlySDRServers"], allowed
            )
    return calls, text


def _cap_groups(parameters, current):
    calls, text = [], ""
    for option, field, method in (
        ("user_groups", "UserGroupNames", "SetUserGroupNames"),
        ("computer_groups", "ComputerGroupNames", "SetComputerGroupNames"),
    ):
        groups = parameters[option]
        old = _group_list(current[field])
        if groups is not None and not _same_groups(old, groups):
            calls.append((method, {field: ";".join(groups)}))
            text += _diff(
                "UserGroups" if option == "user_groups" else "ComputerGroups",
                old,
                groups,
            )
    return calls, text


def _cap_changes(parameters, current):
    changes = [
        _policy_enabled(current, parameters["state"]),
        _cap_authentication(parameters, current),
        _cap_timeouts(parameters, current),
        _cap_redirection(parameters, current),
        _cap_groups(parameters, current),
    ]
    return (
        [call for calls, _text_value in changes for call in calls],
        "".join(text for _calls, text in changes),
    )


def _cap_order(current, requested, count):
    if requested is None:
        return None, "", []
    target = min(requested, count)
    warnings = []
    if requested > count:
        warnings.append(
            (
                "Given value '{0}' for parameter 'order' is greater than the number "
                "of existing CAPs. The actual order will be capped to '{1}'."
            ).format(requested, count)
        )
    if target == current["Order"]:
        return None, "", warnings
    return target, _diff("Order", current["Order"], target), warnings


def _move_cap(gateway, current, target_order):
    if target_order is None:
        return
    step = "MoveDown" if target_order > current["Order"] else "MoveUp"
    for _index in range(abs(target_order - current["Order"])):
        gateway.call(current["__PATH"], step)


# Keep a policy's creation, native identity and ordered setters together; its
# independent authentication, timeout, redirection and group planners are above.
# pylint: disable-next=too-many-locals
def _cap(gateway, parameters, preview):
    parameters = _cap_options(parameters)
    name = parameters["name"]
    records = gateway.records(_CAP, _cap_fields(parameters))
    current = _find(records, name)
    if parameters["state"] == "absent":
        if current is not None:
            gateway.validate(_CAP, [("Delete", None)])
            if not preview:
                gateway.call(current["__PATH"], "Delete")
        return _policy_result(current is not None, "-[" + name + "]", parameters, [])
    created = current is None
    if created and parameters["user_groups"] is None:
        raise ValueError("User groups must be defined to create a new CAP.")
    creation = {
        "Name": name,
        "UserGroupNames": ";".join(parameters["user_groups"] or []),
    }
    if created:
        parameters["auth_method"] = parameters["auth_method"] or "password"
        current = _cap_defaults(parameters["user_groups"])
    calls, text = _cap_changes(parameters, current)
    target_order, order_text, warnings = _cap_order(
        current, parameters["order"], len(records) + int(created)
    )
    required = ([("Create", creation)] if created else []) + calls
    if target_order is not None:
        required.extend([("MoveUp", None), ("MoveDown", None)])
    gateway.validate(_CAP, required)
    if not preview:
        if created:
            gateway.call(_CAP, "Create", creation)
            current["__PATH"] = _find(gateway.records(_CAP, ["Name", "__PATH"]), name)[
                "__PATH"
            ]
        for method, arguments in calls:
            gateway.call(current["__PATH"], method, arguments)
        _move_cap(gateway, current, target_order)
    text = ("+" if created else "") + "[" + name + "]\n" + order_text + text
    return _policy_result(
        created or bool(calls) or target_order is not None, text, parameters, warnings
    )


def _cap_redirection(parameters, current):
    if not any(
        parameters.get(option) is not None
        for option, _field, _method_name in _REDIRECTIONS
    ):
        return [], ""
    calls, text = [], ""
    changes = []
    for option, field, method in _REDIRECTIONS:
        if current["DeviceRedirectionType"] == 0:
            allowed = True
        elif current["DeviceRedirectionType"] == 1:
            allowed = False
        else:
            allowed = not current[field]
        requested = parameters.get(option)
        desired = allowed if requested is None else as_bool(requested, option)
        if desired != allowed:
            text += _diff(option, allowed, desired)
        if current["DeviceRedirectionType"] != 2 or desired != allowed:
            changes.append((method, {"Disabled": not desired}))
    if text:
        if current["DeviceRedirectionType"] != 2:
            calls.append(("SetDeviceRedirectionType", {"DeviceRedirectionType": 2}))
        calls.extend(changes)
    return calls, text


def _certificate_digest(certificate):
    if certificate is None:
        return None
    certificate = as_string(certificate, "certificate_hash")
    with open_store("My", "LocalMachine", "system", True) as store:
        selected = matches(store.records, certificate)
        if not selected:
            raise ValueError(
                "Unable to locate certificate at LocalMachine\\My\\" + certificate
            )
        return binascii.unhexlify(selected[0]["thumbprint"])


def _settings_fields(parameters):
    fields = ["__PATH"]
    if parameters.get("certificate_hash") is not None:
        fields.extend(["CertHash", "IsConfigured"])
    if parameters.get("max_connections") is not None:
        fields.extend(
            ["MaxConnections", "MaximumAllowedConnectionsBySku", "UnlimitedConnections"]
        )
    if parameters.get("ssl_bridging") is not None:
        fields.append("SslBridging")
    if parameters.get("enable_only_messaging_capable_clients") is not None:
        fields.append("OnlyConsentCapableClients")
    return fields


def _settings_changes(parameters, current, digest):
    calls, text = [], ""
    if digest is not None and bytes(current["CertHash"] or []) != digest:
        calls.extend([("SetCertificate", {"CertHash": digest}), ("Configure", None)])
        before = (
            binascii.hexlify(bytes(current["CertHash"] or [])).decode("ascii").upper()
        )
        text += _diff("Certificate", before, parameters["certificate_hash"])
    elif digest is not None:
        # IsConfigured describes the whole gateway, not whether a preceding
        # SetCertificate reached its required Configure call. Always finish an
        # explicit certificate request, including retries after partial failure.
        calls.append(("Configure", None))
        if not current["IsConfigured"]:
            text += _diff("Configured", False, True)
    maximum = _integer(parameters, "max_connections", -1)
    if maximum is not None:
        target = current["MaximumAllowedConnectionsBySku"] if maximum == -1 else maximum
        if target > current["MaximumAllowedConnectionsBySku"]:
            raise ValueError(
                "max_connections exceeds the gateway's installed license/SKU limit."
            )
        unlimited = maximum == -1 or target == current["MaximumAllowedConnectionsBySku"]
        if (
            current["MaxConnections"] != target
            or current["UnlimitedConnections"] != unlimited
        ):
            calls.append(
                (
                    "SetMaxConnections",
                    {"Connections": target, "IsUnlimited": unlimited},
                )
            )
            text += _diff("MaxConnections", current["MaxConnections"], target)
            if current["UnlimitedConnections"] != unlimited:
                text += _diff(
                    "UnlimitedConnections",
                    current["UnlimitedConnections"],
                    unlimited,
                )
    bridging = _choice(parameters, "ssl_bridging", _BRIDGING)
    if bridging is not None and _BRIDGING.index(bridging) != current["SslBridging"]:
        calls.append(("SetSslBridging", {"SslBridging": _BRIDGING.index(bridging)}))
        text += _diff("SSLBridging", _BRIDGING[current["SslBridging"]], bridging)
    messaging = parameters.get("enable_only_messaging_capable_clients")
    if messaging is not None:
        messaging = as_bool(messaging, "enable_only_messaging_capable_clients")
        if messaging != current["OnlyConsentCapableClients"]:
            calls.append(
                (
                    "EnableOnlyConsentCapableClients",
                    {"OnlyConsentCapableClients": messaging},
                )
            )
            text += _diff(
                "EnableOnlyMessagingCapableClients",
                current["OnlyConsentCapableClients"],
                messaging,
            )
    return calls, text


def _settings(gateway, parameters, preview):
    digest = _certificate_digest(parameters.get("certificate_hash"))
    records = gateway.records(_SETTINGS, _settings_fields(parameters))
    if len(records) != 1:
        raise ValueError(
            "The installed gateway provider returned no unique server settings instance."
        )
    current = records[0]
    calls, text = _settings_changes(parameters, current, digest)
    gateway.validate(_SETTINGS, calls)
    if not preview:
        for method, arguments in calls:
            gateway.call(current["__PATH"], method, arguments)
            if method == "SetMaxConnections":
                current["__PATH"] = gateway.records(_SETTINGS, ["__PATH"])[0]["__PATH"]
    return _policy_result(bool(text), text, parameters, [])


def manage(module, parameters):
    """Execute one released gateway interface against installed capabilities.

    :param str module: Released module name.
    :param dict parameters: Released WANT_JSON arguments.
    :returns: Accurate changed flag, optional prepared diff and warnings.
    :rtype: dict
    :raises OSError: The installed native gateway provider rejects the operation.
    :raises ValueError: Inputs or requested capabilities are invalid.
    """
    preview = as_bool(
        parameters.get("_ansible_check_mode", False), "_ansible_check_mode"
    )
    with Gateway() as gateway:
        if module == "win_rds_rap":
            return _rap(gateway, parameters, preview)
        if module == "win_rds_cap":
            return _cap(gateway, parameters, preview)
        return _settings(gateway, parameters, preview)
