# -*- coding: utf-8 -*-
# Copyright 2026 Joe Lustri
# SPDX-License-Identifier: GPL-3.0-or-later
"""Manage DNS zones through the native provider used by DNS Server cmdlets."""

import ctypes
import socket
import uuid
from contextlib import ExitStack

import legacy_windows_dns_classic as classic  # pylint: disable=import-error
import legacy_windows_wmi as wmi  # pylint: disable=import-error

_NAMESPACE = r"ROOT\Microsoft\Windows\Dns"
_ZONE_CLASS = "PS_DnsServerZone"
_CLASSES = {
    "primary": "PS_DnsServerPrimaryZone",
    "secondary": "PS_DnsServerSecondaryZone",
    "stub": "PS_DnsServerStubZone",
    "forwarder": "PS_DnsServerConditionalForwarder",
}
_COMPARISON_PROPERTIES = (
    "ZoneType",
    "DynamicUpdate",
    "IsDsIntegrated",
    "MasterServers",
    "ForwarderTimeout",
    "ReplicationScope",
    "DirectoryPartitionName",
)


def _project(zone):
    result = {
        "name": zone["ZoneName"].lower(),
        "type": zone["ZoneType"].lower(),
        "paused": zone["IsPaused"],
        "shutdown": zone["IsShutdown"],
    }
    if zone.get("DynamicUpdate"):
        result["dynamic_update"] = zone["DynamicUpdate"].lower()
    if zone.get("IsReverseLookupZone"):
        result["reverse_lookup"] = zone["IsReverseLookupZone"]
    if result["type"] == "forwarder":
        result["forwarder_timeout"] = zone.get("ForwarderTimeout")
    servers = zone.get("MasterServers")
    if servers:
        result["dns_servers"] = servers[0] if len(servers) == 1 else servers
    if not zone["IsDsIntegrated"]:
        result["replication"] = "none"
        result["zone_file"] = zone.get("ZoneFile")
    elif zone.get("ReplicationScope") == "Custom":
        result["replication"] = "custom"
        result["directory_partition"] = zone.get("DirectoryPartitionName")
    else:
        result["replication"] = zone["ReplicationScope"].lower()
    return result


# DNS needs native UInt32 construction and immediate extended-error retrieval
# before COM cleanup. Keep those measured provider details out of shared WMI APIs.
# pylint: disable=protected-access
def _provider_message(connection):
    ole = ctypes.WinDLL("oleaut32")
    ole.GetErrorInfo.argtypes = [wmi._ULONG, wmi._POINTER_OUT]
    ole.GetErrorInfo.restype = wmi._LONG
    with ExitStack() as cleanup:
        error_info = wmi._POINTER()
        status = ole.GetErrorInfo(0, ctypes.byref(error_info))
        cleanup.callback(wmi._release, error_info)
        if status != 0 or not error_info:
            return None
        instance = wmi._POINTER()
        cleanup.callback(wmi._release, instance)
        identifier = wmi._Guid.from_buffer_copy(
            uuid.UUID("dc12a681-737f-11cf-884d-00aa004b2e24").bytes_le
        )
        query_interface = wmi._method(
            error_info,
            0,
            wmi._LONG,
            [ctypes.POINTER(wmi._Guid), wmi._POINTER_OUT],
        )
        if (
            query_interface(
                error_info, ctypes.byref(identifier), ctypes.byref(instance)
            )
            != 0
            or not instance
        ):
            return None
        try:
            return wmi._read_property(instance, connection._automation, "Message")
        except OSError:
            return None


def _call(connection, class_name, method_name, inputs, output=False):
    # DNS's UInt32 timeout is the only numeric method input here. Its native
    # construction stays local rather than broadening the shared WMI contract.
    with ExitStack() as cleanup:
        arguments = connection._method_inputs(
            cleanup,
            class_name,
            method_name,
            {
                name: value
                for name, value in inputs.items()
                if name != "ForwarderTimeout"
            },
        )
        if "ForwarderTimeout" in inputs:
            wmi._put_integer(
                arguments,
                connection._automation,
                "ForwarderTimeout",
                inputs["ForwarderTimeout"],
            )
        result = wmi._POINTER()
        cleanup.callback(wmi._release, result)
        execute = wmi._method(
            connection._services,
            24,
            wmi._LONG,
            [
                wmi._POINTER,
                wmi._POINTER,
                wmi._LONG,
                wmi._POINTER,
                wmi._POINTER,
                wmi._POINTER_OUT,
                wmi._POINTER,
            ],
        )
        status = execute(
            connection._services,
            wmi._bstr(connection._automation, cleanup, class_name),
            wmi._bstr(connection._automation, cleanup, method_name),
            0,
            None,
            arguments,
            ctypes.byref(result),
            None,
        )
        if status & 0x80000000:
            # GetErrorInfo must precede every further COM call, including Release.
            message = _provider_message(connection)
            if message:
                error = OSError(message)
                error.hresult = status & 0xFFFFFFFF
                raise error
            wmi._check(status, "IWbemServices.ExecMethod({0})".format(method_name))
        if not result:
            raise OSError(
                "DNS method {0} returned no output object.".format(method_name)
            )
        properties = ["ReturnValue", "cmdletOutput"] if output else ["ReturnValue"]
        return connection._properties(result, properties)


# pylint: enable=protected-access


def _invoke(connection, class_name, method_name, inputs, output=False):
    if isinstance(connection, classic.Zones):
        return connection.invoke(class_name, method_name, inputs, output)
    packet = _call(connection, class_name, method_name, inputs, output)
    code = packet["ReturnValue"]
    if code:
        raise OSError(
            "DNS provider {0}.{1} returned error {2}: {3}".format(
                class_name, method_name, code, ctypes.FormatError(code)
            )
        )
    return packet.get("cmdletOutput")


def _read(connection, name):
    if not name:
        raise ValueError(
            "Cannot validate argument on parameter 'Name'. The argument is null or "
            "empty. Provide an argument that is not null or empty, and then try "
            "the command again."
        )
    rows = _invoke(connection, _ZONE_CLASS, "Get", {"Name": [name]}, True) or []
    if not rows:
        raise OSError(
            "DNS zone {0} was not returned by the local DNS Server provider.".format(
                name
            )
        )
    if len(rows) != 1:
        raise OSError(
            "DNS Server returned multiple zones for the exact name {0}.".format(name)
        )
    return rows[0]


def _addresses(servers):
    for address in servers or []:
        try:
            if (
                not address
                or "\0" in address
                or any(character.isspace() for character in address)
            ):
                raise ValueError("empty or whitespace address")
            if ":" in address:
                socket.inet_pton(socket.AF_INET6, address.split("%", 1)[0])
            else:
                socket.inet_aton(address)
        except (OSError, ValueError) as error:
            raise ValueError(
                "Invalid DNS server IP address: {0}".format(address)
            ) from error


def _storage(options, current):
    name, replication = options["name"], options["replication"]
    if options["directory_partition"]:
        return {
            "ReplicationScope": "Custom",
            "DirectoryPartitionName": options["directory_partition"],
        }
    if not replication and current is not None:
        result = {"ReplicationScope": current.get("ReplicationScope")}
        if current.get("DirectoryPartitionName"):
            result["DirectoryPartitionName"] = current["DirectoryPartitionName"]
        return result
    if replication == "none" or not replication:
        return {"ZoneFile": "{0}.dns".format(name)}
    return {"ReplicationScope": replication.capitalize()}


def _conversion_guard(current, name):
    if current["IsShutdown"]:
        raise ValueError(
            "Failed to convert DNS zone {0}: this zone is shutdown and cannot "
            "be modified".format(name)
        )


def _scope_inputs(inputs):
    field = (
        "DirectoryPartitionName"
        if inputs.get("DirectoryPartitionName")
        else "ReplicationScope"
    )
    return {"Name": inputs["Name"], field: inputs.get(field), "PassThru": True}


def _primary_operations(options, current, inputs, warnings):
    class_name, update = _CLASSES["primary"], options["dynamic_update"]
    if inputs.get("ZoneFile") and update in ("secure", "nonsecureandsecure"):
        inputs.pop("DynamicUpdate", None)
        warnings.append(
            "Secure DNS updates are available only for Active Directory-integrated zones"
        )
    if current is None:
        method = (
            "AddByFileForwardLookupZone"
            if "ZoneFile" in inputs
            else "AddByADForwardLookupZone"
        )
        return [(class_name, method, dict(inputs))]
    operations = []
    if current["ZoneType"].lower() != "primary":
        _conversion_guard(current, options["name"])
        if current.get("ReplicationScope"):
            inputs["ReplicationScope"] = current["ReplicationScope"]
        else:
            inputs.pop("ReplicationScope", None)
        if current.get("ZoneFile"):
            inputs["ZoneFile"] = current["ZoneFile"]
        else:
            inputs.pop("ReplicationScope", None)
        method = (
            "ConvertToByFileZone" if inputs.get("ZoneFile") else "ConvertToByADZone"
        )
        operations.append((class_name, method, dict(inputs, Force=True)))
    if not inputs.get("ZoneFile"):
        operations.append((class_name, "SetByADZone", _scope_inputs(inputs)))
    if update:
        operations.append(
            (
                class_name,
                "SetByParameters",
                {
                    "Name": options["name"],
                    "DynamicUpdate": inputs.get("DynamicUpdate"),
                    "PassThru": True,
                },
            )
        )
    return operations


def _secondary_operations(options, current, inputs):
    class_name, name = _CLASSES["secondary"], options["name"]
    inputs.pop("ReplicationScope", None)
    inputs.pop("DynamicUpdate", None)
    if current is None:
        inputs["ZoneFile"] = name + ".dns"
        return [(class_name, "AddByForwardLookupZone", dict(inputs))]
    operations = []
    if current["ZoneType"].lower() != "secondary":
        _conversion_guard(current, name)
        inputs["MasterServers"] = current.get("MasterServers")
        inputs["ZoneFile"] = current.get("ZoneFile")
        operations.append((class_name, "ConvertTo", dict(inputs, Force=True)))
    if options["dns_servers"]:
        operations.append(
            (
                class_name,
                "Set",
                {
                    "Name": name,
                    "MasterServers": options["dns_servers"],
                    "PassThru": True,
                },
            )
        )
    return operations


def _transfer_operations(options, current, zone_type, inputs):
    class_name, name = _CLASSES[zone_type], options["name"]
    if current["ZoneType"].lower() != zone_type:
        raise ValueError(
            "Failed to convert DNS zone {0} to {1}, unsupported conversion".format(
                name, zone_type
            )
        )
    operations = []
    if inputs.get("DirectoryPartitionName") or inputs.get("ReplicationScope"):
        operations.append((class_name, "SetByADZone", _scope_inputs(inputs)))
    method = "SetByParameter" if zone_type == "stub" else "SetByParameters"
    if options["forwarder_timeout"]:
        operations.append(
            (
                class_name,
                method,
                {
                    "Name": name,
                    "ForwarderTimeout": options["forwarder_timeout"],
                    "PassThru": True,
                },
            )
        )
    if options["dns_servers"]:
        operations.append(
            (
                class_name,
                method,
                {
                    "Name": name,
                    "MasterServers": options["dns_servers"],
                    "PassThru": True,
                },
            )
        )
    return operations


def _operations(options, current, zone_type, warnings):
    inputs = dict(_storage(options, current), Name=options["name"], PassThru=True)
    if options["dynamic_update"]:
        inputs["DynamicUpdate"] = options["dynamic_update"]
    if options["dns_servers"] and zone_type != "primary":
        inputs["MasterServers"] = options["dns_servers"]
    if (
        current is None
        and zone_type in ("secondary", "stub", "forwarder")
        and not options["dns_servers"]
    ):
        raise ValueError(
            "The dns_servers param is required when creating new stub, forwarder "
            "or secondary zones"
        )
    if zone_type == "primary":
        return _primary_operations(options, current, inputs, warnings), inputs
    if zone_type == "secondary":
        return _secondary_operations(options, current, inputs), inputs
    if zone_type not in ("stub", "forwarder"):
        return [], inputs
    inputs.pop("DynamicUpdate", None)
    if zone_type == "forwarder":
        inputs.pop("ZoneFile", None)
        if inputs.get("ReplicationScope") == "None":
            inputs.pop("ReplicationScope")
        timeout = options["forwarder_timeout"]
        if timeout and 0 <= timeout <= 15:
            inputs["ForwarderTimeout"] = timeout
        elif timeout:
            warnings.append(
                "The forwarder_timeout param must be an integer value between 0 and 15"
            )
    if current is not None:
        return _transfer_operations(options, current, zone_type, inputs), inputs
    file_backed = (
        "ZoneFile" in inputs
        if zone_type == "stub"
        else "ReplicationScope" not in inputs
    )
    method = "AddByFileForwardLookupZone" if file_backed else "AddByADForwardLookupZone"
    return [(_CLASSES[zone_type], method, dict(inputs))], inputs


def _validate_operation(class_name, method_name, inputs):
    # The cmdlets perform binding before WhatIf. Validate the measured binding
    # constraints even in check mode, immediately before each sequential call.
    if not inputs.get("Name"):
        raise ValueError(
            "Cannot validate argument on parameter 'Name'. The argument is null or "
            "empty. Provide an argument that is not null or empty, and then try "
            "the command again."
        )
    if "MasterServers" in inputs:
        if not inputs["MasterServers"]:
            raise ValueError("MasterServers must be a nonempty IP address collection.")
        _addresses(inputs["MasterServers"])
    if "DynamicUpdate" in inputs and inputs["DynamicUpdate"] is None:
        raise ValueError(
            "Cannot validate argument on parameter 'DynamicUpdate'. The argument "
            '"" does not belong to the set "None,Secure,NonsecureAndSecure" specified '
            "by the ValidateSet attribute. Supply an argument that is in the set "
            "and then try the command again."
        )
    if "ReplicationScope" in inputs and inputs["ReplicationScope"] not in (
        "Forest",
        "Domain",
        "Legacy",
        "Custom",
    ):
        raise ValueError("ReplicationScope must be Forest, Domain, Legacy or Custom.")
    if method_name.endswith("ByADZone") and "ReplicationScope" not in inputs:
        raise ValueError("The ReplicationScope parameter is required.")
    if (
        method_name.startswith("Convert")
        and "ZoneFile" in inputs
        and "ReplicationScope" in inputs
    ):
        raise ValueError(
            "ZoneFile and ReplicationScope belong to different parameter sets."
        )
    if class_name == _CLASSES["stub"] and "ForwarderTimeout" in inputs:
        raise ValueError(
            "A parameter cannot be found that matches parameter name 'ForwarderTimeout'."
        )
    if "ForwarderTimeout" in inputs and not 0 <= inputs["ForwarderTimeout"] <= 15:
        raise ValueError("ForwarderTimeout must be between 0 and 15.")


def _apply_operations(connection, operations, zone_type, name, check_mode):
    for class_name, method_name, inputs in operations:
        try:
            _validate_operation(class_name, method_name, inputs)
            if not check_mode:
                _invoke(connection, class_name, method_name, inputs)
        except (OSError, ValueError) as error:
            if method_name.startswith("Add"):
                prefix = "Failed to add {0} zone {1}: ".format(zone_type, name)
            elif method_name.startswith("Convert"):
                prefix = "Failed to convert DNS zone {0}: ".format(name)
            else:
                prefix = "Failed to set properties on the zone {0}: ".format(name)
            return prefix + str(error)
    return None


def _failure(result, message):
    result.update(failed=True, msg=message)
    return result


def _storage_failure(options, current):
    scope, replication = current.get("ReplicationScope"), options["replication"]
    if (
        scope
        and scope.lower() == "none"
        and (
            replication in ("legacy", "forest", "domain")
            or options["directory_partition"]
        )
    ):
        return (
            "Converting a file backed DNS zone to Active Directory integrated zone "
            "is unsupported"
        )
    if (
        scope
        and scope.lower() in ("legacy", "forest", "domain", "custom")
        and replication == "none"
    ):
        return (
            "Converting Active Directory integrated zone to a file backed DNS zone "
            "is unsupported"
        )
    return None


def _remove(connection, name, result):
    try:
        _invoke(
            connection,
            _ZONE_CLASS,
            "Remove",
            {"Name": name, "Force": True, "PassThru": True},
        )
    except (OSError, ValueError) as error:
        return _failure(result, "Failed to remove DNS zone: " + str(error))
    result["changed"] = True
    if "diff" in result:
        result["diff"]["after"] = ""
    return result


# Explicit source inputs keep the final read and preview intelligible without
# introducing a state container just for this one operation.
def _finish(  # pylint: disable=too-many-arguments
    connection, options, current, inputs, result, *, check_mode
):
    diff = result.get("diff", {})
    try:
        updated = _read(connection, options["name"])
        if current is None or any(
            current.get(name) != updated.get(name) for name in _COMPARISON_PROPERTIES
        ):
            result["changed"] = True
            result["zone"] = _project(updated)
            diff["after"] = _project(updated)
        if check_mode:
            predicted = {
                name: inputs[name] if inputs.get(name) else value
                for name, value in current.items()
            }
            diff["after"] = _project(predicted)
            converted_secondary = (
                options["type"] == "secondary"
                and current["ZoneType"].lower() != "secondary"
            )
            if inputs.get("MasterServers") and not converted_secondary:
                # The source preview substitutes input strings for IPAddress
                # objects, whose IPAddressToString projection then becomes null.
                # Secondary conversion instead retains the old provider objects.
                diff["after"]["dns_servers"] = None
    except (OSError, ValueError) as error:
        return _failure(
            result, "Failed to lookup new zone {0}: {1}".format(options["name"], error)
        )
    return result


def _manage(connection, options, check_mode, diff_mode):
    result, warnings = {"changed": False}, []
    diff = {}
    if diff_mode:
        result["diff"] = diff
    try:
        current = _read(connection, options["name"])
    except (OSError, ValueError):
        current = None
    diff["before"] = _project(current) if current is not None else ""
    message = _storage_failure(options, current) if current is not None else None
    if message:
        return _failure(result, message)
    if options["state"] == "absent":
        return (
            result
            if current is None or check_mode
            else _remove(connection, options["name"], result)
        )
    zone_type = options["type"] or (
        current["ZoneType"].lower() if current is not None else None
    )
    try:
        operations, inputs = (
            _operations(options, current, zone_type, warnings)
            if options["state"] == "present"
            else ([], {})
        )
    except (OSError, ValueError) as error:
        if warnings:
            result["warnings"] = warnings
        return _failure(result, str(error))
    if warnings:
        result["warnings"] = warnings
    message = _apply_operations(
        connection, operations, zone_type, options["name"], check_mode
    )
    if message:
        return _failure(result, message)
    return _finish(connection, options, current, inputs, result, check_mode=check_mode)


def manage(options, check_mode=False, diff_mode=False):
    """Apply one bound DNS zone request through the local native provider.

    :param dict options: Bound upstream zone arguments.
    :param bool check_mode: Validate without submitting zone writes.
    :param bool diff_mode: Include source-compatible before/after properties.
    :returns: Public changed/zone/diff/warning or failure fields.
    :rtype: dict
    :raises OSError: DNS provider is unavailable or its connection fails.
    """
    with ExitStack() as cleanup:
        try:
            connection = cleanup.enter_context(wmi.WmiConnection(_NAMESPACE))
            definitions = connection.query(
                "SELECT * FROM meta_class WHERE __CLASS='PS_DnsServerZone'", ["__CLASS"]
            )
        except OSError as error:
            if not classic.unavailable(error):
                raise
            definitions = []
        if definitions:
            return _manage(connection, options, check_mode, diff_mode)
    try:
        with wmi.WmiConnection(classic.NAMESPACE) as connection:
            definitions = connection.query(
                "SELECT * FROM meta_class WHERE __CLASS='MicrosoftDNS_Zone'",
                ["__CLASS"],
            )
            if not definitions:
                raise OSError(
                    "Windows DNS Server management provider is unavailable "
                    "(modern DNS and ROOT\\MicrosoftDNS)."
                )
            return _manage(classic.Zones(connection), options, check_mode, diff_mode)
    except OSError as error:
        if classic.unavailable(error):
            raise OSError(
                "Windows DNS Server management provider is unavailable "
                "(modern DNS and ROOT\\MicrosoftDNS)."
            ) from error
        raise
