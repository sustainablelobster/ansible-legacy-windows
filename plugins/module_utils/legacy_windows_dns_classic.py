# -*- coding: utf-8 -*-
# Copyright 2026 sustainablelobster
# SPDX-License-Identifier: GPL-3.0-or-later
"""Use the installed MicrosoftDNS provider for older DNS server operations."""

import ctypes
import os
import subprocess
from contextlib import ExitStack

import legacy_windows_wmi as wmi  # pylint: disable=import-error

NAMESPACE = r"ROOT\MicrosoftDNS"
_ZONE_TYPES = {1: "Primary", 2: "Secondary", 3: "Stub", 4: "Forwarder"}
_UPDATES = {0: "None", 1: "NonsecureAndSecure", 2: "Secure"}
_ZONE_PROPERTIES = (
    "__PATH",
    "Name",
    "ZoneType",
    "DsIntegrated",
    "AllowUpdate",
    "DataFile",
    "Paused",
    "Shutdown",
    "Reverse",
    "MasterServers",
    "ForwarderTimeout",
)


def unavailable(error):
    """Recognize absent namespaces/classes, not authorization or runtime errors.

    :param OSError error: Native WMI failure.
    :returns: Whether another installed provider may be selected safely.
    :rtype: bool
    """
    return getattr(error, "hresult", None) in (0x8004100E, 0x80041010)


def literal(value):
    """Encode an exact WQL string without permitting query interpolation.

    :param str value: Name obtained from a public argument or the provider.
    :returns: Quoted WQL literal.
    :rtype: str
    :raises ValueError: A name contains a null character.
    """
    if "\0" in value:
        raise ValueError("DNS names cannot contain a null character.")
    return "'" + value.replace("\\", "\\\\").replace("'", "\\'") + "'"


# Classic DNS has UInt32 inputs and void methods, unlike the modern cmdlet
# provider. Keep this leaf's native encoding out of shared WMI interfaces.
# pylint: disable=protected-access
def _check_call(connection, status, method_name):
    if not status & 0x80000000:
        return
    automation = connection._automation
    automation.GetErrorInfo.argtypes = [wmi._ULONG, wmi._POINTER_OUT]
    automation.GetErrorInfo.restype = wmi._LONG
    information = wmi._POINTER()
    description = wmi._POINTER()
    message = None
    try:
        if automation.GetErrorInfo(0, ctypes.byref(information)) == 0 and information:
            get_description = wmi._method(information, 5, wmi._LONG, [wmi._POINTER_OUT])
            if (
                get_description(information, ctypes.byref(description)) == 0
                and description
            ):
                message = ctypes.wstring_at(description)
    finally:
        if description:
            automation.SysFreeString(description)
        wmi._release(information)
    error = OSError(
        message
        or "Classic DNS method {0} failed (HRESULT 0x{1:08X}).".format(
            method_name, status & 0xFFFFFFFF
        )
    )
    error.hresult = status & 0xFFFFFFFF
    raise error


def call(connection, object_path, method_name, inputs, properties=()):
    """Invoke an installed classic DNS method with its real output contract.

    :param connection: Open MicrosoftDNS WMI connection.
    :type connection: legacy_windows_wmi.WmiConnection
    :param str object_path: Actual object path or static class name.
    :param str method_name: Method supplied by that class.
    :param dict inputs: Native boolean, string, string-array or integer inputs.
    :param properties: Output property names; void mutations need none.
    :type properties: tuple
    :returns: Selected actual output properties.
    :rtype: dict
    :raises OSError: Windows rejects the request.
    """
    with ExitStack() as cleanup:
        numbers = {
            name: value
            for name, value in inputs.items()
            if isinstance(value, int) and not isinstance(value, bool)
        }
        arguments = (
            connection._method_inputs(
                cleanup,
                object_path,
                method_name,
                {name: value for name, value in inputs.items() if name not in numbers},
            )
            if inputs
            else None
        )
        for name, value in numbers.items():
            wmi._put_integer(arguments, connection._automation, name, value)
        output = wmi._POINTER()
        cleanup.callback(wmi._release, output)
        # The exact native ExecMethod ABI is repeated intentionally: this older
        # provider owns void outputs and integer inputs, not cmdlet envelopes.
        # pylint: disable=duplicate-code
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
            wmi._bstr(connection._automation, cleanup, object_path),
            wmi._bstr(connection._automation, cleanup, method_name),
            0,
            None,
            arguments,
            ctypes.byref(output),
            None,
        )
        # Retrieve thread-local extended diagnostics before any COM Release.
        _check_call(connection, status, method_name)
        # pylint: enable=duplicate-code
        return connection._properties(output, properties) if properties else {}


def delete(connection, object_path):
    """Delete exactly the instance identified by an actual provider object path.

    :param connection: Open MicrosoftDNS WMI connection.
    :type connection: legacy_windows_wmi.WmiConnection
    :param str object_path: Observed locatable object path.
    :raises OSError: Windows rejects the deletion.
    """
    with ExitStack() as cleanup:
        operation = wmi._method(
            connection._services,
            16,
            wmi._LONG,
            [wmi._POINTER, wmi._LONG, wmi._POINTER, wmi._POINTER_OUT],
        )
        wmi._check(
            operation(
                connection._services,
                wmi._bstr(connection._automation, cleanup, object_path),
                0,
                None,
                None,
            ),
            "IWbemServices.DeleteInstance",
        )


def update(connection, object_path, values):
    """Save requested properties on an existing classic DNS instance.

    :param connection: Open MicrosoftDNS WMI connection.
    :type connection: legacy_windows_wmi.WmiConnection
    :param str object_path: Actual locatable instance path.
    :param dict values: Property names and their native values.
    :raises OSError: Windows rejects the property or instance write.
    """
    with ExitStack() as cleanup:
        instance = wmi._get_object(
            connection._services, connection._automation, cleanup, object_path
        )
        # Keep the fixed WMI VARIANT encodings beside this native instance write.
        # pylint: disable=duplicate-code
        for name, value in values.items():
            if isinstance(value, bool):
                wmi._put_boolean(instance, connection._automation, name, value)
            elif isinstance(value, int):
                wmi._put_integer(instance, connection._automation, name, value)
            elif isinstance(value, list):
                wmi._put_string_array(instance, connection._automation, name, value)
            else:
                wmi._put_string(instance, connection._automation, name, value)
        # pylint: enable=duplicate-code
        wmi._update_instance(connection._services, instance)


# pylint: enable=protected-access


class Zones:
    """Adapt installed classic DNS zone operations to the public zone workflow.

    :param connection: Open MicrosoftDNS WMI connection.
    :type connection: legacy_windows_wmi.WmiConnection
    """

    def __init__(self, connection):
        self.connection = connection

    def read(self, name):
        """Read one exact zone and preserve the fields Windows actually supplies.

        :param str name: Exact zone name.
        :returns: Native fields normalized for the existing zone projection.
        :rtype: dict
        :raises OSError: The exact zone is missing or metadata cannot be read.
        """
        rows = self.connection.query(
            "SELECT * FROM MicrosoftDNS_Zone WHERE Name=" + literal(name),
            list(_ZONE_PROPERTIES),
        )
        if len(rows) != 1:
            raise OSError("Classic DNS did not return exactly one zone: " + name)
        zone = rows[0]
        scope, partition = self._scope(zone) if zone["DsIntegrated"] else ("None", None)
        return {
            "ZoneName": zone["Name"],
            "ZoneType": _ZONE_TYPES[zone["ZoneType"]],
            "IsPaused": zone["Paused"],
            "IsShutdown": zone["Shutdown"],
            "IsReverseLookupZone": zone["Reverse"],
            "IsDsIntegrated": zone["DsIntegrated"],
            "DynamicUpdate": _UPDATES.get(zone["AllowUpdate"]),
            "ZoneFile": zone["DataFile"],
            "MasterServers": zone["MasterServers"],
            "ForwarderTimeout": zone["ForwarderTimeout"],
            "ReplicationScope": scope,
            "DirectoryPartitionName": partition,
            "__classic_path": zone["__PATH"],
        }

    def _scope(self, zone):
        distinguished = call(
            self.connection,
            zone["__PATH"],
            "GetDistinguishedName",
            {},
            ("ReturnValue",),
        )["ReturnValue"]
        marker = ",CN=MicrosoftDNS,"
        position = distinguished.lower().find(marker.lower())
        if position < 0:
            raise OSError("Classic DNS returned no directory storage identity.")
        suffix = distinguished[position + len(marker) :]
        if suffix.upper().startswith("CN=SYSTEM,"):
            return "Legacy", None
        labels = suffix.split(",")
        if not labels or any(not label.upper().startswith("DC=") for label in labels):
            raise OSError("Classic DNS returned an unsupported directory identity.")
        partition = ".".join(label[3:] for label in labels)
        prefix = labels[0][3:].lower()
        scope = {"forestdnszones": "Forest", "domaindnszones": "Domain"}.get(
            prefix, "Custom"
        )
        return scope, partition if scope == "Custom" else None

    def _partition(self, name, inputs):
        scope = inputs.get("ReplicationScope")
        selected = inputs.get("DirectoryPartitionName")
        if not scope and not selected:
            return
        tool = os.path.join(os.environ["SystemRoot"], "System32", "dnscmd.exe")
        if not os.path.isfile(tool):
            raise OSError(
                "Selecting an Active Directory DNS partition requires installed dnscmd.exe."
            )
        command = [
            tool,
            "/ZoneChangeDirectoryPartition",
            name,
            selected if selected else "/" + scope.lower(),
        ]
        with subprocess.Popen(
            command, stdout=subprocess.PIPE, stderr=subprocess.PIPE
        ) as process:
            stdout, stderr = process.communicate()
        if process.returncode:
            raise OSError(
                "Changing DNS directory partition failed: "
                + (stdout + stderr).decode("mbcs", "replace")
            )

    def _change_type(self, name, kind, method_name, inputs):
        integrated = "ReplicationScope" in inputs or "DirectoryPartitionName" in inputs
        if integrated:
            servers = self.connection.query(
                "SELECT * FROM MicrosoftDNS_Server", ["DsAvailable"]
            )
            if len(servers) != 1 or not servers[0]["DsAvailable"]:
                raise OSError(
                    "This DNS server has no Active Directory zone storage facility."
                )
            # Verify the extra partition-management facility before creation.
            if not os.path.isfile(
                os.path.join(os.environ["SystemRoot"], "System32", "dnscmd.exe")
            ):
                raise OSError(
                    "Selecting an Active Directory DNS partition requires installed dnscmd.exe."
                )
        arguments = {"ZoneType": kind, "DsIntegrated": integrated}
        if inputs.get("ZoneFile") and method_name.startswith("Convert"):
            arguments["DataFileName"] = inputs["ZoneFile"]
        # With CreateZone a named file imports an existing zone and fails if
        # that file is absent. Omit it to create the native name.dns file.
        if inputs.get("MasterServers"):
            arguments["IpAddr"] = inputs["MasterServers"]
        if method_name.startswith("Add"):
            arguments["ZoneName"] = name
            call(self.connection, "MicrosoftDNS_Zone", "CreateZone", arguments)
        else:
            call(
                self.connection,
                self.read(name)["__classic_path"],
                "ChangeZoneType",
                arguments,
            )
        if integrated:
            self._partition(name, inputs)

    def invoke(self, class_name, method_name, inputs, output=False):
        """Submit a planned existing-module operation through the classic provider.

        :param str class_name: Existing workflow's DNS zone class.
        :param str method_name: Existing workflow's operation.
        :param dict inputs: Validated existing-module inputs.
        :param bool output: Whether the caller requires the final zone record.
        :returns: Read results or None after a mutation.
        :rtype: list or None
        :raises OSError: A genuinely unavailable facility or native failure.
        """
        name = inputs["Name"]
        if method_name == "Get":
            return [self.read(name[0])]
        if method_name == "Remove":
            delete(self.connection, self.read(name)["__classic_path"])
            return None
        if method_name.startswith(("Add", "Convert")):
            kind = {
                "PS_DnsServerPrimaryZone": 0,
                "PS_DnsServerSecondaryZone": 1,
                "PS_DnsServerStubZone": 2,
                "PS_DnsServerConditionalForwarder": 3,
            }[class_name]
            self._change_type(name, kind, method_name, inputs)
        elif "ADZone" in method_name:
            self._partition(name, inputs)
        values = {}
        if "DynamicUpdate" in inputs:
            values["AllowUpdate"] = {
                value.lower(): key for key, value in _UPDATES.items()
            }[inputs["DynamicUpdate"].lower()]
        for key in ("MasterServers", "ForwarderTimeout"):
            if key in inputs:
                values[key] = inputs[key]
        if values:
            update(self.connection, self.read(name)["__classic_path"], values)
        return [self.read(name)] if output else None
