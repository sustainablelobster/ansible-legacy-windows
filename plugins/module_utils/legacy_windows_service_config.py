# -*- coding: utf-8 -*-
# Copyright 2026 Joe Lustri
# SPDX-License-Identifier: GPL-3.0-or-later

"""Decode read-only service configuration, including optional Windows features."""

import base64
import ctypes
import struct
import uuid

_FAILURE_ACTIONS = {0: "none", 1: "restart", 2: "reboot", 3: "run_command"}
_TRIGGER_TYPES = {
    1: "device_interface_arrival",
    2: "ip_address_availability",
    3: "domain_join",
    4: "firewall_port_event",
    5: "group_policy",
    6: "network_endpoint",
    20: "custom",
}
_TRIGGER_SUBTYPES = {
    "1f81d131-3fac-4537-9e0c-7e7b0c2f4b55": "named_pipe_event",
    "bc90d167-9470-4139-a9ba-be0bbbf5b74d": "rpc_interface_event",
    "1ce20aba-9851-4421-9430-1ddeb766e809": "domain_join",
    "ddaf516e-58c2-4866-9574-c3b615d42ea1": "domain_leave",
    "b7569e07-8421-4ee0-ad10-86915afdad09": "firewall_port_open",
    "a144ed38-8e12-4de4-9d96-e64740b1a524": "firewall_port_close",
    "659fcae6-5bdb-4da9-b1ff-ca2a178d46e0": "machine_policy_present",
    "54fb46c8-f089-464c-b1fd-59d1b62c3b50": "user_policy_present",
    "4f27f2de-14e2-430b-a549-7cd48cbc8245": "network_first_ip_arrival",
    "cc4ba62a-162e-4648-847a-b6bdf993e335": "network_last_ip_removal",
}
_TRIGGER_DATA_TYPES = {
    1: "binary",
    2: "string",
    3: "level",
    4: "keyword_any",
    5: "keyword_all",
}


# This pointer is nullable independently of an empty description string.
class _Description(ctypes.Structure):  # pylint: disable=too-few-public-methods
    _fields_ = [("description", ctypes.c_wchar_p)]


# Native failure actions contain two DWORDs, including on 64-bit Windows.
class _FailureAction(ctypes.Structure):  # pylint: disable=too-few-public-methods
    _fields_ = [("type", ctypes.c_uint32), ("delay", ctypes.c_uint32)]


# Strings and actions are borrowed from the configuration buffer.
class _FailureActions(ctypes.Structure):  # pylint: disable=too-few-public-methods
    _fields_ = [
        ("reset_period", ctypes.c_uint32),
        ("reboot_message", ctypes.c_wchar_p),
        ("command", ctypes.c_wchar_p),
        ("count", ctypes.c_uint32),
        ("actions", ctypes.POINTER(_FailureAction)),
    ]


# Trigger payloads are byte-counted and may contain embedded UTF-16 NULs.
class _TriggerData(ctypes.Structure):  # pylint: disable=too-few-public-methods
    _fields_ = [
        ("type", ctypes.c_uint32),
        ("size", ctypes.c_uint32),
        ("data", ctypes.c_void_p),
    ]


# A native GUID and the item array remain owned by the query buffer.
class _Trigger(ctypes.Structure):  # pylint: disable=too-few-public-methods
    _fields_ = [
        ("type", ctypes.c_uint32),
        ("action", ctypes.c_uint32),
        ("subtype", ctypes.c_void_p),
        ("count", ctypes.c_uint32),
        ("items", ctypes.POINTER(_TriggerData)),
    ]


# The reserved pointer belongs to the fixed Windows ABI and is not consumed.
class _Triggers(ctypes.Structure):  # pylint: disable=too-few-public-methods
    _fields_ = [
        ("count", ctypes.c_uint32),
        ("triggers", ctypes.POINTER(_Trigger)),
        ("reserved", ctypes.c_void_p),
    ]


def multi_string_values(pointer):
    """Copy a native UTF-16 MULTI_SZ list, retaining its original order.

    :param pointer: Address of a NUL-terminated string list, or a null pointer.
    :type pointer: int or None
    :returns: Decoded strings, or an empty list for a null/empty string list.
    :rtype: list[str]
    """
    values = []
    while pointer:
        units = ctypes.cast(pointer, ctypes.POINTER(ctypes.c_uint16))
        length = 0
        while units[length]:
            length += 1
        if not length:
            break
        values.append(
            ctypes.string_at(pointer, length * 2).decode("utf-16-le", "surrogatepass")
        )
        pointer += (length + 1) * 2
    return values


def _read_buffer(library, service, level):
    needed = ctypes.c_uint32()
    buffer, size = None, 0
    while True:
        if library.QueryServiceConfig2W(
            service, level, buffer, size, ctypes.byref(needed)
        ):
            return buffer, 0
        error = ctypes.get_last_error()
        if error != 122:
            return None, error
        size = max(needed.value, size * 2, 1)
        buffer = ctypes.create_string_buffer(size)


def _failure_fields(library, service):
    buffer, error = _read_buffer(library, service, 2)
    if error:
        # A failed getter supplies no actions, while its scalar properties are null.
        return {
            "failure_actions": [],
            "failure_command": None,
            "failure_reboot_msg": None,
            "failure_reset_period_sec": None,
        }
    failures = _FailureActions.from_buffer(buffer)
    return {
        "failure_actions": [
            {"type": _FAILURE_ACTIONS.get(action.type, {}), "delay_ms": action.delay}
            for action in failures.actions[: failures.count]
        ],
        "failure_command": failures.command,
        "failure_reboot_msg": failures.reboot_message,
        "failure_reset_period_sec": failures.reset_period,
    }


def _trigger_item(item):
    if item.size and not item.data:
        raise ValueError("Trigger data has a nonzero size but no data pointer.")
    data = ctypes.string_at(item.data, item.size) if item.size else b""
    if item.type == 2:
        value = data.decode("utf-16-le", "replace")
        if value.endswith("\0\0"):
            value = [part for part in value.split("\0") if part]
        else:
            if not value:
                raise ValueError("A single trigger string has no final UTF-16 unit.")
            # The reference removes one UTF-16 unit, not one Python code point.
            value = value.encode("utf-16-le", "surrogatepass")[:-2].decode(
                "utf-16-le", "replace"
            )
    elif item.type in (4, 5):
        value = struct.unpack_from("<Q", data)[0]
    else:
        if item.type == 3:
            data = bytes(bytearray([data[0]]))
        value = base64.b64encode(data).decode("ascii")
    return {"type": _TRIGGER_DATA_TYPES.get(item.type, {}), "data": value}


def _triggers(buffer):
    information = _Triggers.from_buffer(buffer)
    triggers = []
    try:
        for native in information.triggers[: information.count]:
            if not native.subtype:
                raise ValueError("A trigger has no subtype GUID pointer.")
            subtype = str(uuid.UUID(bytes_le=ctypes.string_at(native.subtype, 16)))
            triggers.append(
                {
                    "action": {1: "start_service", 2: "stop_service"}.get(
                        native.action, {}
                    ),
                    "type": _TRIGGER_TYPES.get(native.type, {}),
                    "sub_type": _TRIGGER_SUBTYPES.get(subtype, "custom"),
                    "sub_type_guid": subtype,
                    "data_items": [
                        _trigger_item(item) for item in native.items[: native.count]
                    ],
                }
            )
    except (ValueError, IndexError, struct.error):
        # Decoding belongs to the upstream Triggers getter; any failed item
        # makes that getter null and its surrounding foreach produce no triggers.
        return []
    return triggers


def _modern_fields(read, start_mode):
    result = {"start_mode": start_mode}
    if start_mode == "auto":
        buffer, error = read(3, "start_mode")
        if error:
            result["start_mode"] = None if error == 124 else {}
        else:
            result["start_mode"] = (
                "delayed" if ctypes.c_uint32.from_buffer(buffer).value else "auto"
            )

    buffer, error = read(4, "failure_actions_on_non_crash_failure")
    result["failure_actions_on_non_crash_failure"] = (
        None if error else bool(ctypes.c_uint32.from_buffer(buffer).value)
    )
    buffer, error = read(5, "sid_info")
    if error and error != 124:
        # Unlike ordinary getters, this property is followed by ToString();
        # calling it on a failed/null getter terminates the reference module.
        raise ValueError("You cannot call a method on a null-valued expression.")
    if error:
        result["sid_info"] = None
    else:
        # ServiceSidInfo is a uint-backed enum in the pinned upstream source.
        sid_type = ctypes.c_uint32.from_buffer(buffer).value
        result["sid_info"] = {0: "none", 1: "unrestricted", 3: "restricted"}.get(
            sid_type, str(sid_type)
        )
    buffer, error = read(6, "required_privileges")
    result["required_privileges"] = (
        None
        if error
        else multi_string_values(ctypes.c_void_p.from_buffer(buffer).value)
    )
    buffer, error = read(7, "pre_shutdown_timeout_ms")
    result["pre_shutdown_timeout_ms"] = (
        None if error else ctypes.c_uint32.from_buffer(buffer).value
    )
    buffer, error = read(8, "triggers")
    result["triggers"] = None if error == 124 else ([] if error else _triggers(buffer))
    buffer, error = read(9, "preferred_node")
    # Only the leading USHORT is consumed; the following BOOLEAN is not a DWORD.
    result["preferred_node"] = (
        None if error else ctypes.c_uint16.from_buffer(buffer).value
    )
    buffer, error = read(12, "launch_protection")
    if error:
        result["launch_protection"] = None if error == 124 else "none"
    else:
        result["launch_protection"] = {
            0: "none",
            1: "windows",
            2: "windows_light",
            3: "antimalware_light",
        }.get(ctypes.c_uint32.from_buffer(buffer).value, {})
    return result


def query_config(library, service, name, start_mode, warnings):
    """Read Config2 properties, warning when a modern level is unsupported.

    Native error 124 gives null and a warning for the affected modern field.
    Other failures retain the reference's individual getter behavior, including
    its fatal SID getter failure and ordinary null/list/default values.

    :param library: Configured advapi32 library exposing QueryServiceConfig2W.
    :type library: object
    :param service: Open service handle with query-config access; owned by caller.
    :type service: int
    :param name: Service name included in unsupported-field warning messages.
    :type name: str
    :param start_mode: Base start mode; only automatic services query delayed start.
    :type start_mode: str or dict
    :param warnings: List receiving deterministic, service-specific warning strings.
    :type warnings: list[str]
    :returns: Copied configuration fields, including the complete start mode.
    :rtype: dict
    :raises ValueError: If the SID property fails for a reason other than error 124.
    """
    unsupported = []

    def _optional(level, field):
        buffer, error = _read_buffer(library, service, level)
        if error == 124:
            unsupported.append(field)
        return buffer, error

    result = _failure_fields(library, service)
    buffer, error = _read_buffer(library, service, 1)
    result["description"] = (
        None if error else _Description.from_buffer(buffer).description
    )
    try:
        result.update(_modern_fields(_optional, start_mode))
    finally:
        if unsupported:
            message = (
                "Service '{0}': fields {1} are unavailable (Windows error 124); "
                "returning null for those fields."
            ).format(name, ", ".join(unsupported))
            if "start_mode" in unsupported:
                message += (
                    " Automatic and delayed automatic start cannot be distinguished."
                )
            warnings.append(message)
    return result
