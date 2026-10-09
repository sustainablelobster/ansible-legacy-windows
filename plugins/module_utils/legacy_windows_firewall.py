# -*- coding: utf-8 -*-
# Copyright 2026 Joe Lustri
# SPDX-License-Identifier: GPL-3.0-or-later

"""Manage installed Windows Firewall profile facilities through native APIs."""

import ctypes
import os
import uuid
from contextlib import ExitStack

from legacy_windows_wmi import WmiConnection  # pylint: disable=import-error

PROFILES = ("Domain", "Private", "Public")
ACTION_VALUES = {"not_configured": 0, "allow": 2, "block": 4}
_PROPERTIES = ("Name", "Enabled", "DefaultInboundAction", "DefaultOutboundAction")
_ENUM_VALUES = {
    "Enabled": (0, 1, 2),
    "DefaultInboundAction": (0, 2, 4),
    "DefaultOutboundAction": (0, 2, 4),
}


class FirewallUnavailableError(OSError):
    """The installed firewall cannot represent a requested profile or setting."""


# The interface identifiers and vtable slots are defined by Windows netfw.h.
_POLICY2_CLASS = "e2b3c97f-6ae1-41ac-817a-f6f92166d7dd"
_POLICY2_INTERFACE = "98325047-c671-4174-8d81-defcd3f03186"
_MANAGER_CLASS = "304ce942-6e39-40d8-943a-b913c40c9cd4"
_MANAGER_INTERFACE = "f7898af5-cac4-4632-a2ec-da06e5111af2"


# Keep the platform GUID layout local so the firewall ABI has no WMI internals
# dependency. Its repetition is more explicit than importing a private record.
# pylint: disable=duplicate-code
class _Guid(ctypes.Structure):
    # Only opaque native GUID bytes are inspected; their alignment is four.
    # pylint: disable=too-few-public-methods
    _fields_ = [
        ("data1", ctypes.c_uint32),
        ("data2", ctypes.c_uint16),
        ("data3", ctypes.c_uint16),
        ("data4", ctypes.c_ubyte * 8),
    ]


# pylint: enable=duplicate-code
def _check(status, operation):
    if status & 0x80000000:
        error = OSError(
            "{0} failed (HRESULT 0x{1:08X}).".format(operation, status & 0xFFFFFFFF)
        )
        error.hresult = status & 0xFFFFFFFF
        raise error


def _method(pointer, slot, result, arguments):
    table = ctypes.cast(pointer, ctypes.POINTER(ctypes.POINTER(ctypes.c_void_p)))[0]
    function = ctypes.WINFUNCTYPE(result, ctypes.c_void_p, *arguments)
    return function(table[slot])


def _release(pointer):
    if pointer:
        _method(pointer, 2, ctypes.c_uint32, [])(pointer)


def _ole_library():
    if os.name != "nt":
        raise OSError("Windows Firewall management requires Windows.")
    ole = ctypes.WinDLL("ole32")
    ole.CoInitializeEx.argtypes = [ctypes.c_void_p, ctypes.c_uint32]
    ole.CoInitializeEx.restype = ctypes.c_int32
    ole.CoUninitialize.argtypes = []
    ole.CoUninitialize.restype = None
    ole.CoCreateInstance.argtypes = [
        ctypes.POINTER(_Guid),
        ctypes.c_void_p,
        ctypes.c_uint32,
        ctypes.POINTER(_Guid),
        ctypes.POINTER(ctypes.c_void_p),
    ]
    ole.CoCreateInstance.restype = ctypes.c_int32
    return ole


def _create(ole, cleanup, class_id, interface_id):
    pointer = ctypes.c_void_p()
    cleanup.callback(_release, pointer)
    class_guid = _Guid.from_buffer_copy(uuid.UUID(class_id).bytes_le)
    interface_guid = _Guid.from_buffer_copy(uuid.UUID(interface_id).bytes_le)
    _check(
        ole.CoCreateInstance(
            ctypes.byref(class_guid),
            None,
            1,
            ctypes.byref(interface_guid),
            ctypes.byref(pointer),
        ),
        "CoCreateInstance(Windows Firewall)",
    )
    return pointer


class _ComProfiles:
    """Own the installed advanced or classic firewall's local policy interface."""

    def __init__(self):
        self.available_profiles = PROFILES
        self._cleanup = None
        self._policy = None
        self._classic = False

    def __enter__(self):
        ole = _ole_library()
        with ExitStack() as cleanup:
            status = ole.CoInitializeEx(None, 0)
            if (
                status & 0xFFFFFFFF != 0x80010106
            ):  # Existing STA remains owned by its caller.
                _check(status, "CoInitializeEx")
                cleanup.callback(ole.CoUninitialize)
            try:
                self._policy = _create(ole, cleanup, _POLICY2_CLASS, _POLICY2_INTERFACE)
            except OSError as error:
                if getattr(error, "hresult", None) not in (0x80040154, 0x80004002):
                    raise
                manager = _create(ole, cleanup, _MANAGER_CLASS, _MANAGER_INTERFACE)
                self._policy = ctypes.c_void_p()
                cleanup.callback(_release, self._policy)
                _check(
                    _method(
                        manager, 7, ctypes.c_int32, [ctypes.POINTER(ctypes.c_void_p)]
                    )(manager, ctypes.byref(self._policy)),
                    "INetFwMgr.get_LocalPolicy",
                )
                self._classic = True
                self.available_profiles = ("Domain",)
            self._cleanup = cleanup.pop_all()
        return self

    def __exit__(self, exc_type, exc_value, traceback):
        self._cleanup.close()
        self._policy = None

    def validate_request(self, parameters):
        """Check selected profiles and actions before any native mutation.

        :param dict parameters: Validated public state/profile/action arguments.
        :raises FirewallUnavailableError: The local API lacks a requested setting.
        """
        selected = parameters["profiles"] or []
        unavailable = [
            name
            for name in selected
            if name.lower()
            not in [profile.lower() for profile in self.available_profiles]
        ]
        if unavailable:
            raise FirewallUnavailableError(
                "The installed classic firewall exposes Domain/Standard profiles; "
                "Private/Public profiles are unavailable. Select Domain explicitly."
            )
        if (
            not selected
            or not parameters["state"]
            or parameters["state"].lower() != "enabled"
        ):
            return
        actions = [parameters[name] for name in ("inbound_action", "outbound_action")]
        if self._classic and any(action is not None for action in actions):
            raise FirewallUnavailableError(
                "The installed classic firewall cannot configure default inbound "
                "or outbound actions. Omit the action options."
            )
        if "not_configured" in actions:
            raise FirewallUnavailableError(
                "The installed firewall policy API supports allow/block actions "
                "but cannot restore a NotConfigured action."
            )

    def _profile(self, cleanup, name):
        if name not in self.available_profiles:
            raise ValueError("Unknown installed Windows Firewall profile: " + str(name))
        if not self._classic:
            return self._policy, [ctypes.c_int32], [1 << PROFILES.index(name)]
        pointer = ctypes.c_void_p()
        cleanup.callback(_release, pointer)
        _check(
            _method(
                self._policy,
                8,
                ctypes.c_int32,
                [ctypes.c_int32, ctypes.POINTER(ctypes.c_void_p)],
            )(self._policy, 0, ctypes.byref(pointer)),
            "INetFwPolicy.GetProfileByType(Domain)",
        )
        return pointer, [], []

    def read(self, name):
        """Read genuine local policy values without synthesizing an unset enum.

        :param str name: Public name present in ``available_profiles``.
        :returns: Name, integer enabled state and concrete or absent actions.
        :rtype: dict
        :raises OSError: A native getter fails or returns an invalid value.
        """
        with ExitStack() as cleanup:
            pointer, argument_types, arguments = self._profile(cleanup, name)
            enabled = ctypes.c_int16()
            _check(
                _method(
                    pointer,
                    8,
                    ctypes.c_int32,
                    argument_types + [ctypes.POINTER(ctypes.c_int16)],
                )(pointer, *(arguments + [ctypes.byref(enabled)])),
                "Windows Firewall.get_FirewallEnabled",
            )
            if enabled.value not in (0, -1):
                raise OSError("Windows Firewall returned an invalid enabled boolean.")
            row = {
                "Name": name,
                "Enabled": int(enabled.value != 0),
                "DefaultInboundAction": None,
                "DefaultOutboundAction": None,
            }
            if not self._classic:
                for property_name, slot in (
                    ("DefaultInboundAction", 23),
                    ("DefaultOutboundAction", 25),
                ):
                    action = ctypes.c_int32()
                    _check(
                        _method(
                            pointer,
                            slot,
                            ctypes.c_int32,
                            argument_types + [ctypes.POINTER(ctypes.c_int32)],
                        )(pointer, *(arguments + [ctypes.byref(action)])),
                        "INetFwPolicy2.get_" + property_name,
                    )
                    if action.value not in (0, 1):
                        raise OSError(
                            "Windows Firewall returned an invalid default action."
                        )
                    row[property_name] = 4 if action.value == 0 else 2
            return row

    def set_property(self, profile, name, value):
        """Write one setting the installed policy interface can represent.

        :param dict profile: Previously read profile with its public name.
        :param str name: Enabled or an available default-action property.
        :param int value: A supported public integer enum, never NotConfigured.
        :raises ValueError: The profile, property or value is unavailable.
        :raises OSError: The native setter fails.
        """
        allowed = {"Enabled": (0, 1)}
        if not self._classic:
            allowed.update(DefaultInboundAction=(2, 4), DefaultOutboundAction=(2, 4))
        if (
            isinstance(value, bool)
            or not isinstance(value, int)
            or value not in allowed.get(name, ())
        ):
            raise ValueError(
                "The installed firewall cannot represent this " + name + " value."
            )
        slot = {"Enabled": 9, "DefaultInboundAction": 24, "DefaultOutboundAction": 26}[
            name
        ]
        value_type = ctypes.c_int16 if name == "Enabled" else ctypes.c_int32
        native_value = (
            (-1 if value == 1 else 0) if name == "Enabled" else (1 if value == 2 else 0)
        )
        with ExitStack() as cleanup:
            pointer, argument_types, arguments = self._profile(cleanup, profile["Name"])
            _check(
                _method(pointer, slot, ctypes.c_int32, argument_types + [value_type])(
                    pointer, *(arguments + [native_value])
                ),
                "Windows Firewall.put_" + name,
            )


class FirewallProfiles:
    """Own available local settings, preferring the configured-profile provider.

    WMI preserves ``NotConfigured`` enums. Older policy interfaces expose local
    booleans and concrete actions, not effective group-policy overrides. Only
    genuinely available public names appear in ``available_profiles``.
    """

    def __init__(self):
        self.available_profiles = PROFILES
        self._connection = WmiConnection(r"ROOT\StandardCimv2")
        self._com = None

    def __enter__(self):
        entered = False
        try:
            self._connection.__enter__()
            entered = True
            self._connection.query("SELECT Name FROM MSFT_NetFirewallProfile", ["Name"])
        except (OSError, ValueError) as error:
            if entered:
                self._connection.__exit__(type(error), error, error.__traceback__)
            if getattr(error, "hresult", None) not in (0x8004100E, 0x80041010):
                raise
            self._com = _ComProfiles()
            self._com.__enter__()
            self.available_profiles = self._com.available_profiles
        return self

    def __exit__(self, exc_type, exc_value, traceback):
        if self._com is not None:
            return self._com.__exit__(exc_type, exc_value, traceback)
        return self._connection.__exit__(exc_type, exc_value, traceback)

    def validate_request(self, parameters):
        """Reject settings absent from the installed API before any profile write.

        :param dict parameters: Validated public profile/state/action arguments.
        :raises FirewallUnavailableError: The installed API cannot represent them.
        """
        if self._com is not None:
            self._com.validate_request(parameters)

    def read(self, profile):
        """Read one named profile's local enabled state and available actions.

        :param str profile: Domain, Private, or Public.
        :returns: Name and integer enums; absent actions are null. WMI also
            supplies the native instance path used by its setter.
        :rtype: dict
        :raises ValueError: The profile name is not supported.
        :raises OSError: The provider fails or returns an invalid profile.
        """
        if profile not in PROFILES:
            raise ValueError("Unknown Windows Firewall profile: " + str(profile))
        if self._com is not None:
            return self._com.read(profile)
        rows = self._connection.query(
            "SELECT * FROM MSFT_NetFirewallProfile WHERE Name='" + profile + "'",
            list(_PROPERTIES) + ["__PATH"],
        )
        if len(rows) != 1 or rows[0].get("Name") != profile:
            raise OSError(
                "Windows Firewall returned no unique " + profile + " profile."
            )
        row = rows[0]
        if not isinstance(row.get("__PATH"), str) or not row["__PATH"]:
            raise OSError("Windows Firewall returned no native profile identity.")
        for name, allowed in _ENUM_VALUES.items():
            value = row.get(name)
            if (
                isinstance(value, bool)
                or not isinstance(value, int)
                or value not in allowed
            ):
                raise OSError("Windows Firewall returned an invalid " + name + " enum.")
        return row

    def set_property(self, profile, name, value):
        """Update exactly one supported enum on a previously read profile.

        :param dict profile: Native profile returned by :meth:`read`.
        :param str name: Enabled, DefaultInboundAction, or DefaultOutboundAction.
        :param int value: Configured enum value, including NotConfigured.
        :raises ValueError: The property, value, or profile identity is invalid.
        :raises OSError: The native API cannot update the local profile.
        """
        if self._com is not None:
            self._com.set_property(profile, name, value)
            return
        if (
            name not in _ENUM_VALUES
            or isinstance(value, bool)
            or not isinstance(value, int)
            or value not in _ENUM_VALUES[name]
        ):
            raise ValueError("Invalid configured firewall enum: " + str(name))
        if profile.get("Name") not in PROFILES or not profile.get("__PATH"):
            raise ValueError(
                "A configured firewall update requires a native profile identity."
            )
        self._connection.set_integer_property(profile["__PATH"], name, value)
