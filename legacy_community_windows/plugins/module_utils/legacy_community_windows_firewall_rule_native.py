# -*- coding: utf-8 -*-
# Copyright 2026 sustainablelobster
# SPDX-License-Identifier: GPL-3.0-or-later

"""Own advanced firewall rules or classic port/application exception interfaces."""

import ctypes
import uuid
from contextlib import ExitStack

from legacy_windows_wmi import (  # pylint: disable=import-error
    _check,
    _Guid,
    _libraries,
    _method,
    _release,
    _Variant,
)

_POINTER = ctypes.c_void_p
_LONG = ctypes.c_int32
_BOOL = ctypes.c_int16
_RULE_ID = "af230d27-baba-4e42-aced-f524f22cfce2"
_PORT_ID = "e0483ba0-47ff-4d9c-a6d6-7741d0b195f7"
_APPLICATION_ID = "b5e64ffa-c2c5-444e-a301-fb5e00018050"
_MODERN_FIELDS = {
    "Name": (7, _POINTER),
    "Description": (9, _POINTER),
    "ApplicationName": (11, _POINTER),
    "ServiceName": (13, _POINTER),
    "Protocol": (15, _LONG),
    "LocalPorts": (17, _POINTER),
    "RemotePorts": (19, _POINTER),
    "LocalAddresses": (21, _POINTER),
    "RemoteAddresses": (23, _POINTER),
    "IcmpTypesAndCodes": (25, _POINTER),
    "Direction": (27, _LONG),
    "InterfaceTypes": (31, _POINTER),
    "Enabled": (33, _BOOL),
    "Grouping": (35, _POINTER),
    "Profiles": (37, _LONG),
    "Action": (41, _LONG),
}
_PORT_FIELDS = {
    "Name": (7, _POINTER),
    "Protocol": (11, _LONG),
    "LocalPorts": (13, _LONG),
    "RemoteAddresses": (17, _POINTER),
    "Enabled": (19, _BOOL),
}
_APPLICATION_FIELDS = {
    "Name": (7, _POINTER),
    "ApplicationName": (9, _POINTER),
    "RemoteAddresses": (15, _POINTER),
    "Enabled": (17, _BOOL),
}


def _guid(value):
    return _Guid.from_buffer_copy(uuid.UUID(value).bytes_le)


def _text(automation, pointer):
    if not pointer:
        return None
    return ctypes.string_at(pointer, automation.SysStringLen(pointer) * 2).decode(
        "utf-16-le", "surrogatepass"
    )


def _bstr(automation, cleanup, text):
    if text is None:
        return None
    length = len(text.encode("utf-16-le", "surrogatepass")) // 2
    pointer = automation.SysAllocStringLen(text, length)
    if not pointer:
        raise MemoryError("Could not allocate a firewall string")
    cleanup.callback(automation.SysFreeString, pointer)
    return pointer


class _Rule:
    # Pointer ownership, native kind and collection/profile identity remain
    # explicit instead of being hidden in a second context data structure.
    def __init__(  # pylint: disable=too-many-arguments,too-many-positional-arguments
        self, owner, pointer, kind="modern", collection=None, profile=None
    ):
        self.owner, self.pointer, self.kind = owner, pointer, kind
        self.collection, self.profile = collection, profile
        self.fields = dict(
            {
                "modern": _MODERN_FIELDS,
                "port": _PORT_FIELDS,
                "application": _APPLICATION_FIELDS,
            }[kind]
        )
        self.extensions = {}
        if kind == "modern":
            for field, identifier, slot in (
                ("EdgeTraversalOptions", "9c27c8da-189b-4dde-89f7-8b39a316782c", 43),
                ("SecureFlags", "b21563ff-d696-4222-ab46-4e89b73ab34a", 55),
            ):
                try:
                    self.extensions[field] = owner.interface(pointer, identifier)
                    self.fields[field] = (slot, _LONG)
                except OSError as error:
                    if getattr(error, "hresult", None) != 0x80004002:
                        raise

    # These private property wrappers directly mirror typed native getters and
    # setters; repeating ceremonial docstrings would obscure their mappings.
    # pylint: disable=missing-function-docstring,missing-return-doc,missing-return-type-doc
    def get(self, field):
        if field not in self.fields:
            defaults = {
                "Direction": 1,
                "Action": 1,
                "Protocol": 256,
                "Profiles": 1 if self.profile == 0 else 6,
                "LocalAddresses": "*",
                "LocalPorts": "*",
                "RemotePorts": "*",
                "InterfaceTypes": "All",
                "EdgeTraversalOptions": 0,
                "SecureFlags": 0,
            }
            return defaults.get(field)
        slot, kind = self.fields[field]
        value = kind()
        pointer = self.extensions.get(field, self.pointer)
        _check(
            _method(pointer, slot, _LONG, [ctypes.POINTER(kind)])(
                pointer, ctypes.byref(value)
            ),
            "Firewall.get_" + field,
        )
        if kind is _POINTER:
            try:
                return _text(self.owner.automation, value)
            finally:
                self.owner.automation.SysFreeString(value)
        if kind is _BOOL:
            return bool(value.value)
        return str(value.value) if field == "LocalPorts" else value.value

    def put(self, field, value):
        slot, kind = self.fields[field]
        pointer = self.extensions.get(field, self.pointer)
        with ExitStack() as cleanup:
            encoded = (
                _bstr(self.owner.automation, cleanup, value)
                if kind is _POINTER
                else (-1 if value else 0) if kind is _BOOL else int(value)
            )
            if kind is _LONG:
                if (
                    self.kind == "port"
                    and field == "LocalPorts"
                    and not 1 <= encoded <= 65535
                ):
                    raise ValueError(
                        "Classic localport must be one integer from 1 through 65535"
                    )
                if not -(2**31) <= encoded < 2**31:
                    raise ValueError(field + " must fit a signed 32-bit integer")
            _check(
                _method(pointer, slot + 1, _LONG, [kind])(pointer, encoded),
                "Firewall.put_" + field,
            )

    # pylint: enable=missing-function-docstring,missing-return-doc,missing-return-type-doc


class FirewallRules:
    """Own the installed firewall's rules without changing profile enablement."""

    def __init__(self):
        self.cleanup = None
        self.ole, self.automation = None, None
        self.policy, self.collection = None, None
        self.classic = False

    def __enter__(self):
        self.ole, self.automation = _libraries()
        with ExitStack() as cleanup:
            self.cleanup = cleanup
            initialized = self.ole.CoInitializeEx(None, 2)
            if initialized & 0xFFFFFFFF != 0x80010106:
                _check(initialized, "CoInitializeEx(firewall rules)")
                cleanup.callback(self.ole.CoUninitialize)
            try:
                self.policy = self.create(
                    "e2b3c97f-6ae1-41ac-817a-f6f92166d7dd",
                    "98325047-c671-4174-8d81-defcd3f03186",
                )
                self.collection = self.object_property(self.policy, 18)
            except OSError as error:
                if getattr(error, "hresult", None) not in (0x80040154, 0x80004002):
                    raise
                manager = self.create(
                    "304ce942-6e39-40d8-943a-b913c40c9cd4",
                    "f7898af5-cac4-4632-a2ec-da06e5111af2",
                )
                self.policy = self.object_property(manager, 7)
                self.classic = True
            self.cleanup = cleanup.pop_all()
        return self

    def __exit__(self, *arguments):
        self.cleanup.__exit__(*arguments)

    def create(self, class_id, interface_id):
        """Create one typed firewall object, retaining it until context exit.

        :param str class_id: Published firewall coclass identifier.
        :param str interface_id: Published requested interface identifier.
        :returns: Owned typed COM pointer.
        :rtype: ctypes.c_void_p
        :raises OSError: The native object is unavailable or creation fails.
        """
        pointer = _POINTER()
        self.cleanup.callback(_release, pointer)
        _check(
            self.ole.CoCreateInstance(
                ctypes.byref(_guid(class_id)),
                None,
                1,
                ctypes.byref(_guid(interface_id)),
                ctypes.byref(pointer),
            ),
            "CoCreateInstance(firewall rule)",
        )
        return pointer

    def interface(self, pointer, identifier):
        """Retain a requested native interface until the owning context exits.

        :param pointer: Existing COM pointer.
        :type pointer: ctypes.c_void_p
        :param str identifier: Native interface identifier.
        :returns: Owned typed interface.
        :rtype: ctypes.c_void_p
        :raises OSError: The installed object does not expose this interface.
        """
        value = _POINTER()
        self.cleanup.callback(_release, value)
        _check(
            _method(
                pointer, 0, _LONG, [ctypes.POINTER(_Guid), ctypes.POINTER(_POINTER)]
            )(pointer, ctypes.byref(_guid(identifier)), ctypes.byref(value)),
            "Firewall.QueryInterface",
        )
        return value

    def object_property(self, pointer, slot, profile=None):
        """Read one owned object property, optionally indexed by classic profile.

        :param pointer: Existing native object.
        :type pointer: ctypes.c_void_p
        :param int slot: SDK vtable slot.
        :param profile: Optional Domain/Standard index.
        :type profile: int or None
        :returns: Owned property interface pointer.
        :rtype: ctypes.c_void_p
        :raises OSError: The native property is unavailable.
        """
        value = _POINTER()
        self.cleanup.callback(_release, value)
        arguments = [] if profile is None else [profile]
        types = [] if profile is None else [_LONG]
        _check(
            _method(pointer, slot, _LONG, types + [ctypes.POINTER(_POINTER)])(
                pointer, *(arguments + [ctypes.byref(value)])
            ),
            "Firewall.object_property",
        )
        return value

    def _items(self, collection, identifier):
        enumeration = self.interface(
            self.object_property(collection, 11), "00020404-0000-0000-c000-000000000046"
        )
        values = []
        while True:
            value, fetched = _Variant(), ctypes.c_uint32()
            try:
                _check(
                    _method(
                        enumeration,
                        3,
                        _LONG,
                        [
                            ctypes.c_uint32,
                            ctypes.POINTER(_Variant),
                            ctypes.POINTER(ctypes.c_uint32),
                        ],
                    )(enumeration, 1, ctypes.byref(value), ctypes.byref(fetched)),
                    "IEnumVARIANT.Next(firewall)",
                )
                if not fetched.value:
                    return values
                if value.kind not in (9, 13):
                    raise ValueError(
                        "The firewall enumerator returned a non-object rule"
                    )
                values.append(self.interface(value.data.bstr, identifier))
            finally:
                self.automation.VariantClear(ctypes.byref(value))

    def records(self):
        """Read actual advanced rules or all classic port/application exceptions.

        :returns: Owned property-access objects in native enumeration order.
        :rtype: list
        :raises OSError: Firewall enumeration or interface access fails.
        :raises ValueError: A native collection contains an invalid object.
        """
        if not self.classic:
            return [
                _Rule(self, pointer, collection=self.collection)
                for pointer in self._items(self.collection, _RULE_ID)
            ]
        result = []
        for profile in (0, 1):
            pointer = self.object_property(self.policy, 8, profile)
            for kind, slot, identifier in (
                ("port", 18, _PORT_ID),
                ("application", 20, _APPLICATION_ID),
            ):
                collection = self.object_property(pointer, slot)
                result.extend(
                    _Rule(self, entry, kind, collection, profile)
                    for entry in self._items(collection, identifier)
                )
        return result

    def new(self, kind="modern", profile=None):
        """Create a detached rule or exception, without adding it to policy.

        :param str kind: Modern, port or application rule facility.
        :param profile: Classic profile index when applicable.
        :type profile: int or None
        :returns: Detached native rule.
        :rtype: _Rule
        :raises OSError: The native rule object cannot be created.
        """
        definitions = {
            "modern": ("2c5bc43e-3369-4c33-ab0c-be9469677af4", _RULE_ID),
            "port": ("0ca545c6-37ad-4a6c-bf92-9f7610067ef5", _PORT_ID),
            "application": ("ec9846b3-2762-4a6b-a214-6acb603462d2", _APPLICATION_ID),
        }
        collection = self.collection
        if kind != "modern":
            pointer = self.object_property(self.policy, 8, profile)
            collection = self.object_property(pointer, 18 if kind == "port" else 20)
        return _Rule(self, self.create(*definitions[kind]), kind, collection, profile)

    def add(self, rule):
        """Add one validated detached rule to its selected policy collection.

        :param _Rule rule: Detached rule returned by new().
        :raises OSError: Native policy rejects the rule or the caller's access.
        """
        _check(
            _method(rule.collection, 8, _LONG, [_POINTER])(
                rule.collection, rule.pointer
            ),
            "Firewall.Rules.Add",
        )

    def remove(self, rule):
        """Remove the exact native key for a previously enumerated rule.

        :param _Rule rule: Existing native rule to remove.
        :raises OSError: The native collection cannot remove the rule.
        """
        with ExitStack() as cleanup:
            if rule.kind == "port":
                values, types = [int(rule.get("LocalPorts")), rule.get("Protocol")], [
                    _LONG,
                    _LONG,
                ]
            else:
                field = "ApplicationName" if rule.kind == "application" else "Name"
                values, types = [_bstr(self.automation, cleanup, rule.get(field))], [
                    _POINTER
                ]
            _check(
                _method(rule.collection, 9, _LONG, types)(rule.collection, *values),
                "Firewall.Rules.Remove",
            )
