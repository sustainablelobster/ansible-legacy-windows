# -*- coding: utf-8 -*-
# Copyright 2026 sustainablelobster
# SPDX-License-Identifier: GPL-3.0-or-later

"""Own native network configuration and adapter binding-path interfaces."""

import ctypes
import uuid
from contextlib import ExitStack

from legacy_windows_wmi import (  # pylint: disable=import-error
    _check,
    _Guid,
    _libraries,
    _method,
    _release,
)

_POINTER = ctypes.c_void_p
_LONG = ctypes.c_int32
_ULONG = ctypes.c_uint32
_ADAPTER_CLASS = "4d36e972-e325-11ce-bfc1-08002be10318"
_BINDINGS = "c0e8ae9e-306e-11d1-aacf-00805fc1270e"


def _guid(value):
    return _Guid.from_buffer_copy(uuid.UUID(value).bytes_le)


def _connection_name(identifier):
    import winreg  # pylint: disable=import-outside-toplevel,import-error

    path = (
        "SYSTEM\\CurrentControlSet\\Control\\Network\\{"
        + _ADAPTER_CLASS
        + "}\\{"
        + identifier
        + "}\\Connection"
    )
    try:
        with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, path) as key:
            return winreg.QueryValueEx(key, "Name")[0]
    except OSError as error:
        if getattr(error, "winerror", None) == 2:
            return None
        raise


class NetworkBindings:
    """Hold the native configuration lock and the binding paths being managed.

    :param bool writable: Acquire the system network configuration write lock.
    """

    def __init__(self, writable):
        self.writable = writable
        self.cleanup = None
        self.ole = None
        self.configuration = None
        self.lock = None
        self.pending = False

    def __enter__(self):
        self.ole, _automation = _libraries()
        self.ole.CoTaskMemFree.argtypes = [_POINTER]
        self.ole.CoTaskMemFree.restype = None
        with ExitStack() as cleanup:
            self.cleanup = cleanup
            initialized = self.ole.CoInitializeEx(None, 2)
            if initialized & 0xFFFFFFFF != 0x80010106:
                _check(initialized, "CoInitializeEx(network bindings)")
                cleanup.callback(self.ole.CoUninitialize)
            self.configuration = self._owned_pointer()
            _check(
                self.ole.CoCreateInstance(
                    ctypes.byref(_guid("5b035261-40f9-11d1-aaec-00805fc1270e")),
                    None,
                    1,
                    ctypes.byref(_guid("c0e8ae93-306e-11d1-aacf-00805fc1270e")),
                    ctypes.byref(self.configuration),
                ),
                "CoCreateInstance(network configuration)",
            )
            if self.writable:
                self.lock = self._interface(
                    self.configuration, "c0e8ae9f-306e-11d1-aacf-00805fc1270e"
                )
                self._acquire_lock()
                cleanup.callback(self._call, self.lock, 4, ())
            self._call(self.configuration, 3, [_POINTER], None)
            cleanup.callback(self._call, self.configuration, 4, ())
            self.cleanup = cleanup.pop_all()
        return self

    def __exit__(self, *arguments):
        try:
            if self.pending:
                self._call(self.configuration, 6, ())
        finally:
            self.cleanup.__exit__(*arguments)

    def _owned_pointer(self):
        pointer = _POINTER()
        self.cleanup.callback(_release, pointer)
        return pointer

    @staticmethod
    def _call(pointer, slot, argument_types, *arguments):
        result = _method(pointer, slot, _LONG, argument_types)(pointer, *arguments)
        _check(result, "Network configuration method " + str(slot))
        return result

    def _object(self, pointer, slot, argument_types, *arguments):
        value = self._owned_pointer()
        self._call(
            pointer,
            slot,
            list(argument_types) + [ctypes.POINTER(_POINTER)],
            *(tuple(arguments) + (ctypes.byref(value),))
        )
        return value

    def _interface(self, pointer, identifier):
        return self._object(
            pointer, 0, [ctypes.POINTER(_Guid)], ctypes.byref(_guid(identifier))
        )

    def _string(self, pointer, slot):
        value = _POINTER()
        try:
            self._call(pointer, slot, [ctypes.POINTER(_POINTER)], ctypes.byref(value))
            return ctypes.wstring_at(value) if value else ""
        finally:
            self.ole.CoTaskMemFree(value)

    def _instance_id(self, pointer):
        value = _Guid()
        self._call(pointer, 8, [ctypes.POINTER(_Guid)], ctypes.byref(value))
        return str(uuid.UUID(bytes_le=bytes(value)))

    def _enumerate(self, enumerator):
        while True:
            value, fetched = self._owned_pointer(), _ULONG()
            result = self._call(
                enumerator,
                3,
                [_ULONG, ctypes.POINTER(_POINTER), ctypes.POINTER(_ULONG)],
                1,
                ctypes.byref(value),
                ctypes.byref(fetched),
            )
            if result == 1 or not fetched.value:
                return
            if not value:
                raise OSError(
                    "Network configuration returned an empty enumerated object"
                )
            yield value

    def _acquire_lock(self):
        owner = _POINTER()
        try:
            result = self._call(
                self.lock,
                3,
                [_ULONG, ctypes.c_wchar_p, ctypes.POINTER(_POINTER)],
                10000,
                "sustainablelobster.legacy_community_windows.win_net_adapter_feature",
                ctypes.byref(owner),
            )
            if result == 1:
                name = ctypes.wstring_at(owner) if owner else "another application"
                raise OSError("Network configuration is locked by " + name)
        finally:
            self.ole.CoTaskMemFree(owner)

    def adapters(self):
        """Read connection names and native adapter instance identifiers.

        :returns: Connection name to instance GUID mapping.
        :rtype: dict
        :raises OSError: Network configuration or connection-name access fails.
        """
        enumerator = self._object(
            self.configuration,
            7,
            [ctypes.POINTER(_Guid)],
            ctypes.byref(_guid(_ADAPTER_CLASS)),
        )
        result = {}
        for component in self._enumerate(enumerator):
            identifier = self._instance_id(component)
            name = _connection_name(identifier)
            if name is not None:
                result[name] = identifier
        return result

    def paths(self, component_id, adapters):
        """Read a component's native paths terminating at the selected adapters.

        :param str component_id: Installed component's INF identifier.
        :param dict adapters: Connection names mapped to native instance GUIDs.
        :returns: Adapter names mapped to enabled-state/path-pointer records.
        :rtype: dict
        :raises ValueError: The component is not installed.
        :raises OSError: Native path enumeration fails.
        """
        component = self._object(
            self.configuration, 8, [ctypes.c_wchar_p], component_id
        )
        if not component:
            raise ValueError("Invalid componentID: " + component_id)
        bindings = self._interface(component, _BINDINGS)
        enumerator = self._object(bindings, 8, [_ULONG], 2)
        names = {identifier.lower(): name for name, identifier in adapters.items()}
        result = {name: [] for name in adapters}
        for path in self._enumerate(enumerator):
            interfaces = self._object(path, 10, ())
            for interface in self._enumerate(interfaces):
                lower = self._object(interface, 5, ())
                name = names.get(self._instance_id(lower).lower())
                if name is not None:
                    enabled = self._call(path, 5, ()) == 0
                    result[name].append({"pointer": path, "enabled": enabled})
                    break
        return result

    def enable(self, path, enabled):
        """Stage one binding-path state without applying unrelated settings.

        :param dict path: Path record returned by :meth:`paths`.
        :param bool enabled: Requested binding state.
        :raises OSError: Windows rejects the pending binding change.
        :raises ValueError: The configuration was opened read-only.
        """
        if not self.writable:
            raise ValueError("Network configuration was opened read-only")
        self.pending = True
        self._call(path["pointer"], 6, [_LONG], 1 if enabled else 0)

    def apply(self):
        """Commit pending binding changes through the native configuration API.

        :returns: Whether Windows reports that a restart is required.
        :rtype: bool
        :raises OSError: Windows rejects the configuration change.
        """
        result = self._call(self.configuration, 5, ())
        self.pending = False
        return result == 0x0004A020
