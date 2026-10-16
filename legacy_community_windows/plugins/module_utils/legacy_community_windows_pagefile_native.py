# -*- coding: utf-8 -*-
# Copyright 2026 sustainablelobster
# SPDX-License-Identifier: GPL-3.0-or-later

"""Read and configure the installed Win32 pagefile provider and its settings."""

import ctypes
import re
import uuid
from contextlib import ExitStack

try:
    import winreg
except ImportError:
    winreg = None

from legacy_windows_wmi import (  # pylint: disable=import-error
    WmiConnection,
    _bstr,
    _check,
    _get_object,
    _Guid,
    _libraries,
    _method,
    _put_boolean,
    _put_integer,
    _put_string,
    _release,
    _Variant,
)

_POINTER = ctypes.c_void_p
_LONG = ctypes.c_int32
_PROPERTIES = ("__PATH", "Name", "InitialSize", "MaximumSize", "Caption", "Description")
_MEMORY_KEY = r"SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management"


# These provider writes intentionally reuse the shared connection's native
# handles and ABI functions; keeping ownership with it avoids a second client.
# pylint: disable=protected-access


def _save(connection, instance, flags, context=None):
    _check(
        _method(
            connection._services,
            14,
            _LONG,
            [
                _POINTER,
                _LONG,
                _POINTER,
                ctypes.POINTER(_POINTER),
            ],
        )(connection._services, instance, flags, context, None),
        "IWbemServices.PutInstance(pagefile)",
    )


def _automatic_context(connection, cleanup):
    # Submit only the requested property. A whole ComputerSystem update also
    # writes unrelated privileged settings and can fail after changing pagefiles.
    # This is WMI's documented partial-instance update, not a provider workaround.
    ole, automation = _libraries()
    context = _POINTER()
    cleanup.callback(_release, context)
    class_id = _Guid.from_buffer_copy(
        uuid.UUID("674b6698-ee92-11d0-ad71-00c04fd8fdff").bytes_le
    )
    interface_id = _Guid.from_buffer_copy(
        uuid.UUID("44aca674-e8fc-11d0-a07c-00c04fb68820").bytes_le
    )
    _check(
        ole.CoCreateInstance(
            ctypes.byref(class_id),
            None,
            1,
            ctypes.byref(interface_id),
            ctypes.byref(context),
        ),
        "CoCreateInstance(IWbemContext)",
    )
    set_value = _method(
        context, 8, _LONG, [ctypes.c_wchar_p, _LONG, ctypes.POINTER(_Variant)]
    )
    enabled = _Variant(kind=11)
    enabled.data.signed16 = -1
    for name in ("__PUT_EXTENSIONS", "__PUT_EXT_CLIENT_REQUEST"):
        _check(
            set_value(context, name, 0, ctypes.byref(enabled)),
            "IWbemContext.SetValue(" + name + ")",
        )
    properties = _Variant(kind=0x2008)
    try:
        properties.data.array = automation.SafeArrayCreateVector(8, 0, 1)
        if not properties.data.array:
            raise MemoryError("Could not allocate the pagefile property list")
        pointer = _bstr(connection._automation, cleanup, "AutomaticManagedPagefile")
        index = _LONG(0)
        _check(
            automation.SafeArrayPutElement(
                properties.data.array, ctypes.byref(index), pointer
            ),
            "SafeArrayPutElement(AutomaticManagedPagefile)",
        )
        _check(
            set_value(context, "__PUT_EXT_PROPERTIES", 0, ctypes.byref(properties)),
            "IWbemContext.SetValue(__PUT_EXT_PROPERTIES)",
        )
    finally:
        _check(automation.VariantClear(ctypes.byref(properties)), "VariantClear")
    return context


class Pagefiles:
    """Own a local pagefile provider for one management operation."""

    def __init__(self):
        self.connection = WmiConnection()
        self.automatic_supported = True
        self.computer = None

    def __enter__(self):
        self.connection.__enter__()
        return self

    def __exit__(self, *arguments):
        self.connection.__exit__(*arguments)

    def records(self):
        """Read configured pagefiles, retaining native instance identities.

        :returns: Native names, sizes, descriptions and instance paths.
        :rtype: list
        :raises OSError: The native pagefile provider cannot be queried.
        """
        return self.connection.query(
            "SELECT * FROM Win32_PageFileSetting", list(_PROPERTIES)
        )

    def automatic(self):
        """Read the global automatic mode if the installed provider exposes it.

        :returns: The actual automatic setting, or None when unavailable.
        :rtype: bool or None
        :raises OSError: A native error other than an absent property occurs.
        """
        try:
            self.computer = self.connection.query(
                "SELECT * FROM Win32_ComputerSystem",
                ["__PATH", "AutomaticManagedPagefile"],
            )[0]
        except OSError as error:
            if getattr(error, "hresult", None) != 0x80041002:
                raise
            self.automatic_supported = False
            return None
        return self.computer["AutomaticManagedPagefile"]

    def set_automatic(self, enabled):
        """Persist global automatic mode through the provider's boolean schema.

        :param bool enabled: Requested global setting.
        :raises ValueError: This property is unavailable in the installed provider.
        :raises OSError: Native property update fails.
        """
        if not self.automatic_supported:
            raise ValueError(
                "The installed Win32_ComputerSystem provider does not expose "
                "AutomaticManagedPagefile"
            )
        with ExitStack() as cleanup:
            connection = self.connection
            instance = _get_object(
                connection._services,
                connection._automation,
                cleanup,
                self.computer["__PATH"],
            )
            _put_boolean(
                instance, connection._automation, "AutomaticManagedPagefile", enabled
            )
            context = _automatic_context(connection, cleanup)
            _save(connection, instance, 1, context)

    def create(self, name):
        """Create a system-managed configuration and return its native record.

        :param str name: Full pagefile path.
        :returns: The created provider instance.
        :rtype: dict
        :raises OSError: Native creation or immediate readback fails.
        """
        connection = self.connection
        with ExitStack() as cleanup:
            definition = _get_object(
                connection._services,
                connection._automation,
                cleanup,
                "Win32_PageFileSetting",
            )
            instance = _POINTER()
            cleanup.callback(_release, instance)
            _check(
                _method(definition, 15, _LONG, [_LONG, ctypes.POINTER(_POINTER)])(
                    definition, 0, ctypes.byref(instance)
                ),
                "IWbemClassObject.SpawnInstance(pagefile)",
            )
            _put_string(instance, connection._automation, "Name", name)
            _save(connection, instance, 2)
        record = next(
            (
                record
                for record in self.records()
                if record["Name"].lower() == name.lower()
            ),
            None,
        )
        if record is None:
            raise OSError(
                "The pagefile provider did not return its newly created configuration"
            )
        return record

    def set_sizes(self, record, initial, maximum):
        """Update both pagefile sizes in one native provider write.

        :param dict record: Existing native instance returned by records().
        :param int initial: Initial size in megabytes.
        :param int maximum: Maximum size in megabytes.
        :raises OSError: The provider rejects or cannot save these sizes.
        """
        connection = self.connection
        with ExitStack() as cleanup:
            instance = _get_object(
                connection._services, connection._automation, cleanup, record["__PATH"]
            )
            for field, value in (("InitialSize", initial), ("MaximumSize", maximum)):
                _put_integer(instance, connection._automation, field, value)
            _save(connection, instance, 1)

    def delete(self, record):
        """Remove an existing pagefile configuration through its exact WMI path.

        :param dict record: Existing native provider instance.
        :raises OSError: The provider cannot delete this configuration.
        """
        connection = self.connection
        with ExitStack() as cleanup:
            _check(
                _method(
                    connection._services,
                    16,
                    _LONG,
                    [
                        _POINTER,
                        _LONG,
                        _POINTER,
                        ctypes.POINTER(_POINTER),
                    ],
                )(
                    connection._services,
                    _bstr(connection._automation, cleanup, record["__PATH"]),
                    0,
                    None,
                    None,
                ),
                "IWbemServices.DeleteInstance(pagefile)",
            )


# pylint: enable=protected-access


def registry_sizes(name, initial, maximum):
    """Use the released registry workaround when the size provider rejects a write.

    :param str name: Full pagefile path.
    :param int initial: Initial size in megabytes.
    :param int maximum: Maximum size in megabytes.
    :raises OSError: Native registry access or update fails.
    :raises ValueError: PagingFiles is not its required multi-string type.
    """
    with winreg.OpenKey(
        winreg.HKEY_LOCAL_MACHINE,
        _MEMORY_KEY,
        0,
        winreg.KEY_QUERY_VALUE | winreg.KEY_SET_VALUE,
    ) as key:
        values, kind = winreg.QueryValueEx(key, "PagingFiles")
        if kind != winreg.REG_MULTI_SZ or not isinstance(values, list):
            raise ValueError(
                "Memory Management\\PagingFiles must be a REG_MULTI_SZ value"
            )
        retained = []
        for value in values:
            match = re.match(r'^"([^"]+)"|^(\S+)', value)
            path = next((part for part in match.groups() if part), "") if match else ""
            if path.lower() != name.lower():
                retained.append(value)
        retained.append("{0} {1} {2}".format(name, initial, maximum))
        winreg.SetValueEx(key, "PagingFiles", 0, kind, retained)
