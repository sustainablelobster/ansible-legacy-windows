# -*- coding: utf-8 -*-
# Copyright 2026 sustainablelobster
# SPDX-License-Identifier: GPL-3.0-or-later

"""Read local WMI scalars, string arrays, and embedded-object properties."""

import ctypes
import datetime
import os
import uuid
from contextlib import ExitStack

_POINTER = ctypes.c_void_p
_LONG = ctypes.c_int32
_ULONG = ctypes.c_uint32
_POINTER_OUT = ctypes.POINTER(_POINTER)


# These are native ABI layouts, not objects with public operations.
# pylint: disable=too-few-public-methods
class _Guid(ctypes.Structure):
    _fields_ = [
        ("data1", ctypes.c_uint32),
        ("data2", ctypes.c_uint16),
        ("data3", ctypes.c_uint16),
        ("data4", ctypes.c_ubyte * 8),
    ]


class _VariantData(ctypes.Union):
    # The record pair determines the union's size on 64-bit Windows; the
    # 64-bit integer preserves its alignment and size on 32-bit Windows.
    _fields_ = [
        ("bstr", _POINTER),
        ("array", _POINTER),
        ("integer", ctypes.c_int64),
        ("signed32", _LONG),
        ("unsigned32", _ULONG),
        ("signed16", ctypes.c_int16),
        ("unsigned16", ctypes.c_uint16),
        ("byte", ctypes.c_ubyte),
        ("record", _POINTER * 2),
    ]


class _Variant(ctypes.Structure):
    _fields_ = [
        ("kind", ctypes.c_uint16),
        ("reserved", ctypes.c_uint16 * 3),
        ("data", _VariantData),
    ]


# pylint: enable=too-few-public-methods


def _libraries():
    if os.name != "nt":
        raise OSError("Reading local WMI requires Windows.")
    ole32 = ctypes.WinDLL("ole32")
    automation = ctypes.WinDLL("oleaut32")
    ole32.CoInitializeEx.argtypes = [_POINTER, _ULONG]
    ole32.CoInitializeEx.restype = _LONG
    ole32.CoUninitialize.argtypes = []
    ole32.CoUninitialize.restype = None
    ole32.CoInitializeSecurity.argtypes = [
        _POINTER,
        _LONG,
        _POINTER,
        _POINTER,
        _ULONG,
        _ULONG,
        _POINTER,
        _ULONG,
        _POINTER,
    ]
    ole32.CoInitializeSecurity.restype = _LONG
    ole32.CoCreateInstance.argtypes = [
        ctypes.POINTER(_Guid),
        _POINTER,
        _ULONG,
        ctypes.POINTER(_Guid),
        _POINTER_OUT,
    ]
    ole32.CoCreateInstance.restype = _LONG
    ole32.CoSetProxyBlanket.argtypes = [
        _POINTER,
        _ULONG,
        _ULONG,
        ctypes.c_wchar_p,
        _ULONG,
        _ULONG,
        _POINTER,
        _ULONG,
    ]
    ole32.CoSetProxyBlanket.restype = _LONG
    automation.SysAllocString.argtypes = [ctypes.c_wchar_p]
    automation.SysAllocString.restype = _POINTER
    automation.SysAllocStringLen.argtypes = [ctypes.c_wchar_p, _ULONG]
    automation.SysAllocStringLen.restype = _POINTER
    automation.SysFreeString.argtypes = [_POINTER]
    automation.SysFreeString.restype = None
    automation.SysStringLen.argtypes = [_POINTER]
    automation.SysStringLen.restype = _ULONG
    automation.VariantClear.argtypes = [ctypes.POINTER(_Variant)]
    automation.VariantClear.restype = _LONG
    automation.SafeArrayCreateVector.argtypes = [ctypes.c_uint16, _LONG, _ULONG]
    automation.SafeArrayCreateVector.restype = _POINTER
    automation.SafeArrayDestroy.argtypes = [_POINTER]
    automation.SafeArrayDestroy.restype = _LONG
    automation.SafeArrayGetDim.argtypes = [_POINTER]
    automation.SafeArrayGetDim.restype = _ULONG
    for name in ("SafeArrayGetLBound", "SafeArrayGetUBound"):
        function = getattr(automation, name)
        function.argtypes = [_POINTER, _ULONG, ctypes.POINTER(_LONG)]
        function.restype = _LONG
    automation.SafeArrayGetElement.argtypes = [
        _POINTER,
        ctypes.POINTER(_LONG),
        _POINTER_OUT,
    ]
    automation.SafeArrayGetElement.restype = _LONG
    automation.SafeArrayPutElement.argtypes = [
        _POINTER,
        ctypes.POINTER(_LONG),
        _POINTER,
    ]
    automation.SafeArrayPutElement.restype = _LONG
    return ole32, automation


def _check(result, operation):
    if result & 0x80000000:
        error = OSError(
            "{0} failed (HRESULT 0x{1:08X}).".format(operation, result & 0xFFFFFFFF)
        )
        error.hresult = result & 0xFFFFFFFF
        raise error


def _method(interface, slot, result_type, argument_types):
    table = ctypes.cast(interface, ctypes.POINTER(ctypes.POINTER(_POINTER)))[0]
    prototype = ctypes.WINFUNCTYPE(result_type, _POINTER, *argument_types)
    return prototype(table[slot])


def _release(interface):
    if interface:
        _method(interface, 2, _ULONG, [])(interface)


def _bstr(automation, cleanup, value):
    pointer = automation.SysAllocString(value)
    if not pointer:
        raise MemoryError("Could not allocate the WMI query string.")
    cleanup.callback(automation.SysFreeString, pointer)
    return pointer


def _connect(ole32, automation, cleanup, namespace, dynamic_cloaking=False):
    locator = _POINTER()
    cleanup.callback(_release, locator)
    class_id = _Guid.from_buffer_copy(
        uuid.UUID("4590f811-1d3a-11d0-891f-00aa004b2e24").bytes_le
    )
    interface_id = _Guid.from_buffer_copy(
        uuid.UUID("dc12a687-737f-11cf-884d-00aa004b2e24").bytes_le
    )
    _check(
        ole32.CoCreateInstance(
            ctypes.byref(class_id),
            None,
            1,
            ctypes.byref(interface_id),
            ctypes.byref(locator),
        ),
        "CoCreateInstance(WbemLocator)",
    )
    services = _POINTER()
    cleanup.callback(_release, services)
    connect = _method(
        locator,
        3,
        _LONG,
        [
            _POINTER,
            _POINTER,
            _POINTER,
            _POINTER,
            _LONG,
            _POINTER,
            _POINTER,
            _POINTER_OUT,
        ],
    )
    # Local namespace, current credentials, and WMI's bounded connection wait.
    _check(
        connect(
            locator,
            _bstr(automation, cleanup, namespace),
            None,
            None,
            None,
            0x80,
            None,
            None,
            ctypes.byref(services),
        ),
        "IWbemLocator.ConnectServer",
    )
    # NTLM authentication, call-level protection, and impersonation are the
    # documented WMI client proxy settings; no credentials are stored here.
    # Opt-in dynamic cloaking uses the calling thread's current token per call,
    # without changing process-wide COM security or supplying explicit identity.
    _check(
        ole32.CoSetProxyBlanket(
            services, 10, 0, None, 3, 3, None, 0x40 if dynamic_cloaking else 0
        ),
        "CoSetProxyBlanket(IWbemServices)",
    )
    return services


def _query(services, automation, cleanup, query, flags):
    enumeration = _POINTER()
    cleanup.callback(_release, enumeration)
    execute = _method(
        services,
        20,
        _LONG,
        [_POINTER, _POINTER, _LONG, _POINTER, _POINTER_OUT],
    )
    _check(
        execute(
            services,
            _bstr(automation, cleanup, "WQL"),
            _bstr(automation, cleanup, query),
            flags,
            None,
            ctypes.byref(enumeration),
        ),
        "IWbemServices.ExecQuery",
    )
    return enumeration


# Distinct VARIANT conversions remain explicit while sharing native cleanup.
# pylint: disable-next=too-many-return-statements
def _read_property(instance, automation, name):
    value = _Variant()  # VT_EMPTY makes cleanup safe even when Get fails.
    cim_type = _LONG()
    get_value = _method(
        instance,
        4,
        _LONG,
        [
            ctypes.c_wchar_p,
            _LONG,
            ctypes.POINTER(_Variant),
            ctypes.POINTER(_LONG),
            ctypes.POINTER(_LONG),
        ],
    )
    try:
        _check(
            get_value(
                instance, name, 0, ctypes.byref(value), ctypes.byref(cim_type), None
            ),
            "IWbemClassObject.Get({0})".format(name),
        )
        if value.kind in (0, 1):  # VT_EMPTY, VT_NULL
            return None
        if value.kind == 8:  # VT_BSTR
            return (
                ctypes.wstring_at(
                    value.data.bstr, automation.SysStringLen(value.data.bstr)
                )
                if value.data.bstr
                else None
            )
        if value.kind == 0x2008:  # VT_ARRAY | VT_BSTR
            return _read_string_array(automation, value.data.array)
        if value.kind == 13:  # VT_UNKNOWN owns the embedded object's reference.
            return _read_embedded_object(automation, value.data.bstr)
        if value.kind == 0x200D:  # VT_ARRAY | VT_UNKNOWN
            return _read_embedded_array(automation, value.data.array)
        if value.kind == 3:  # WMI also packs CIM_UINT32 into VT_I4.
            if cim_type.value == 19:
                return value.data.unsigned32
            return value.data.signed32
        if value.kind == 11:  # VT_BOOL stores a signed 16-bit VARIANT_BOOL.
            return value.data.signed16 != 0
        integer_fields = {2: "signed16", 17: "byte", 18: "unsigned16", 19: "unsigned32"}
        if value.kind in integer_fields:
            return getattr(value.data, integer_fields[value.kind])
        raise ValueError(
            "WMI {0} has unsupported VARIANT type {1}.".format(name, value.kind)
        )
    finally:
        _check(automation.VariantClear(ctypes.byref(value)), "VariantClear")


def _read_string_array(automation, array):
    if not array:
        return []
    if automation.SafeArrayGetDim(array) != 1:
        raise ValueError("WMI string arrays must have one dimension.")
    lower, upper = _LONG(), _LONG()
    _check(
        automation.SafeArrayGetLBound(array, 1, ctypes.byref(lower)),
        "SafeArrayGetLBound",
    )
    _check(
        automation.SafeArrayGetUBound(array, 1, ctypes.byref(upper)),
        "SafeArrayGetUBound",
    )
    values = []
    for index in range(lower.value, upper.value + 1):
        position, text = _LONG(index), _POINTER()
        try:
            _check(
                automation.SafeArrayGetElement(
                    array, ctypes.byref(position), ctypes.byref(text)
                ),
                "SafeArrayGetElement",
            )
            values.append(
                ctypes.wstring_at(text, automation.SysStringLen(text.value))
                if text
                else ""
            )
        finally:
            if text:
                automation.SysFreeString(text.value)
    return values


def _read_embedded_object(automation, unknown):
    if not unknown:
        return None
    with ExitStack() as cleanup:
        instance = _POINTER()
        cleanup.callback(_release, instance)
        interface_id = _Guid.from_buffer_copy(
            uuid.UUID("dc12a681-737f-11cf-884d-00aa004b2e24").bytes_le
        )
        query_interface = _method(
            unknown, 0, _LONG, [ctypes.POINTER(_Guid), _POINTER_OUT]
        )
        _check(
            query_interface(
                unknown, ctypes.byref(interface_id), ctypes.byref(instance)
            ),
            "IUnknown.QueryInterface(IWbemClassObject)",
        )
        names = _POINTER()
        get_names = _method(
            instance,
            7,
            _LONG,
            [ctypes.c_wchar_p, _LONG, ctypes.POINTER(_Variant), _POINTER_OUT],
        )
        _check(
            get_names(instance, None, 0x40, None, ctypes.byref(names)),
            "IWbemClassObject.GetNames",
        )
        if names:
            cleanup.callback(automation.SafeArrayDestroy, names)
        # Keep the concrete embedded class so callers can read its metadata;
        # provider properties remain separate from WMI's other system fields.
        values = {"__CLASS": _read_property(instance, automation, "__CLASS")}
        for name in _read_string_array(automation, names.value):
            values[name] = _read_property(instance, automation, name)
        return values


def _read_embedded_array(automation, array):
    if not array:
        return []
    if automation.SafeArrayGetDim(array) != 1:
        raise ValueError("WMI embedded-object arrays must have one dimension.")
    lower, upper = _LONG(), _LONG()
    _check(
        automation.SafeArrayGetLBound(array, 1, ctypes.byref(lower)),
        "SafeArrayGetLBound",
    )
    _check(
        automation.SafeArrayGetUBound(array, 1, ctypes.byref(upper)),
        "SafeArrayGetUBound",
    )
    values = []
    for index in range(lower.value, upper.value + 1):
        position, unknown = _LONG(index), _POINTER()
        try:
            _check(
                automation.SafeArrayGetElement(
                    array, ctypes.byref(position), ctypes.byref(unknown)
                ),
                "SafeArrayGetElement",
            )
            values.append(_read_embedded_object(automation, unknown))
        finally:
            # SafeArrayGetElement AddRefs each interface; VariantClear still
            # owns the array and the references stored inside it.
            _release(unknown)
    return values


def _get_object(services, automation, cleanup, object_path):
    instance = _POINTER()
    cleanup.callback(_release, instance)
    get_object = _method(
        services, 6, _LONG, [_POINTER, _LONG, _POINTER, _POINTER_OUT, _POINTER]
    )
    _check(
        get_object(
            services,
            _bstr(automation, cleanup, object_path),
            0,
            None,
            ctypes.byref(instance),
            None,
        ),
        "IWbemServices.GetObject({0})".format(object_path),
    )
    if not instance:
        raise OSError("WMI returned no object for {0}.".format(object_path))
    return instance


def _put_boolean(instance, automation, name, enabled):
    value = _Variant(kind=11)  # VT_BOOL stores VARIANT_TRUE as -1, not C BOOL's 1.
    value.data.signed16 = -1 if enabled else 0
    put_value = _method(
        instance,
        5,
        _LONG,
        [ctypes.c_wchar_p, _LONG, ctypes.POINTER(_Variant), _LONG],
    )
    try:
        _check(
            put_value(instance, name, 0, ctypes.byref(value), 0),
            "IWbemClassObject.Put({0})".format(name),
        )
    finally:
        _check(automation.VariantClear(ctypes.byref(value)), "VariantClear")


def _put_string(instance, automation, name, text):
    # VT_NULL restores an originally unset property; VT_BSTR owns its text.
    value = _Variant(kind=1 if text is None else 8)
    try:
        if text is not None:
            units = len(text.encode("utf-16-le", "surrogatepass")) // 2
            value.data.bstr = automation.SysAllocStringLen(text, units)
            if not value.data.bstr:
                raise MemoryError("Could not allocate the WMI property string.")
        put_value = _method(
            instance,
            5,
            _LONG,
            [ctypes.c_wchar_p, _LONG, ctypes.POINTER(_Variant), _LONG],
        )
        _check(
            put_value(instance, name, 0, ctypes.byref(value), 0),
            "IWbemClassObject.Put({0})".format(name),
        )
    finally:
        _check(automation.VariantClear(ctypes.byref(value)), "VariantClear")


def _put_integer(instance, automation, name, number):
    # WMI represents CIM_UINT16 properties as VT_I4 too; VT_UI2 is rejected
    # by the measured Firewall provider before an instance can be saved.
    value = _Variant(kind=3)
    value.data.signed32 = number
    put_value = _method(
        instance,
        5,
        _LONG,
        [ctypes.c_wchar_p, _LONG, ctypes.POINTER(_Variant), _LONG],
    )
    try:
        _check(
            put_value(instance, name, 0, ctypes.byref(value), 0),
            "IWbemClassObject.Put({0})".format(name),
        )
    finally:
        _check(automation.VariantClear(ctypes.byref(value)), "VariantClear")


def _update_instance(services, instance):
    update = _method(
        services,
        14,
        _LONG,
        [_POINTER, _LONG, _POINTER, _POINTER_OUT],
    )
    _check(
        update(services, instance, 1, None, None),
        "IWbemServices.PutInstance",
    )


def _put_string_array(instance, automation, name, texts):
    value = _Variant(kind=0x2008)  # VariantClear owns the SAFEARRAY and its BSTRs.
    try:
        value.data.array = automation.SafeArrayCreateVector(8, 0, len(texts))
        if not value.data.array:
            raise MemoryError("Could not allocate the WMI string array.")
        for index, text in enumerate(texts):
            units = len(text.encode("utf-16-le", "surrogatepass")) // 2
            pointer = automation.SysAllocStringLen(text, units)
            if not pointer:
                raise MemoryError("Could not allocate a WMI string-array element.")
            try:
                position = _LONG(index)
                _check(
                    automation.SafeArrayPutElement(
                        value.data.array, ctypes.byref(position), pointer
                    ),
                    "SafeArrayPutElement",
                )
            finally:
                # SafeArrayPutElement copies the BSTR rather than taking ownership.
                automation.SysFreeString(pointer)
        put_value = _method(
            instance,
            5,
            _LONG,
            [ctypes.c_wchar_p, _LONG, ctypes.POINTER(_Variant), _LONG],
        )
        _check(
            put_value(instance, name, 0, ctypes.byref(value), 0),
            "IWbemClassObject.Put({0})".format(name),
        )
    finally:
        _check(automation.VariantClear(ctypes.byref(value)), "VariantClear")


def parse_datetime(value, property_name):
    """Parse a complete WMI DMTF timestamp, preserving its UTC offset.

    :param str value: Timestamp with microseconds and a numeric minute offset.
    :param str property_name: WMI property name for actionable errors.
    :returns: Offset-aware datetime with the reported microseconds.
    :rtype: datetime.datetime
    :raises ValueError: The value is not a complete, valid DMTF timestamp.
    """
    if not isinstance(value, str):
        raise ValueError("WMI {0} is not a datetime string.".format(property_name))
    digits = value[:14] + value[15:21] + value[22:]
    if (
        len(value) != 25
        or value[14] != "."
        or value[21] not in ("+", "-")
        or any(character < "0" or character > "9" for character in digits)
    ):
        raise ValueError(
            "WMI {0} is not a complete DMTF timestamp: {1!r}".format(
                property_name, value
            )
        )
    local = datetime.datetime(
        int(value[:4]),
        int(value[4:6]),
        int(value[6:8]),
        int(value[8:10]),
        int(value[10:12]),
        int(value[12:14]),
        int(value[15:21]),
    )
    offset = int(value[22:]) * (-1 if value[21] == "-" else 1)
    return local.replace(tzinfo=datetime.timezone(datetime.timedelta(minutes=offset)))


class WmiConnection:
    """Own a local WMI connection and its COM resources for one ``with`` block.

    :param str namespace: Local namespace used for queries and method calls.
    :param bool dynamic_cloaking: Use the calling thread's current token for each
        WMI service call. The default retains process-identity authentication.
        This setting changes only this connection's proxy, not global COM
        security. Keep the intended thread impersonation active during calls.
    :raises ValueError: The thread-identity setting is not a boolean.
    """

    def __init__(self, namespace="ROOT\\CIMV2", dynamic_cloaking=False):
        if not isinstance(dynamic_cloaking, bool):
            raise ValueError("WMI dynamic_cloaking must be a boolean.")
        self._namespace = namespace
        self._dynamic_cloaking = dynamic_cloaking
        self._cleanup = None
        self._services = None
        self._automation = None

    def __enter__(self):
        ole32, automation = _libraries()
        with ExitStack() as cleanup:
            initialized = ole32.CoInitializeEx(None, 0)
            # A pre-existing STA is usable too, but a failed initialization must
            # not decrement that caller's COM initialization count.
            if initialized & 0xFFFFFFFF != 0x80010106:  # RPC_E_CHANGED_MODE
                _check(initialized, "CoInitializeEx")
                cleanup.callback(ole32.CoUninitialize)
            security = ole32.CoInitializeSecurity(
                None, -1, None, None, 0, 3, None, 0, None
            )
            if security & 0xFFFFFFFF != 0x80010119:  # RPC_E_TOO_LATE
                _check(security, "CoInitializeSecurity")
            self._services = _connect(
                ole32, automation, cleanup, self._namespace, self._dynamic_cloaking
            )
            self._automation = automation
            self._cleanup = cleanup.pop_all()
        return self

    def __exit__(self, exc_type, exc_value, traceback):
        self._cleanup.close()
        self._services = None

    def query(self, query, properties):
        """Read selected properties in the provider's enumeration order.

        :param str query: WQL query for the connected namespace.
        :param properties: Sequence of string property names to retrieve.
        :type properties: list
        :returns: Dictionaries containing scalars, string lists, embedded-object
            dictionaries or lists, or None. Embedded dictionaries include
            ``__CLASS`` and the object's non-system properties.
        :rtype: list
        :raises OSError: WMI cannot execute the query or retrieve a property.
        :raises ValueError: A property is not a supported VARIANT.
        :raises MemoryError: Allocation of a WMI query string fails.
        """
        rows = []
        with ExitStack() as cleanup:
            # A projected query otherwise returns a null __PATH. GetOwner
            # needs the locatable object identity, not just its selected fields.
            flags = 0x130 if "__PATH" in properties else 0x30
            enumeration = _query(
                self._services, self._automation, cleanup, query, flags
            )
            advance = _method(
                enumeration,
                4,
                _LONG,
                [_LONG, _ULONG, _POINTER_OUT, ctypes.POINTER(_ULONG)],
            )
            while True:
                with ExitStack() as row_cleanup:
                    instance, returned = _POINTER(), _ULONG()
                    row_cleanup.callback(_release, instance)
                    result = advance(
                        enumeration,
                        -1,
                        1,
                        ctypes.byref(instance),
                        ctypes.byref(returned),
                    )
                    _check(result, "IEnumWbemClassObject.Next")
                    if not returned.value:
                        break
                    if returned.value != 1 or not instance:
                        raise OSError("WMI returned an invalid enumeration result.")
                    rows.append(self._properties(instance, properties))
                    if result == 1:  # WBEM_S_FALSE can accompany the final object.
                        break
        return rows

    # Keep the existing input contract and make the empty-output opt-in explicit.
    def call_method(  # pylint: disable=too-many-arguments
        self, object_path, method_name, properties, inputs=None, *, allow_empty=False
    ):
        """Invoke a WMI method and read selected native property values.

        :param str object_path: WMI object path returned by a query.
        :param str method_name: Method defined by that object's WMI class.
        :param properties: Sequence of output property names to retrieve.
        :type properties: list
        :param inputs: Optional dictionary of input names to booleans, strings,
            string lists, or None. An empty dictionary supplies a default input
            object; None omits that object entirely.
        :type inputs: dict or None
        :param bool allow_empty: Permit a successful native call with no output
            object. Streaming DHCP methods use this shape for an empty result.
        :returns: Scalars, string lists, embedded-object dictionaries or lists,
            or None from the output object, or an empty dictionary when
            allow_empty permits a successful call without an output object.
        :rtype: dict
        :raises OSError: WMI cannot execute the method or retrieve its output.
        :raises ValueError: An input is not a supported scalar or string list,
            or an output property is not a supported VARIANT.
        :raises MemoryError: Allocation of a WMI method string fails.
        """
        with ExitStack() as cleanup:
            arguments = None
            if inputs is not None:
                arguments = self._method_inputs(
                    cleanup, object_path, method_name, inputs
                )
            output = _POINTER()
            cleanup.callback(_release, output)
            execute = _method(
                self._services,
                24,
                _LONG,
                [_POINTER, _POINTER, _LONG, _POINTER, _POINTER, _POINTER_OUT, _POINTER],
            )
            _check(
                execute(
                    self._services,
                    _bstr(self._automation, cleanup, object_path),
                    _bstr(self._automation, cleanup, method_name),
                    0,
                    None,
                    arguments,
                    ctypes.byref(output),
                    None,
                ),
                "IWbemServices.ExecMethod({0})".format(method_name),
            )
            if not output:
                if allow_empty:
                    return {}
                raise OSError(
                    "WMI method {0} returned no output object.".format(method_name)
                )
            return self._properties(output, properties)

    def set_string_property(self, object_path, name, value):
        """Update one string property on an existing local WMI instance.

        :param str object_path: Locatable instance path returned by a query.
        :param str name: String property defined by the instance's WMI class.
        :param value: New text, or None to restore a null property.
        :type value: str or None
        :raises ValueError: The value is neither a string nor None.
        :raises OSError: WMI rejects the property or cannot update the instance.
        :raises MemoryError: Allocation of a property or path string fails.
        """
        if value is not None and not isinstance(value, str):
            raise ValueError("WMI property {0} must be a string or None.".format(name))
        with ExitStack() as cleanup:
            instance = _get_object(
                self._services, self._automation, cleanup, object_path
            )
            _put_string(instance, self._automation, name, value)
            _update_instance(self._services, instance)

    def set_integer_property(self, object_path, name, value):
        """Update one existing WMI integer property using its provider's schema.

        :param str object_path: Locatable instance path returned by a query.
        :param str name: Integer property defined by the instance's WMI class.
        :param int value: Signed 32-bit value encoded as a VT_I4 VARIANT.
        :raises ValueError: The value is boolean, not an integer, or out of range.
        :raises OSError: WMI rejects the property or cannot update the instance.
        :raises MemoryError: Allocation of the instance-path string fails.
        """
        if isinstance(value, bool) or not isinstance(value, int):
            raise ValueError(
                "WMI property {0} must be an integer, not boolean.".format(name)
            )
        if not -(2**31) <= value < 2**31:
            raise ValueError(
                "WMI property {0} must fit a signed 32-bit integer.".format(name)
            )
        with ExitStack() as cleanup:
            instance = _get_object(
                self._services, self._automation, cleanup, object_path
            )
            _put_integer(instance, self._automation, name, value)
            _update_instance(self._services, instance)

    def _method_inputs(self, cleanup, object_path, method_name, inputs):
        for name, value in inputs.items():
            string_list = isinstance(value, list) and all(
                isinstance(entry, str) for entry in value
            )
            if (
                value is not None
                and not isinstance(value, (bool, str))
                and not string_list
            ):
                raise ValueError(
                    "WMI input {0} must be boolean, string, a string list, or None.".format(
                        name
                    )
                )
        instance = _get_object(self._services, self._automation, cleanup, object_path)
        class_name = _read_property(instance, self._automation, "__CLASS")
        if not isinstance(class_name, str) or not class_name:
            raise OSError("WMI returned no class name for {0}.".format(object_path))
        # GetMethod requires the class definition, not the queried instance.
        definition = _get_object(self._services, self._automation, cleanup, class_name)
        signature = _POINTER()
        cleanup.callback(_release, signature)
        get_method = _method(
            definition,
            19,
            _LONG,
            [ctypes.c_wchar_p, _LONG, _POINTER_OUT, _POINTER_OUT],
        )
        _check(
            get_method(definition, method_name, 0, ctypes.byref(signature), None),
            "IWbemClassObject.GetMethod({0})".format(method_name),
        )
        if not signature:
            raise OSError("WMI method {0} has no input signature.".format(method_name))
        arguments = _POINTER()
        cleanup.callback(_release, arguments)
        spawn = _method(signature, 15, _LONG, [_LONG, _POINTER_OUT])
        _check(
            spawn(signature, 0, ctypes.byref(arguments)),
            "IWbemClassObject.SpawnInstance",
        )
        if not arguments:
            raise OSError("WMI returned no method input instance.")
        for name, value in inputs.items():
            if isinstance(value, bool):
                _put_boolean(arguments, self._automation, name, value)
            elif isinstance(value, list):
                _put_string_array(arguments, self._automation, name, value)
            else:
                _put_string(arguments, self._automation, name, value)
        return arguments

    def _properties(self, instance, properties):
        return {
            name: _read_property(instance, self._automation, name)
            for name in properties
        }
