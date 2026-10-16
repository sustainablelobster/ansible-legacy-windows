# -*- coding: utf-8 -*-
# Copyright 2026 sustainablelobster
# SPDX-License-Identifier: GPL-3.0-or-later

"""Own the Automation objects exposed by IIS configuration and ADSI."""

import ctypes
import uuid
from contextlib import ExitStack

# IIS exposes the same Windows Automation ABI records as the WMI reader.
from legacy_windows_wmi import (  # pylint: disable=import-error
    _check,
    _Guid,
    _libraries,
    _method,
    _release,
    _Variant,
)

# These Windows Automation SDK records repeat other provider bindings exactly;
# keep their published field order and widths visible beside their IIS owner.
# pylint: disable=duplicate-code
_POINTER = ctypes.c_void_p
_LONG = ctypes.c_int32
_ULONG = ctypes.c_uint32
_DISPATCH = "00020400-0000-0000-c000-000000000046"


# Native dispatch argument and exception records have no independent behavior.
# pylint: disable=too-few-public-methods
class _Arguments(ctypes.Structure):
    _fields_ = [
        ("values", ctypes.POINTER(_Variant)),
        ("names", ctypes.POINTER(_LONG)),
        ("count", _ULONG),
        ("named_count", _ULONG),
    ]


class _ExceptionInfo(ctypes.Structure):
    _fields_ = [
        ("code", ctypes.c_uint16),
        ("reserved", ctypes.c_uint16),
        ("source", _POINTER),
        ("description", _POINTER),
        ("help_file", _POINTER),
        ("help_context", _ULONG),
        ("reserved_pointer", _POINTER),
        ("fill", _POINTER),
        ("status", _LONG),
    ]


# pylint: enable=too-few-public-methods
# pylint: enable=duplicate-code


def _guid(value):
    return _Guid.from_buffer_copy(uuid.UUID(value).bytes_le)


def _text(automation, pointer):
    return (
        ctypes.string_at(pointer, automation.SysStringLen(pointer) * 2).decode(
            "utf-16-le", "surrogatepass"
        )
        if pointer
        else ""
    )


def _encode_integer(variant, value):
    if -(2**31) <= value < 2**31:
        variant.kind, variant.data.signed32 = 3, value
    elif 0 <= value < 2**32:
        variant.kind, variant.data.unsigned32 = 19, value
    elif -(2**63) <= value < 2**63:
        variant.kind, variant.data.integer = 20, value
    elif 0 <= value < 2**64:
        # The shared ABI union has a signed 64-bit field; store the exact UI8
        # bit pattern explicitly rather than relying on ctypes truncation.
        variant.kind, variant.data.integer = 21, value - 2**64
    else:
        raise ValueError(
            "IIS Automation integers must fit a signed or unsigned 64-bit value."
        )


class AutomationObject:
    """Retain an IIS Automation reference until the owning context closes."""

    def __init__(self, owner, pointer):
        self.owner = owner
        self.pointer = pointer
        owner.cleanup.callback(_release, pointer)

    def get(self, name):
        """Read the named Automation property.

        :param name: Native property, method, site or pool name.
        :type name: str
        :returns: Native operation result.
        :rtype: object
        :raises OSError: The installed native provider rejects the requested operation.
        """
        return self._invoke(name, (), 2)

    def put(self, name, value):
        """Set the named Automation property.

        :param name: Native property, method, site or pool name.
        :type name: str
        :param value: Requested native Automation value.
        :type value: object
        :returns: Native operation result.
        :rtype: object
        :raises OSError: The installed native provider rejects the requested operation.
        """
        return self._invoke(name, (value,), 4)

    def call(self, name, *values):
        """Invoke a method or an indexed Automation property.

        :param name: Native property, method, site or pool name.
        :type name: str
        :param values: Ordered native Automation method arguments.
        :type values: tuple
        :returns: Native operation result.
        :rtype: object
        :raises OSError: The installed native provider rejects the requested operation.
        """
        # Item is an indexed property; the remaining operations are methods.
        return self._invoke(name, values, 2 if name == "Item" else 1)

    def _identifier(self, name):
        # GetIDsOfNames has a fixed IDispatch vtable slot and native call layout.
        # pylint: disable=duplicate-code
        identifier, null = _LONG(), _guid("00000000-0000-0000-0000-000000000000")
        names = (ctypes.c_wchar_p * 1)(name)
        _check(
            _method(
                self.pointer,
                5,
                _LONG,
                [
                    ctypes.POINTER(_Guid),
                    ctypes.POINTER(ctypes.c_wchar_p),
                    _ULONG,
                    _ULONG,
                    ctypes.POINTER(_LONG),
                ],
            )(self.pointer, ctypes.byref(null), names, 1, 0, ctypes.byref(identifier)),
            "IIS.GetIDsOfNames({0})".format(name),
        )
        # pylint: enable=duplicate-code
        return identifier

    def _invoke(self, name, values, flags):
        # IDispatch.Invoke requires this argument order, VARIANT ownership and
        # EXCEPINFO cleanup in every independent native provider binding.
        # pylint: disable=duplicate-code
        null = _guid("00000000-0000-0000-0000-000000000000")
        with ExitStack() as cleanup:
            inputs = (_Variant * len(values))()
            for index, value in enumerate(reversed(values)):
                cleanup.callback(
                    self.owner.automation.VariantClear, ctypes.byref(inputs[index])
                )
                self.owner.encode(inputs[index], value)
            arguments = _Arguments(
                inputs,
                ctypes.pointer(_LONG(-3)) if flags == 4 else None,
                len(values),
                int(flags == 4),
            )
            output, exception, failed_argument = _Variant(), _ExceptionInfo(), _ULONG()
            cleanup.callback(self.owner.automation.VariantClear, ctypes.byref(output))
            status = _method(
                self.pointer,
                6,
                _LONG,
                [
                    _LONG,
                    ctypes.POINTER(_Guid),
                    _ULONG,
                    ctypes.c_uint16,
                    ctypes.POINTER(_Arguments),
                    ctypes.POINTER(_Variant),
                    ctypes.POINTER(_ExceptionInfo),
                    ctypes.POINTER(_ULONG),
                ],
            )(
                self.pointer,
                self._identifier(name),
                ctypes.byref(null),
                0,
                flags,
                ctypes.byref(arguments),
                ctypes.byref(output),
                ctypes.byref(exception),
                ctypes.byref(failed_argument),
            )
            try:
                self._check_exception(status, exception, name)
                return self.owner.decode(output, enumeration=name == "_NewEnum")
            finally:
                for pointer in (
                    exception.source,
                    exception.description,
                    exception.help_file,
                ):
                    if pointer:
                        self.owner.automation.SysFreeString(pointer)
        # pylint: enable=duplicate-code

    def _check_exception(self, status, exception, name):
        if status & 0xFFFFFFFF == 0x80020009 and exception.fill:
            fill = ctypes.WINFUNCTYPE(_LONG, ctypes.POINTER(_ExceptionInfo))(
                exception.fill
            )
            _check(fill(ctypes.byref(exception)), "IIS deferred Automation exception")
        if status & 0x80000000:
            detail = _text(self.owner.automation, exception.description)
            if detail:
                error = OSError("IIS.{0}: {1}".format(name, detail))
                error.hresult = exception.status & 0xFFFFFFFF or status & 0xFFFFFFFF
                raise error
            _check(
                exception.status if exception.status & 0x80000000 else status,
                "IIS." + name,
            )

    def children(self):
        """Enumerate an ADSI container through its explicit native interface.

        :returns: Owned child Automation objects.
        :rtype: list
        :raises OSError: The object is not an ADSI container.
        """
        pointer = _POINTER()
        _check(
            _method(
                self.pointer,
                0,
                _LONG,
                [ctypes.POINTER(_Guid), ctypes.POINTER(_POINTER)],
            )(
                self.pointer,
                ctypes.byref(_guid("001677d0-fd16-11ce-abc4-02608c9e7553")),
                ctypes.byref(pointer),
            ),
            "QueryInterface(IADsContainer)",
        )
        try:
            library, enumerator = ctypes.WinDLL("activeds"), _POINTER()
            library.ADsBuildEnumerator.argtypes = [_POINTER, ctypes.POINTER(_POINTER)]
            library.ADsBuildEnumerator.restype = _LONG
            _check(
                library.ADsBuildEnumerator(pointer, ctypes.byref(enumerator)),
                "ADsBuildEnumerator(IIS)",
            )
            try:
                # Both native interfaces share this context's owned enumerator.
                # pylint: disable-next=protected-access
                return self.owner._enumerate(enumerator)
            finally:
                _release(enumerator)
        finally:
            _release(pointer)


class IisAutomation:
    """Initialize native IIS/ADSI Automation with deterministic object cleanup."""

    def __init__(self):
        self.cleanup = None
        self.ole = None
        self.automation = None

    def __enter__(self):
        self.ole, self.automation = _libraries()
        self.cleanup = ExitStack()
        status = self.ole.CoInitializeEx(None, 0)
        if status & 0xFFFFFFFF != 0x80010106:
            _check(status, "CoInitializeEx(IIS)")
            self.cleanup.callback(self.ole.CoUninitialize)
        self.automation.SafeArrayPutElement.argtypes = [
            _POINTER,
            ctypes.POINTER(_LONG),
            _POINTER,
        ]
        self.automation.SafeArrayPutElement.restype = _LONG
        self.automation.SafeArrayGetElement.argtypes = [
            _POINTER,
            ctypes.POINTER(_LONG),
            _POINTER,
        ]
        return self

    def __exit__(self, exc_type, exc_value, traceback):
        self.cleanup.close()

    def create(self, name):
        """Create an installed IIS Automation class by its ProgID.

        :param name: Native property, method, site or pool name.
        :type name: str
        :returns: Owned native Automation object.
        :rtype: object
        :raises OSError: The installed native provider rejects the requested operation.
        """
        class_id, pointer = _Guid(), _POINTER()
        self.ole.CLSIDFromProgID.argtypes = [ctypes.c_wchar_p, ctypes.POINTER(_Guid)]
        self.ole.CLSIDFromProgID.restype = _LONG
        _check(
            self.ole.CLSIDFromProgID(name, ctypes.byref(class_id)),
            "CLSIDFromProgID(IIS)",
        )
        _check(
            self.ole.CoCreateInstance(
                ctypes.byref(class_id),
                None,
                1,
                ctypes.byref(_guid(_DISPATCH)),
                ctypes.byref(pointer),
            ),
            "CoCreateInstance(IIS)",
        )
        return AutomationObject(self, pointer)

    def bind(self, path):
        """Bind to a local IIS metabase object through the installed ADSI provider.

        :param path: Native provider object path.
        :type path: str
        :returns: Owned ADSI metabase object.
        :rtype: object
        :raises OSError: The installed native provider rejects the requested operation.
        """
        library, pointer = ctypes.WinDLL("activeds"), _POINTER()
        library.ADsGetObject.argtypes = [
            ctypes.c_wchar_p,
            ctypes.POINTER(_Guid),
            ctypes.POINTER(_POINTER),
        ]
        library.ADsGetObject.restype = _LONG
        _check(
            library.ADsGetObject(
                path, ctypes.byref(_guid(_DISPATCH)), ctypes.byref(pointer)
            ),
            "ADsGetObject({0})".format(path),
        )
        return AutomationObject(self, pointer)

    def encode(self, variant, value):
        """Encode a scalar, native object or list as an owned Automation value.

        :param variant: Native Automation VARIANT record.
        :type variant: object
        :param value: Requested native Automation value.
        :type value: object
        :raises MemoryError: Native Automation argument storage cannot be allocated.
        :raises ValueError: An argument or requested feature cannot be represented.
        """
        if value is None:
            variant.kind = 0
        elif isinstance(value, bool):
            variant.kind, variant.data.signed16 = 11, -1 if value else 0
        elif isinstance(value, int):
            _encode_integer(variant, value)
        elif isinstance(value, str):
            variant.kind = 8
            variant.data.bstr = self.automation.SysAllocStringLen(
                value, len(value.encode("utf-16-le", "surrogatepass")) // 2
            )
            if not variant.data.bstr:
                raise MemoryError("Could not allocate IIS Automation argument.")
        elif isinstance(value, AutomationObject):
            variant.kind, variant.data.bstr = 9, value.pointer
            _method(value.pointer, 1, _ULONG, [])(value.pointer)
        elif isinstance(value, (bytes, tuple, list)):
            self._encode_array(variant, value)
        else:
            raise ValueError("Unsupported IIS Automation value type.")

    def _encode_array(self, variant, value):
        element_type = 17 if isinstance(value, bytes) else 12
        variant.kind = 0x2000 | element_type
        variant.data.array = self.automation.SafeArrayCreateVector(
            element_type, 0, len(value)
        )
        if not variant.data.array:
            raise MemoryError("Could not allocate IIS Automation array.")
        for index, item in enumerate(value):
            element = _Variant()
            try:
                if element_type == 17:
                    element.kind, element.data.byte = 17, item
                else:
                    self.encode(element, item)
                _check(
                    self.automation.SafeArrayPutElement(
                        variant.data.array,
                        ctypes.byref(_LONG(index)),
                        (
                            ctypes.byref(element.data)
                            if element_type == 17
                            else ctypes.byref(element)
                        ),
                    ),
                    "SafeArrayPutElement(IIS)",
                )
            finally:
                self.automation.VariantClear(ctypes.byref(element))

    def decode(self, variant, enumeration=False):
        """Decode an IIS Automation value, retaining returned object ownership.

        :param variant: Native Automation VARIANT record.
        :type variant: object
        :param enumeration: Whether the requested property is an ADSI enumerator.
        :type enumeration: bool
        :returns: Decoded scalar, list or owned native object.
        :rtype: object
        :raises ValueError: An argument or requested feature cannot be represented.
        """
        scalars = {
            0: None,
            1: None,
            2: variant.data.signed16,
            3: variant.data.signed32,
            22: variant.data.signed32,
            17: variant.data.byte,
            18: variant.data.unsigned16,
            19: variant.data.unsigned32,
            23: variant.data.unsigned32,
            20: variant.data.integer,
            21: variant.data.integer & 0xFFFFFFFFFFFFFFFF,
            11: bool(variant.data.signed16),
        }
        if variant.kind in scalars:
            return scalars[variant.kind]
        if variant.kind == 8:
            return _text(self.automation, variant.data.bstr)
        if variant.kind & 0x2000:
            return self._array(variant)
        if variant.kind == 13 and enumeration:
            return self._enumerate(variant.data.bstr)
        if variant.kind in (9, 13):
            return self._object(variant)
        raise ValueError(
            "Unsupported IIS Automation result type: {0}".format(variant.kind)
        )

    def _object(self, variant):
        if not variant.data.bstr:
            return None
        if variant.kind == 13:
            pointer = _POINTER()
            # QueryInterface's published IUnknown slot and IID/output-pointer
            # layout are identical across these independent provider bindings.
            # pylint: disable=duplicate-code
            _check(
                _method(
                    variant.data.bstr,
                    0,
                    _LONG,
                    [ctypes.POINTER(_Guid), ctypes.POINTER(_POINTER)],
                )(
                    variant.data.bstr,
                    ctypes.byref(_guid(_DISPATCH)),
                    ctypes.byref(pointer),
                ),
                "QueryInterface(IIS IDispatch)",
            )
            # pylint: enable=duplicate-code
            return AutomationObject(self, pointer)
        _method(variant.data.bstr, 1, _ULONG, [])(variant.data.bstr)
        return AutomationObject(self, variant.data.bstr)

    def _array(self, variant):
        lower, upper, result = _LONG(), _LONG(), []
        _check(
            self.automation.SafeArrayGetLBound(
                variant.data.array, 1, ctypes.byref(lower)
            ),
            "IIS array lower bound",
        )
        _check(
            self.automation.SafeArrayGetUBound(
                variant.data.array, 1, ctypes.byref(upper)
            ),
            "IIS array upper bound",
        )
        for index in range(lower.value, upper.value + 1):
            value = _Variant()
            value.kind = variant.kind & 0xFFF
            target = (
                ctypes.byref(value) if value.kind == 12 else ctypes.byref(value.data)
            )
            _check(
                self.automation.SafeArrayGetElement(
                    variant.data.array, ctypes.byref(_LONG(index)), target
                ),
                "SafeArrayGetElement(IIS)",
            )
            try:
                result.append(self.decode(value))
            finally:
                self.automation.VariantClear(ctypes.byref(value))
        return result

    def _enumerate(self, unknown):
        pointer = _POINTER()
        _check(
            _method(
                unknown, 0, _LONG, [ctypes.POINTER(_Guid), ctypes.POINTER(_POINTER)]
            )(
                unknown,
                ctypes.byref(_guid("00020404-0000-0000-c000-000000000046")),
                ctypes.byref(pointer),
            ),
            "QueryInterface(IEnumVARIANT)",
        )
        result = []
        try:
            while True:
                value, count = _Variant(), _ULONG()
                status = _method(
                    pointer,
                    3,
                    _LONG,
                    [_ULONG, ctypes.POINTER(_Variant), ctypes.POINTER(_ULONG)],
                )(pointer, 1, ctypes.byref(value), ctypes.byref(count))
                _check(status, "IEnumVARIANT.Next(IIS)")
                if not count.value:
                    break
                try:
                    result.append(self.decode(value))
                finally:
                    self.automation.VariantClear(ctypes.byref(value))
        finally:
            _release(pointer)
        return result
