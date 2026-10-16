# -*- coding: utf-8 -*-
# Copyright 2026 sustainablelobster
# SPDX-License-Identifier: GPL-3.0-or-later

"""Own MSXML documents and their native XPath/DOM automation objects."""

import ctypes
import uuid
from contextlib import ExitStack

# MSXML and WMI use the same native COM ABI layouts and allocation functions.
from legacy_windows_wmi import (  # pylint: disable=import-error
    _check,
    _Guid,
    _libraries,
    _method,
    _release,
    _Variant,
)

# Fixed Automation records stay with the DOM owner; sharing them would couple
# independent feature helpers without reducing the native ABI to understand.
# pylint: disable=duplicate-code
_POINTER = ctypes.c_void_p
_LONG = ctypes.c_int32
_ULONG = ctypes.c_uint32
_DISPATCH = "00020400-0000-0000-c000-000000000046"


# These exact layouts describe Windows Automation records, not public objects.
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


def _guid(value):
    return _Guid.from_buffer_copy(uuid.UUID(value).bytes_le)


# pylint: enable=duplicate-code


def _string(automation, pointer):
    # BSTR decoding is fixed by Automation's UTF-16 length and allocation ABI.
    # pylint: disable=duplicate-code
    if not pointer:
        return ""
    return ctypes.string_at(pointer, automation.SysStringLen(pointer) * 2).decode(
        "utf-16-le", "surrogatepass"
    )


class _Node:
    # Keep the dispatch ABI and DOM-specific reference/exception ownership
    # together rather than coupling it to another feature's object proxy.
    # pylint: disable=duplicate-code
    def __init__(self, owner, pointer):
        self.owner = owner
        self.pointer = pointer
        owner.cleanup.callback(_release, pointer)

    def get(self, name):
        """Read one DOM Automation property.

        :param str name: DOM property name.
        :returns: Decoded value owned by this document context.
        :rtype: object
        """
        return self._invoke(name, (), 2)

    def put(self, name, value):
        """Set one DOM Automation property.

        :param str name: DOM property name.
        :param object value: Scalar or owned node to assign.
        :returns: Native property-set result.
        :rtype: object
        """
        return self._invoke(name, (value,), 4)

    def call(self, name, *values):
        """Invoke a DOM method or indexed property.

        :param str name: DOM member name.
        :param values: Positional arguments in their public order.
        :type values: tuple
        :returns: Decoded scalar or node owned by this document context.
        :rtype: object
        """
        # Indexed DOM properties such as NodeList.item use PROPERTYGET; normal
        # methods use METHOD. Automation accepts the combined dispatch flags.
        return self._invoke(name, values, 3)

    def items(self):
        """Read every item in a DOM node collection in native order.

        :returns: Owned DOM nodes.
        :rtype: list
        """
        return [self.call("item", index) for index in range(self.get("length"))]

    def _identifier(self, name):
        identifier = _LONG()
        names = (ctypes.c_wchar_p * 1)(name)
        null = _guid("00000000-0000-0000-0000-000000000000")
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
            "MSXML.GetIDsOfNames({0})".format(name),
        )
        return identifier

    def _invoke(self, name, values, flags):
        with ExitStack() as cleanup:
            inputs = (_Variant * len(values))()
            for index, value in enumerate(reversed(values)):
                cleanup.callback(
                    self.owner.automation.VariantClear, ctypes.byref(inputs[index])
                )
                self.owner.input_value(inputs[index], value)
            arguments = _Arguments(
                inputs,
                ctypes.pointer(_LONG(-3)) if flags == 4 else None,
                len(values),
                1 if flags == 4 else 0,
            )
            output, exception = _Variant(), _ExceptionInfo()
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
                ctypes.byref(_guid("00000000-0000-0000-0000-000000000000")),
                0,
                flags,
                ctypes.byref(arguments),
                ctypes.byref(output),
                ctypes.byref(exception),
                ctypes.byref(_ULONG()),
            )
            try:
                if status & 0xFFFFFFFF == 0x80020009 and exception.fill:
                    fill = ctypes.WINFUNCTYPE(_LONG, ctypes.POINTER(_ExceptionInfo))(
                        exception.fill
                    )
                    _check(fill(ctypes.byref(exception)), "MSXML deferred exception")
                if status & 0x80000000:
                    message = _string(self.owner.automation, exception.description)
                    if message:
                        raise OSError("MSXML.{0}: {1}".format(name, message))
                    _check(status, "MSXML." + name)
                return self.owner.output_value(output)
            finally:
                for pointer in (
                    exception.source,
                    exception.description,
                    exception.help_file,
                ):
                    if pointer:
                        self.owner.automation.SysFreeString(pointer)


class XmlDocument:
    """Own MSXML documents and nodes until leaving this context manager.

    :raises OSError: Neither MSXML 6.0 nor MSXML 3.0 can be created.
    """

    def __init__(self):
        self.cleanup = None
        self.automation = None
        self.ole = None
        self.document = None

    def __enter__(self):
        self.ole, self.automation = _libraries()
        with ExitStack() as cleanup:
            initialized = self.ole.CoInitializeEx(None, 0)
            if initialized & 0xFFFFFFFF != 0x80010106:
                _check(initialized, "CoInitializeEx(MSXML)")
                cleanup.callback(self.ole.CoUninitialize)
            self.cleanup = cleanup
            failure = None
            for class_id in (
                "88d96a05-f192-11d4-a65f-0040963251e5",
                "f5078f32-c551-11d3-89b9-0000f81fe221",
            ):
                pointer = _POINTER()
                # CoCreateInstance's fixed ABI must name this DOM class locally.
                # pylint: disable=duplicate-code
                status = self.ole.CoCreateInstance(
                    ctypes.byref(_guid(class_id)),
                    None,
                    1,
                    ctypes.byref(_guid(_DISPATCH)),
                    ctypes.byref(pointer),
                )
                # pylint: enable=duplicate-code
                if not status & 0x80000000:
                    self.document = _Node(self, pointer)
                    break
                _release(pointer)
                failure = status
                if status & 0xFFFFFFFF not in (0x80040154, 0x80004002):
                    _check(status, "CoCreateInstance(MSXML)")
            if self.document is None:
                _check(failure, "MSXML 6.0 or 3.0 is required for native XPath")
            self.document.put("async", False)
            self.document.put("validateOnParse", False)
            self.document.put("resolveExternals", False)
            if class_id == "88d96a05-f192-11d4-a65f-0040963251e5":
                # Match XmlResolver=null: allow declarations but never fetch them.
                self.document.call("setProperty", "ProhibitDTD", False)
            self.document.call("setProperty", "SelectionLanguage", "XPath")
            self.cleanup = cleanup.pop_all()
        return self

    def __exit__(self, exc_type, exc_value, traceback):
        self.cleanup.close()
        self.document = None

    def input_value(self, variant, value):
        """Encode one DOM method argument with Automation-owned storage.

        :param variant: Empty VARIANT initialized by the caller.
        :type variant: _Variant
        :param value: String, integer, boolean, node, or null argument.
        :type value: object
        :raises ValueError: The argument type is not supported by DOM operations.
        :raises MemoryError: Allocation of a DOM string argument fails.
        """
        # This scalar ABI repeats elsewhere, but DOM node references and their
        # lifetime belong to this document, not another feature's encoder.
        # pylint: disable=duplicate-code
        if value is None:
            variant.kind = 0
        elif isinstance(value, bool):
            variant.kind = 11
            variant.data.signed16 = -1 if value else 0
        elif isinstance(value, int):
            variant.kind = 3
            variant.data.signed32 = value
        elif isinstance(value, str):
            variant.kind = 8
            units = len(value.encode("utf-16-le", "surrogatepass")) // 2
            variant.data.bstr = self.automation.SysAllocStringLen(value, units)
            if not variant.data.bstr:
                raise MemoryError("Could not allocate MSXML argument text.")
        elif isinstance(value, _Node):
            variant.kind = 9
            _method(value.pointer, 1, _ULONG, [])(value.pointer)
            variant.data.bstr = value.pointer
        else:
            raise ValueError("Unsupported MSXML argument type.")

    def output_value(self, variant):
        """Decode DOM output while retaining object references until context exit.

        :param variant: Automation-owned returned VARIANT.
        :type variant: _Variant
        :returns: A string, integer, boolean, owned node, or None.
        :rtype: object
        :raises ValueError: MSXML returned a type outside its supported contract.
        """
        if variant.kind in (0, 1):
            return None
        if variant.kind == 3:
            return variant.data.signed32
        if variant.kind == 11:
            return bool(variant.data.signed16)
        if variant.kind == 8:
            return _string(self.automation, variant.data.bstr)
        if variant.kind == 9:
            if not variant.data.bstr:
                return None
            _method(variant.data.bstr, 1, _ULONG, [])(variant.data.bstr)
            return _Node(self, variant.data.bstr)
        raise ValueError(
            "Unsupported MSXML output VARIANT type: {0}".format(variant.kind)
        )
