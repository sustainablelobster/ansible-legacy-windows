# -*- coding: utf-8 -*-
# Copyright 2026 sustainablelobster
# SPDX-License-Identifier: GPL-3.0-or-later

"""Own the native Task Scheduler 2.0 automation service and its objects."""

import ctypes
import uuid
from contextlib import ExitStack

# This existing SCM helper is staged beside the payload, not installed on the controller.
# pylint: disable=import-error
from legacy_windows_service import _buffer as _service_buffer
from legacy_windows_service import _handles as _service_handles
from legacy_windows_service import _Status as _ServiceStatus

# Task Scheduler and WMI use the same native COM ABI layouts and allocation functions.
from legacy_windows_wmi import (  # pylint: disable=import-error
    _check,
    _Guid,
    _libraries,
    _method,
    _release,
    _Variant,
)

# pylint: enable=import-error


# Automation and SYSTEMTIME layouts are fixed Windows ABIs. Keep these records
# beside their task-specific owner rather than sharing unrelated feature state.
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


class _TypeAttributes(ctypes.Structure):
    # Only the fixed prefix through cFuncs is read from TYPEATTR.
    _fields_ = [
        ("identifier", _Guid),
        ("locale", _ULONG),
        ("reserved", _ULONG),
        ("constructor", _LONG),
        ("destructor", _LONG),
        ("schema", _POINTER),
        ("size", _ULONG),
        ("kind", _LONG),
        ("function_count", ctypes.c_uint16),
    ]


class _FunctionDescription(ctypes.Structure):
    # FUNCDESC's prefix identifies unparameterized property getters.
    _fields_ = [
        ("identifier", _LONG),
        ("statuses", _POINTER),
        ("parameters", _POINTER),
        ("kind", _LONG),
        ("invocation", _LONG),
        ("calling_convention", _LONG),
        ("parameter_count", ctypes.c_int16),
    ]


class _SystemTime(ctypes.Structure):
    _fields_ = [
        ("year", ctypes.c_uint16),
        ("month", ctypes.c_uint16),
        ("weekday", ctypes.c_uint16),
        ("day", ctypes.c_uint16),
        ("hour", ctypes.c_uint16),
        ("minute", ctypes.c_uint16),
        ("second", ctypes.c_uint16),
        ("millisecond", ctypes.c_uint16),
    ]


# pylint: enable=too-few-public-methods


def _guid(value):
    return _Guid.from_buffer_copy(uuid.UUID(value).bytes_le)


# pylint: enable=duplicate-code


def require_running_service():
    """Reject registration when the scheduler's native service is stopped.

    Windows 7's validation-only registration can fault inside taskschd.dll
    instead of returning a service error. Query status before entering it.

    :raises OSError: The service cannot be queried or is not running.
    """
    with _service_handles("Schedule", 4) as (library, _manager, service):
        status = _ServiceStatus.from_buffer(
            _service_buffer(library.QueryServiceStatusEx, service, 0)
        )
        if status.state != 4:
            raise OSError(
                "The Task Scheduler (Schedule) service must be running before "
                "registering or validating a task. Start it and its dependencies."
            )


def _string(automation, pointer):
    # BSTR decoding is fixed by Automation's UTF-16 length and allocation ABI.
    # pylint: disable=duplicate-code
    if not pointer:
        return ""
    return ctypes.string_at(pointer, automation.SysStringLen(pointer) * 2).decode(
        "utf-16-le", "surrogatepass"
    )


class _TaskObject:
    # These direct dispatch mappings stay with the task-specific owner. Sharing
    # a proxy with other features would hide their different object lifetimes.
    # pylint: disable=duplicate-code
    def __init__(self, owner, pointer):
        self.owner = owner
        self.pointer = pointer
        owner.cleanup.callback(_release, pointer)

    # These private proxy operations directly mirror COM dispatch. Repeating
    # ceremonial API docstrings would obscure their straightforward mappings.
    # pylint: disable=missing-function-docstring,missing-return-doc,missing-return-type-doc
    def get(self, name):
        return self._invoke(name, (), 2)

    def put(self, name, value):
        return self._invoke(name, (value,), 4)

    def call(self, name, *values):
        # Indexed task collection properties use PROPERTYGET; ordinary
        # methods use METHOD. Automation accepts the combined dispatch flags.
        return self._invoke(name, values, 3)

    # pylint: enable=duplicate-code

    def items(self):
        return [self.call("Item", index) for index in range(1, self.get("Count") + 1)]

    # pylint: enable=missing-function-docstring,missing-return-doc,missing-return-type-doc

    def properties(self):
        """Read zero-argument getters declared by this native COM object.

        :returns: Native property names and their owned scalar/object values.
        :rtype: dict
        :raises OSError: The object's type information or a getter fails.
        """
        with ExitStack() as cleanup:
            information = _POINTER()
            _check(
                _method(
                    self.pointer, 4, _LONG, [_ULONG, _ULONG, ctypes.POINTER(_POINTER)]
                )(self.pointer, 0, 0, ctypes.byref(information)),
                "Task Scheduler.GetTypeInfo",
            )
            cleanup.callback(_release, information)
            attributes = _POINTER()
            _check(
                _method(information, 3, _LONG, [ctypes.POINTER(_POINTER)])(
                    information, ctypes.byref(attributes)
                ),
                "ITypeInfo.GetTypeAttr",
            )
            cleanup.callback(
                _method(information, 19, None, [_POINTER]), information, attributes
            )
            count = ctypes.cast(
                attributes, ctypes.POINTER(_TypeAttributes)
            ).contents.function_count
            result = {}
            for index in range(count):
                description = _POINTER()
                _check(
                    _method(information, 5, _LONG, [_ULONG, ctypes.POINTER(_POINTER)])(
                        information, index, ctypes.byref(description)
                    ),
                    "ITypeInfo.GetFuncDesc",
                )
                try:
                    function = ctypes.cast(
                        description, ctypes.POINTER(_FunctionDescription)
                    ).contents
                    if function.invocation != 2 or function.parameter_count != 0:
                        continue
                    name, returned = _POINTER(), _ULONG()
                    _check(
                        _method(
                            information,
                            7,
                            _LONG,
                            [
                                _LONG,
                                ctypes.POINTER(_POINTER),
                                _ULONG,
                                ctypes.POINTER(_ULONG),
                            ],
                        )(
                            information,
                            function.identifier,
                            ctypes.byref(name),
                            1,
                            ctypes.byref(returned),
                        ),
                        "ITypeInfo.GetNames",
                    )
                    try:
                        text = _string(self.owner.automation, name)
                    finally:
                        self.owner.automation.SysFreeString(name)
                    if text != "XmlText":
                        result[text] = self.get(text)
                finally:
                    _method(information, 20, None, [_POINTER])(information, description)
            return result

    def _identifier(self, name):
        # GetIDsOfNames has a fixed ABI; errors must retain task context.
        # pylint: disable=duplicate-code
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
            "Task Scheduler.GetIDsOfNames({0})".format(name),
        )
        return identifier

    # Keep input VARIANTs, EXCEPINFO, output ownership and the dispatch ABI
    # visible together instead of hiding this single call in state bundles.
    def _invoke(self, name, values, flags):  # pylint: disable=too-many-locals
        # The fixed Invoke ABI belongs beside this task owner's input variants,
        # returned references, deferred exceptions, and cleanup callbacks.
        # pylint: disable=duplicate-code
        with ExitStack() as cleanup:
            inputs = (_Variant * len(values))()
            for index, value in enumerate(reversed(values)):
                cleanup.callback(
                    self.owner.automation.VariantClear, ctypes.byref(inputs[index])
                )
                self.owner.input_value(inputs[index], value)
            named = ctypes.pointer(_LONG(-3)) if flags == 4 else None
            arguments = _Arguments(inputs, named, len(values), 1 if flags == 4 else 0)
            output, exception, argument_error = _Variant(), _ExceptionInfo(), _ULONG()
            cleanup.callback(self.owner.automation.VariantClear, ctypes.byref(output))
            null = _guid("00000000-0000-0000-0000-000000000000")
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
                ctypes.byref(argument_error),
            )
            try:
                if status & 0xFFFFFFFF == 0x80020009 and exception.fill:
                    fill = ctypes.WINFUNCTYPE(_LONG, ctypes.POINTER(_ExceptionInfo))(
                        exception.fill
                    )
                    _check(
                        fill(ctypes.byref(exception)),
                        "Task Scheduler deferred exception",
                    )
                if status & 0x80000000:
                    message = _string(self.owner.automation, exception.description)
                    if message:
                        error = OSError("Task Scheduler.{0}: {1}".format(name, message))
                        error.hresult = (exception.status or status) & 0xFFFFFFFF
                        raise error
                    _check(status, "Task Scheduler." + name)
                return self.owner.output_value(output)
            finally:
                for pointer in (
                    exception.source,
                    exception.description,
                    exception.help_file,
                ):
                    if pointer:
                        self.owner.automation.SysFreeString(pointer)


class TaskSchedulerUnavailable(OSError):
    """The installed scheduler does not expose its version 2.0 service."""


class TaskScheduler:
    """Own the installed Task Scheduler 2.0 service and returned COM objects.

    :raises TaskSchedulerUnavailable: The native scheduler service is absent.
    :raises OSError: COM initialization or connecting to the service fails.
    """

    def __init__(self):
        self.cleanup = None
        self.automation = None
        self.ole = None
        self.service = None

    def __enter__(self):
        self.ole, self.automation = _libraries()
        with ExitStack() as cleanup:
            initialized = self.ole.CoInitializeEx(None, 2)
            if initialized & 0xFFFFFFFF != 0x80010106:
                _check(initialized, "CoInitializeEx(Task Scheduler)")
                cleanup.callback(self.ole.CoUninitialize)
            self.cleanup = cleanup
            pointer = _POINTER()
            # CoCreateInstance's fixed ABI must name this scheduler class here.
            # pylint: disable=duplicate-code
            status = self.ole.CoCreateInstance(
                ctypes.byref(_guid("0f87369f-a4e5-4cfc-bd3e-73e6154572dd")),
                None,
                1,
                ctypes.byref(_guid(_DISPATCH)),
                ctypes.byref(pointer),
            )
            # pylint: enable=duplicate-code
            if status & 0x80000000:
                _release(pointer)
                if status & 0xFFFFFFFF in (0x80040154, 0x80004002):
                    raise TaskSchedulerUnavailable(
                        "Task Scheduler 2.0 service is not installed."
                    )
                _check(status, "CoCreateInstance(Task Scheduler)")
            self.service = _TaskObject(self, pointer)
            self.service.call("Connect")
            self.cleanup = cleanup.pop_all()
        return self

    def __exit__(self, exc_type, exc_value, traceback):
        self.cleanup.close()
        self.service = None

    def input_value(self, variant, value):
        """Encode one task method argument with Automation-owned storage.

        :param variant: Empty VARIANT initialized by the caller.
        :type variant: _Variant
        :param value: String, integer, boolean, task object, or null argument.
        :type value: object
        :raises ValueError: The argument type is not supported by task operations.
        :raises MemoryError: Windows cannot allocate a BSTR argument.
        """
        # Scalar tags share Automation's ABI; task-object references and their
        # lifetime remain local to this scheduler's argument encoder.
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
                raise MemoryError("Could not allocate Task Scheduler argument text.")
        elif isinstance(value, _TaskObject):
            variant.kind = 9
            _method(value.pointer, 1, _ULONG, [])(value.pointer)
            variant.data.bstr = value.pointer
        else:
            raise ValueError("Unsupported Task Scheduler argument type.")

    # A direct VARIANT type switch makes each scalar conversion and owned
    # reference visible; a conversion registry would hide their lifetimes.
    def output_value(self, variant):  # pylint: disable=too-many-return-statements
        """Decode task output while retaining object references until context exit.

        :param variant: Automation-owned returned VARIANT.
        :type variant: _Variant
        :returns: A string, integer, boolean, owned task object, or None.
        :rtype: str or int or bool or _TaskObject or None
        :raises ValueError: Task Scheduler returned a type outside its supported contract.
        """
        if variant.kind in (0, 1):
            return None
        if variant.kind == 3:
            return variant.data.signed32
        if variant.kind == 2:
            return variant.data.signed16
        if variant.kind == 18:
            return variant.data.unsigned16
        if variant.kind == 19:
            return variant.data.unsigned32
        if variant.kind == 7:
            value = ctypes.c_double.from_buffer(variant, 8).value
            system = _SystemTime()
            convert = self.automation.VariantTimeToSystemTime
            convert.argtypes = [ctypes.c_double, ctypes.POINTER(_SystemTime)]
            convert.restype = ctypes.c_int
            if not convert(value, ctypes.byref(system)):
                raise ValueError("Task Scheduler returned an invalid Automation date.")
            return "{0:04d}-{1:02d}-{2:02d}T{3:02d}:{4:02d}:{5:02d}".format(
                system.year,
                system.month,
                system.day,
                system.hour,
                system.minute,
                system.second,
            )
        if variant.kind == 11:
            return bool(variant.data.signed16)
        if variant.kind == 8:
            return (
                _string(self.automation, variant.data.bstr)
                if variant.data.bstr
                else None
            )
        if variant.kind in (9, 13):
            if not variant.data.bstr:
                return None
            if variant.kind == 13:
                dispatch = _POINTER()
                # IUnknown.QueryInterface has a fixed ABI and transfers this
                # returned task reference into the scheduler's cleanup owner.
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
                        ctypes.byref(dispatch),
                    ),
                    "Task Scheduler.QueryInterface(IDispatch)",
                )
                # pylint: enable=duplicate-code
                return _TaskObject(self, dispatch)
            _method(variant.data.bstr, 1, _ULONG, [])(variant.data.bstr)
            return _TaskObject(self, variant.data.bstr)
        raise ValueError(
            "Unsupported Task Scheduler output VARIANT type: {0}".format(variant.kind)
        )
