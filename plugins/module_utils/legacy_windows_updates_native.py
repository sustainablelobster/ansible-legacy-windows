# -*- coding: utf-8 -*-
# Copyright 2026 Joe Lustri
# SPDX-License-Identifier: GPL-3.0-or-later

"""Own native WUA automation objects and their asynchronous callbacks."""

import ctypes
import decimal
import os
import sys
import threading
import time
import uuid
from contextlib import ExitStack

# WUA and WMI share Windows' native COM ABI, not a third-party Python binding.
from legacy_windows_wmi import (  # pylint: disable=import-error
    _Guid,
    _libraries,
    _method,
    _release,
    _Variant,
)

# The owned dispatch proxies/callbacks share this module's private COM ABI.
# pylint: disable=protected-access


_POINTER = ctypes.c_void_p
_LONG = ctypes.c_int32
_ULONG = ctypes.c_uint32
_UNKNOWN = "00000000-0000-0000-c000-000000000046"
_DISPATCH = "00020400-0000-0000-c000-000000000046"
_CALLBACK_IDS = {
    "Search": (None, "88aee058-d4b0-4725-a2f1-814a67ae964c"),
    "Download": (
        "8c3f1cdd-6173-4591-aebd-a56a53ca77c1",
        "77254866-9f5b-4c8e-b9e2-c77a8530d64b",
    ),
    "Install": (
        "e01402d5-f8da-43ba-a012-38894bd048f1",
        "45f4f6f3-d602-4f98-9a8a-3efa152ad2d3",
    ),
}
# A failed native CleanUp must not leave WUA with freed Python function pointers.
# Retain those exceptional callbacks until their dedicated worker process exits.
_RETAINED_CALLBACKS = []


# These structures describe the native Automation ABI rather than application
# objects; giving them methods would obscure their layout.
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


class WuaError(OSError):
    """Retain a native HRESULT for the controller's released WUA diagnostics."""

    def __init__(self, message, hresult):
        super().__init__(message)
        self.hresult = hresult & 0xFFFFFFFF


def _guid(value):
    return _Guid.from_buffer_copy(uuid.UUID(value).bytes_le)


def _check(status, operation):
    if status & 0x80000000:
        raise WuaError(
            "{0} failed (HRESULT 0x{1:08X}).".format(operation, status & 0xFFFFFFFF),
            status,
        )


def hresult_description(hresult):
    """Read a localized system message without replacing an unknown HRESULT.

    :param int hresult: Signed or unsigned native result code.
    :returns: The system description, or None when no message is available.
    :rtype: str or None
    """
    kernel = ctypes.WinDLL("kernel32", use_last_error=True)
    formatter = kernel.FormatMessageW
    formatter.argtypes = [
        ctypes.c_uint32,
        ctypes.c_void_p,
        ctypes.c_uint32,
        ctypes.c_uint32,
        ctypes.c_wchar_p,
        ctypes.c_uint32,
        ctypes.c_void_p,
    ]
    formatter.restype = ctypes.c_uint32
    message = ctypes.create_unicode_buffer(32768)
    # IGNORE_INSERTS avoids interpreting message placeholders as missing pointers.
    # Query only Windows' system table; WUA-specific codes may have no entry.
    length = formatter(
        0x1200, None, hresult & 0xFFFFFFFF, 0, message, len(message), None
    )
    if not length:
        return None
    return message.value.strip() or None


def _keep_awake():
    kernel = ctypes.WinDLL("kernel32", use_last_error=True)
    kernel.SetThreadExecutionState.argtypes = [ctypes.c_uint32]
    kernel.SetThreadExecutionState.restype = ctypes.c_uint32
    # The source requests ES_CONTINUOUS | ES_SYSTEM_REQUIRED every minute and
    # does not treat a rejected power request as a failed update operation.
    kernel.SetThreadExecutionState(0x80000001)


def _string(automation, pointer):
    if not pointer:
        return ""
    units = automation.SysStringLen(pointer)
    return ctypes.string_at(pointer, units * 2).decode("utf-16-le", "surrogatepass")


class _UpdateObject:
    """Private owned IDispatch proxy; get/call/put/items map directly to COM."""

    def __init__(self, agent, pointer, cleanup=None):
        if not pointer:
            raise OSError("WUA returned a null automation object.")
        self.agent = agent
        self.pointer = pointer
        self.cleanup = cleanup if cleanup is not None else agent._cleanup
        self.cleanup.callback(_release, pointer)

    # These four private-proxy operations are direct, obvious Automation calls.
    # pylint: disable=missing-function-docstring,missing-return-doc,missing-return-type-doc
    def get(self, name):
        return self._invoke(name, (), 2)

    def call(self, name, *values):
        return self._invoke(name, values, 3)

    def put(self, name, value):
        return self._invoke(name, (value,), 4)

    def items(self):
        return [self.call("Item", index) for index in range(self.get("Count"))]

    # pylint: enable=missing-function-docstring,missing-return-doc,missing-return-type-doc

    def _identifier(self, name):
        null = _guid("00000000-0000-0000-0000-000000000000")
        identifier = _LONG()
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
            "WUA.GetIDsOfNames({0})".format(name),
        )
        return identifier

    def _arguments(self, values, flags, cleanup):
        inputs = (_Variant * len(values))()
        for index, value in enumerate(reversed(values)):
            cleanup.callback(self.agent._clear, ctypes.byref(inputs[index]))
            self.agent._input(inputs[index], value)
        if flags == 4:
            # DISPID_PROPERTYPUT is required for setters. ctypes retains the
            # pointed-to named argument and input array with this structure.
            return _Arguments(inputs, ctypes.pointer(_LONG(-3)), len(inputs), 1)
        return _Arguments(inputs, None, len(inputs), 0)

    def _invoke(self, name, values, flags):
        identifier = self._identifier(name)
        null = _guid("00000000-0000-0000-0000-000000000000")
        with ExitStack() as cleanup:
            arguments = self._arguments(values, flags, cleanup)
            output, exception, argument_error = _Variant(), _ExceptionInfo(), _ULONG()
            cleanup.callback(self.agent._clear, ctypes.byref(output))
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
                identifier,
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
                    _check(fill(ctypes.byref(exception)), "WUA deferred exception")
                if status & 0x80000000:
                    description = _string(self.agent._automation, exception.description)
                    if description:
                        raise WuaError(description, exception.status or status)
                    _check(exception.status or status, "WUA.{0}".format(name))
                return self.agent._output(output, self.cleanup)
            finally:
                for pointer in (
                    exception.source,
                    exception.description,
                    exception.help_file,
                ):
                    if pointer:
                        self.agent._automation.SysFreeString(pointer)


# Callback function pointers, vtable storage and its lock must remain live
# together; these native ABI resources cannot be split into independent objects.
class _Callback(
    ctypes.Structure
):  # pylint: disable=too-many-instance-attributes,too-few-public-methods
    _fields_ = [("table", ctypes.POINTER(_POINTER))]

    def __init__(self, identifier, handler):
        super().__init__()
        self.references = 1
        self.error = None
        self._lock = threading.Lock()
        self._handler = handler
        self._identifiers = [
            uuid.UUID(value).bytes_le for value in (_UNKNOWN, identifier)
        ]
        self._query = ctypes.WINFUNCTYPE(
            _LONG, _POINTER, ctypes.POINTER(_Guid), ctypes.POINTER(_POINTER)
        )(self._query_interface)
        self._add = ctypes.WINFUNCTYPE(_ULONG, _POINTER)(self._add_reference)
        self._drop = ctypes.WINFUNCTYPE(_ULONG, _POINTER)(self._drop_reference)
        self._invoke = ctypes.WINFUNCTYPE(_LONG, _POINTER, _POINTER, _POINTER)(
            self._receive
        )
        self._functions = (self._query, self._add, self._drop, self._invoke)
        self._entries = (_POINTER * 4)(
            *[ctypes.cast(function, _POINTER).value for function in self._functions]
        )
        self.table = self._entries

    def _query_interface(self, this, identifier, output):
        output[0] = None
        if ctypes.string_at(identifier, 16) not in self._identifiers:
            return -2147467262  # E_NOINTERFACE
        output[0] = this
        self._add_reference(this)
        return 0

    def _add_reference(self, _this):
        with self._lock:
            self.references += 1
            return self.references

    def _drop_reference(self, _this):
        with self._lock:
            self.references -= 1
            return self.references

    def _receive(self, _this, job, arguments):
        try:
            self._handler(job, arguments)
            return 0
        # ctypes callbacks must not leak any Python exception into native code.
        except Exception as error:  # pylint: disable=broad-exception-caught
            self.error = error
            return -2147467259  # E_FAIL


class UpdateAgent:
    """Own local WUA objects until the complete update operation ends.

    :raises OSError: Windows cannot initialize COM or create the WUA session.
    """

    def __init__(self):
        self._cleanup = None
        self._automation = None
        self._ole = None
        self.session = None

    def __enter__(self):
        if os.name != "nt":
            raise OSError("Windows Update Agent access requires Windows.")
        self._ole, self._automation = _libraries()
        with ExitStack() as cleanup:
            initialized = self._ole.CoInitializeEx(None, 0)
            _check(initialized, "CoInitializeEx(WUA MTA)")
            cleanup.callback(self._ole.CoUninitialize)
            self._cleanup = cleanup
            self._cleanup = cleanup.pop_all()
        return self

    def __exit__(self, exc_type, exc_value, traceback):
        self._cleanup.close()

    def create(self, class_id):
        """Create a WUA automation class with resources tied to this agent.

        :param str class_id: CLSID of the specific WUA class to create.
        :returns: The owned WUA automation object.
        :rtype: _UpdateObject
        :raises WuaError: CoCreateInstance fails.
        """
        pointer = _POINTER()
        status = self._ole.CoCreateInstance(
            ctypes.byref(_guid(class_id)),
            None,
            1,
            ctypes.byref(_guid(_DISPATCH)),
            ctypes.byref(pointer),
        )
        if status & 0x80000000:
            _release(pointer)
            _check(status, "CoCreateInstance(WUA)")
        return _UpdateObject(self, pointer)

    def create_session(self):
        """Create the session after the caller has read the initial reboot state.

        :returns: The owned WUA session.
        :rtype: _UpdateObject
        :raises WuaError: WUA cannot create the session.
        """
        self.session = self.create("4cb43d7f-7eee-4906-8698-60da1c38f2fe")
        return self.session

    def reboot_required(self):
        """Read the native WUA system reboot requirement.

        :returns: Whether WUA reports a required reboot.
        :rtype: bool
        :raises WuaError: WUA cannot read the reboot state.
        """
        return self.create("c01b9ba0-bea7-41ba-b604-d0a36f469133").get("RebootRequired")

    def collection(self, updates):
        """Build a native WUA update collection in the supplied order.

        :param updates: Native update objects selected from this agent's search.
        :type updates: list
        :returns: The owned native update collection.
        :rtype: _UpdateObject
        :raises WuaError: WUA cannot create or populate the collection.
        """
        collection = self.create("13639463-00db-4646-803d-528026140d88")
        for update in updates:
            collection.call("Add", update)
        return collection

    # A native job has distinct criteria, cancellation and progress inputs;
    # retaining those explicit inputs is clearer than a generic option bundle.
    def operation(
        self, target, phase, argument, cancelled, progress
    ):  # pylint: disable=too-many-arguments,too-many-positional-arguments,too-many-locals
        """Wait for one native asynchronous WUA operation and clean its callbacks.

        :param target: Native searcher, downloader or installer.
        :type target: _UpdateObject
        :param str phase: Search, Download or Install.
        :param argument: Search criteria, or None for download and installation.
        :type argument: str or None
        :param cancelled: Callable reporting the owned cancellation request.
        :type cancelled: callable
        :param progress: Callable receiving the native transfer-progress object.
        :type progress: callable or None
        :returns: Native completed operation result.
        :rtype: _UpdateObject
        :raises WuaError: Starting, ending or cleaning the job fails.
        :raises Exception: A callback consumer fails, after the job is cleaned.
        """
        completed = threading.Event()
        on_complete = _Callback(
            _CALLBACK_IDS[phase][1], lambda _job, _args: completed.set()
        )
        on_progress = None
        if phase != "Search":

            def receive(_job, arguments):
                # The callback owns borrowed pointers only for its duration.
                # QueryInterface gives this thread an independent reference.
                pointer = _POINTER()
                status = _method(
                    arguments,
                    0,
                    _LONG,
                    [ctypes.POINTER(_Guid), ctypes.POINTER(_POINTER)],
                )(arguments, ctypes.byref(_guid(_DISPATCH)), ctypes.byref(pointer))
                if status & 0x80000000:
                    _release(pointer)
                    _check(status, "WUA callback QueryInterface")
                with ExitStack() as cleanup:
                    # This scope releases both callback arguments and Progress
                    # before returning to the native callback caller.
                    callback = _UpdateObject(self, pointer, cleanup)
                    progress(callback.get("Progress"))

            on_progress = _Callback(_CALLBACK_IDS[phase][0], receive)
        beginning = argument if phase == "Search" else on_progress
        job = target.call("Begin" + phase, beginning, on_complete, phase)
        abort_requested = False
        next_power_request = time.monotonic() + 60
        try:
            while not completed.wait(0.2):
                if time.monotonic() >= next_power_request:
                    _keep_awake()
                    next_power_request = time.monotonic() + 60
                if cancelled() and not abort_requested:
                    abort_requested = True
                    try:
                        job.call("RequestAbort")
                    except WuaError:
                        # RequestAbort is advisory. Like the source, keep the
                        # callbacks alive and await actual completion if denied.
                        pass
            result = target.call("End" + phase, job)
            if on_progress is not None and on_progress.error is not None:
                raise on_progress.error
            if on_complete.error is not None:
                raise on_complete.error
            return result
        finally:
            # CleanUp must not run inside a callback. It releases WUA's callback
            # references before the Python function-pointer storage goes away.
            primary = sys.exc_info()[1]
            try:
                job.call("CleanUp")
                if on_complete.references != 1 or (
                    on_progress is not None and on_progress.references != 1
                ):
                    raise OSError("WUA retained callbacks after job cleanup.")
            # Preserve any primary End/callback failure while keeping native
            # function pointers live if arbitrary cleanup code fails.
            except Exception as error:  # pylint: disable=broad-exception-caught
                _RETAINED_CALLBACKS.extend((on_complete, on_progress))
                if primary is None:
                    raise
                primary.cleanup_error = str(error)

    def _clear(self, value):
        _check(self._automation.VariantClear(value), "WUA VariantClear")

    def _input(self, variant, value):
        if value is None:
            variant.kind = 0
        elif isinstance(value, bool):
            variant.kind = 11
            variant.data.signed16 = -1 if value else 0
        elif isinstance(value, int):
            if not -(2**31) <= value < 2**31:
                raise ValueError("WUA method integer argument exceeds Int32.")
            variant.kind = 3
            variant.data.signed32 = value
        elif isinstance(value, str):
            variant.kind = 8
            units = len(value.encode("utf-16-le", "surrogatepass")) // 2
            variant.data.bstr = self._automation.SysAllocStringLen(value, units)
            if not variant.data.bstr:
                raise MemoryError("Could not allocate WUA argument text.")
        elif isinstance(value, (_UpdateObject, _Callback)):
            variant.kind = 9 if isinstance(value, _UpdateObject) else 13
            pointer = (
                value.pointer
                if isinstance(value, _UpdateObject)
                else ctypes.addressof(value)
            )
            _method(pointer, 1, _ULONG, [])(pointer)
            variant.data.bstr = pointer
        else:
            raise ValueError("Unsupported native WUA method argument.")

    # A direct native type switch makes ownership and conversion visible for
    # every supported VARIANT; a dispatch registry would hide those lifetimes.
    def _output(
        self, variant, cleanup=None
    ):  # pylint: disable=too-many-return-statements,too-many-branches
        kind = variant.kind
        if kind in (0, 1):
            return None
        if kind == 2:
            return variant.data.signed16
        if kind == 3:
            return variant.data.signed32
        if kind == 8:
            return _string(self._automation, variant.data.bstr)
        if kind in (9, 13):
            pointer = variant.data.bstr
            if not pointer:
                return None
            if kind == 13:
                dispatch = _POINTER()
                status = _method(
                    pointer, 0, _LONG, [ctypes.POINTER(_Guid), ctypes.POINTER(_POINTER)]
                )(pointer, ctypes.byref(_guid(_DISPATCH)), ctypes.byref(dispatch))
                if status & 0x80000000:
                    _release(dispatch)
                    _check(status, "WUA output QueryInterface(IDispatch)")
                pointer = dispatch
            else:
                _method(pointer, 1, _ULONG, [])(pointer)
            return _UpdateObject(self, pointer, cleanup)
        if kind == 11:
            return bool(variant.data.signed16)
        if kind == 14:
            # DECIMAL overlays the VARIANT header rather than its data union.
            raw = ctypes.string_at(ctypes.byref(variant), 16)
            scale, sign = raw[2], raw[3]
            magnitude = int.from_bytes(raw[4:8], "little") * 2**64
            magnitude += int.from_bytes(raw[8:16], "little")
            magnitude *= -1 if sign & 0x80 else 1
            if scale == 0:
                return magnitude
            with decimal.localcontext() as context:
                context.prec = 29
                return float(decimal.Decimal(magnitude).scaleb(-scale))
        if kind == 19:
            return variant.data.unsigned32
        if kind == 20:
            return variant.data.integer
        if kind == 21:
            return variant.data.integer & 0xFFFFFFFFFFFFFFFF
        if kind == 5:
            return ctypes.c_double.from_buffer(variant, 8).value
        raise ValueError("Unsupported native WUA VARIANT type {0}.".format(kind))
