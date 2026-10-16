# -*- coding: utf-8 -*-
# Copyright 2026 sustainablelobster
# SPDX-License-Identifier: GPL-3.0-or-later

"""Own Task Scheduler 1.0 interfaces and their native allocations."""

import ctypes
import uuid
from contextlib import ExitStack

# Task Scheduler uses the same fixed COM ABI primitives as the WMI runtime.
from legacy_windows_wmi import (  # pylint: disable=import-error
    _check,
    _Guid,
    _libraries,
    _method,
    _release,
)

_POINTER = ctypes.c_void_p
_WORD = ctypes.c_uint16
_DWORD = ctypes.c_uint32
_HRESULT = ctypes.c_int32
_TASK_ID = "148bd524-a2ab-11ce-b11f-00aa00530503"
_TASK_CLASS = "148bd520-a2ab-11ce-b11f-00aa00530503"


# These records mirror mstask.h, not objects with public operations.
# pylint: disable=too-few-public-methods
class _Daily(ctypes.Structure):
    _fields_ = [("days_interval", _WORD)]


class _Weekly(ctypes.Structure):
    _fields_ = [("weeks_interval", _WORD), ("days", _WORD)]


class _MonthlyDate(ctypes.Structure):
    _fields_ = [("days", _DWORD), ("months", _WORD)]


class _MonthlyDay(ctypes.Structure):
    _fields_ = [("week", _WORD), ("days", _WORD), ("months", _WORD)]


class _TriggerData(ctypes.Union):
    _fields_ = [
        ("daily", _Daily),
        ("weekly", _Weekly),
        ("monthly", _MonthlyDate),
        ("monthly_day", _MonthlyDay),
    ]


class Trigger(ctypes.Structure):
    """Expose the fixed 48-byte TASK_TRIGGER record used by the legacy service."""

    _fields_ = [
        ("size", _WORD),
        ("reserved", _WORD),
        ("begin_year", _WORD),
        ("begin_month", _WORD),
        ("begin_day", _WORD),
        ("end_year", _WORD),
        ("end_month", _WORD),
        ("end_day", _WORD),
        ("hour", _WORD),
        ("minute", _WORD),
        ("duration", _DWORD),
        ("interval", _DWORD),
        ("flags", _DWORD),
        ("kind", _DWORD),
        ("data", _TriggerData),
        ("reserved2", _WORD),
        ("random_minutes", _WORD),
    ]


class _SystemTime(ctypes.Structure):
    _fields_ = [
        ("year", _WORD),
        ("month", _WORD),
        ("weekday", _WORD),
        ("day", _WORD),
        ("hour", _WORD),
        ("minute", _WORD),
        ("second", _WORD),
        ("millisecond", _WORD),
    ]


# pylint: enable=too-few-public-methods


def _guid(value):
    return _Guid.from_buffer_copy(uuid.UUID(value).bytes_le)


def _call(pointer, slot, types, *values):
    result = _method(pointer, slot, _HRESULT, types)(pointer, *values)
    _check(result, "Task Scheduler 1.0 method {0}".format(slot))
    return result


class LegacyTask:
    """Read and change one task object; changes persist only through save()."""

    def __init__(self, scheduler, pointer):
        self.scheduler = scheduler
        self.pointer = pointer
        scheduler.cleanup.callback(_release, pointer)

    def string(self, slot):
        """Read and free an allocated LPCWSTR property at its documented slot.

        :param int slot: Native ITask getter slot.
        :returns: The Unicode property, or an empty string.
        :rtype: str
        """
        value = _POINTER()
        try:
            _call(self.pointer, slot, [ctypes.POINTER(_POINTER)], ctypes.byref(value))
            return ctypes.wstring_at(value) if value else ""
        finally:
            if value:
                self.scheduler.ole32.CoTaskMemFree(value)

    def set_string(self, slot, value):
        """Set an LPCWSTR property in the in-memory task definition.

        :param int slot: Native ITask setter slot.
        :param str value: Unicode property value.
        """
        _call(self.pointer, slot, [ctypes.c_wchar_p], value)

    def number(self, slot):
        """Read a DWORD property at its documented ITask getter slot.

        :param int slot: Native ITask getter slot.
        :returns: Unsigned native property value.
        :rtype: int
        """
        value = _DWORD()
        result = _call(
            self.pointer, slot, [ctypes.POINTER(_DWORD)], ctypes.byref(value)
        )
        return result if slot == 17 and result else value.value

    def set_number(self, slot, value):
        """Set a DWORD property in the in-memory task definition.

        :param int slot: Native ITask setter slot.
        :param int value: Unsigned native property value.
        """
        _call(self.pointer, slot, [_DWORD], value)

    def account(self, name, password):
        """Set execution credentials using an empty name for LocalSystem.

        :param str name: Qualified account name, or empty for LocalSystem.
        :param password: Password, or None for System/interactive execution.
        :type password: str or None
        """
        _call(self.pointer, 30, [ctypes.c_wchar_p, ctypes.c_wchar_p], name, password)

    def triggers(self):
        """Read each task trigger into its independent fixed-size record.

        :returns: Native TASK_TRIGGER records in scheduler order.
        :rtype: list
        """
        count = _WORD()
        _call(self.pointer, 5, [ctypes.POINTER(_WORD)], ctypes.byref(count))
        result = []
        for index in range(count.value):
            pointer = _POINTER()
            _call(
                self.pointer,
                6,
                [_WORD, ctypes.POINTER(_POINTER)],
                index,
                ctypes.byref(pointer),
            )
            try:
                value = Trigger(size=ctypes.sizeof(Trigger))
                _call(pointer, 4, [ctypes.POINTER(Trigger)], ctypes.byref(value))
                result.append(value)
            finally:
                _release(pointer)
        return result

    def set_triggers(self, triggers):
        """Replace task triggers without persisting intermediate definitions.

        :param list triggers: Fully validated native TASK_TRIGGER records.
        """
        count = _WORD()
        _call(self.pointer, 5, [ctypes.POINTER(_WORD)], ctypes.byref(count))
        for index in reversed(range(count.value)):
            _call(self.pointer, 4, [_WORD], index)
        for trigger in triggers:
            index, pointer = _WORD(), _POINTER()
            _call(
                self.pointer,
                3,
                [ctypes.POINTER(_WORD), ctypes.POINTER(_POINTER)],
                ctypes.byref(index),
                ctypes.byref(pointer),
            )
            try:
                _call(pointer, 3, [ctypes.POINTER(Trigger)], ctypes.byref(trigger))
            finally:
                _release(pointer)

    def time(self, slot):
        """Read a local SYSTEMTIME without inventing dates for never-run tasks.

        :param int slot: Native next/last run time getter slot.
        :returns: Local ISO date/time, or None if no run is recorded/planned.
        :rtype: str or None
        """
        value = _SystemTime()
        result = _call(
            self.pointer, slot, [ctypes.POINTER(_SystemTime)], ctypes.byref(value)
        )
        if result != 0 or not value.year:
            return None
        return "{0:04d}-{1:02d}-{2:02d}T{3:02d}:{4:02d}:{5:02d}".format(
            value.year, value.month, value.day, value.hour, value.minute, value.second
        )

    def idle(self):
        """Read the legacy idle threshold and maximum wait, in minutes.

        :returns: Idle minutes and deadline minutes.
        :rtype: tuple
        """
        idle, wait = _WORD(), _WORD()
        _call(
            self.pointer,
            11,
            [ctypes.POINTER(_WORD), ctypes.POINTER(_WORD)],
            ctypes.byref(idle),
            ctypes.byref(wait),
        )
        return idle.value, wait.value

    def save(self):
        """Persist the task through IPersistFile, retaining its registered name."""
        pointer = _POINTER()
        _call(
            self.pointer,
            0,
            [ctypes.POINTER(_Guid), ctypes.POINTER(_POINTER)],
            ctypes.byref(_guid("0000010b-0000-0000-c000-000000000046")),
            ctypes.byref(pointer),
        )
        try:
            _call(pointer, 6, [ctypes.c_wchar_p, ctypes.c_int32], None, 1)
        finally:
            _release(pointer)


class LegacyScheduler:
    """Own a local Task Scheduler 1.0 session and every activated task object."""

    def __init__(self):
        self.cleanup = ExitStack()
        self.ole32 = None
        self.pointer = _POINTER()

    def __enter__(self):
        try:
            self.ole32, _automation = _libraries()
            result = self.ole32.CoInitializeEx(None, 2)
            if (
                result & 0xFFFFFFFF != 0x80010106
            ):  # Existing COM apartments remain owned by their caller.
                _check(result, "CoInitializeEx(Task Scheduler 1.0)")
                self.cleanup.callback(self.ole32.CoUninitialize)
            self.ole32.CoTaskMemFree.argtypes = [_POINTER]
            self.ole32.CoTaskMemFree.restype = None
            class_id = _guid("148bd52a-a2ab-11ce-b11f-00aa00530503")
            interface_id = _guid("148bd527-a2ab-11ce-b11f-00aa00530503")
            _check(
                self.ole32.CoCreateInstance(
                    ctypes.byref(class_id),
                    None,
                    1,
                    ctypes.byref(interface_id),
                    ctypes.byref(self.pointer),
                ),
                "CoCreateInstance(Task Scheduler 1.0)",
            )
            self.cleanup.callback(_release, self.pointer)
            return self
        except BaseException:
            self.cleanup.close()
            raise

    def __exit__(self, *arguments):
        self.cleanup.__exit__(*arguments)

    def names(self):
        """Enumerate visible native task names, excluding the .job suffix.

        :returns: Task names in the service's enumeration order.
        :rtype: list
        """
        pointer = _POINTER()
        _call(self.pointer, 5, [ctypes.POINTER(_POINTER)], ctypes.byref(pointer))
        try:
            result = []
            while True:
                names, count = _POINTER(), _DWORD()
                status = _call(
                    pointer,
                    3,
                    [_DWORD, ctypes.POINTER(_POINTER), ctypes.POINTER(_DWORD)],
                    1,
                    ctypes.byref(names),
                    ctypes.byref(count),
                )
                try:
                    if count.value:
                        item = ctypes.cast(names, ctypes.POINTER(_POINTER))[0]
                        try:
                            name = ctypes.wstring_at(item)
                            result.append(
                                name[:-4] if name.lower().endswith(".job") else name
                            )
                        finally:
                            self.ole32.CoTaskMemFree(item)
                finally:
                    if names:
                        self.ole32.CoTaskMemFree(names)
                if status == 1 or count.value == 0:
                    return result
        finally:
            _release(pointer)

    def task(self, name, create=False):
        """Activate an existing task or construct an unsaved new task.

        :param str name: Public task name, excluding only the storage suffix.
        :param bool create: Construct instead of activating an existing task.
        :returns: Owned native task object.
        :rtype: LegacyTask
        """
        pointer = _POINTER()
        identifier = _guid(_TASK_ID)
        types = [ctypes.c_wchar_p, ctypes.POINTER(_Guid), ctypes.POINTER(_POINTER)]
        # Task Scheduler 1.0 interprets a dotted name as a filename and rejects
        # extensions other than .job. Append the storage suffix explicitly so
        # dots, including a public name ending in .job, remain part of the name.
        values = [name + ".job", ctypes.byref(identifier), ctypes.byref(pointer)]
        if create:
            types.insert(1, ctypes.POINTER(_Guid))
            values.insert(1, ctypes.byref(_guid(_TASK_CLASS)))
        _call(self.pointer, 8 if create else 6, types, *values)
        return LegacyTask(self, pointer)

    def delete(self, name):
        """Delete the exact named task through the scheduler service.

        :param str name: Public task name, excluding only the storage suffix.
        """
        _call(self.pointer, 7, [ctypes.c_wchar_p], name + ".job")
