# -*- coding: utf-8 -*-
# Copyright 2026 sustainablelobster
# SPDX-License-Identifier: GPL-3.0-or-later

"""Independently start one already-registered native Task Scheduler 1.0 task."""

import ctypes
import json
import sys
import uuid


# These fixed COM ABI records and slots follow Microsoft's mstask.h. This
# fixture deliberately does not import the collection's scheduler bindings.
# pylint: disable=too-few-public-methods,duplicate-code
class _Guid(ctypes.Structure):
    _fields_ = [
        ("data1", ctypes.c_uint32),
        ("data2", ctypes.c_uint16),
        ("data3", ctypes.c_uint16),
        ("data4", ctypes.c_ubyte * 8),
    ]


# pylint: enable=duplicate-code


def _guid(value):
    return _Guid.from_buffer_copy(uuid.UUID(value).bytes_le)


def _check(result, operation):
    if result & 0x80000000:
        raise OSError("{0}: HRESULT 0x{1:08X}".format(operation, result & 0xFFFFFFFF))


def _method(pointer, slot, result, arguments):
    table = ctypes.cast(pointer, ctypes.POINTER(ctypes.POINTER(ctypes.c_void_p)))[0]
    return ctypes.WINFUNCTYPE(result, ctypes.c_void_p, *arguments)(table[slot])


def _release(pointer):
    if pointer:
        _method(pointer, 2, ctypes.c_uint32, [])(pointer)


def run_task(name):
    """Start the exact public name using ITaskScheduler.Activate and ITask.Run.

    :param str name: Public task name, including any dots or .job ending.
    :returns: Successful native start operation and the exact public name.
    :rtype: dict
    :raises OSError: Native scheduler activation or execution fails.
    """
    pointer, task = ctypes.c_void_p(), ctypes.c_void_p()
    # Declare the fixed COM entry points independently: importing production
    # bindings would make this scheduler execution check circular.
    # pylint: disable=duplicate-code
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
    # pylint: enable=duplicate-code
    initialized = ole.CoInitializeEx(None, 2)
    _check(initialized, "CoInitializeEx")
    try:
        _check(
            ole.CoCreateInstance(
                ctypes.byref(_guid("148bd52a-a2ab-11ce-b11f-00aa00530503")),
                None,
                1,
                ctypes.byref(_guid("148bd527-a2ab-11ce-b11f-00aa00530503")),
                ctypes.byref(pointer),
            ),
            "CoCreateInstance(ITaskScheduler)",
        )
        activate = _method(
            pointer,
            6,
            ctypes.c_int32,
            [
                ctypes.c_wchar_p,
                ctypes.POINTER(_Guid),
                ctypes.POINTER(ctypes.c_void_p),
            ],
        )
        _check(
            activate(
                pointer,
                name + ".job",
                ctypes.byref(_guid("148bd524-a2ab-11ce-b11f-00aa00530503")),
                ctypes.byref(task),
            ),
            "ITaskScheduler.Activate",
        )
        _check(_method(task, 12, ctypes.c_int32, [])(task), "ITask.Run")
        return {"started": True, "name": name, "launcher": "ITask.Run"}
    finally:
        _release(task)
        _release(pointer)
        ole.CoUninitialize()


if __name__ == "__main__":
    print(json.dumps(run_task(sys.argv[1]), ensure_ascii=True))
