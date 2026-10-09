# -*- coding: utf-8 -*-
# Copyright 2026 Joe Lustri
# SPDX-License-Identifier: GPL-3.0-or-later

"""Read and change local user-right assignments through the LSA policy API."""

import ctypes
import os
from contextlib import contextmanager

import legacy_windows_account as accounts  # pylint: disable=import-error


# These records mirror the native ABI and have no independent behavior.
class _ObjectAttributes(ctypes.Structure):  # pylint: disable=too-few-public-methods
    _fields_ = [
        ("length", ctypes.c_uint32),
        ("root_directory", ctypes.c_void_p),
        ("object_name", ctypes.c_void_p),
        ("attributes", ctypes.c_uint32),
        ("security_descriptor", ctypes.c_void_p),
        ("security_quality_of_service", ctypes.c_void_p),
    ]


class _UnicodeString(ctypes.Structure):  # pylint: disable=too-few-public-methods
    _fields_ = [
        ("length", ctypes.c_uint16),
        ("maximum_length", ctypes.c_uint16),
        ("buffer", ctypes.c_wchar_p),
    ]


def _libraries():
    if os.name != "nt":
        raise OSError("User-right operations require a Windows target.")
    library = ctypes.WinDLL("advapi32", use_last_error=True)
    pointer = ctypes.c_void_p
    string_pointer = ctypes.POINTER(_UnicodeString)
    signatures = {
        "LsaOpenPolicy": [
            string_pointer,
            ctypes.POINTER(_ObjectAttributes),
            ctypes.c_uint32,
            ctypes.POINTER(pointer),
        ],
        "LsaEnumerateAccountsWithUserRight": [
            pointer,
            string_pointer,
            ctypes.POINTER(pointer),
            ctypes.POINTER(ctypes.c_uint32),
        ],
        "LsaAddAccountRights": [pointer, pointer, string_pointer, ctypes.c_uint32],
        "LsaRemoveAccountRights": [
            pointer,
            pointer,
            ctypes.c_ubyte,
            string_pointer,
            ctypes.c_uint32,
        ],
        "LsaFreeMemory": [pointer],
        "LsaClose": [pointer],
        "LsaNtStatusToWinError": [ctypes.c_int32],
    }
    for name, arguments in signatures.items():
        function = getattr(library, name)
        function.argtypes = arguments
        function.restype = ctypes.c_uint32
    library.ConvertStringSidToSidW.argtypes = [
        ctypes.c_wchar_p,
        ctypes.POINTER(pointer),
    ]
    library.ConvertStringSidToSidW.restype = ctypes.c_int32
    kernel = ctypes.WinDLL("kernel32", use_last_error=True)
    kernel.LocalFree.argtypes = [pointer]
    kernel.LocalFree.restype = pointer
    return library, kernel


def _right_string(name):
    length = len(name.encode("utf-16-le"))
    if length > 0xFFFC:
        raise ValueError("String too long")
    return _UnicodeString(length, length + 2, name)


def _check_status(library, status):
    if status:
        code = library.LsaNtStatusToWinError(ctypes.c_int32(status).value)
        raise ctypes.WinError(ctypes.c_int32(code).value)


class _Policy:
    def __init__(self, library, kernel, handle):
        self._library = library
        self._kernel = kernel
        self._handle = handle

    def accounts(self, name):
        """Enumerate assigned SIDs, preserving the native policy order.

        :param name: Windows privilege or logon-right constant.
        :type name: str
        :returns: Canonical SID strings, including unmapped SIDs.
        :rtype: list
        :raises ValueError: The right is unknown or its name is too long.
        :raises OSError: Native enumeration or SID conversion fails.
        """
        right = _right_string(name)
        buffer = ctypes.c_void_p()
        count = ctypes.c_uint32()
        try:
            status = (
                self._library.LsaEnumerateAccountsWithUserRight(
                    self._handle,
                    ctypes.byref(right),
                    ctypes.byref(buffer),
                    ctypes.byref(count),
                )
                & 0xFFFFFFFF
            )
            if status == 0x8000001A:
                return []
            if status == 0xC0000060:
                raise ValueError("Invalid user right: " + name)
            _check_status(self._library, status)
            entries = ctypes.cast(buffer, ctypes.POINTER(ctypes.c_void_p))
            return [
                accounts.sid_to_string(entries[index]) for index in range(count.value)
            ]
        finally:
            if buffer:
                self._library.LsaFreeMemory(buffer)

    def _change(self, sid, name, remove):
        right = _right_string(name)
        pointer = ctypes.c_void_p()
        try:
            if not self._library.ConvertStringSidToSidW(sid, ctypes.byref(pointer)):
                raise ctypes.WinError(ctypes.get_last_error())
            arguments = [self._handle, pointer]
            if remove:
                # BOOLEAN is one byte, and false limits removal to this right.
                arguments.append(0)
                function = self._library.LsaRemoveAccountRights
            else:
                function = self._library.LsaAddAccountRights
            arguments.extend([ctypes.byref(right), 1])
            _check_status(self._library, function(*arguments))
        finally:
            if pointer:
                self._kernel.LocalFree(pointer)

    def add(self, sid, name):
        """Assign one right to an account SID.

        :param sid: Canonical numeric SID string.
        :type sid: str
        :param name: Windows privilege or logon-right constant.
        :type name: str
        :raises ValueError: The right name is too long.
        :raises OSError: Native SID conversion or assignment fails.
        """
        self._change(sid, name, False)

    def remove(self, sid, name):
        """Remove only the named right from an account SID.

        :param sid: Canonical numeric SID string.
        :type sid: str
        :param name: Windows privilege or logon-right constant.
        :type name: str
        :raises ValueError: The right name is too long.
        :raises OSError: Native SID conversion or removal fails.
        """
        self._change(sid, name, True)


@contextmanager
def open_policy():
    """Open the local LSA policy for a complete user-right operation.

    :returns: Context manager yielding an object exposing ``accounts(name)``,
        ``add(sid, name)``, and ``remove(sid, name)`` while its handle is open.
    :rtype: context manager
    :raises OSError: The target is not Windows or policy access is denied.
    """
    library, kernel = _libraries()
    attributes = _ObjectAttributes(ctypes.sizeof(_ObjectAttributes))
    handle = ctypes.c_void_p()
    try:
        _check_status(
            library,
            library.LsaOpenPolicy(
                None, ctypes.byref(attributes), 0xF0FFF, ctypes.byref(handle)
            ),
        )
        yield _Policy(library, kernel, handle)
    finally:
        if handle:
            library.LsaClose(handle)
