# -*- coding: utf-8 -*-
# Copyright 2026 Joe Lustri
# SPDX-License-Identifier: GPL-3.0-or-later

"""Inspect Windows Installer products without opening an installation session."""

import ctypes
import os
import uuid


class _Guid(ctypes.Structure):  # pylint: disable=too-few-public-methods
    # Repeat the fixed Windows record layout without adding a staging dependency.
    # pylint: disable=duplicate-code
    _fields_ = [
        ("data1", ctypes.c_uint32),
        ("data2", ctypes.c_uint16),
        ("data3", ctypes.c_uint16),
        ("data4", ctypes.c_ubyte * 8),
    ]
    # pylint: enable=duplicate-code


def _error(status):
    if status:
        raise ctypes.WinError(status)


class WindowsInstaller:
    """Own COM initialization and native Windows Installer metadata handles."""

    def __init__(self):
        self.library = None
        self.ole = None
        self._uninitialize = False

    def __enter__(self):
        if os.name != "nt":
            raise OSError("Windows Installer requires a Windows target.")
        self.ole = ctypes.WinDLL("ole32")
        self.ole.CoInitializeEx.argtypes = [ctypes.c_void_p, ctypes.c_uint32]
        self.ole.CoInitializeEx.restype = ctypes.c_int32
        self.ole.CoUninitialize.argtypes = []
        self.ole.CoUninitialize.restype = None
        self.ole.GetClassFile.argtypes = [ctypes.c_wchar_p, ctypes.POINTER(_Guid)]
        self.ole.GetClassFile.restype = ctypes.c_int32
        status = self.ole.CoInitializeEx(None, 2)
        if status not in (0, 1, -2147417850):  # RPC_E_CHANGED_MODE retains caller COM.
            raise OSError(
                "CoInitializeEx failed (HRESULT 0x{0:08X}).".format(status & 0xFFFFFFFF)
            )
        self._uninitialize = status in (0, 1)
        try:
            self.library = ctypes.WinDLL("msi")
            signatures = {
                "MsiOpenPackageExW": [
                    ctypes.c_wchar_p,
                    ctypes.c_uint32,
                    ctypes.POINTER(ctypes.c_uint32),
                ],
                "MsiGetPropertyW": [
                    ctypes.c_uint32,
                    ctypes.c_wchar_p,
                    ctypes.c_wchar_p,
                    ctypes.POINTER(ctypes.c_uint32),
                ],
                "MsiCloseHandle": [ctypes.c_uint32],
                "MsiQueryProductStateW": [ctypes.c_wchar_p],
                "MsiGetSummaryInformationW": [
                    ctypes.c_uint32,
                    ctypes.c_wchar_p,
                    ctypes.c_uint32,
                    ctypes.POINTER(ctypes.c_uint32),
                ],
                "MsiSummaryInfoGetPropertyW": [
                    ctypes.c_uint32,
                    ctypes.c_uint32,
                    ctypes.POINTER(ctypes.c_uint32),
                    ctypes.POINTER(ctypes.c_int32),
                    ctypes.POINTER(ctypes.c_uint64),
                    ctypes.c_wchar_p,
                    ctypes.POINTER(ctypes.c_uint32),
                ],
            }
            for name, arguments in signatures.items():
                operation = getattr(self.library, name)
                operation.argtypes = arguments
                operation.restype = ctypes.c_uint32
            self.library.MsiQueryProductStateW.restype = ctypes.c_int32
        except Exception:
            self.__exit__(None, None, None)
            raise
        return self

    def __exit__(self, _exc_type, _exc_value, _traceback):
        if self._uninitialize:
            self._uninitialize = False
            self.ole.CoUninitialize()

    def package_type(self, path):
        """Read the compound-file class used by upstream automatic selection.

        :param str path: Literal package filename; its extension is not trusted.
        :returns: ``msi``, ``msp``, or None for any other or unreadable file.
        :rtype: str or None
        """
        value = _Guid()
        if self.ole.GetClassFile(path, ctypes.byref(value)):
            return None
        identifier = uuid.UUID(bytes_le=ctypes.string_at(ctypes.byref(value), 16))
        return {
            uuid.UUID("000c1084-0000-0000-c000-000000000046"): "msi",
            uuid.UUID("000c1086-0000-0000-c000-000000000046"): "msp",
        }.get(identifier)

    def product_state(self, identifier):
        """Return the native installation state for the current user/machine.

        :param str identifier: ProductCode GUID or arbitrary caller identifier.
        :returns: Native INSTALLSTATE; five means installed.
        :rtype: int
        """
        return self.library.MsiQueryProductStateW(identifier)

    def product_code(self, path):
        """Read ProductCode through an explicitly machine-independent handle.

        :param str path: Literal local MSI package path.
        :returns: ProductCode from the package property table.
        :rtype: str
        :raises OSError: Opening or reading the package fails.
        """
        handle = ctypes.c_uint32()
        _error(self.library.MsiOpenPackageExW(path, 1, ctypes.byref(handle)))
        try:
            size = ctypes.c_uint32()
            buffer = ctypes.create_unicode_buffer(1)
            status = self.library.MsiGetPropertyW(
                handle, "ProductCode", buffer, ctypes.byref(size)
            )
            if status not in (0, 234):
                _error(status)
            size.value += 1
            buffer = ctypes.create_unicode_buffer(size.value)
            _error(
                self.library.MsiGetPropertyW(
                    handle, "ProductCode", buffer, ctypes.byref(size)
                )
            )
            return buffer.value
        finally:
            _error(self.library.MsiCloseHandle(handle))

    def summary_property(self, path, property_id):
        """Read one string summary property, retaining exact package identity.

        :param str path: Literal Windows Installer compound-file path.
        :param int property_id: Summary-information property identifier.
        :returns: Native property string.
        :rtype: str
        :raises OSError: Opening or reading summary information fails.
        """
        handle = ctypes.c_uint32()
        _error(self.library.MsiGetSummaryInformationW(0, path, 0, ctypes.byref(handle)))
        try:
            kind = ctypes.c_uint32()
            number = ctypes.c_int32()
            filetime = ctypes.c_uint64()
            size = ctypes.c_uint32()
            buffer = ctypes.create_unicode_buffer(1)
            arguments = (
                handle,
                property_id,
                ctypes.byref(kind),
                ctypes.byref(number),
                ctypes.byref(filetime),
            )
            status = self.library.MsiSummaryInfoGetPropertyW(
                *(arguments + (buffer, ctypes.byref(size)))
            )
            if status not in (0, 234):
                _error(status)
            size.value += 1
            buffer = ctypes.create_unicode_buffer(size.value)
            _error(
                self.library.MsiSummaryInfoGetPropertyW(
                    *(arguments + (buffer, ctypes.byref(size)))
                )
            )
            return buffer.value
        finally:
            _error(self.library.MsiCloseHandle(handle))

    def patches(self):
        """Enumerate current-user and machine patches in native encounter order.

        :returns: Patch/product/context records, including the native user SID.
        :rtype: list
        :raises OSError: Windows Installer cannot enumerate the patch catalogue.
        """
        operation = self.library.MsiEnumPatchesExW
        operation.argtypes = [
            ctypes.c_wchar_p,
            ctypes.c_wchar_p,
            ctypes.c_uint32,
            ctypes.c_uint32,
            ctypes.c_uint32,
            ctypes.c_wchar_p,
            ctypes.c_wchar_p,
            ctypes.POINTER(ctypes.c_uint32),
            ctypes.c_wchar_p,
            ctypes.POINTER(ctypes.c_uint32),
        ]
        operation.restype = ctypes.c_uint32
        rows = []
        while True:
            patch = ctypes.create_unicode_buffer(39)
            product = ctypes.create_unicode_buffer(39)
            context, size = ctypes.c_uint32(), ctypes.c_uint32()
            sid = ctypes.create_unicode_buffer(1)
            arguments = (
                None,
                None,
                7,
                15,
                len(rows),
                patch,
                product,
                ctypes.byref(context),
            )
            status = operation(*(arguments + (sid, ctypes.byref(size))))
            if status == 234:
                size.value += 1
                sid = ctypes.create_unicode_buffer(size.value)
                status = operation(*(arguments + (sid, ctypes.byref(size))))
            if status == 259:
                return rows
            _error(status)
            rows.append(
                {
                    "patch": patch.value,
                    "product": product.value,
                    "context": context.value,
                    "sid": sid.value or None,
                }
            )

    def patch_state(self, patch, product, context):
        """Read the current-user/machine patch state for one product context.

        :param str patch: PatchCode GUID.
        :param str product: ProductCode GUID.
        :param int context: MSIINSTALLCONTEXT value, one, two or four.
        :returns: Native MSIPATCHSTATE value.
        :rtype: int
        :raises OSError: The patch/product is unknown or cannot be inspected.
        """
        operation = self.library.MsiGetPatchInfoExW
        operation.argtypes = [
            ctypes.c_wchar_p,
            ctypes.c_wchar_p,
            ctypes.c_wchar_p,
            ctypes.c_uint32,
            ctypes.c_wchar_p,
            ctypes.c_wchar_p,
            ctypes.POINTER(ctypes.c_uint32),
        ]
        operation.restype = ctypes.c_uint32
        size = ctypes.c_uint32()
        buffer = ctypes.create_unicode_buffer(1)
        arguments = (patch, product, None, context, "State")
        operation(*(arguments + (buffer, ctypes.byref(size))))
        size.value += 1
        buffer = ctypes.create_unicode_buffer(size.value)
        _error(operation(*(arguments + (buffer, ctypes.byref(size)))))
        return int(buffer.value)
