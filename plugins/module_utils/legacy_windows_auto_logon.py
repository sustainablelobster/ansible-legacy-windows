# -*- coding: utf-8 -*-
# Copyright 2026 Joe Lustri
# SPDX-License-Identifier: GPL-3.0-or-later

"""Read Winlogon values and manage its password in the native LSA store."""

import ctypes
import os

import legacy_windows_account as accounts  # pylint: disable=import-error

try:
    import winreg
except ImportError:
    winreg = None

WINLOGON = r"SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon"
VALUE_NAMES = (
    "AutoAdminLogon",
    "DefaultUserName",
    "DefaultDomainName",
    "AutoLogonCount",
    "DefaultPassword",
)
_NOT_FOUND = 0xC0000034


# These structures describe the native LSA ABI rather than public objects.
# pylint: disable=too-few-public-methods
class _UnicodeString(ctypes.Structure):
    _fields_ = [
        ("length", ctypes.c_uint16),
        ("maximum_length", ctypes.c_uint16),
        ("buffer", ctypes.c_void_p),
    ]


class _ObjectAttributes(ctypes.Structure):
    _fields_ = [
        ("length", ctypes.c_uint32),
        ("root", ctypes.c_void_p),
        ("name", ctypes.c_void_p),
        ("attributes", ctypes.c_uint32),
        ("descriptor", ctypes.c_void_p),
        ("quality", ctypes.c_void_p),
    ]


# pylint: enable=too-few-public-methods


def _lsa():
    if os.name != "nt":
        raise OSError("Automatic logon operations require a Windows target.")
    library = ctypes.WinDLL("advapi32")
    pointer = ctypes.c_void_p
    text = ctypes.POINTER(_UnicodeString)
    signatures = {
        "LsaOpenPolicy": [
            pointer,
            ctypes.POINTER(_ObjectAttributes),
            ctypes.c_uint32,
            ctypes.POINTER(pointer),
        ],
        "LsaRetrievePrivateData": [pointer, text, ctypes.POINTER(pointer)],
        "LsaStorePrivateData": [pointer, text, text],
        "LsaClose": [pointer],
        "LsaFreeMemory": [pointer],
        "LsaNtStatusToWinError": [ctypes.c_uint32],
    }
    for name, arguments in signatures.items():
        function = getattr(library, name)
        function.argtypes = arguments
        function.restype = ctypes.c_uint32
    return library


def _string(value):
    encoded = value.encode("utf-16-le", "surrogatepass")
    buffer = ctypes.create_string_buffer(encoded)
    record = _UnicodeString(
        len(encoded), len(encoded), ctypes.cast(buffer, ctypes.c_void_p)
    )
    # The pointer in the C record borrows this Python-owned allocation.
    # pylint: disable-next=attribute-defined-outside-init
    record.storage = buffer
    return record


def _check(library, status, operation):
    if status:
        code = library.LsaNtStatusToWinError(status)
        raise OSError(
            "{0} - {1} (Win32 Error Code {2}: 0x{2:08X})".format(
                operation, ctypes.FormatError(code).rstrip("\r\n ."), code
            )
        )


class SecretStore:
    """Own a local LSA policy handle for the DefaultPassword private value."""

    def __init__(self):
        self._library = None
        self._handle = ctypes.c_void_p()

    def __enter__(self):
        self._library = _lsa()
        attributes = _ObjectAttributes()
        status = self._library.LsaOpenPolicy(
            None, ctypes.byref(attributes), 0x24, ctypes.byref(self._handle)
        )
        try:
            _check(
                self._library,
                status,
                "LsaOpenPolicy(GetPrivateInformation, CreateSecret) failed",
            )
        except OSError:
            if self._handle:
                self._library.LsaClose(self._handle)
            raise
        return self

    def __exit__(self, exc_type, exc_value, traceback):
        if self._handle:
            self._library.LsaClose(self._handle)
            self._handle = ctypes.c_void_p()

    def read(self):
        """Retrieve the secret, distinguishing an empty value from no value.

        :returns: Stored password, or None when the LSA value is absent.
        :rtype: str or None
        :raises OSError: LSA cannot read the private value.
        """
        key = _string("DefaultPassword")
        pointer = ctypes.c_void_p()
        try:
            status = self._library.LsaRetrievePrivateData(
                self._handle, ctypes.byref(key), ctypes.byref(pointer)
            )
            if status == _NOT_FOUND:
                return None
            _check(
                self._library, status, "LsaRetrievePrivateData(DefaultPassword) failed"
            )
            value = ctypes.cast(pointer, ctypes.POINTER(_UnicodeString)).contents
            return ctypes.string_at(value.buffer, value.length).decode(
                "utf-16-le", "replace"
            )
        finally:
            if pointer:
                self._library.LsaFreeMemory(pointer)

    def write(self, password):
        """Replace or remove the private value without logging its contents.

        :param password: New secret; None removes it and an empty string stores it.
        :type password: str or None
        :raises OSError: LSA rejects the requested change.
        """
        key = _string("DefaultPassword")
        value = None if password is None else _string(password)
        status = self._library.LsaStorePrivateData(
            self._handle,
            ctypes.byref(key),
            ctypes.byref(value) if value is not None else None,
        )
        if password is None and status == _NOT_FOUND:
            return
        _check(self._library, status, "LsaStorePrivateData(DefaultPassword) failed")


def resolve_account(username):
    """Round-trip an account through its SID to its canonical Netlogon name.

    :param str username: Account name accepted by the native account translator.
    :returns: Domain and username, preserving the provider's spelling.
    :rtype: tuple
    :raises ValueError: The supplied account is invalid or cannot be resolved.
    :raises OSError: A native account operation fails.
    """
    try:
        sid = accounts.account_name_to_sid(username)
    except OSError as error:
        if getattr(error, "winerror", error.errno) != 1332:
            raise
        raise ValueError(
            "Failed to find a local or domain user with the name '" + username + "'"
        ) from error
    name = accounts.sid_to_name(sid)
    parts = name.split("\\")
    return (parts[0], parts[1]) if len(parts) > 1 else (parts[0], None)


def _key(access):
    if winreg is None:
        raise OSError("Automatic logon operations require a Windows target.")
    return winreg.OpenKey(
        winreg.HKEY_LOCAL_MACHINE, WINLOGON, 0, access | winreg.KEY_WOW64_64KEY
    )


def read_values():
    """Read existing Winlogon properties from the native registry view.

    :returns: Present property names mapped to their provider-style values.
    :rtype: dict
    :raises OSError: The registry key or a present value cannot be read.
    """
    values = {}
    with _key(1) as key:
        for name in VALUE_NAMES:
            try:
                value, kind = winreg.QueryValueEx(key, name)
            except OSError as error:
                if getattr(error, "winerror", error.errno) == 2:
                    continue
                raise
            if kind == winreg.REG_EXPAND_SZ:
                value = winreg.ExpandEnvironmentStrings(value)
            elif kind == winreg.REG_DWORD and value >= 2**31:
                value -= 2**32
            elif isinstance(value, bytes):
                value = list(bytearray(value))
            values[name] = value
    return values


def write_value(name, value):
    """Write a Winlogon value, preserving an existing provider-inferred type.

    :param str name: Winlogon property name.
    :param value: String or signed 32-bit integer to store.
    :type value: str or int
    :raises OSError: Windows rejects reading the existing type or writing the value.
    """
    kind = winreg.REG_DWORD if isinstance(value, int) else winreg.REG_SZ
    with _key(3) as key:
        # Only the activation property has an explicit DWORD type upstream.
        # Other New-ItemProperty calls retain the kind of an existing value.
        if name != "AutoAdminLogon":
            try:
                unused_value, kind = winreg.QueryValueEx(key, name)
            except OSError as error:
                if getattr(error, "winerror", error.errno) != 2:
                    raise
        if kind in (winreg.REG_SZ, winreg.REG_EXPAND_SZ):
            value = str(value)
        elif kind == winreg.REG_DWORD:
            value &= 0xFFFFFFFF
        winreg.SetValueEx(key, name, 0, kind, value)


def delete_value(name):
    """Remove an existing Winlogon property.

    :param str name: Existing property to remove.
    :raises OSError: Windows rejects the registry deletion.
    """
    with _key(2) as key:
        winreg.DeleteValue(key, name)
