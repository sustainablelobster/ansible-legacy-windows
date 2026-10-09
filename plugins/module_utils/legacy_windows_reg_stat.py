# -*- coding: utf-8 -*-
# Copyright 2026 Joe Lustri
# SPDX-License-Identifier: GPL-3.0-or-later

"""Read registry keys using the reference module's value representation."""

import ctypes
import os
import re

try:
    import winreg
except ImportError:
    winreg = None

HIVES = {
    "HKCC": "HKEY_CURRENT_CONFIG",
    "HKCR": "HKEY_CLASSES_ROOT",
    "HKCU": "HKEY_CURRENT_USER",
    "HKLM": "HKEY_LOCAL_MACHINE",
    "HKU": "HKEY_USERS",
}
_TYPES = {
    0: "REG_NONE",
    1: "REG_SZ",
    2: "REG_EXPAND_SZ",
    3: "REG_BINARY",
    4: "REG_DWORD",
    7: "REG_MULTI_SZ",
    11: "REG_QWORD",
}


def _registry():
    registry = ctypes.WinDLL("advapi32", use_last_error=True)
    registry.RegQueryValueExW.argtypes = [
        ctypes.c_void_p,
        ctypes.c_wchar_p,
        ctypes.c_void_p,
        ctypes.POINTER(ctypes.c_uint32),
        ctypes.c_void_p,
        ctypes.POINTER(ctypes.c_uint32),
    ]
    registry.RegQueryValueExW.restype = ctypes.c_long
    registry.RegEnumValueW.argtypes = [
        ctypes.c_void_p,
        ctypes.c_uint32,
        ctypes.c_wchar_p,
        ctypes.POINTER(ctypes.c_uint32),
        ctypes.c_void_p,
        ctypes.c_void_p,
        ctypes.c_void_p,
        ctypes.c_void_p,
    ]
    registry.RegEnumValueW.restype = ctypes.c_long
    return registry


def _kernel():
    kernel = ctypes.WinDLL("kernel32", use_last_error=True)
    # These fixed Win32 signatures also serve the environment helper. Keeping
    # them local avoids staging its unrelated environment-writing operations.
    # pylint: disable=duplicate-code
    kernel.ExpandEnvironmentStringsW.argtypes = [
        ctypes.c_wchar_p,
        ctypes.c_wchar_p,
        ctypes.c_uint32,
    ]
    kernel.ExpandEnvironmentStringsW.restype = ctypes.c_uint32
    kernel.CompareStringW.argtypes = [
        ctypes.c_uint32,
        ctypes.c_uint32,
        ctypes.c_wchar_p,
        ctypes.c_int,
        ctypes.c_wchar_p,
        ctypes.c_int,
    ]
    kernel.CompareStringW.restype = ctypes.c_int
    # pylint: enable=duplicate-code
    return kernel


def _expand(value):
    if not value:
        return value
    capacity = 128
    kernel = _kernel()
    # Environment reads need this same short Win32 resize loop. Keeping it
    # local avoids another staged target helper for a single API operation.
    # pylint: disable=duplicate-code
    while True:
        buffer = ctypes.create_unicode_buffer(capacity)
        required = kernel.ExpandEnvironmentStringsW(value, buffer, capacity)
        if not required:
            raise ctypes.WinError(ctypes.get_last_error())
        if required <= capacity:
            return buffer.value
        capacity = required
    # pylint: enable=duplicate-code


def _decode_value(kind, data, error, expand):
    if kind in (0, 3, 5) or (kind in (4, 11) and len(data) > 8):
        return list(bytearray(data))
    if kind in (4, 11):
        return int.from_bytes(data, byteorder="little", signed=True)
    value = data.decode("utf-16-le", "surrogatepass")
    if kind == 7:
        if error or not value:
            return []
        if not value.endswith("\0"):
            value += "\0"
        values = value.split("\0")[:-1]
        # An empty string at the very end is the extra list terminator.
        if values and not values[-1]:
            values.pop()
        return values
    if value.endswith("\0"):
        value = value[:-1]
    return _expand(value) if kind == 2 and expand else value


def _read_value(registry, key, name, expand):
    kind = ctypes.c_uint32()
    size = ctypes.c_uint32()
    query = registry.RegQueryValueExW
    error = query(int(key), name, None, ctypes.byref(kind), None, ctypes.byref(size))
    if error not in (0, 234):
        return None, 0
    value_kind = kind.value
    if value_kind not in _TYPES and value_kind != 5:
        return None, 0
    capacity = size.value
    if value_kind in (1, 2, 7):
        capacity += capacity % 2
    elif value_kind in (4, 11):
        capacity = 4 if value_kind == 4 and capacity <= 4 else max(8, capacity)
    buffer = ctypes.create_string_buffer(capacity)
    # Framework allocates zero-filled storage and does not retry its second
    # read. Preserve that behavior if a value changes between the two calls.
    if value_kind in (1, 2, 7):
        size.value = capacity
    error = query(int(key), name, None, ctypes.byref(kind), buffer, ctypes.byref(size))
    return _decode_value(value_kind, buffer.raw, error, expand), capacity


def _property(registry, key, name):
    value, capacity = _read_value(registry, key, name, True)
    if value is None:
        return None
    raw_value, _ = _read_value(registry, key, name, False)
    kind = ctypes.c_uint32(1)
    if name and not _names_equal(name, ""):
        size = ctypes.c_uint32()
        error = registry.RegQueryValueExW(
            int(key), name, None, ctypes.byref(kind), None, ctypes.byref(size)
        )
        if error:
            raise ctypes.WinError(error)
    if kind.value in (0, 3):
        raw_value = ["0x{0:02x}".format(byte) for byte in value]
    elif kind.value in (4, 11):
        bits = 32 if kind.value == 4 else 64
        if not isinstance(value, int):
            raise ValueError("Registry integer value contains too many bytes.")
        if value < 0:
            value += 1 << (capacity * 8)
        if not 0 <= value < (1 << bits):
            raise ValueError("Registry integer value is outside its unsigned range.")
        raw_value = value
    return {
        "type": _TYPES.get(kind.value, "Unknown - Unknown"),
        "value": value,
        "raw_value": raw_value,
    }


def read_value(key, name, expand=False):
    """Read a value and its actual kind from an already open registry key.

    Unlike the public ``win_reg_stat`` representation, integers remain signed
    and an unnamed value retains its actual storage kind. This is the raw
    representation used when comparing registry edits.

    :param key: Open Windows registry key owned by the caller.
    :type key: winreg.HKEYType
    :param name: Value name, or an empty string for the default value.
    :type name: str
    :param expand: Expand environment references in expandable strings.
    :type expand: bool
    :returns: Value and native kind, or ``(None, None)`` if not readable.
    :rtype: tuple
    :raises OSError: If querying the kind or expanding the value fails.
    """
    registry = _registry()
    value, _ = _read_value(registry, key, name, expand)
    if value is None:
        return None, None
    kind = ctypes.c_uint32()
    size = ctypes.c_uint32()
    error = registry.RegQueryValueExW(
        int(key), name, None, ctypes.byref(kind), None, ctypes.byref(size)
    )
    if error:
        raise ctypes.WinError(error)
    return value, kind.value


def _value_names(registry, key):
    count = winreg.QueryInfoKey(key)[1]
    names = []
    for index in range(count):
        buffer = ctypes.create_unicode_buffer(16384)
        size = ctypes.c_uint32(len(buffer))
        error = registry.RegEnumValueW(
            int(key), index, buffer, ctypes.byref(size), None, None, None, None
        )
        if error:
            raise ctypes.WinError(error)
        names.append(buffer.value)
    return names


def _names_equal(left, right):
    if left == right:
        return True
    comparison = _kernel().CompareStringW(
        0x7F,
        1,
        left,
        len(left.encode("utf-16-le", "surrogatepass")) // 2,
        right,
        len(right.encode("utf-16-le", "surrogatepass")) // 2,
    )
    if not comparison:
        raise ctypes.WinError(ctypes.get_last_error())
    return comparison == 2


def _store_property(properties, name, value):
    for existing in properties:
        if _names_equal(existing, name):
            properties[existing] = value
            return
    properties[name] = value


def query_key(hive, subkey, name=None):
    """Read a registry key or one of its values without changing registry state.

    The target process determines the registry view. Named binary values are
    integer lists, with hexadecimal strings in ``raw_value``. The reference always
    labels a defined default value ``REG_SZ``, regardless of its storage kind.

    :param hive: Short hive name, such as ``HKCU``.
    :type hive: str
    :param subkey: Registry path after the hive and leading separator.
    :type subkey: str
    :param name: Value name, ``""`` for the default, or ``None`` for all values.
    :type name: str or None
    :returns: An ``exists`` flag and the requested value or key information.
    :rtype: dict
    :raises ValueError: If the hive or subkey is invalid, a malformed integer
        cannot be represented, or the target is not Windows.
    :raises OSError: If access, enumeration, or native value conversion fails.
    """
    if os.name != "nt":
        raise ValueError("Registry operations require a Windows target.")
    if hive not in HIVES:
        raise ValueError("Unknown registry hive: {0}".format(hive))
    if subkey is None or any(
        len(part.encode("utf-16-le", "surrogatepass")) // 2 > 255
        for part in subkey.split("\\")
    ):
        raise ValueError("Registry key names must contain at most 255 UTF-16 units.")
    subkey = subkey[:1] + re.sub(r"\\{2,}", r"\\", subkey[1:])
    subkey = subkey[:-1] if subkey.endswith("\\") else subkey
    # Framework validates the full string before its WCHAR API truncates at NUL;
    # Python 3.4's winreg rejects embedded NUL instead of passing that prefix.
    subkey = subkey.split("\0", 1)[0]
    try:
        key = winreg.OpenKey(getattr(winreg, HIVES[hive]), subkey, 0, winreg.KEY_READ)
    except OSError as error:
        if getattr(error, "winerror", None) in (5, 1346):
            raise
        return {"exists": False}
    with key:
        registry = _registry()
        if name is not None:
            value = _property(registry, key, name)
            if value is None:
                return {"exists": False}
            value["exists"] = True
            return value
        properties = {}
        for value_name in _value_names(registry, key):
            _store_property(
                properties, value_name, _property(registry, key, value_name)
            )
        default = _property(registry, key, "")
        if default is not None:
            _store_property(properties, "", default)
        count = winreg.QueryInfoKey(key)[0]
        return {
            "exists": True,
            "properties": properties,
            "sub_keys": [winreg.EnumKey(key, index) for index in range(count)],
        }
