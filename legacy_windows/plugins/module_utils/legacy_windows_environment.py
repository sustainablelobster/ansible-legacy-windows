# -*- coding: utf-8 -*-
# Copyright 2026 sustainablelobster
# SPDX-License-Identifier: GPL-3.0-or-later

"""Read and change Windows environment variables without a managed runtime."""

import ctypes
import os

try:
    import winreg
except ImportError:
    winreg = None

_MACHINE_KEY = r"SYSTEM\CurrentControlSet\Control\Session Manager\Environment"
_NAME_LIMITS = {"process": 32767, "machine": 1024, "user": 255}


def _kernel():
    if os.name != "nt":
        raise ValueError("Environment operations require a Windows target.")
    kernel = ctypes.WinDLL("kernel32", use_last_error=True)
    kernel.GetEnvironmentVariableW.argtypes = [
        ctypes.c_wchar_p,
        ctypes.c_wchar_p,
        ctypes.c_uint32,
    ]
    kernel.GetEnvironmentVariableW.restype = ctypes.c_uint32
    kernel.SetEnvironmentVariableW.argtypes = [ctypes.c_wchar_p, ctypes.c_wchar_p]
    kernel.SetEnvironmentVariableW.restype = ctypes.c_int
    kernel.ExpandEnvironmentStringsW.argtypes = [
        ctypes.c_wchar_p,
        ctypes.c_wchar_p,
        ctypes.c_uint32,
    ]
    kernel.ExpandEnvironmentStringsW.restype = ctypes.c_uint32
    # Matching uses these same fixed NLS signatures. Keeping them here lets
    # environment operations stage only their own native helper.
    # pylint: disable=duplicate-code
    kernel.CompareStringW.argtypes = [
        ctypes.c_uint32,
        ctypes.c_uint32,
        ctypes.c_wchar_p,
        ctypes.c_int,
        ctypes.c_wchar_p,
        ctypes.c_int,
    ]
    kernel.CompareStringW.restype = ctypes.c_int
    kernel.LCMapStringW.argtypes = [
        ctypes.c_uint32,
        ctypes.c_uint32,
        ctypes.c_wchar_p,
        ctypes.c_int,
        ctypes.c_wchar_p,
        ctypes.c_int,
    ]
    kernel.LCMapStringW.restype = ctypes.c_int
    # pylint: enable=duplicate-code
    return kernel


def _utf16_length(value):
    return len(value.encode("utf-16-le", "surrogatepass")) // 2


def _registry_location(level):
    if os.name != "nt":
        raise ValueError("Environment operations require a Windows target.")
    if level == "user":
        return winreg.HKEY_CURRENT_USER, "Environment"
    if level == "machine":
        return winreg.HKEY_LOCAL_MACHINE, _MACHINE_KEY
    raise ValueError("Environment level must be process, user, or machine.")


def _get_process(name):
    kernel = _kernel()
    capacity = 128
    while True:
        buffer = ctypes.create_unicode_buffer(capacity)
        ctypes.set_last_error(0)
        required = kernel.GetEnvironmentVariableW(name, buffer, capacity)
        if not required:
            error = ctypes.get_last_error()
            if error == 203:
                return None
            # The reference Framework getter treats other zero returns as empty.
            return ""
        if required < capacity:
            return buffer.value
        capacity = required + 1


def _expand(value):
    kernel = _kernel()
    capacity = 256
    while True:
        buffer = ctypes.create_unicode_buffer(capacity)
        required = kernel.ExpandEnvironmentStringsW(value, buffer, capacity)
        if not required:
            raise ctypes.WinError(ctypes.get_last_error())
        if required <= capacity:
            return buffer.value
        capacity = required


def get_value(name, level):
    """Read a process or persisted environment value.

    Registry expansion uses the current native process environment. Non-string
    registry values are not environment strings and return ``None``.
    Process reads return ``None`` for a missing variable, but treat other native
    zero returns as an empty string, matching the reference Framework getter.

    :param name: Variable name; Windows performs case-insensitive lookup.
    :type name: str
    :param level: One of ``process``, ``user``, or ``machine``.
    :type level: str
    :returns: The value, including an empty string, or ``None`` if absent.
    :rtype: str or None
    :raises ValueError: If the name is None, the level is invalid, or the host
        is not Windows.
    :raises OSError: If a registry read or expansion fails.
    """
    if name is None:
        raise ValueError("Environment variable name must not be null.")
    if level == "process":
        return _get_process(name)
    hive, path = _registry_location(level)
    try:
        with winreg.OpenKey(hive, path, 0, winreg.KEY_READ) as key:
            value, kind = winreg.QueryValueEx(key, name)
    except OSError as error:
        if getattr(error, "winerror", None) in (2, 3):
            return None
        raise
    if kind == winreg.REG_EXPAND_SZ:
        return _expand(value)
    return value if kind == winreg.REG_SZ else None


def _validate_set(name, value, level):
    if level not in _NAME_LIMITS:
        raise ValueError("Environment level must be process, user, or machine.")
    if not name or name[0] == "\0" or "=" in name:
        raise ValueError(
            "Environment variable name must be nonempty and contain no '='."
        )
    if _utf16_length(name) >= _NAME_LIMITS[level]:
        raise ValueError(
            "Environment variable name must contain fewer than {0} UTF-16 "
            "characters for level {1}.".format(_NAME_LIMITS[level], level)
        )
    if value and value[0] != "\0" and level == "process":
        if _utf16_length(value) >= 32767:
            raise ValueError(
                "Process environment value must contain fewer than 32767 "
                "UTF-16 characters."
            )


def _broadcast(flags, timeout, checked):
    if os.name != "nt":
        raise ValueError("Environment operations require a Windows target.")
    user = ctypes.WinDLL("user32", use_last_error=True)
    user.SendMessageTimeoutW.argtypes = [
        ctypes.c_void_p,
        ctypes.c_uint32,
        ctypes.c_size_t,
        ctypes.c_wchar_p,
        ctypes.c_uint32,
        ctypes.c_uint32,
        ctypes.POINTER(ctypes.c_size_t),
    ]
    user.SendMessageTimeoutW.restype = ctypes.c_ssize_t
    result = ctypes.c_size_t()
    ctypes.set_last_error(0)
    success = user.SendMessageTimeoutW(
        0xFFFF, 0x1A, 0, "Environment", flags, timeout, ctypes.byref(result)
    )
    if not success and checked:
        error = ctypes.get_last_error()
        if error:
            raise ctypes.WinError(error)
        raise OSError(
            "SendMessageTimeoutW failed to broadcast the environment change; "
            "Windows did not report an error code."
        )


def set_value(name, value, level):
    """Set or remove a process or persisted environment value.

    Empty values and values beginning with NUL mean removal, matching the
    reference Framework setter. Persisted writes use REG_SZ and do not change
    this process's environment. A missing registry key is not created.
    Persisted operations also send the Framework's unchecked notification;
    callers must separately call :func:`broadcast_change` after a change.

    :param name: Variable name; Windows performs case-insensitive lookup.
    :type name: str
    :param value: New value, or ``None`` to delete the variable.
    :type value: str or None
    :param level: One of ``process``, ``user``, or ``machine``.
    :type level: str
    :raises ValueError: If a setter argument is invalid or the host is not Windows.
    :raises OSError: If a native write fails.
    """
    _validate_set(name, value, level)
    if not value or value[0] == "\0":
        value = None
    if level == "process":
        if not _kernel().SetEnvironmentVariableW(name, value):
            error = ctypes.get_last_error()
            if error != 203:
                raise ctypes.WinError(error)
        return
    hive, path = _registry_location(level)
    try:
        key = winreg.OpenKey(hive, path, 0, winreg.KEY_READ | winreg.KEY_WRITE)
    except OSError as error:
        if getattr(error, "winerror", None) not in (2, 3):
            raise
    else:
        with key:
            if value is None:
                try:
                    winreg.DeleteValue(key, name)
                except OSError as error:
                    if getattr(error, "winerror", None) != 2:
                        raise
            else:
                winreg.SetValueEx(key, name, 0, winreg.REG_SZ, value)
    _broadcast(0, 1000, False)


def broadcast_change():
    """Send the module's checked environment-change notification.

    Each recipient has a five-second timeout. This does not update environment
    snapshots in processes that do not handle WM_SETTINGCHANGE.

    :raises ValueError: If called outside Windows.
    :raises OSError: If SendMessageTimeoutW reports failure or timeout.
    """
    _broadcast(2, 5000, True)


def values_equal(left, right, invariant=True):
    """Compare strings with Windows case-insensitive collation.

    Native collation tables belong to the target's Windows version.

    :param left: Existing environment string or ``None``.
    :type left: str or None
    :param right: Requested environment string or ``None``.
    :type right: str or None
    :param invariant: Use invariant collation by default. False selects the
        user's culture, as required for registry-provider value-name aliases.
    :type invariant: bool
    :returns: Whether the values compare equal; ``None`` differs from ``""``.
    :rtype: bool
    :raises ValueError: If native comparison is needed outside Windows.
    :raises OSError: If native comparison fails.
    """
    if left is None or right is None:
        return left is right
    result = _kernel().CompareStringW(
        0x7F if invariant else 0x400,
        1,
        left,
        _utf16_length(left),
        right,
        _utf16_length(right),
    )
    if not result:
        raise ctypes.WinError(ctypes.get_last_error())
    return result == 2


def name_key(name):
    """Build a simple invariant-uppercase key for JSON variable names.

    This ordinal-style key keeps UTF-16 units, including NUL and surrogate
    halves, distinct. It does not use linguistic collation or expand characters
    into multiple units. Native case tables belong to the Windows version.

    :param name: A raw variable dictionary key, before setter validation.
    :type name: str
    :returns: The uppercase UTF-16-unit string used to detect duplicate keys.
    :rtype: str
    :raises ValueError: If called outside Windows.
    :raises OSError: If native uppercase mapping fails.
    """
    kernel = _kernel()
    encoded = name.encode("utf-16-le", "surrogatepass")
    uppercase = {}
    result = []
    for index in range(0, len(encoded), 2):
        unit = encoded[index] | (encoded[index + 1] << 8)
        character = chr(unit)
        if unit == 0 or 0xD800 <= unit <= 0xDFFF:
            result.append(character)
            continue
        if character not in uppercase:
            buffer = ctypes.create_unicode_buffer(1)
            if not kernel.LCMapStringW(0x7F, 0x200, character, 1, buffer, 1):
                raise ctypes.WinError(ctypes.get_last_error())
            uppercase[character] = buffer[0]
        result.append(uppercase[character])
    return "".join(result)
