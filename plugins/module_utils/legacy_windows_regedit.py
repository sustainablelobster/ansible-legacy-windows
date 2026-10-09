# -*- coding: utf-8 -*-
# Copyright 2026 Joe Lustri
# SPDX-License-Identifier: GPL-3.0-or-later

"""Native registry writes and offline-hive handling for Python 3.4.4."""

import ctypes
import os
import re

from legacy_windows_module import as_string  # pylint: disable=import-error
from legacy_windows_reg_stat import HIVES  # pylint: disable=import-error

try:
    import winreg
except ImportError:
    winreg = None

KINDS = {
    "none": 0,
    "string": 1,
    "expandstring": 2,
    "binary": 3,
    "dword": 4,
    "multistring": 7,
    "qword": 11,
}


# A Win32 structure declares fields, not a Python behavioral interface.
class _Privilege(ctypes.Structure):  # pylint: disable=too-few-public-methods
    _fields_ = [
        ("count", ctypes.c_uint32),
        ("low", ctypes.c_uint32),
        ("high", ctypes.c_int32),
        ("attributes", ctypes.c_uint32),
    ]


def _registry():
    library = ctypes.WinDLL("advapi32", use_last_error=True)
    # Fixed Win32 argument types can coincide with unrelated APIs; keeping
    # this declaration local avoids importing unrelated filesystem operations.
    # pylint: disable=duplicate-code
    library.RegSetValueExW.argtypes = [
        ctypes.c_void_p,
        ctypes.c_wchar_p,
        ctypes.c_uint32,
        ctypes.c_uint32,
        ctypes.c_void_p,
        ctypes.c_uint32,
    ]
    library.RegSetValueExW.restype = ctypes.c_long
    # pylint: enable=duplicate-code
    library.RegDeleteValueW.argtypes = [ctypes.c_void_p, ctypes.c_wchar_p]
    library.RegDeleteValueW.restype = ctypes.c_long
    library.RegUnLoadKeyW.argtypes = [ctypes.c_void_p, ctypes.c_wchar_p]
    library.RegUnLoadKeyW.restype = ctypes.c_long
    return library


def _root(hive):
    if os.name != "nt":
        raise ValueError("Registry operations require a Windows target.")
    return getattr(winreg, HIVES[hive])


def _subkey(path):
    if any(
        len(part.encode("utf-16-le", "surrogatepass")) // 2 > 255
        for part in path.split("\\")
    ):
        raise ValueError("Registry key names must contain at most 255 UTF-16 units.")
    path = path[:1] + re.sub(r"\\{2,}", r"\\", path[1:])
    return path.rstrip("\\").split("\0", 1)[0]


def open_key(hive, path, create=False):
    """Open a writable key in the Python process's default registry view.

    :param hive: Short hive name such as ``HKCU``.
    :type hive: str
    :param path: Subkey path without the hive prefix.
    :type path: str
    :param create: Create the key and missing ancestors when true.
    :type create: bool
    :returns: A caller-owned key handle, or None when opening fails for a
        non-access error, including a missing key, matching the reference.
    :rtype: winreg.HKEYType or None
    :raises OSError: If opening is denied or creating the key fails.
    :raises ValueError: If a key component is too long or the target is not Windows.
    """
    root = _root(hive)
    path = _subkey(path)
    access = winreg.KEY_READ | winreg.KEY_WRITE
    if create:
        return winreg.CreateKeyEx(root, path, 0, access)
    try:
        return winreg.OpenKey(root, path, 0, access)
    except OSError as error:
        if getattr(error, "winerror", None) in (5, 1346):
            raise
        return None


def set_value(key, name, kind, data):
    """Write converted registry data without Python 3.4's QWORD limitations.

    :param key: Open writable key owned by the caller.
    :type key: winreg.HKEYType
    :param name: Value name, including the empty default name.
    :type name: str
    :param kind: Normalized registry type name.
    :type kind: str
    :param data: Converted data for the selected registry kind.
    :type data: object
    :raises ValueError: If data or the value name is invalid.
    :raises OSError: If Windows rejects the write.
    """
    if len(name.encode("utf-16-le", "surrogatepass")) // 2 > 16383:
        raise ValueError(
            "Registry value names must contain at most 16383 UTF-16 units."
        )
    if kind in ("string", "expandstring"):
        encoded = (as_string(data, "data") + "\0").encode("utf-16-le", "surrogatepass")
    elif kind == "multistring":
        text = "".join(value + "\0" for value in data) + "\0"
        encoded = text.encode("utf-16-le", "surrogatepass")
    elif kind in ("dword", "qword"):
        encoded = data.to_bytes(4 if kind == "dword" else 8, "little", signed=True)
    else:
        if not isinstance(data, list):
            raise ValueError("Binary registry data must be a byte array.")
        encoded = bytes(bytearray(data))
    buffer = ctypes.create_string_buffer(encoded)
    error = _registry().RegSetValueExW(
        int(key), name, 0, KINDS[kind], buffer, len(encoded)
    )
    if error:
        raise ctypes.WinError(error)


def delete_value(key, name):
    """Delete one named or default value from an open writable key.

    :param key: Caller-owned writable registry key.
    :type key: winreg.HKEYType
    :param name: Value name; empty selects the default.
    :type name: str
    :raises OSError: If Windows rejects deletion.
    """
    error = _registry().RegDeleteValueW(int(key), name)
    if error:
        raise ctypes.WinError(error)


def delete_tree(hive, path):
    """Delete a key and its descendants using APIs available on Windows XP.

    :param hive: Short hive name.
    :type hive: str
    :param path: Subkey to remove, without the hive prefix.
    :type path: str
    :raises OSError: If a key cannot be opened or removed; earlier removals remain.
    :raises ValueError: If the supplied subkey is empty or invalid.
    """
    path = _subkey(path)
    if not path:
        raise ValueError("A registry hive root cannot be deleted.")
    key = open_key(hive, path)
    if key is None:
        return
    with key:
        for _ in range(winreg.QueryInfoKey(key)[0]):
            child = winreg.EnumKey(key, 0)
            delete_tree(hive, path + "\\" + child)
    winreg.DeleteKey(_root(hive), path)


def enable_hive_privileges():
    """Enable the process token's existing backup and restore privileges.

    No privileges are granted to the account. Changes end with the module
    process, matching the reference module's privilege lifetime.

    :raises ValueError: If either privilege has been removed from the token.
    :raises OSError: If a native token call fails.
    """
    library = ctypes.WinDLL("advapi32", use_last_error=True)
    kernel = ctypes.WinDLL("kernel32", use_last_error=True)
    library.OpenProcessToken.argtypes = [
        ctypes.c_void_p,
        ctypes.c_uint32,
        ctypes.POINTER(ctypes.c_void_p),
    ]
    library.OpenProcessToken.restype = ctypes.c_int
    library.LookupPrivilegeValueW.argtypes = [
        ctypes.c_wchar_p,
        ctypes.c_wchar_p,
        ctypes.c_void_p,
    ]
    library.LookupPrivilegeValueW.restype = ctypes.c_int
    library.AdjustTokenPrivileges.argtypes = [
        ctypes.c_void_p,
        ctypes.c_int,
        ctypes.c_void_p,
        ctypes.c_uint32,
        ctypes.c_void_p,
        ctypes.c_void_p,
    ]
    library.AdjustTokenPrivileges.restype = ctypes.c_int
    kernel.GetCurrentProcess.argtypes = []
    kernel.GetCurrentProcess.restype = ctypes.c_void_p
    kernel.CloseHandle.argtypes = [ctypes.c_void_p]
    kernel.CloseHandle.restype = ctypes.c_int
    token = ctypes.c_void_p()
    if not library.OpenProcessToken(
        kernel.GetCurrentProcess(), 0x28, ctypes.byref(token)
    ):
        raise ctypes.WinError(ctypes.get_last_error())
    try:
        for name in ("SeBackupPrivilege", "SeRestorePrivilege"):
            privilege = _Privilege(1, 0, 0, 2)
            if not library.LookupPrivilegeValueW(
                None, name, ctypes.byref(privilege, _Privilege.low.offset)
            ):
                raise ctypes.WinError(ctypes.get_last_error())
            ctypes.set_last_error(0)
            success = library.AdjustTokenPrivileges(
                token, False, ctypes.byref(privilege), 0, None, None
            )
            error = ctypes.get_last_error()
            if error == 1300:
                raise ValueError(
                    "Cannot enable the privilege '{0}' as it has been removed "
                    "from the token".format(name)
                )
            # Other helpers use this same short token-error/cleanup sequence.
            # Keeping it here makes ownership of this process token explicit.
            # pylint: disable=duplicate-code
            if not success or error:
                raise ctypes.WinError(error)
    finally:
        kernel.CloseHandle(token)
    # pylint: enable=duplicate-code


def hive_mount_exists():
    """Check the fixed hive mount without requesting write access.

    Access denial also means the mount is occupied, matching the registry
    provider's existence check. The probe owns and closes its read handle.

    :returns: Whether HKLM\\ANSIBLE exists or denies inspection.
    :rtype: bool
    """
    try:
        with winreg.OpenKey(_root("HKLM"), "ANSIBLE", 0, winreg.KEY_READ):
            return True
    except OSError as error:
        return getattr(error, "winerror", None) in (5, 1346)


def load_hive(path):
    """Mount a saved hive at the upstream module's fixed HKLM\\ANSIBLE path.

    :param path: Existing local hive file.
    :type path: str
    :raises OSError: If Windows cannot load the hive.
    """
    winreg.LoadKey(_root("HKLM"), "ANSIBLE", path)


def unload_hive():
    """Unload HKLM\\ANSIBLE after all operation handles have been closed.

    :raises OSError: If Windows cannot unload the hive.
    """
    error = _registry().RegUnLoadKeyW(int(_root("HKLM")), "ANSIBLE")
    if error:
        raise ctypes.WinError(error)
