# -*- coding: utf-8 -*-
# Copyright 2026 sustainablelobster
# SPDX-License-Identifier: GPL-3.0-or-later

"""Read, create and delete user profiles through Windows registry and Userenv."""

import ctypes
import os

try:
    import winreg
except ImportError:
    winreg = None

PROFILE_LIST = r"SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProfileList"


def _library():
    if os.name != "nt":
        raise ValueError("Windows user profiles require a Windows target.")
    library = ctypes.WinDLL("userenv", use_last_error=True)
    library.GetProfilesDirectoryW.argtypes = [
        ctypes.c_wchar_p,
        ctypes.POINTER(ctypes.c_uint32),
    ]
    library.GetProfilesDirectoryW.restype = ctypes.c_int
    library.DeleteProfileW.argtypes = [
        ctypes.c_wchar_p,
        ctypes.c_void_p,
        ctypes.c_void_p,
    ]
    library.DeleteProfileW.restype = ctypes.c_int
    return library


def profile_sids():
    """Enumerate registered profile key names without reading their paths.

    :returns: Registry-order profile SID strings.
    :rtype: list of str
    :raises ValueError: If called outside Windows.
    :raises OSError: If Windows cannot enumerate the profile registry key.
    """
    if winreg is None:
        raise ValueError("Windows user profiles require a Windows target.")
    with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, PROFILE_LIST) as root:
        return [
            winreg.EnumKey(root, index) for index in range(winreg.QueryInfoKey(root)[0])
        ]


def profile_path(sid):
    """Read only the selected profile's expanded image path.

    :param sid: Registered profile key name.
    :type sid: str
    :returns: ProfileImagePath, expanding only REG_EXPAND_SZ values.
    :rtype: str
    :raises ValueError: If called outside Windows.
    :raises OSError: If the key or value cannot be read.
    """
    if winreg is None:
        raise ValueError("Windows user profiles require a Windows target.")
    with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, PROFILE_LIST + "\\" + sid) as key:
        path, kind = winreg.QueryValueEx(key, "ProfileImagePath")
    return (
        winreg.ExpandEnvironmentStrings(path) if kind == winreg.REG_EXPAND_SZ else path
    )


def profiles_directory():
    """Read the Windows-managed root directory of user profiles.

    :returns: Absolute profile root from ``GetProfilesDirectoryW``.
    :rtype: str
    :raises ValueError: If called outside Windows.
    :raises OSError: If Windows cannot determine the directory.
    """
    library = _library()
    size = ctypes.c_uint32()
    library.GetProfilesDirectoryW(None, ctypes.byref(size))
    output = ctypes.create_unicode_buffer(size.value)
    if not library.GetProfilesDirectoryW(output, ctypes.byref(size)):
        raise ctypes.WinError(ctypes.get_last_error())
    return output.value


def _creation_error(status):
    unsigned = status & 0xFFFFFFFF
    # These CLR exception messages do not use Win32's native description.
    # Retained original-runtime probes establish the observable wording.
    if unsigned == 0x80070057:
        return "Value does not fall within the expected range."
    if unsigned == 0x80004005:
        return "Error HRESULT E_FAIL has been returned from a call to a COM component."
    code = unsigned & 0xFFFF if unsigned & 0xFFFF0000 == 0x80070000 else unsigned
    message = ctypes.FormatError(code).rstrip("\r\n")
    suffix = "0x{0:08X}".format(unsigned)
    if unsigned == 0x80070005:
        suffix += " (E_ACCESSDENIED)"
    return message + " (Exception from HRESULT: " + suffix + ")"


def create_profile(sid, name):
    """Create the profile for an account using the native collision policy.

    :param sid: Canonical account SID string.
    :type sid: str
    :param name: Profile-directory base name.
    :type name: str
    :returns: Actual created directory, including any native collision suffix.
    :rtype: str
    :raises ValueError: If called outside Windows or CreateProfile is absent.
    :raises OSError: If the native creation call returns a failed HRESULT.
    """
    library = _library()
    try:
        create = library.CreateProfile
    except AttributeError as error:
        raise ValueError(
            "Windows profile creation API is unavailable on this target "
            "(CreateProfile requires Windows Vista or Server 2008 or newer)."
        ) from error
    create.argtypes = [
        ctypes.c_wchar_p,
        ctypes.c_wchar_p,
        ctypes.c_wchar_p,
        ctypes.c_uint32,
    ]
    create.restype = ctypes.c_int32
    output = ctypes.create_unicode_buffer(260)
    status = create(sid, name, output, len(output))
    if status:
        error = OSError(_creation_error(status))
        error.hresult = status
        raise error
    return output.value


def delete_profile(sid):
    """Delete the local profile registered for a SID, not the account itself.

    :param sid: Registered profile SID string, including a deleted account SID.
    :type sid: str
    :raises ValueError: If called outside Windows.
    :raises OSError: If the native deletion call fails.
    """
    if not _library().DeleteProfileW(sid, None, None):
        raise ctypes.WinError(ctypes.get_last_error())
