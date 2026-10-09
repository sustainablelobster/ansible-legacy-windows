# -*- coding: utf-8 -*-
# Copyright 2026 Joe Lustri
# SPDX-License-Identifier: GPL-3.0-or-later

"""Read and set file owners using Windows security APIs on Python 3.4.4."""

import ctypes
import os
from contextlib import contextmanager

# The action stages these existing account helpers beside the target payload.
import legacy_windows_account as account  # pylint: disable=import-error
from legacy_windows_group import list_groups  # pylint: disable=import-error

_PRIVILEGES = (
    "SeBackupPrivilege",
    "SeChangeNotifyPrivilege",
    "SeRestorePrivilege",
    "SeTakeOwnershipPrivilege",
)
_READ_CONTROL = 0x00020000
_WRITE_DAC = 0x00040000
_WRITE_OWNER = 0x00080000
_OWNER_SECURITY_INFORMATION = 1
_GROUP_SECURITY_INFORMATION = 2
_DACL_SECURITY_INFORMATION = 4
_PROTECTED_DACL_SECURITY_INFORMATION = 0x80000000
_UNPROTECTED_DACL_SECURITY_INFORMATION = 0x20000000
_SE_DACL_PROTECTED = 0x1000
_SE_FILE_OBJECT = 1


# These fixed-width structures retain DWORD alignment on both Windows ABIs.
class _Luid(ctypes.Structure):  # pylint: disable=too-few-public-methods
    _fields_ = [("low", ctypes.c_uint32), ("high", ctypes.c_int32)]


class _Privilege(ctypes.Structure):  # pylint: disable=too-few-public-methods
    _fields_ = [("luid", _Luid), ("attributes", ctypes.c_uint32)]


# At most the four requested privileges can appear in the previous-state buffer.
class _OwnershipPrivileges(ctypes.Structure):  # pylint: disable=too-few-public-methods
    _fields_ = [("count", ctypes.c_uint32), ("privileges", _Privilege * 4)]


def _libraries():
    if os.name != "nt":
        raise ValueError("File ownership operations require a Windows target.")
    security = ctypes.WinDLL("advapi32", use_last_error=True)
    kernel = ctypes.WinDLL("kernel32", use_last_error=True)
    # Keep this independently staged wrapper's native ABI declarations local.
    # pylint: disable=duplicate-code
    security.OpenProcessToken.argtypes = [
        ctypes.c_void_p,
        ctypes.c_uint32,
        ctypes.POINTER(ctypes.c_void_p),
    ]
    security.OpenProcessToken.restype = ctypes.c_int
    security.LookupPrivilegeValueW.argtypes = [
        ctypes.c_wchar_p,
        ctypes.c_wchar_p,
        ctypes.POINTER(_Luid),
    ]
    security.LookupPrivilegeValueW.restype = ctypes.c_int
    security.AdjustTokenPrivileges.argtypes = [
        ctypes.c_void_p,
        ctypes.c_int,
        ctypes.POINTER(_OwnershipPrivileges),
        ctypes.c_uint32,
        ctypes.POINTER(_OwnershipPrivileges),
        ctypes.POINTER(ctypes.c_uint32),
    ]
    security.AdjustTokenPrivileges.restype = ctypes.c_int
    security.GetSecurityInfo.argtypes = [
        ctypes.c_void_p,
        ctypes.c_int,
        ctypes.c_uint32,
        ctypes.POINTER(ctypes.c_void_p),
        ctypes.POINTER(ctypes.c_void_p),
        ctypes.POINTER(ctypes.c_void_p),
        ctypes.POINTER(ctypes.c_void_p),
        ctypes.POINTER(ctypes.c_void_p),
    ]
    security.GetSecurityInfo.restype = ctypes.c_uint32
    security.GetSecurityDescriptorControl.argtypes = [
        ctypes.c_void_p,
        ctypes.POINTER(ctypes.c_uint16),
        ctypes.POINTER(ctypes.c_uint32),
    ]
    security.GetSecurityDescriptorControl.restype = ctypes.c_int
    security.SetSecurityInfo.argtypes = [
        ctypes.c_void_p,
        ctypes.c_int,
        ctypes.c_uint32,
        ctypes.c_void_p,
        ctypes.c_void_p,
        ctypes.c_void_p,
        ctypes.c_void_p,
    ]
    security.SetSecurityInfo.restype = ctypes.c_uint32
    kernel.GetCurrentProcess.argtypes = []
    kernel.GetCurrentProcess.restype = ctypes.c_void_p
    kernel.CreateFileW.argtypes = [
        ctypes.c_wchar_p,
        ctypes.c_uint32,
        ctypes.c_uint32,
        ctypes.c_void_p,
        ctypes.c_uint32,
        ctypes.c_uint32,
        ctypes.c_void_p,
    ]
    kernel.CreateFileW.restype = ctypes.c_void_p
    kernel.CloseHandle.argtypes = [ctypes.c_void_p]
    kernel.CloseHandle.restype = ctypes.c_int
    kernel.LocalFree.argtypes = [ctypes.c_void_p]
    kernel.LocalFree.restype = ctypes.c_void_p
    # pylint: enable=duplicate-code
    return security, kernel


def resolve_owner(user):
    """Resolve the upstream owner syntax, including local groups and SID aliases.

    Machine-qualified local groups are looked up without their domain, matching
    the upstream resolver's handling of built-in groups on legacy Windows.

    :param user: Account name, SID string, or SDDL alias supplied by the user.
    :type user: str
    :returns: Canonical SID string.
    :rtype: str
    :raises OSError: If native SID parsing, group enumeration, or lookup fails.
    :raises ValueError: If an account name is invalid or called outside Windows.
    """
    try:
        return account.parse_sid(user)
    except OSError as error:
        if getattr(error, "winerror", None) != 1337:
            raise
    if "\\" in user:
        domain, name = user.split("\\", 1)
        computer = os.environ.get("COMPUTERNAME", "")
        if domain == ".":
            domain = computer
        if domain.lower() == computer.lower() and any(
            group["name"].lower() == name.lower() for group in list_groups()
        ):
            domain = ""
        user = domain + "\\" + name if domain else name
    return account.account_name_to_sid(user)


@contextmanager
def ownership_privileges(privileges=_PRIVILEGES):
    """Temporarily enable existing process privileges needed for file ownership.

    Missing privileges are ignored, as in the upstream non-strict enabler.
    Previously enabled or disabled privileges are restored when the operation
    succeeds or raises; no privilege is added to the process token.

    :param privileges: At most four existing privilege names to enable.
        Defaults to the four privileges used by file ownership operations.
    :type privileges: tuple
    :returns: Context manager yielding None with available privileges enabled.
    :rtype: context manager
    :raises OSError: If privilege lookup, token access, adjustment, or restoration
        fails for reasons other than a requested privilege being absent.
    :raises ValueError: If more than four privileges are requested or called
        outside Windows.
    """
    if len(privileges) > 4:
        raise ValueError("At most four privileges can be enabled together.")
    security, kernel = _libraries()
    requested = _OwnershipPrivileges(len(privileges))
    for index, name in enumerate(privileges):
        privilege = requested.privileges[index]
        if not security.LookupPrivilegeValueW(None, name, ctypes.byref(privilege.luid)):
            raise ctypes.WinError(ctypes.get_last_error())
        privilege.attributes = 2  # SE_PRIVILEGE_ENABLED
    token = ctypes.c_void_p()
    if not security.OpenProcessToken(
        kernel.GetCurrentProcess(), 0x28, ctypes.byref(token)
    ):
        raise ctypes.WinError(ctypes.get_last_error())
    previous = _OwnershipPrivileges()
    needed = ctypes.c_uint32()
    try:
        try:
            # This privilege owner retains the exact native restoration buffer.
            # pylint: disable=duplicate-code
            adjusted = security.AdjustTokenPrivileges(
                token,
                False,
                ctypes.byref(requested),
                ctypes.sizeof(previous),
                ctypes.byref(previous),
                ctypes.byref(needed),
            )
            # pylint: enable=duplicate-code
            error = ctypes.get_last_error()
            if not adjusted or error not in (0, 1300):
                raise ctypes.WinError(error)
            yield
        finally:
            if previous.count:
                # This privilege owner retains the exact native restoration buffer.
                # pylint: disable=duplicate-code
                restored = security.AdjustTokenPrivileges(
                    token, False, ctypes.byref(previous), 0, None, None
                )
                # pylint: enable=duplicate-code
                error = ctypes.get_last_error()
                if not restored or error:
                    raise ctypes.WinError(error)
    finally:
        kernel.CloseHandle(token)


@contextmanager
def _file_handle(kernel, path, access):
    handle = kernel.CreateFileW(path, access, 7, None, 3, 0x02000000, None)
    if handle == ctypes.c_void_p(-1).value:
        raise ctypes.WinError(ctypes.get_last_error())
    try:
        yield handle
    finally:
        kernel.CloseHandle(handle)


def get_owner(path):
    """Read a file or directory's owner without reading or changing its DACL.

    Backup semantics permit enabled backup privileges to satisfy READ_CONTROL.
    Reparse points follow their targets, matching the upstream ACL operations.

    :param path: Literal Windows file or directory path.
    :type path: str
    :returns: Canonical owner SID, or None when the descriptor has no owner.
    :rtype: str or None
    :raises OSError: If opening the object or reading/converting its owner fails.
    :raises ValueError: If called outside Windows.
    """
    security, kernel = _libraries()
    with _file_handle(kernel, path, _READ_CONTROL) as handle:
        owner, descriptor = ctypes.c_void_p(), ctypes.c_void_p()
        try:
            # The owner-only query retains its own descriptor and handle lifetime.
            # pylint: disable=duplicate-code
            status = security.GetSecurityInfo(
                handle,
                _SE_FILE_OBJECT,
                _OWNER_SECURITY_INFORMATION,
                ctypes.byref(owner),
                None,
                None,
                None,
                ctypes.byref(descriptor),
            )
            # pylint: enable=duplicate-code
            if status:
                raise ctypes.WinError(status)
            return account.sid_to_string(owner) if owner else None
        finally:
            if descriptor:
                kernel.LocalFree(descriptor)


def set_owner(path, sid):
    """Set an owner and persist the existing group and DACL as upstream does.

    DACL protection is preserved; Windows refreshes inheritance metadata on
    the object and its inheriting descendants. The SACL is not read or written.
    Backup semantics allow enabled backup and restore privileges to satisfy
    the required READ_CONTROL, WRITE_DAC, and WRITE_OWNER access.
    Call within ``ownership_privileges`` when those privileges are required.

    :param path: Literal Windows file or directory path.
    :type path: str
    :param sid: Canonical SID identifying the new owner.
    :type sid: str
    :raises OSError: If SID parsing or file security access fails; Windows
        enforces ownership and privilege restrictions.
    :raises ValueError: If called outside Windows.
    """
    binary_sid = ctypes.create_string_buffer(account.sid_bytes(sid))
    security, kernel = _libraries()
    with _file_handle(
        kernel, path, _READ_CONTROL | _WRITE_DAC | _WRITE_OWNER
    ) as handle:
        group, dacl, descriptor = (
            ctypes.c_void_p(),
            ctypes.c_void_p(),
            ctypes.c_void_p(),
        )
        information = _GROUP_SECURITY_INFORMATION | _DACL_SECURITY_INFORMATION
        try:
            # Owner preserves this descriptor's group and DACL during its native write.
            # pylint: disable=duplicate-code
            status = security.GetSecurityInfo(
                handle,
                _SE_FILE_OBJECT,
                information,
                None,
                ctypes.byref(group),
                ctypes.byref(dacl),
                None,
                ctypes.byref(descriptor),
            )
            if status:
                raise ctypes.WinError(status)
            control, revision = ctypes.c_uint16(), ctypes.c_uint32()
            if not security.GetSecurityDescriptorControl(
                descriptor, ctypes.byref(control), ctypes.byref(revision)
            ):
                raise ctypes.WinError(ctypes.get_last_error())
            # pylint: enable=duplicate-code
            information |= _OWNER_SECURITY_INFORMATION
            information |= (
                _PROTECTED_DACL_SECURITY_INFORMATION
                if control.value & _SE_DACL_PROTECTED
                else _UNPROTECTED_DACL_SECURITY_INFORMATION
            )
            status = security.SetSecurityInfo(
                handle, _SE_FILE_OBJECT, information, binary_sid, group, dacl, None
            )
            if status:
                raise ctypes.WinError(status)
        finally:
            if descriptor:
                kernel.LocalFree(descriptor)
