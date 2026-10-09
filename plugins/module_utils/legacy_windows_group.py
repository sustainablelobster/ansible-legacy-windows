# -*- coding: utf-8 -*-
# Copyright 2026 Joe Lustri
# SPDX-License-Identifier: GPL-3.0-or-later

"""Read and change local groups through Windows NetAPI on Python 3.4.4."""

import ctypes
import os

from legacy_windows_account import (  # pylint: disable=import-error
    sid_bytes,
    sid_to_string,
)

_ERROR_MORE_DATA = 234
_MAX_PREFERRED_LENGTH = 0xFFFFFFFF


# These structures describe native buffers and have no Python methods.
class _LocalGroupInfo1(ctypes.Structure):  # pylint: disable=too-few-public-methods
    _fields_ = [("name", ctypes.c_wchar_p), ("comment", ctypes.c_wchar_p)]


# The level-1002 structure changes only the group's comment.
class _LocalGroupInfo1002(ctypes.Structure):  # pylint: disable=too-few-public-methods
    _fields_ = [("comment", ctypes.c_wchar_p)]


# Each native membership entry is a borrowed SID pointer.
class _LocalGroupMemberInfo0(
    ctypes.Structure
):  # pylint: disable=too-few-public-methods
    _fields_ = [("sid", ctypes.c_void_p)]


def _netapi():
    if os.name != "nt":
        raise ValueError("Local group operations require a Windows target.")
    library = ctypes.WinDLL("netapi32")
    # This fixed enumeration signature resembles other NetAPI declarations.
    # Keeping it local avoids staging unrelated filesystem inspection helpers.
    # pylint: disable=duplicate-code
    library.NetLocalGroupEnum.argtypes = [
        ctypes.c_wchar_p,
        ctypes.c_uint32,
        ctypes.POINTER(ctypes.c_void_p),
        ctypes.c_uint32,
        ctypes.POINTER(ctypes.c_uint32),
        ctypes.POINTER(ctypes.c_uint32),
        ctypes.POINTER(ctypes.c_size_t),
    ]
    library.NetLocalGroupEnum.restype = ctypes.c_uint32
    library.NetLocalGroupGetMembers.argtypes = [
        ctypes.c_wchar_p,
        ctypes.c_wchar_p,
        ctypes.c_uint32,
        ctypes.POINTER(ctypes.c_void_p),
        ctypes.c_uint32,
        ctypes.POINTER(ctypes.c_uint32),
        ctypes.POINTER(ctypes.c_uint32),
        ctypes.POINTER(ctypes.c_size_t),
    ]
    library.NetLocalGroupGetMembers.restype = ctypes.c_uint32
    # pylint: enable=duplicate-code
    library.NetApiBufferFree.argtypes = [ctypes.c_void_p]
    library.NetApiBufferFree.restype = ctypes.c_uint32
    library.NetLocalGroupAdd.argtypes = [
        ctypes.c_wchar_p,
        ctypes.c_uint32,
        ctypes.c_void_p,
        ctypes.POINTER(ctypes.c_uint32),
    ]
    library.NetLocalGroupAdd.restype = ctypes.c_uint32
    # This group operation needs NetAPI's fixed server/name/info ABI locally.
    # pylint: disable=duplicate-code
    library.NetLocalGroupSetInfo.argtypes = [
        ctypes.c_wchar_p,
        ctypes.c_wchar_p,
        ctypes.c_uint32,
        ctypes.c_void_p,
        ctypes.POINTER(ctypes.c_uint32),
    ]
    library.NetLocalGroupSetInfo.restype = ctypes.c_uint32
    # pylint: enable=duplicate-code
    library.NetLocalGroupDel.argtypes = [ctypes.c_wchar_p, ctypes.c_wchar_p]
    library.NetLocalGroupDel.restype = ctypes.c_uint32
    library.NetLocalGroupAddMembers.argtypes = [
        ctypes.c_wchar_p,
        ctypes.c_wchar_p,
        ctypes.c_uint32,
        ctypes.c_void_p,
        ctypes.c_uint32,
    ]
    library.NetLocalGroupAddMembers.restype = ctypes.c_uint32
    library.NetLocalGroupDelMembers.argtypes = [
        ctypes.c_wchar_p,
        ctypes.c_wchar_p,
        ctypes.c_uint32,
        ctypes.c_void_p,
        ctypes.c_uint32,
    ]
    library.NetLocalGroupDelMembers.restype = ctypes.c_uint32
    return library


def _validate_name(name):
    if not isinstance(name, str):
        raise ValueError("Local group name must be a string.")


def list_groups():
    """Read every local group and its description, consuming every native page.

    :returns: Dictionaries containing copied ``name`` and ``description`` strings.
    :rtype: list
    :raises OSError: If Windows cannot enumerate local groups.
    :raises ValueError: If the target is not Windows.
    """
    library = _netapi()
    resume = ctypes.c_size_t()
    groups = []
    while True:
        buffer = ctypes.c_void_p()
        count = ctypes.c_uint32()
        total = ctypes.c_uint32()
        try:
            status = library.NetLocalGroupEnum(
                None,
                1,
                ctypes.byref(buffer),
                _MAX_PREFERRED_LENGTH,
                ctypes.byref(count),
                ctypes.byref(total),
                ctypes.byref(resume),
            )
            if status not in (0, _ERROR_MORE_DATA):
                raise ctypes.WinError(status)
            entries = ctypes.cast(buffer, ctypes.POINTER(_LocalGroupInfo1))
            for index in range(count.value):
                groups.append(
                    {
                        "name": entries[index].name,
                        "description": entries[index].comment or "",
                    }
                )
        finally:
            if buffer:
                library.NetApiBufferFree(buffer)
        if status != _ERROR_MORE_DATA:
            return groups


def member_sids(name):
    """Read all member SIDs from a local group without resolving account names.

    :param name: Exact local group name; Windows performs case-insensitive lookup.
    :type name: str
    :returns: Copied canonical SID strings in native enumeration order.
    :rtype: list
    :raises OSError: If reading members fails.
    :raises Exception: If copying or converting a SID fails; the original
        exception is re-raised after the remaining native pages are consumed.
    :raises ValueError: If the name is invalid or the target is not Windows.
    """
    _validate_name(name)
    library = _netapi()
    resume = ctypes.c_size_t()
    members = []
    conversion_error = None
    while True:
        buffer = ctypes.c_void_p()
        count = ctypes.c_uint32()
        total = ctypes.c_uint32()
        try:
            status = library.NetLocalGroupGetMembers(
                None,
                name,
                0,
                ctypes.byref(buffer),
                _MAX_PREFERRED_LENGTH,
                ctypes.byref(count),
                ctypes.byref(total),
                ctypes.byref(resume),
            )
            if status not in (0, _ERROR_MORE_DATA):
                raise ctypes.WinError(status)
            if conversion_error is None:
                try:
                    entries = ctypes.cast(
                        buffer, ctypes.POINTER(_LocalGroupMemberInfo0)
                    )
                    for index in range(count.value):
                        members.append(sid_to_string(entries[index].sid))
                # GetMembers can leak its RPC context unless ERROR_MORE_DATA
                # is drained. Defer local conversion failures until completion.
                except Exception as error:  # pylint: disable=broad-exception-caught
                    conversion_error = error
        finally:
            if buffer:
                library.NetApiBufferFree(buffer)
        if status != _ERROR_MORE_DATA:
            if conversion_error is not None:
                raise conversion_error
            return members


def create_group(name):
    """Create one empty local group with an initially empty description.

    :param name: Local group name to create.
    :type name: str
    :raises OSError: If Windows rejects creation, including an existing name.
    :raises ValueError: If the name is invalid or the target is not Windows.
    """
    _validate_name(name)
    information = _LocalGroupInfo1(name, "")
    status = _netapi().NetLocalGroupAdd(None, 1, ctypes.byref(information), None)
    if status:
        raise ctypes.WinError(status)


def set_description(name, value):
    """Replace a local group's description without renaming it.

    :param name: Exact local group name.
    :type name: str
    :param value: Literal description, including an empty string to clear it.
    :type value: str
    :raises OSError: If Windows rejects the description change.
    :raises ValueError: If an argument is invalid or the target is not Windows.
    """
    _validate_name(name)
    if not isinstance(value, str):
        raise ValueError("Local group description must be a string.")
    information = _LocalGroupInfo1002(value)
    status = _netapi().NetLocalGroupSetInfo(
        None, name, 1002, ctypes.byref(information), None
    )
    if status:
        raise ctypes.WinError(status)


def delete_group(name):
    """Delete the supplied local group without searching or matching other names.

    :param name: Exact local group name; Windows performs case-insensitive lookup.
    :type name: str
    :raises OSError: If Windows rejects deletion, including a missing group.
    :raises ValueError: If the name is invalid or the target is not Windows.
    """
    _validate_name(name)
    status = _netapi().NetLocalGroupDel(None, name)
    if status:
        raise ctypes.WinError(status)


def add_member(name, sid):
    """Add exactly one SID to a local group in one native operation.

    :param name: Exact local group name.
    :type name: str
    :param sid: Canonical SID string of the member to add.
    :type sid: str
    :raises OSError: If Windows rejects SID conversion or the membership change.
    :raises ValueError: If an argument is invalid or the target is not Windows.
    """
    _validate_name(name)
    library = _netapi()
    buffer = ctypes.create_string_buffer(sid_bytes(sid))
    information = _LocalGroupMemberInfo0(ctypes.cast(buffer, ctypes.c_void_p))
    status = library.NetLocalGroupAddMembers(
        None, name, 0, ctypes.byref(information), 1
    )
    if status:
        raise ctypes.WinError(status)


def remove_member(name, sid):
    """Remove exactly one SID from a local group in one native operation.

    :param name: Exact local group name.
    :type name: str
    :param sid: Canonical SID string of the member to remove.
    :type sid: str
    :raises OSError: If Windows rejects SID conversion or the membership change.
    :raises ValueError: If an argument is invalid or the target is not Windows.
    """
    _validate_name(name)
    library = _netapi()
    buffer = ctypes.create_string_buffer(sid_bytes(sid))
    information = _LocalGroupMemberInfo0(ctypes.cast(buffer, ctypes.c_void_p))
    status = library.NetLocalGroupDelMembers(
        None, name, 0, ctypes.byref(information), 1
    )
    if status:
        raise ctypes.WinError(status)
