# -*- coding: utf-8 -*-
# Copyright 2026 Joe Lustri
# SPDX-License-Identifier: GPL-3.0-or-later

"""Read and manage local SMB shares through Windows NetAPI."""

import ctypes
import os
import struct

import legacy_windows_account as account  # pylint: disable=import-error
import legacy_windows_owner as owner  # pylint: disable=import-error

_MISSING_SHARE = 2310
_RIGHTS = {"Read": 0x1200A9, "Change": 0x1301BF, "Full": 0x1F01FF}
_CACHING = {
    "Manual": 0,
    "Documents": 0x10,
    "Programs": 0x20,
    "None": 0x30,
    "BranchCache": 0x2000,
}
_ABE = 0x800
_ENCRYPT = 0x8000


# These classes describe borrowed NetAPI records, not Python domain objects.
class _ShareInfo502(ctypes.Structure):  # pylint: disable=too-few-public-methods
    _fields_ = [
        ("name", ctypes.c_wchar_p),
        ("type", ctypes.c_uint32),
        ("remark", ctypes.c_wchar_p),
        ("permissions", ctypes.c_uint32),
        ("max_uses", ctypes.c_uint32),
        ("current_uses", ctypes.c_uint32),
        ("path", ctypes.c_wchar_p),
        ("password", ctypes.c_wchar_p),
        ("reserved", ctypes.c_uint32),
        ("descriptor", ctypes.c_void_p),
    ]


class _ShareInfo1004(ctypes.Structure):  # pylint: disable=too-few-public-methods
    _fields_ = [("remark", ctypes.c_wchar_p)]


class _ShareInfo1005(ctypes.Structure):  # pylint: disable=too-few-public-methods
    _fields_ = [("flags", ctypes.c_uint32)]


def _netapi():
    if os.name != "nt":
        raise ValueError("Share operations require a Windows target.")
    library = ctypes.WinDLL("netapi32")
    library.NetShareGetInfo.argtypes = [
        ctypes.c_wchar_p,
        ctypes.c_wchar_p,
        ctypes.c_uint32,
        ctypes.POINTER(ctypes.c_void_p),
    ]
    library.NetShareGetInfo.restype = ctypes.c_uint32
    library.NetShareAdd.argtypes = [
        ctypes.c_wchar_p,
        ctypes.c_uint32,
        ctypes.c_void_p,
        ctypes.POINTER(ctypes.c_uint32),
    ]
    library.NetShareAdd.restype = ctypes.c_uint32
    library.NetShareSetInfo.argtypes = [
        ctypes.c_wchar_p,
        ctypes.c_wchar_p,
        ctypes.c_uint32,
        ctypes.c_void_p,
        ctypes.POINTER(ctypes.c_uint32),
    ]
    library.NetShareSetInfo.restype = ctypes.c_uint32
    library.NetShareDel.argtypes = [ctypes.c_wchar_p, ctypes.c_wchar_p, ctypes.c_uint32]
    library.NetShareDel.restype = ctypes.c_uint32
    library.NetApiBufferFree.argtypes = [ctypes.c_void_p]
    library.NetApiBufferFree.restype = ctypes.c_uint32
    return library


def _security():
    library = ctypes.WinDLL("advapi32", use_last_error=True)
    library.GetSecurityDescriptorControl.argtypes = [
        ctypes.c_void_p,
        ctypes.POINTER(ctypes.c_uint16),
        ctypes.POINTER(ctypes.c_uint32),
    ]
    library.GetSecurityDescriptorControl.restype = ctypes.c_int
    for suffix in ("Dacl", "Sacl"):
        function = getattr(library, "GetSecurityDescriptor" + suffix)
        function.argtypes = [
            ctypes.c_void_p,
            ctypes.POINTER(ctypes.c_int),
            ctypes.POINTER(ctypes.c_void_p),
            ctypes.POINTER(ctypes.c_int),
        ]
        function.restype = ctypes.c_int
    for suffix in ("Owner", "Group"):
        function = getattr(library, "GetSecurityDescriptor" + suffix)
        function.argtypes = [
            ctypes.c_void_p,
            ctypes.POINTER(ctypes.c_void_p),
            ctypes.POINTER(ctypes.c_int),
        ]
        function.restype = ctypes.c_int
    library.GetLengthSid.argtypes = [ctypes.c_void_p]
    library.GetLengthSid.restype = ctypes.c_uint32
    return library


def _copy_descriptor(pointer):
    if not pointer:
        raise ValueError("The share did not provide a security descriptor.")
    library = _security()
    control, revision = ctypes.c_uint16(), ctypes.c_uint32()
    if not library.GetSecurityDescriptorControl(
        pointer, ctypes.byref(control), ctypes.byref(revision)
    ):
        raise ctypes.WinError(ctypes.get_last_error())
    result = {"control": control.value}
    for name in ("owner", "group", "sacl", "dacl"):
        part, defaulted = ctypes.c_void_p(), ctypes.c_int()
        function = getattr(library, "GetSecurityDescriptor" + name.capitalize())
        if name.endswith("acl"):
            present = ctypes.c_int()
            succeeded = function(
                pointer,
                ctypes.byref(present),
                ctypes.byref(part),
                ctypes.byref(defaulted),
            )
        else:
            succeeded = function(pointer, ctypes.byref(part), ctypes.byref(defaulted))
        if not succeeded:
            raise ctypes.WinError(ctypes.get_last_error())
        if not part:
            result[name] = None
        else:
            size = (
                struct.unpack("<H", ctypes.string_at(part.value + 2, 2))[0]
                if name.endswith("acl")
                else library.GetLengthSid(part)
            )
            result[name] = ctypes.string_at(part, size)
    return result


def _pack_descriptor(snapshot):
    body, offsets = bytearray(), {}
    # Windows share descriptors serialize ACLs before the owner and group SIDs.
    for name in ("sacl", "dacl", "owner", "group"):
        value = snapshot[name]
        if value is None:
            offsets[name] = 0
        else:
            while len(body) % 4:
                body.append(0)
            offsets[name] = 20 + len(body)
            body.extend(value)
    return struct.pack(
        "<BBHLLLL",
        1,
        0,
        snapshot["control"] | 0x8000,
        offsets["owner"],
        offsets["group"],
        offsets["sacl"],
        offsets["dacl"],
    ) + bytes(body)


def _get_buffer(library, name, level):
    pointer = ctypes.c_void_p()
    status = library.NetShareGetInfo(None, name, level, ctypes.byref(pointer))
    if status:
        if pointer:
            library.NetApiBufferFree(pointer)
        if status == _MISSING_SHARE:
            return None
        raise ctypes.WinError(status)
    return pointer


def get_share(name):
    """Read a local share's properties and copy its complete security data.

    :param name: Exact share name; Windows performs case-insensitive lookup.
    :type name: str
    :returns: Share properties and descriptor components, or None if absent.
    :rtype: dict or None
    :raises ValueError: If called outside Windows.
    :raises OSError: If reading properties or security fails.
    """
    if name == "":
        return None
    library = _netapi()
    pointer = _get_buffer(library, name, 502)
    if pointer is None:
        return None
    try:
        information = ctypes.cast(pointer, ctypes.POINTER(_ShareInfo502)).contents
        result = {
            "name": information.name,
            "path": information.path,
            "description": information.remark or "",
            "security": _copy_descriptor(information.descriptor),
        }
    finally:
        library.NetApiBufferFree(pointer)
    pointer = _get_buffer(library, name, 1005)
    if pointer is None:
        raise ctypes.WinError(_MISSING_SHARE)
    try:
        flags = ctypes.cast(pointer, ctypes.POINTER(_ShareInfo1005)).contents.flags
    finally:
        library.NetApiBufferFree(pointer)
    result.update(
        flags=flags,
        list=not bool(flags & _ABE),
        encrypt=bool(flags & _ENCRYPT),
        caching_mode=next(
            (key for key, value in _CACHING.items() if value == flags & 0x2030),
            "Unknown",
        ),
        scope_name="*",
    )
    return result


def _set_info(name, level, information):
    status = _netapi().NetShareSetInfo(
        None, name, level, ctypes.byref(information), None
    )
    if status:
        raise ctypes.WinError(status)


def _set_security(name, descriptor):
    library = _netapi()
    pointer = _get_buffer(library, name, 502)
    if pointer is None:
        raise ctypes.WinError(_MISSING_SHARE)
    try:
        information = _ShareInfo502.from_buffer_copy(
            ctypes.string_at(pointer, ctypes.sizeof(_ShareInfo502))
        )
        # Level 1501 cleared an existing description on Server 2025. Level 502
        # carries the current metadata with the changed security descriptor.
        information.descriptor = ctypes.cast(descriptor, ctypes.c_void_p)
        _set_info(name, 502, information)
    finally:
        library.NetApiBufferFree(pointer)


def create_share(name, path):
    """Create a disk share with the source provider's initial security.

    The measured initial descriptor has SYSTEM owner and group and grants
    Everyone Read access. Permission replacement revokes that grant when it
    is not requested.

    :param name: Share name to create.
    :type name: str
    :param path: Existing local filesystem path.
    :type path: str
    :raises ValueError: If called outside Windows.
    :raises OSError: If Windows rejects creation.
    """
    system = account.sid_bytes("S-1-5-18")
    everyone = account.sid_bytes("S-1-1-0")
    entry = struct.pack("<BBHL", 0, 0, 8 + len(everyone), _RIGHTS["Read"]) + everyone
    acl = struct.pack("<BBHHH", 2, 0, 8 + len(entry), 1, 0) + entry
    # Both NetShareAdd levels 2 and 502 with NULL returned no descriptor, unlike
    # New-SmbShare. Supply the measured provider descriptor instead of guessing.
    descriptor = ctypes.create_string_buffer(
        _pack_descriptor(
            {
                "control": 0x8004,
                "owner": system,
                "group": system,
                "sacl": None,
                "dacl": acl,
            }
        )
    )
    information = _ShareInfo502(
        name,
        0,
        "",
        0,
        0xFFFFFFFF,
        0,
        path,
        None,
        0,
        ctypes.cast(descriptor, ctypes.c_void_p),
    )
    status = _netapi().NetShareAdd(None, 502, ctypes.byref(information), None)
    if status:
        raise ctypes.WinError(status)


def delete_share(name):
    """Remove exactly one local share, leaving its filesystem data untouched.

    :param name: Share name to remove.
    :type name: str
    :raises ValueError: If called outside Windows.
    :raises OSError: If Windows rejects deletion.
    """
    status = _netapi().NetShareDel(None, name, 0)
    if status:
        raise ctypes.WinError(status)


def set_property(name, field, value):
    """Change one supported property without overwriting unrelated share flags.

    :param name: Existing share name.
    :type name: str
    :param field: Description, list, caching_mode, encrypt, or scope_name.
    :type field: str
    :param value: Requested property value.
    :type value: object
    :raises ValueError: If the property or caching value is unknown.
    :raises OSError: If Windows rejects the change.
    """
    if field == "description":
        _set_info(name, 1004, _ShareInfo1004(value))
        return
    if field == "scope_name":
        raise ValueError(
            "Unhandled exception while executing module: No matching MSFT_SMBShare "
            "objects found by CIM query for instances of the "
            "ROOT/Microsoft/Windows/SMB/MSFT_SMBShare class on the  CIM server: "
            "SELECT * FROM MSFT_SMBShare  WHERE ((Name = '"
            + name
            + "')) AND ((ScopeName = '"
            + value
            + "')). Verify query parameters and retry."
        )
    share = get_share(name)
    if share is None:
        raise ctypes.WinError(_MISSING_SHARE)
    flags = share["flags"]
    if field == "list":
        flags = flags & ~_ABE if value else flags | _ABE
    elif field == "encrypt":
        flags = flags | _ENCRYPT if value else flags & ~_ENCRYPT
    elif field == "caching_mode":
        canonical = next(
            (key for key in _CACHING if key.lower() == value.lower()), None
        )
        if canonical is None:
            raise ValueError("Unsupported caching mode: " + value)
        flags = (flags & ~0x2030) | _CACHING[canonical]
    else:
        raise ValueError("Unsupported share property: " + field)
    _set_info(name, 1005, _ShareInfo1005(flags))


def _aces(acl):
    if acl is None:
        raise ValueError("A share with a null DACL is not supported.")
    if len(acl) < 8:
        raise ValueError("Malformed share DACL.")
    count = struct.unpack_from("<H", acl, 4)[0]
    offset, entries = 8, []
    for _ in range(count):
        if offset + 4 > len(acl):
            raise ValueError("Malformed share ACE.")
        size = struct.unpack_from("<H", acl, offset + 2)[0]
        if size < 4 or offset + size > len(acl):
            raise ValueError("Malformed share ACE.")
        entries.append(acl[offset : offset + size])
        offset += size
    return entries


def access_entries(share):
    """Read allow and deny entries in the share's native DACL order.

    :param share: Snapshot returned by get_share.
    :type share: dict
    :returns: Account name, SID, control type, and right for each entry.
    :rtype: list
    :raises ValueError: If an ACE type or access mask is unsupported.
    :raises OSError: If native SID translation fails.
    """
    entries = _aces(share["security"]["dacl"])
    if not entries:
        return [
            {
                "account": account.sid_to_name("S-1-1-0"),
                "sid": "S-1-1-0",
                "control": "Deny",
                "right": "Full",
            }
        ]
    result = []
    for entry in entries:
        if entry[0] not in (0, 1) or len(entry) < 16:
            raise ValueError("Unsupported share ACE type.")
        sid = account.sid_to_string(ctypes.create_string_buffer(entry[8:]))
        mask = struct.unpack_from("<L", entry, 4)[0]
        right = next((key for key, value in _RIGHTS.items() if value == mask), None)
        if right is None:
            raise ValueError("Unsupported share access mask: " + str(mask))
        result.append(
            {
                "account": account.sid_to_name(sid),
                "sid": sid,
                "control": "Deny" if entry[0] else "Allow",
                "right": right,
            }
        )
    return result


def normalize_account(name):
    """Resolve an upstream account form and return its canonical account name.

    :param name: Account name, SID string, or SDDL alias.
    :type name: str
    :returns: Canonical DOMAIN/account spelling used by share access results.
    :rtype: str
    :raises ValueError: If the account is malformed or the target is not Windows.
    :raises OSError: If account or SID translation fails.
    """
    return account.sid_to_name(owner.resolve_owner(name))


def change_access(name, identity, right, control, remove=False):
    """Add, replace, or remove one account's allow or deny share entry.

    :param name: Existing share name.
    :type name: str
    :param identity: Canonical account name.
    :type identity: str
    :param right: Read, Change, or Full access.
    :type right: str
    :param control: Allow or Deny.
    :type control: str
    :param remove: Remove the matching control entry instead of adding one.
    :type remove: bool
    :raises ValueError: If the ACL, right, or control type is unsupported.
    :raises OSError: If Windows rejects account lookup or the security update.
    """
    if control not in ("Allow", "Deny") or right not in _RIGHTS:
        raise ValueError("Unsupported share access right or control type.")
    share = get_share(name)
    if share is None:
        raise ctypes.WinError(_MISSING_SHARE)
    sid = account.sid_bytes(owner.resolve_owner(identity))
    ace_type = {"Allow": 0, "Deny": 1}[control]
    entries = [
        entry
        for entry in _aces(share["security"]["dacl"])
        if not (entry[0] == ace_type and entry[8:] == sid)
    ]
    if not remove:
        entry = struct.pack("<BBHL", ace_type, 0, 8 + len(sid), _RIGHTS[right]) + sid
        if ace_type:
            entries.insert(0, entry)
        else:
            entries.append(entry)
    acl_size = 8 + sum(len(entry) for entry in entries)
    if acl_size > 65535:
        raise ValueError("Share DACL exceeds the native size limit.")
    share["security"]["dacl"] = struct.pack(
        "<BBHHH", 2, 0, acl_size, len(entries), 0
    ) + b"".join(entries)
    descriptor = ctypes.create_string_buffer(_pack_descriptor(share["security"]))
    _set_security(name, descriptor)
