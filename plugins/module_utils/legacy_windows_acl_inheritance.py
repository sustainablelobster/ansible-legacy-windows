# -*- coding: utf-8 -*-
# Copyright 2026 Joe Lustri
# SPDX-License-Identifier: GPL-3.0-or-later

"""Change filesystem and registry DACL inheritance with native Windows APIs."""

import ctypes
import os
import re
import struct
from contextlib import contextmanager

_READ_CONTROL = 0x00020000
_WRITE_DAC = 0x00040000
_DACL_SECURITY_INFORMATION = 4
_SE_DACL_PROTECTED = 0x1000
_INHERITED = 0x10
_HIVES = {
    "HKCR": ("HKEY_CLASSES_ROOT", 0x80000000),
    "HKCU": ("HKEY_CURRENT_USER", 0x80000001),
    "HKLM": ("HKEY_LOCAL_MACHINE", 0x80000002),
    "HKU": ("HKEY_USERS", 0x80000003),
    "HKCC": ("HKEY_CURRENT_CONFIG", 0x80000005),
}


def _libraries():
    if os.name != "nt":
        raise ValueError("ACL inheritance operations require a Windows target.")
    security = ctypes.WinDLL("advapi32", use_last_error=True)
    kernel = ctypes.WinDLL("kernel32", use_last_error=True)
    # Keep fixed native signatures local so this operation stages no unrelated
    # account, token, or privilege-changing helpers.
    # pylint: disable=duplicate-code
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
    kernel.ExpandEnvironmentStringsW.argtypes = [
        ctypes.c_wchar_p,
        ctypes.c_wchar_p,
        ctypes.c_uint32,
    ]
    kernel.ExpandEnvironmentStringsW.restype = ctypes.c_uint32
    # pylint: enable=duplicate-code
    security.RegOpenKeyExW.argtypes = [
        ctypes.c_void_p,
        ctypes.c_wchar_p,
        ctypes.c_uint32,
        ctypes.c_uint32,
        ctypes.POINTER(ctypes.c_void_p),
    ]
    security.RegOpenKeyExW.restype = ctypes.c_int32
    security.RegCloseKey.argtypes = [ctypes.c_void_p]
    security.RegCloseKey.restype = ctypes.c_int32
    return security, kernel


def normalize_path(path):
    """Expand Windows environment variables unless the path is extended length.

    :param path: User-supplied filesystem or registry path.
    :type path: str
    :returns: Expanded path, preserving unknown variables and extended paths.
    :rtype: str
    :raises OSError: If Windows environment expansion fails.
    :raises ValueError: If called outside Windows.
    """
    # The ACL path wrapper owns environment expansion and extended-path handling.
    # pylint: disable=duplicate-code
    if path.startswith("\\\\?\\"):
        return path
    _, kernel = _libraries()
    capacity = 256
    while True:
        buffer = ctypes.create_unicode_buffer(capacity)
        required = kernel.ExpandEnvironmentStringsW(path, buffer, capacity)
        if not required:
            raise ctypes.WinError(ctypes.get_last_error())
        if required <= capacity:
            return buffer.value
        capacity = required
    # pylint: enable=duplicate-code


def _registry_path(path):
    path = re.sub(
        r"^(?:Microsoft\.PowerShell\.Core\\)?Registry::", "", path, flags=re.I
    )
    parts = path.replace("/", "\\").split("\\", 1)
    root = parts[0].rstrip(":").upper()
    for short, (long_name, handle) in _HIVES.items():
        if root in (short, long_name):
            return ctypes.c_void_p(ctypes.c_int32(handle).value).value, (
                parts[1] if len(parts) > 1 else ""
            )
    return None


@contextmanager
def _object_handle(security, kernel, path, access, open_reparse_point=False):
    registry = _registry_path(path)
    if registry is not None:
        handle = ctypes.c_void_p()
        status = security.RegOpenKeyExW(
            registry[0], registry[1], 0, access, ctypes.byref(handle)
        )
        if status:
            raise ctypes.WinError(status)
        try:
            yield handle, 4
        finally:
            security.RegCloseKey(handle)
    else:
        flags = 0x02200000 if open_reparse_point else 0x02000000
        handle = kernel.CreateFileW(path, access, 7, None, 3, flags, None)
        if handle == ctypes.c_void_p(-1).value:
            raise ctypes.WinError(ctypes.get_last_error())
        try:
            yield handle, 1
        finally:
            kernel.CloseHandle(handle)


def _aces(dacl):
    if len(dacl) < 8:
        raise ValueError("The DACL header is truncated.")
    _, _, size, count, _ = struct.unpack_from("<BBHHH", dacl)
    if size < 8 or size > len(dacl):
        raise ValueError("The DACL size is invalid.")
    entries = []
    offset = 8
    for _ in range(count):
        if offset + 4 > size:
            raise ValueError("The DACL contains a truncated ACE header.")
        length = struct.unpack_from("<H", dacl, offset + 2)[0]
        if length < 4 or length % 4 or offset + length > size:
            raise ValueError("The DACL contains an invalid ACE size.")
        entries.append(dacl[offset : offset + length])
        offset += length
    return entries


def _pack_acl(entries, revision=2):
    body = b"".join(entries)
    if len(body) + 8 > 65535:
        raise ValueError("The resulting DACL exceeds the Windows ACL size limit.")
    return struct.pack("<BBHHH", revision, 0, len(body) + 8, len(entries), 0) + body


def _replace_ace(ace, flags=None, mask=None):
    value = bytearray(ace)
    if flags is not None:
        value[1] = flags
    if mask is not None:
        struct.pack_into("<I", value, 4, mask)
    return bytes(value)


def _common_rule(ace):
    if ace[0] not in (0, 1):
        return None
    if len(ace) < 16 or len(ace) != 16 + 4 * ace[9]:
        raise ValueError("The DACL contains a malformed access-rule SID.")
    return ace[0], ace[1] & 15, struct.unpack_from("<I", ace, 4)[0], ace[8:]


def _canonical(entries):
    stage = 0
    for ace in entries:
        if ace[1] & _INHERITED:
            next_stage = 2
        elif ace[0] in (1, 6, 10, 12):
            next_stage = 0
        elif ace[0] in (0, 5, 9, 11):
            next_stage = 1
        else:
            return False
        if next_stage < stage:
            return False
        stage = next_stage
    return True


def _scope(flags):
    # The five bits describe this object, child containers, child leaves,
    # deeper containers, and deeper leaves respectively.
    scope = 0 if flags & 8 else 1
    if flags & 2:
        scope |= 2 if flags & 4 else 10
    if flags & 1:
        scope |= 4 if flags & 4 else 20
    return scope


_SCOPE_FLAGS = {_scope(flags): flags for flags in range(16) if flags & 3 or not flags}


def _merge_common(left, right):
    first, second = _common_rule(left), _common_rule(right)
    if first is None or second is None:
        return None
    if (
        left[1] & _INHERITED
        or right[1] & _INHERITED
        or first[0] != second[0]
        or first[3] != second[3]
    ):
        return None
    if first[1] == second[1]:
        return _replace_ace(left, mask=first[2] | second[2])
    if first[2] == second[2]:
        flags = _SCOPE_FLAGS.get(_scope(first[1]) | _scope(second[1]))
        if flags is not None:
            return _replace_ace(left, flags=flags)
    return None


def _ace_sid(ace):
    offset = 8
    if ace[0] in (5, 6, 7, 11, 12, 15):
        if len(ace) < 12:
            raise ValueError("The ACL contains a truncated object ACE.")
        flags = struct.unpack_from("<I", ace, 8)[0]
        if flags & ~3:
            raise ValueError("The ACL contains unsupported object ACE flags.")
        offset = 12 + 16 * (bool(flags & 1) + bool(flags & 2))
    if len(ace) < offset + 8 or ace[offset] != 1 or ace[offset + 1] > 15:
        raise ValueError("The ACL contains a malformed ACE SID.")
    end = offset + 8 + 4 * ace[offset + 1]
    callback = ace[0] in (9, 10, 11, 12, 13, 15)
    if end > len(ace) or not callback and end != len(ace):
        raise ValueError("The ACL contains a malformed ACE SID.")
    return ace[offset:end]


def _sort_aces(entries):
    priorities = {1: 0, 10: 0, 6: 1, 12: 1, 0: 2, 9: 2, 5: 3, 11: 3}

    def _order(pair):
        index, ace = pair
        if ace[1] & _INHERITED:
            return (4, index, ())
        if ace[0] not in priorities:
            raise ValueError("The DACL contains an unsupported explicit ACE type.")
        sid = _ace_sid(ace)
        sid_key = (sid[2:8], sid[1], struct.unpack("<" + "I" * sid[1], sid[8:]))
        # Preserve whole ACEs, including callback data and object GUIDs. Common
        # entries precede object entries within each explicit deny/allow group.
        return (priorities[ace[0]], 0, sid_key)

    return [ace for _, ace in sorted(enumerate(entries), key=_order)]


def _normalize_acl(dacl, container):
    entries = []
    for ace in _aces(dacl):
        flags = ace[1] & ~0xC0
        if flags & 8 and (not container or not flags & 3):
            continue
        if not container:
            flags &= ~15
        elif not flags & 3:
            flags &= ~4
        rule = _common_rule(ace)
        if rule is not None and not rule[2]:
            continue
        if ace[0] in (2, 3, 7, 8, 13, 14, 15, 16):
            continue
        entries.append(_replace_ace(ace, flags=flags))
    if _canonical(entries) and all(
        ace[1] & _INHERITED or _common_rule(ace) is not None for ace in entries
    ):
        # Ordinary filesystem/registry rules are ordered by SID within the
        # explicit deny/allow groups. Inherited order comes from the parent.
        entries = _sort_aces(entries)
        index = 0
        while index + 1 < len(entries):
            merged = _merge_common(entries[index], entries[index + 1])
            if merged is not None:
                entries[index : index + 2] = [merged]
            # Upstream advances after a merge too; a third adjacent rule is
            # not folded into the first merged pair during this read.
            index += 1
    return _pack_acl(entries, dacl[0])


def read_acl(path, open_reparse_point=False, container=None):
    """Read a DACL and inheritance state without acquiring extra privileges.

    :param path: Expanded filesystem or registry path.
    :type path: str
    :param open_reparse_point: Read the link itself when True.
    :type open_reparse_point: bool
    :param container: Optional known object type; otherwise inspect the path.
    :type container: bool or None
    :returns: Snapshot with protected, dacl, registry, and container fields.
        A null DACL is represented by None; an empty DACL remains ACL bytes.
    :rtype: dict
    :raises OSError: If opening or reading the object fails.
    :raises ValueError: If the DACL is malformed or called outside Windows.
    """
    security, kernel = _libraries()
    with _object_handle(
        security, kernel, path, _READ_CONTROL, open_reparse_point
    ) as opened:
        handle, kind = opened
        descriptor, dacl = ctypes.c_void_p(), ctypes.c_void_p()
        try:
            # Keep the DACL query's exact native descriptor ownership explicit.
            # pylint: disable=duplicate-code
            status = security.GetSecurityInfo(
                handle,
                kind,
                4,
                None,
                None,
                ctypes.byref(dacl),
                None,
                ctypes.byref(descriptor),
            )
            # pylint: enable=duplicate-code
            if status:
                raise ctypes.WinError(status)
            control, revision = ctypes.c_uint16(), ctypes.c_uint32()
            # Read descriptor control under the same DACL object's lifetime.
            # pylint: disable=duplicate-code
            if not security.GetSecurityDescriptorControl(
                descriptor, ctypes.byref(control), ctypes.byref(revision)
            ):
                raise ctypes.WinError(ctypes.get_last_error())
            # pylint: enable=duplicate-code
            if container is None:
                container = kind == 4 or os.path.isdir(path)
            contents = None
            if dacl:
                size = struct.unpack_from("<H", ctypes.string_at(dacl, 8), 2)[0]
                contents = _normalize_acl(ctypes.string_at(dacl, size), container)
            return {
                "protected": bool(control.value & _SE_DACL_PROTECTED),
                "dacl": contents,
                "registry": kind == 4,
                "container": container,
            }
        finally:
            if descriptor:
                kernel.LocalFree(descriptor)


def set_protection(snapshot, protected, preserve_inherited=False):
    """Prepare the upstream protection change without accessing the object.

    :param snapshot: DACL snapshot returned by read_acl.
    :type snapshot: dict
    :param protected: Whether to disable inheritance.
    :type protected: bool
    :param preserve_inherited: Keep inherited ACEs when disabling inheritance.
    :type preserve_inherited: bool
    :returns: New snapshot; the input is unchanged. Windows converts retained
        inherited entries when the protected DACL is persisted.
    :rtype: dict
    :raises ValueError: If inherited ACE removal encounters a noncanonical ACL.
    """
    result = dict(snapshot)
    dacl = snapshot["dacl"]
    if dacl is None:
        # Managed ACL protection materializes a null DACL as Everyone/full
        # access. An empty ACL must never take this path: it denies all access.
        flags = 3 if snapshot.get("container", snapshot["registry"]) else 0
        everyone = b"\x01\x01\x00\x00\x00\x00\x00\x01\x00\x00\x00\x00"
        dacl = _pack_acl([struct.pack("<BBHI", 0, flags, 20, 0xFFFFFFFF) + everyone])
    if protected and not preserve_inherited:
        entries = _aces(dacl)
        if not _canonical(entries):
            raise ValueError(
                "Inherited permissions cannot be removed from a noncanonical DACL."
            )
        dacl = _pack_acl([ace for ace in entries if not ace[1] & _INHERITED], dacl[0])
    result["dacl"] = dacl
    result["protected"] = protected
    return result


def _subtract_rule(entries, rule, project_rule=_common_rule):
    result = []
    for ace in entries:
        current = project_rule(ace)
        if (
            current is None
            or ace[1] & _INHERITED
            or current[0] != rule[0]
            or current[3] != rule[3]
            or not current[2] & rule[2]
        ):
            result.append(ace)
            continue
        remaining_scope = _scope(current[1]) & ~_scope(rule[1])
        flags = _SCOPE_FLAGS.get(remaining_scope)
        if remaining_scope and flags is None:
            return entries
        remaining_mask = current[2] & ~rule[2]
        if remaining_mask:
            result.append(_replace_ace(ace, mask=remaining_mask))
        if remaining_scope:
            result.append(_replace_ace(ace, flags=flags, mask=current[2] & rule[2]))
    return result


def remove_explicit_duplicates(snapshot):
    """Remove explicit rules equal to rules already inherited in this snapshot.

    A matching rule removes its permission bits from overlapping explicit rules,
    as RemoveAccessRule does. This never reads newly inherited entries from disk.

    :param snapshot: In-memory DACL after enabling inheritance.
    :type snapshot: dict
    :returns: New snapshot containing the deduplicated DACL.
    :rtype: dict
    :raises ValueError: If a matching rule occurs in a noncanonical DACL.
    """
    result = dict(snapshot)
    if snapshot["dacl"] is None:
        return result
    entries = _aces(snapshot["dacl"])
    inherited = [ace for ace in entries if ace[1] & _INHERITED]
    for ace in inherited:
        rule = _common_rule(ace)
        if rule is None:
            continue
        matches = [
            candidate
            for candidate in entries
            if not candidate[1] & _INHERITED and _common_rule(candidate) == rule
        ]
        for _ in matches:
            if not _canonical(entries):
                raise ValueError(
                    "Duplicate rules cannot be removed from a noncanonical DACL."
                )
            entries = _subtract_rule(entries, rule)
    result["dacl"] = _pack_acl(entries, snapshot["dacl"][0])
    return result


def write_acl(path, snapshot, open_reparse_point=False):
    """Persist only DACL and protection, allowing Windows inheritance propagation.

    :param path: Expanded filesystem or registry path.
    :type path: str
    :param snapshot: Prepared DACL snapshot; owner, group, and SACL are untouched.
    :type snapshot: dict
    :param open_reparse_point: Change the link itself when True.
    :type open_reparse_point: bool
    :raises OSError: If opening or changing the object's DACL fails.
    :raises ValueError: If called outside Windows.
    """
    security, kernel = _libraries()
    with _object_handle(
        security, kernel, path, _READ_CONTROL | _WRITE_DAC, open_reparse_point
    ) as opened:
        handle, kind = opened
        protection = 0x80000000 if snapshot["protected"] else 0x20000000
        dacl = snapshot["dacl"]
        buffer = ctypes.create_string_buffer(dacl) if dacl is not None else None
        status = security.SetSecurityInfo(
            handle,
            kind,
            _DACL_SECURITY_INFORMATION | protection,
            None,
            None,
            buffer,
            None,
        )
        if status:
            raise ctypes.WinError(status)
