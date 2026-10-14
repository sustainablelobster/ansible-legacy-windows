# -*- coding: utf-8 -*-
# Copyright 2026 sustainablelobster
# SPDX-License-Identifier: GPL-3.0-or-later

"""Read Windows filesystem metadata through APIs available to Python 3.4.4."""

import binascii
import ctypes
import ntpath
import os

_INVALID_HANDLE = int(ctypes.c_void_p(-1).value)
_HASH_ALGORITHMS = {
    "md5": 0x8003,
    "sha1": 0x8004,
    "sha256": 0x800C,
    "sha384": 0x800D,
    "sha512": 0x800E,
}
_ATTRIBUTE_NAMES = (
    (1, "ReadOnly"),
    (2, "Hidden"),
    (4, "System"),
    (16, "Directory"),
    (32, "Archive"),
    (64, "Device"),
    (128, "Normal"),
    (256, "Temporary"),
    (512, "SparseFile"),
    (1024, "ReparsePoint"),
    (2048, "Compressed"),
    (4096, "Offline"),
    (8192, "NotContentIndexed"),
    (16384, "Encrypted"),
    (32768, "IntegrityStream"),
    (131072, "NoScrubData"),
)


# These records describe native memory layouts and do not need methods.
class _FileTime(ctypes.Structure):  # pylint: disable=too-few-public-methods
    _fields_ = [("low", ctypes.c_uint32), ("high", ctypes.c_uint32)]


class _AttributeData(ctypes.Structure):  # pylint: disable=too-few-public-methods
    _fields_ = [
        ("attributes", ctypes.c_uint32),
        ("creation_time", _FileTime),
        ("access_time", _FileTime),
        ("modification_time", _FileTime),
        ("size_high", ctypes.c_uint32),
        ("size_low", ctypes.c_uint32),
    ]


class _FindData(_AttributeData):  # pylint: disable=too-few-public-methods
    _fields_ = [
        ("reserved0", ctypes.c_uint32),
        ("reserved1", ctypes.c_uint32),
        ("name", ctypes.c_wchar * 260),
        ("alternate_name", ctypes.c_wchar * 14),
    ]


class _HandleData(ctypes.Structure):  # pylint: disable=too-few-public-methods
    _fields_ = [
        ("attributes", ctypes.c_uint32),
        ("creation_time", _FileTime),
        ("access_time", _FileTime),
        ("modification_time", _FileTime),
        ("volume_serial", ctypes.c_uint32),
        ("size_high", ctypes.c_uint32),
        ("size_low", ctypes.c_uint32),
        ("link_count", ctypes.c_uint32),
        ("index_high", ctypes.c_uint32),
        ("index_low", ctypes.c_uint32),
    ]


class _ShareInfo(ctypes.Structure):  # pylint: disable=too-few-public-methods
    # Repeat the fixed Windows record layout without adding a staging dependency.
    # pylint: disable=duplicate-code
    _fields_ = [
        ("name", ctypes.c_wchar_p),
        ("kind", ctypes.c_uint32),
        ("remark", ctypes.c_wchar_p),
        ("permissions", ctypes.c_uint32),
        ("max_uses", ctypes.c_uint32),
        ("current_uses", ctypes.c_uint32),
        ("path", ctypes.c_wchar_p),
        ("password", ctypes.c_wchar_p),
    ]
    # pylint: enable=duplicate-code


def _kernel():
    if os.name != "nt":
        raise ValueError("Stat operations require a Windows target.")
    kernel = ctypes.WinDLL("kernel32", use_last_error=True)
    kernel.GetFileAttributesExW.argtypes = [
        ctypes.c_wchar_p,
        ctypes.c_int,
        ctypes.POINTER(_AttributeData),
    ]
    kernel.GetFileAttributesExW.restype = ctypes.c_int
    kernel.FindFirstFileW.argtypes = [ctypes.c_wchar_p, ctypes.POINTER(_FindData)]
    kernel.FindFirstFileW.restype = ctypes.c_void_p
    kernel.FindNextFileW.argtypes = [ctypes.c_void_p, ctypes.POINTER(_FindData)]
    kernel.FindNextFileW.restype = ctypes.c_int
    kernel.FindClose.argtypes = [ctypes.c_void_p]
    kernel.FindClose.restype = ctypes.c_int
    kernel.GetFullPathNameW.argtypes = [
        ctypes.c_wchar_p,
        ctypes.c_uint32,
        ctypes.c_wchar_p,
        ctypes.c_void_p,
    ]
    kernel.GetFullPathNameW.restype = ctypes.c_uint32
    kernel.GetLongPathNameW.argtypes = [
        ctypes.c_wchar_p,
        ctypes.c_wchar_p,
        ctypes.c_uint32,
    ]
    kernel.GetLongPathNameW.restype = ctypes.c_uint32
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
    kernel.GetFileInformationByHandle.argtypes = [
        ctypes.c_void_p,
        ctypes.POINTER(_HandleData),
    ]
    kernel.GetFileInformationByHandle.restype = ctypes.c_int
    kernel.GetFileType.argtypes = [ctypes.c_void_p]
    kernel.GetFileType.restype = ctypes.c_uint32
    kernel.ReadFile.argtypes = [
        ctypes.c_void_p,
        ctypes.c_void_p,
        ctypes.c_uint32,
        ctypes.POINTER(ctypes.c_uint32),
        ctypes.c_void_p,
    ]
    kernel.ReadFile.restype = ctypes.c_int
    kernel.CloseHandle.argtypes = [ctypes.c_void_p]
    kernel.CloseHandle.restype = ctypes.c_int
    kernel.LocalFree.argtypes = [ctypes.c_void_p]
    kernel.LocalFree.restype = ctypes.c_void_p
    return kernel


def _security():
    security = ctypes.WinDLL("advapi32", use_last_error=True)
    # Keep this independently staged wrapper's native ABI declarations local.
    # pylint: disable=duplicate-code
    security.GetNamedSecurityInfoW.argtypes = [
        ctypes.c_wchar_p,
        ctypes.c_uint32,
        ctypes.c_uint32,
        ctypes.POINTER(ctypes.c_void_p),
        ctypes.c_void_p,
        ctypes.c_void_p,
        ctypes.c_void_p,
        ctypes.POINTER(ctypes.c_void_p),
    ]
    security.GetNamedSecurityInfoW.restype = ctypes.c_uint32
    security.LookupAccountSidW.argtypes = [
        ctypes.c_wchar_p,
        ctypes.c_void_p,
        ctypes.c_wchar_p,
        ctypes.POINTER(ctypes.c_uint32),
        ctypes.c_wchar_p,
        ctypes.POINTER(ctypes.c_uint32),
        ctypes.POINTER(ctypes.c_uint32),
    ]
    security.LookupAccountSidW.restype = ctypes.c_int
    security.ConvertSecurityDescriptorToStringSecurityDescriptorW.argtypes = [
        ctypes.c_void_p,
        ctypes.c_uint32,
        ctypes.c_uint32,
        ctypes.POINTER(ctypes.c_void_p),
        ctypes.c_void_p,
    ]
    security.ConvertSecurityDescriptorToStringSecurityDescriptorW.restype = ctypes.c_int
    # pylint: enable=duplicate-code
    return security


def _crypto():
    crypto = ctypes.WinDLL("advapi32", use_last_error=True)
    crypto.CryptAcquireContextW.argtypes = [
        ctypes.POINTER(ctypes.c_size_t),
        ctypes.c_wchar_p,
        ctypes.c_wchar_p,
        ctypes.c_uint32,
        ctypes.c_uint32,
    ]
    crypto.CryptAcquireContextW.restype = ctypes.c_int
    crypto.CryptCreateHash.argtypes = [
        ctypes.c_size_t,
        ctypes.c_uint32,
        ctypes.c_size_t,
        ctypes.c_uint32,
        ctypes.POINTER(ctypes.c_size_t),
    ]
    crypto.CryptCreateHash.restype = ctypes.c_int
    crypto.CryptHashData.argtypes = [
        ctypes.c_size_t,
        ctypes.c_void_p,
        ctypes.c_uint32,
        ctypes.c_uint32,
    ]
    crypto.CryptHashData.restype = ctypes.c_int
    crypto.CryptGetHashParam.argtypes = [
        ctypes.c_size_t,
        ctypes.c_uint32,
        ctypes.c_void_p,
        ctypes.POINTER(ctypes.c_uint32),
        ctypes.c_uint32,
    ]
    crypto.CryptGetHashParam.restype = ctypes.c_int
    crypto.CryptDestroyHash.argtypes = [ctypes.c_size_t]
    crypto.CryptDestroyHash.restype = ctypes.c_int
    crypto.CryptReleaseContext.argtypes = [ctypes.c_size_t, ctypes.c_uint32]
    crypto.CryptReleaseContext.restype = ctypes.c_int
    return crypto


def _ticks(value):
    return (value.high << 32) | value.low


def _entry_info(data):
    return {
        "attributes": data.attributes,
        "creation_time": _ticks(data.creation_time),
        "access_time": _ticks(data.access_time),
        "modification_time": _ticks(data.modification_time),
        "size": (data.size_high << 32) | data.size_low,
    }


def attribute_names(value):
    """Format Windows file attributes in ascending flag order.

    :param value: Unsigned 32-bit Windows file attributes.
    :type value: int
    :returns: Comma-separated flag names, or signed decimal when zero or when
        any bit lacks a known name.
    :rtype: str
    """
    known_bits = sum(bit for bit, _name in _ATTRIBUTE_NAMES)
    if not value or value & ~known_bits:
        return str(value if value < 0x80000000 else value - 0x100000000)
    return ", ".join(name for bit, name in _ATTRIBUTE_NAMES if value & bit)


def file_info(path):
    """Read the named entry, suppressing initial native metadata errors.

    :param path: Literal Windows file or directory path.
    :type path: str
    :returns: Attributes, exact creation/access/modification FILETIME integers,
        and size in bytes; None when the initial metadata lookup fails. A
        final reparse point retains its own attributes.
    :rtype: dict or None
    """
    kernel = _kernel()
    data = _AttributeData()
    if not kernel.GetFileAttributesExW(path, 0, ctypes.byref(data)):
        if ctypes.get_last_error() in (2, 3, 21):
            return None
        # Framework retries enumeration for locked files such as pagefile.sys.
        data = _FindData()
        handle = kernel.FindFirstFileW(path.rstrip("\\/"), ctypes.byref(data))
        if handle == _INVALID_HANDLE:
            return None
        kernel.FindClose(handle)
    return _entry_info(data)


def hardlink_count(path):
    """Read a file's native hard-link count without requesting data access.

    :param path: Literal Windows file path.
    :type path: str
    :returns: The number of hard links reported by the filesystem.
    :rtype: int
    :raises OSError: If the entry cannot be opened or queried.
    """
    kernel = _kernel()
    handle = kernel.CreateFileW(path, 0, 7, None, 3, 0x02000000, None)
    if handle == _INVALID_HANDLE:
        raise ctypes.WinError(ctypes.get_last_error())
    try:
        data = _HandleData()
        if not kernel.GetFileInformationByHandle(handle, ctypes.byref(data)):
            raise ctypes.WinError(ctypes.get_last_error())
        return data.link_count
    finally:
        kernel.CloseHandle(handle)


def full_path(path):
    """Resolve a Windows path and expand any short filename components.

    :param path: Literal Windows path with environment expansion already done.
    :type path: str
    :returns: Absolute path retaining caller casing unless short names expand.
    :rtype: str
    :raises OSError: If Windows cannot resolve the absolute path.
    """
    kernel = _kernel()
    capacity = 260
    while True:
        buffer = ctypes.create_unicode_buffer(capacity)
        length = kernel.GetFullPathNameW(path, capacity, buffer, None)
        if not length:
            raise ctypes.WinError(ctypes.get_last_error())
        if length < capacity:
            break
        capacity = length + 1
    absolute = buffer.value
    if "~" in absolute:
        while True:
            length = kernel.GetLongPathNameW(absolute, buffer, capacity)
            if not length:
                break
            if length < capacity:
                return buffer.value
            capacity = length + 1
            buffer = ctypes.create_unicode_buffer(capacity)
    return absolute


def _account_name(security, sid):
    name_size = ctypes.c_uint32()
    domain_size = ctypes.c_uint32()
    sid_kind = ctypes.c_uint32()
    security.LookupAccountSidW(
        None,
        sid,
        None,
        ctypes.byref(name_size),
        None,
        ctypes.byref(domain_size),
        ctypes.byref(sid_kind),
    )
    error = ctypes.get_last_error()
    if error == 1332:
        return None
    if error != 122:
        raise ctypes.WinError(error)
    name = ctypes.create_unicode_buffer(name_size.value)
    domain = ctypes.create_unicode_buffer(domain_size.value)
    if not security.LookupAccountSidW(
        None,
        sid,
        name,
        ctypes.byref(name_size),
        domain,
        ctypes.byref(domain_size),
        ctypes.byref(sid_kind),
    ):
        error = ctypes.get_last_error()
        if error == 1332:
            return None
        raise ctypes.WinError(error)
    return domain.value + "\\" + name.value if domain.value else name.value


def owner(path):
    """Read an NT account owner, retaining unmapped owners as owner-only SDDL.

    :param path: Literal Windows file or directory path.
    :type path: str
    :returns: DOMAIN\\account, account without a domain, or owner-only SDDL.
    :rtype: str
    :raises OSError: If security data or account translation cannot be read.
    """
    kernel = _kernel()
    security = _security()
    sid = ctypes.c_void_p()
    descriptor = ctypes.c_void_p()
    converted = ctypes.c_void_p()
    try:
        status = security.GetNamedSecurityInfoW(
            path, 1, 7, ctypes.byref(sid), None, None, None, ctypes.byref(descriptor)
        )
        if status:
            raise ctypes.WinError(status)
        account = _account_name(security, sid)
        if account is not None:
            return account
        if not security.ConvertSecurityDescriptorToStringSecurityDescriptorW(
            descriptor, 1, 1, ctypes.byref(converted), None
        ):
            raise ctypes.WinError(ctypes.get_last_error())
        return ctypes.wstring_at(converted)
    finally:
        if converted:
            kernel.LocalFree(converted)
        if descriptor:
            kernel.LocalFree(descriptor)


def shares(path):
    """Find local shares whose stored path equals the supplied directory path.

    :param path: Absolute Windows directory path, compared without case.
    :type path: str
    :returns: Matching share names in native enumeration order.
    :rtype: list
    :raises OSError: If Windows cannot enumerate local shares.
    """
    network = ctypes.WinDLL("netapi32", use_last_error=True)
    network.NetShareEnum.argtypes = [
        ctypes.c_wchar_p,
        ctypes.c_uint32,
        ctypes.POINTER(ctypes.c_void_p),
        ctypes.c_uint32,
        ctypes.POINTER(ctypes.c_uint32),
        ctypes.POINTER(ctypes.c_uint32),
        ctypes.POINTER(ctypes.c_uint32),
    ]
    network.NetShareEnum.restype = ctypes.c_uint32
    network.NetApiBufferFree.argtypes = [ctypes.c_void_p]
    network.NetApiBufferFree.restype = ctypes.c_uint32
    resume = ctypes.c_uint32()
    matches = []
    while True:
        buffer = ctypes.c_void_p()
        received = ctypes.c_uint32()
        total = ctypes.c_uint32()
        try:
            status = network.NetShareEnum(
                None,
                2,
                ctypes.byref(buffer),
                0xFFFFFFFF,
                ctypes.byref(received),
                ctypes.byref(total),
                ctypes.byref(resume),
            )
            if status not in (0, 234):
                raise ctypes.WinError(status)
            entries = ctypes.cast(buffer, ctypes.POINTER(_ShareInfo))
            for index in range(received.value):
                entry = entries[index]
                if entry.path is not None and entry.path.lower() == path.lower():
                    matches.append(entry.name)
        finally:
            if buffer:
                network.NetApiBufferFree(buffer)
        if not status:
            return matches


def _directory_entries(kernel, path):
    data = _FindData()
    handle = kernel.FindFirstFileW(ntpath.join(path, "*"), ctypes.byref(data))
    if handle == _INVALID_HANDLE:
        error = ctypes.get_last_error()
        if error == 2:
            return
        raise ctypes.WinError(error)
    try:
        while True:
            if data.name not in (".", ".."):
                entry = _entry_info(data)
                entry["name"] = data.name
                yield entry
            if not kernel.FindNextFileW(handle, ctypes.byref(data)):
                error = ctypes.get_last_error()
                if error != 18:
                    raise ctypes.WinError(error)
                return
    finally:
        kernel.FindClose(handle)


def directory_entries(path):
    """Snapshot immediate directory children in native enumeration order.

    :param path: Literal Windows directory path.
    :type path: str
    :returns: Independent dictionaries containing name, attributes, exact
        creation/access/modification FILETIME integers, and size in bytes.
        Dot entries are excluded. An initial ERROR_FILE_NOT_FOUND returns an
        empty list; callers must inspect the root separately for existence.
    :rtype: list
    :raises OSError: If enumeration fails with any other native error.
    """
    return list(_directory_entries(_kernel(), path))


def directory_size(path):
    """Sum every file entry, including hidden files and directory link targets.

    :param path: Literal Windows directory path.
    :type path: str
    :returns: Recursive size in bytes; repeated hardlink names count separately.
    :rtype: int
    :raises OSError: If any directory cannot be enumerated.
    """
    kernel = _kernel()
    pending = [path]
    total = 0
    while pending:
        directory = pending.pop()
        for entry in _directory_entries(kernel, directory):
            if entry["attributes"] & 0x10:
                pending.append(ntpath.join(directory, entry["name"]))
            else:
                total += entry["size"]
    return total


def _hash_file(kernel, crypto, hash_handle, path):
    handle = kernel.CreateFileW(path, 0x80000000, 3, None, 3, 0x00100000, None)
    if handle == _INVALID_HANDLE:
        raise ctypes.WinError(ctypes.get_last_error())
    try:
        if kernel.GetFileType(handle) != 1:
            raise ValueError("Only disk files are supported.")
        buffer = ctypes.create_string_buffer(65536)
        received = ctypes.c_uint32()
        while True:
            if not kernel.ReadFile(
                handle, buffer, len(buffer), ctypes.byref(received), None
            ):
                raise ctypes.WinError(ctypes.get_last_error())
            if not received.value:
                return
            if not crypto.CryptHashData(hash_handle, buffer, received.value, 0):
                raise ctypes.WinError(ctypes.get_last_error())
    finally:
        kernel.CloseHandle(handle)


def checksum(path, algorithm):
    """Hash a disk file through the native provider for the requested algorithm.

    :param path: Literal Windows file path, opened with read/write sharing.
    :type path: str
    :param algorithm: md5, sha1, sha256, sha384, or sha512.
    :type algorithm: str
    :returns: Lowercase hexadecimal digest.
    :rtype: str
    :raises ValueError: If the algorithm is unsupported or the file is not disk.
    :raises OSError: If provider initialization, file access, or hashing fails.
    """
    if algorithm not in _HASH_ALGORITHMS:
        raise ValueError("Unsupported hash algorithm supplied '{0}'".format(algorithm))
    kernel = _kernel()
    crypto = _crypto()
    context = ctypes.c_size_t()
    hash_handle = ctypes.c_size_t()
    # MD5 and SHA1 use the baseline RSA provider. SHA2 uses the default RSA/AES
    # provider, available on XP under its Prototype name.
    # Native provider and algorithm policy failures remain observable.
    provider_type = 1 if algorithm in ("md5", "sha1") else 24
    if not crypto.CryptAcquireContextW(
        ctypes.byref(context), None, None, provider_type, 0xF0000000
    ):
        raise ctypes.WinError(ctypes.get_last_error())
    try:
        if not crypto.CryptCreateHash(
            context, _HASH_ALGORITHMS[algorithm], 0, 0, ctypes.byref(hash_handle)
        ):
            raise ctypes.WinError(ctypes.get_last_error())
        _hash_file(kernel, crypto, hash_handle, path)
        length = ctypes.c_uint32()
        if not crypto.CryptGetHashParam(hash_handle, 2, None, ctypes.byref(length), 0):
            raise ctypes.WinError(ctypes.get_last_error())
        digest = ctypes.create_string_buffer(length.value)
        if not crypto.CryptGetHashParam(
            hash_handle, 2, digest, ctypes.byref(length), 0
        ):
            raise ctypes.WinError(ctypes.get_last_error())
        return binascii.hexlify(digest.raw[: length.value]).decode("ascii")
    finally:
        if hash_handle.value:
            crypto.CryptDestroyHash(hash_handle)
        crypto.CryptReleaseContext(context, 0)
