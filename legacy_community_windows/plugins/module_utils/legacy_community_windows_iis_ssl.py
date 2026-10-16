# -*- coding: utf-8 -*-
# Copyright 2026 sustainablelobster
# SPDX-License-Identifier: GPL-3.0-or-later

"""Read and assign exact IIS HTTP.sys SSL endpoints using the HTTP Server API."""

import binascii
import ctypes
import socket
import struct
import uuid

from legacy_windows_wmi import _Guid  # pylint: disable=import-error

_POINTER, _DWORD = ctypes.c_void_p, ctypes.c_uint32


# These declarations mirror http.h records, including SOCKADDR_STORAGE alignment.
# pylint: disable=too-few-public-methods
class _Address(ctypes.Union):
    _fields_ = [("bytes", ctypes.c_ubyte * 128), ("alignment", ctypes.c_int64)]


class _SslKey(ctypes.Structure):
    _fields_ = [("address", _POINTER)]


class _SniKey(ctypes.Structure):
    _fields_ = [("address", _Address), ("host", ctypes.c_wchar_p)]


class _CcsKey(ctypes.Structure):
    _fields_ = [("address", _Address)]


class _Parameters(ctypes.Structure):
    _fields_ = [
        ("hash_length", _DWORD),
        ("hash", _POINTER),
        ("application", _Guid),
        ("store", ctypes.c_wchar_p),
        ("check_mode", _DWORD),
        ("freshness", _DWORD),
        ("retrieval_timeout", _DWORD),
        ("ctl_identifier", ctypes.c_wchar_p),
        ("ctl_store", ctypes.c_wchar_p),
        ("flags", _DWORD),
    ]


class _SslSet(ctypes.Structure):
    _fields_ = [("key", _SslKey), ("parameters", _Parameters)]


class _SniSet(ctypes.Structure):
    _fields_ = [("key", _SniKey), ("parameters", _Parameters)]


class _CcsSet(ctypes.Structure):
    _fields_ = [("key", _CcsKey), ("parameters", _Parameters)]


class _SslQuery(ctypes.Structure):
    _fields_ = [("kind", ctypes.c_int32), ("key", _SslKey), ("token", _DWORD)]


class _SniQuery(ctypes.Structure):
    _fields_ = [("kind", ctypes.c_int32), ("key", _SniKey), ("token", _DWORD)]


class _CcsQuery(ctypes.Structure):
    _fields_ = [("kind", ctypes.c_int32), ("key", _CcsKey), ("token", _DWORD)]


# pylint: enable=too-few-public-methods


def _address(ip, port):
    address = _Address()
    ip = ip.strip("[]")
    if ":" in ip:
        data = (
            struct.pack("<H", 23)
            + struct.pack("!H", port)
            + b"\0" * 4
            + socket.inet_pton(socket.AF_INET6, ip)
            + b"\0" * 4
        )
    else:
        data = (
            struct.pack("<H", 2)
            + struct.pack("!H", port)
            + socket.inet_aton("0.0.0.0" if ip in ("", "*") else ip)
            + b"\0" * 8
        )
    ctypes.memmove(ctypes.byref(address), data, len(data))
    return address


def _library():
    library = ctypes.WinDLL("httpapi")
    library.HttpInitialize.argtypes = [_DWORD, _DWORD, _POINTER]
    library.HttpInitialize.restype = _DWORD
    library.HttpTerminate.argtypes = [_DWORD, _POINTER]
    library.HttpTerminate.restype = _DWORD
    library.HttpQueryServiceConfiguration.argtypes = [
        _POINTER,
        ctypes.c_int32,
        _POINTER,
        _DWORD,
        _POINTER,
        _DWORD,
        ctypes.POINTER(_DWORD),
        _POINTER,
    ]
    library.HttpQueryServiceConfiguration.restype = _DWORD
    for name in ("HttpSetServiceConfiguration", "HttpDeleteServiceConfiguration"):
        function = getattr(library, name)
        function.argtypes = [_POINTER, ctypes.c_int32, _POINTER, _DWORD, _POINTER]
        function.restype = _DWORD
    return library


def _check(code, operation):
    if code:
        raise OSError(code, "{0} failed (Windows error {1}).".format(operation, code))


def _key(parameters, flags):
    port = int(parameters.get("port", 80))
    if int(flags) & 2:
        return 6, _CcsQuery, _CcsSet, _CcsKey(_address("*", port)), None
    if int(flags) & 1:
        header = parameters.get("host_header") or ""
        if not header:
            raise ValueError("SNI requires a non-empty host_header.")
        return 5, _SniQuery, _SniSet, _SniKey(_address("*", port), header), None
    address = _address(parameters.get("ip") or "*", port)
    return (
        1,
        _SslQuery,
        _SslSet,
        _SslKey(ctypes.cast(ctypes.byref(address), _POINTER)),
        address,
    )


def _query(library, config, query_type, set_type, key):
    request, needed = query_type(0, key, 0), _DWORD()
    code = library.HttpQueryServiceConfiguration(
        None,
        config,
        ctypes.byref(request),
        ctypes.sizeof(request),
        None,
        0,
        ctypes.byref(needed),
        None,
    )
    if code in (2, 1168):
        return None, None
    if code != 122:
        _check(code, "HttpQueryServiceConfiguration(size)")
    buffer = ctypes.create_string_buffer(needed.value)
    _check(
        library.HttpQueryServiceConfiguration(
            None,
            config,
            ctypes.byref(request),
            ctypes.sizeof(request),
            buffer,
            needed,
            ctypes.byref(needed),
            None,
        ),
        "HttpQueryServiceConfiguration",
    )
    return buffer, set_type.from_buffer(buffer)


def _information(record):
    if record is None:
        return {"certificateHash": "", "certificateStoreName": "", "_exists": False}
    value = record.parameters
    return {
        "certificateHash": binascii.hexlify(
            ctypes.string_at(value.hash, value.hash_length)
        )
        .decode("ascii")
        .upper(),
        "certificateStoreName": value.store or ("MY" if value.hash_length else ""),
        "_exists": True,
    }


def _replacement(set_type, key, existing, certificate, store):
    record = set_type(
        key, existing.parameters if existing is not None else _Parameters()
    )
    data = ctypes.create_string_buffer(binascii.unhexlify(certificate))
    record.parameters.hash_length = len(certificate) // 2
    record.parameters.hash = ctypes.cast(data, _POINTER) if certificate else None
    record.parameters.store = store or None
    if existing is None:
        record.parameters.application = _Guid.from_buffer_copy(
            uuid.UUID("4dc3e181-e14b-4a21-b022-59fc669b0914").bytes_le
        )
    return record, data


def _replace(library, config, replacement, existing):
    if existing is not None:
        _check(
            library.HttpDeleteServiceConfiguration(
                None, config, ctypes.byref(existing), ctypes.sizeof(existing), None
            ),
            "HttpDeleteServiceConfiguration",
        )
    if not replacement.parameters.hash_length and config != 6:
        return
    code = library.HttpSetServiceConfiguration(
        None, config, ctypes.byref(replacement), ctypes.sizeof(replacement), None
    )
    if code and existing is not None:
        restored = library.HttpSetServiceConfiguration(
            None, config, ctypes.byref(existing), ctypes.sizeof(existing), None
        )
        if restored:
            raise OSError(
                "HTTP SSL update failed ({0}); restoring the prior assignment "
                "also failed ({1}).".format(code, restored)
            )
    _check(code, "HttpSetServiceConfiguration")


def endpoint(parameters, certificate, store, flags, query=False):
    """Query or replace one exact native HTTP.sys certificate endpoint.

    :param parameters: Binding address, port and optional hostname.
    :type parameters: dict
    :param certificate: SHA-1 certificate thumbprint, or empty to remove.
    :type certificate: str
    :param store: LocalMachine certificate store name.
    :type store: str
    :param flags: IIS SNI/central-certificate-store flag string.
    :type flags: str
    :param query: Read without changing the endpoint.
    :type query: bool
    :returns: Certificate hash, store and internal existence indicator.
    :rtype: dict
    :raises OSError: The HTTP Server API rejects the operation.
    """
    library = _library()
    _check(library.HttpInitialize(1, 2, None), "HttpInitialize(configuration)")
    try:
        config, query_type, set_type, key, _address_storage = _key(parameters, flags)
        # Both buffers own storage referenced by native pointers until completion.
        _query_storage, existing = _query(library, config, query_type, set_type, key)
        if query:
            return _information(existing)
        replacement, _hash_storage = _replacement(
            set_type, key, existing, certificate, store
        )
        _replace(library, config, replacement, existing)
        return {"certificateHash": certificate.upper(), "certificateStoreName": store}
    finally:
        _check(library.HttpTerminate(2, None), "HttpTerminate(configuration)")
