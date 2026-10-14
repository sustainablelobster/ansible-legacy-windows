# -*- coding: utf-8 -*-
# Copyright 2026 sustainablelobster
# SPDX-License-Identifier: GPL-3.0-or-later

"""Manage one named Windows credential through the native Credential Manager."""

import binascii
import ctypes
import os
import struct

_DWORD = ctypes.c_uint32
_POINTER = ctypes.c_void_p
_BOOL = ctypes.c_int32
_CERTIFICATE_TYPES = (3, 5)


# These classes describe native memory records, not application objects.
# pylint: disable=too-few-public-methods
class _FileTime(ctypes.Structure):
    _fields_ = [("low", _DWORD), ("high", _DWORD)]


class _Attribute(ctypes.Structure):
    _fields_ = [
        ("keyword", ctypes.c_wchar_p),
        ("flags", _DWORD),
        ("size", _DWORD),
        ("value", _POINTER),
    ]


class _Credential(ctypes.Structure):
    _fields_ = [
        ("flags", _DWORD),
        ("kind", _DWORD),
        ("target", ctypes.c_wchar_p),
        ("comment", ctypes.c_wchar_p),
        ("written", _FileTime),
        ("secret_size", _DWORD),
        ("secret", _POINTER),
        ("persistence", _DWORD),
        ("attribute_count", _DWORD),
        ("attributes", ctypes.POINTER(_Attribute)),
        ("alias", ctypes.c_wchar_p),
        ("username", ctypes.c_wchar_p),
    ]


class _Blob(ctypes.Structure):
    _fields_ = [("size", _DWORD), ("data", _POINTER)]


# pylint: enable=too-few-public-methods


def _library(name, signatures):
    if os.name != "nt":
        raise OSError("Credential Manager operations require a Windows target.")
    library = ctypes.WinDLL(name, use_last_error=True)
    for operation, signature in signatures.items():
        function = getattr(library, operation)
        function.restype, function.argtypes = signature
    return library


def _advapi():
    return _library(
        "advapi32",
        {
            "CredReadW": (
                _BOOL,
                [ctypes.c_wchar_p, _DWORD, _DWORD, ctypes.POINTER(_POINTER)],
            ),
            "CredWriteW": (_BOOL, [ctypes.POINTER(_Credential), _DWORD]),
            "CredDeleteW": (_BOOL, [ctypes.c_wchar_p, _DWORD, _DWORD]),
            "CredFree": (None, [_POINTER]),
            "CredMarshalCredentialW": (
                _BOOL,
                [_DWORD, _POINTER, ctypes.POINTER(_POINTER)],
            ),
            "CredUnmarshalCredentialW": (
                _BOOL,
                [ctypes.c_wchar_p, ctypes.POINTER(_DWORD), ctypes.POINTER(_POINTER)],
            ),
        },
    )


def _error(operation, code=None):
    code = ctypes.get_last_error() if code is None else code
    signed_code = ctypes.c_int32(code).value
    return OSError(
        "{0} - {1} (Win32 Error Code {2}: 0x{3:08X})".format(
            operation,
            ctypes.FormatError(signed_code).rstrip("\r\n"),
            signed_code,
            code & 0xFFFFFFFF,
        )
    )


def _marshal_certificate(library, thumbprint):
    value = binascii.unhexlify(thumbprint)
    data = ctypes.create_string_buffer(struct.pack("<I", len(value) + 4) + value)
    pointer = _POINTER()
    try:
        if not library.CredMarshalCredentialW(1, data, ctypes.byref(pointer)):
            raise _error("CredMarshalCredentialW() failed")
        return ctypes.wstring_at(pointer)
    finally:
        if pointer:
            library.CredFree(pointer)


def _unmarshal_certificate(library, username):
    kind, pointer = _DWORD(), _POINTER()
    try:
        if not library.CredUnmarshalCredentialW(
            username, ctypes.byref(kind), ctypes.byref(pointer)
        ):
            raise _error("CredUnmarshalCredentialW() failed")
        if kind.value != 1:
            names = {
                2: "UsernameTargetCredential",
                3: "BinaryBlobCredential",
                4: "UsernameForPackedCredential",
                5: "BinaryBlobForSystem",
            }
            raise ValueError(
                "Expected unmarshalled cred type of CertCredential, received "
                + names.get(kind.value, str(kind.value))
            )
        size = ctypes.cast(pointer, ctypes.POINTER(_DWORD)).contents.value
        if size < 4:
            raise ValueError("Certificate credential information is truncated.")
        data = ctypes.string_at(pointer.value + 4, size - 4)
        return binascii.hexlify(data).decode("ascii").upper()
    finally:
        if pointer:
            library.CredFree(pointer)


def read(name, kind):
    """Read exactly one credential, copying data before releasing native memory.

    :param str name: Exact credential target; no enumeration is performed.
    :param int kind: Native credential type.
    :returns: Credential dictionary including its readable secret, or None.
    :rtype: dict or None
    :raises OSError: The credential store or native operation is unavailable.
    :raises ValueError: Certificate credential data has an unexpected type.
    """
    library, pointer = _advapi(), _POINTER()
    try:
        if not library.CredReadW(name, kind, 0, ctypes.byref(pointer)):
            code = ctypes.get_last_error()
            if code == 1168:
                return None
            if code == 1312:
                raise OSError(
                    "Failed to access the user's credential store, run the module with become"
                )
            # Preserve the upstream exception's historical operation label.
            raise _error("CredEnumerateW() failed", code)
        native = ctypes.cast(pointer, ctypes.POINTER(_Credential)).contents
        username = native.username
        if native.kind in _CERTIFICATE_TYPES:
            username = _unmarshal_certificate(library, username)
        attributes = []
        for index in range(native.attribute_count):
            entry = native.attributes[index]
            attributes.append(
                {
                    "name": entry.keyword,
                    "flags": entry.flags,
                    "data": (
                        ctypes.string_at(entry.value, entry.size) if entry.size else b""
                    ),
                }
            )
        return {
            "name": native.target,
            "type": native.kind,
            "alias": native.alias,
            "comment": native.comment,
            "username": username,
            "persistence": native.persistence,
            "attributes": attributes,
            "secret": (
                ctypes.string_at(native.secret, native.secret_size)
                if native.secret
                else bytes(native.secret_size)
            ),
        }
    finally:
        if pointer:
            library.CredFree(pointer)


def write(credential, preserve_secret=False):
    """Create or replace one credential with buffers owned through the API call.

    :param dict credential: Native-type record returned by read or built for creation.
    :param bool preserve_secret: Ask Windows to retain the existing credential blob.
    :raises OSError: Credential marshalling or writing fails.
    :raises ValueError: An attribute has no data, as rejected by the upstream writer.
    """
    library = _advapi()
    username = credential["username"]
    if credential["type"] in _CERTIFICATE_TYPES:
        username = _marshal_certificate(library, username)
    secret = credential["secret"] or b""
    secret_buffer = ctypes.create_string_buffer(secret)
    attributes = (_Attribute * len(credential["attributes"]))()
    buffers = []
    for index, entry in enumerate(credential["attributes"]):
        if entry["data"] is None:
            raise ValueError("Object reference not set to an instance of an object.")
        buffer = ctypes.create_string_buffer(entry["data"])
        buffers.append(buffer)
        attributes[index] = _Attribute(
            entry["name"],
            entry.get("flags", 0),
            len(entry["data"]),
            ctypes.cast(buffer, _POINTER),
        )
    native = _Credential(
        kind=credential["type"],
        target=credential["name"],
        comment=credential["comment"],
        alias=credential["alias"],
        username=username,
        persistence=credential["persistence"],
        secret_size=len(secret),
        secret=ctypes.cast(secret_buffer, _POINTER),
        attribute_count=len(attributes),
        attributes=attributes if len(attributes) else None,
    )
    if not library.CredWriteW(ctypes.byref(native), int(preserve_secret)):
        raise _error("CredWriteW({0}) failed".format(credential["name"]))


def delete(name, kind):
    """Delete one credential that the caller has already found.

    :param str name: Exact target name.
    :param int kind: Native credential type.
    :raises OSError: The native deletion fails.
    """
    if not _advapi().CredDeleteW(name, kind, 0):
        raise _error("CredDeleteW({0}) failed".format(name))


def certificate_exists(thumbprint):
    """Find a thumbprint in the current user's My store without acquiring its key.

    :param str thumbprint: Uppercase hexadecimal thumbprint without separators.
    :returns: Whether the certificate, or an explicitly empty store path, exists.
    :rtype: bool
    :raises OSError: The certificate store cannot be opened or searched.
    """
    try:
        digest = binascii.unhexlify(thumbprint)
    except (ValueError, binascii.Error):
        return False
    library = _library(
        "crypt32",
        {
            "CertOpenStore": (
                _POINTER,
                [_POINTER, _DWORD, _POINTER, _DWORD, ctypes.c_wchar_p],
            ),
            "CertCloseStore": (_BOOL, [_POINTER, _DWORD]),
            "CertFindCertificateInStore": (
                _POINTER,
                [_POINTER, _DWORD, _DWORD, _DWORD, _POINTER, _POINTER],
            ),
            "CertFreeCertificateContext": (_BOOL, [_POINTER]),
        },
    )
    store = library.CertOpenStore(10, 0, None, 0x00014000 | 0x8000, "My")
    if not store:
        raise _error("CertOpenStore() failed")
    pointer = None
    try:
        if not thumbprint:
            return True
        buffer = ctypes.create_string_buffer(digest)
        blob = _Blob(len(digest), ctypes.cast(buffer, _POINTER))
        pointer = library.CertFindCertificateInStore(
            store, 0x10001, 0, 0x10000, ctypes.byref(blob), None
        )
        if pointer:
            return True
        code = ctypes.get_last_error() & 0xFFFFFFFF
        if code not in (0x80092004, 1168):
            raise _error("CertFindCertificateInStore() failed", code)
        return False
    finally:
        if pointer:
            library.CertFreeCertificateContext(pointer)
        library.CertCloseStore(store, 0)
