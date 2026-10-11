# -*- coding: utf-8 -*-
# Copyright 2026 sustainablelobster
# SPDX-License-Identifier: GPL-3.0-or-later

"""Read and update certificate private-key DACLs through CAPI or CNG."""

import binascii
import contextlib
import ctypes
import os
import re
import struct
import sys

# The action stages the shared Python 3.4-compatible ACL helper beside this file.
# pylint: disable=import-error
import legacy_windows_acl_inheritance as inheritance

# pylint: enable=import-error

_DWORD = ctypes.c_uint32
_BOOL = ctypes.c_int32
_POINTER = ctypes.c_void_p
_NOT_FOUND = 0x80092004
_CNG_KEY = 0xFFFFFFFF


# This structure only describes the native hash selector's memory layout.
# pylint: disable=too-few-public-methods
class _Blob(ctypes.Structure):
    _fields_ = [("size", _DWORD), ("data", _POINTER)]


# pylint: enable=too-few-public-methods


def _load(name, signatures):
    # Configure only this ACL payload's native API set without another stager.
    # pylint: disable=duplicate-code
    if os.name != "nt":
        raise ValueError("Certificate ACL access requires Windows")
    library = ctypes.WinDLL(name, use_last_error=True)
    for operation, signature in signatures.items():
        function = getattr(library, operation)
        function.restype, function.argtypes = signature
    return library
    # pylint: enable=duplicate-code


def _crypt32():
    # This ACL helper explicitly declares its certificate-store API subset.
    # pylint: disable=duplicate-code
    return _load(
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
            "CryptAcquireCertificatePrivateKey": (
                _BOOL,
                [_POINTER, _DWORD, _POINTER, _POINTER, _POINTER, _POINTER],
            ),
        },
    )
    # pylint: enable=duplicate-code


def _advapi32():
    return _load(
        "advapi32",
        {
            "CryptGetProvParam": (
                _BOOL,
                [_POINTER, _DWORD, _POINTER, _POINTER, _DWORD],
            ),
            "CryptSetProvParam": (_BOOL, [_POINTER, _DWORD, _POINTER, _DWORD]),
            "CryptReleaseContext": (_BOOL, [_POINTER, _DWORD]),
            "GetSecurityDescriptorControl": (_BOOL, [_POINTER] * 3),
            "GetSecurityDescriptorDacl": (_BOOL, [_POINTER] * 4),
            "IsValidSecurityDescriptor": (_BOOL, [_POINTER]),
        },
    )


def _ncrypt():
    return _load(
        "ncrypt",
        {
            "NCryptGetProperty": (
                ctypes.c_int32,
                [_POINTER, ctypes.c_wchar_p, _POINTER, _DWORD, _POINTER, _DWORD],
            ),
            "NCryptSetProperty": (
                ctypes.c_int32,
                [_POINTER, ctypes.c_wchar_p, _POINTER, _DWORD, _DWORD],
            ),
            "NCryptFreeObject": (ctypes.c_int32, [_POINTER]),
        },
    )


def _require(success, operation):
    if not success:
        raise OSError(
            ctypes.get_last_error(),
            "{0} failed: {1}".format(
                operation, ctypes.FormatError(ctypes.get_last_error()).strip()
            ),
        )


def _status(code, operation):
    if code:
        code &= 0xFFFFFFFF
        raise OSError(
            code,
            "{0} failed: {1}".format(
                operation, ctypes.FormatError(ctypes.c_int32(code).value).strip()
            ),
        )


def _path_parts(path):
    match = re.match(
        r"^Cert:\\(CurrentUser|LocalMachine)\\([^\\/]+)\\([0-9a-f]{40})\\?$",
        path,
        re.IGNORECASE,
    )
    if match is None:
        raise ValueError(
            "Certificate ACL paths must identify "
            "Cert:\\CurrentUser|LocalMachine\\store\\SHA1-thumbprint"
        )
    location, store, thumbprint = match.groups()
    return (
        (0x10000 if location.lower() == "currentuser" else 0x20000),
        store,
        thumbprint,
    )


@contextlib.contextmanager
def _certificate(path):
    location, store_name, thumbprint = _path_parts(path)
    crypt = _crypt32()
    # Open only an existing store and forbid changes to its certificates.
    store = crypt.CertOpenStore(10, 0, None, location | 0x4000 | 0x8000, store_name)
    if not store and ctypes.get_last_error() & 0xFFFFFFFF in (2, 3, _NOT_FOUND):
        raise OSError(2, "Certificate path does not exist: " + path)
    _require(store, "CertOpenStore")
    certificate = None
    try:
        digest = ctypes.create_string_buffer(binascii.unhexlify(thumbprint))
        selector = _Blob(20, ctypes.cast(digest, _POINTER))
        certificate = crypt.CertFindCertificateInStore(
            store, 0x10001, 0, 0x10000, ctypes.byref(selector), None
        )
        if not certificate and ctypes.get_last_error() & 0xFFFFFFFF == _NOT_FOUND:
            raise OSError(2, "Certificate path does not exist: " + path)
        _require(certificate, "CertFindCertificateInStore")
        yield crypt, certificate
    finally:
        try:
            if certificate:
                _require(
                    crypt.CertFreeCertificateContext(certificate),
                    "CertFreeCertificateContext",
                )
        finally:
            _require(crypt.CertCloseStore(store, 0), "CertCloseStore")


def resolve_target(path):
    """Check that a certificate exists without acquiring its private key.

    :param path: Certificate provider path including a SHA-1 thumbprint.
    :type path: str
    :returns: Certificate target for :func:`open_acl`, or None when absent.
    :rtype: dict
    :raises OSError: If the store or certificate cannot be opened.
    :raises ValueError: If the path is malformed or the host is not Windows.
    """
    try:
        with _certificate(path):
            return {"path": path, "kind": "certificate", "container": False}
    except OSError as error:
        if error.errno == 2:
            return None
        raise


@contextlib.contextmanager
def _private_key(crypt, certificate, security):
    handle, specification, owned = _POINTER(), _DWORD(), _BOOL()
    # Microsoft documents CNG acquisition flags as unsupported on XP/2003.
    # This sys API exists only on the Windows target interpreter.
    # pylint: disable-next=no-member
    flags = 0x40 | (0x10000 if sys.getwindowsversion().major >= 6 else 0)
    _require(
        crypt.CryptAcquireCertificatePrivateKey(
            certificate,
            flags,
            None,
            ctypes.byref(handle),
            ctypes.byref(specification),
            ctypes.byref(owned),
        ),
        "CryptAcquireCertificatePrivateKey",
    )
    cng = None
    try:
        if specification.value == _CNG_KEY:
            cng = _ncrypt()
        yield handle, cng
    finally:
        if owned.value:
            if specification.value == _CNG_KEY:
                cng = cng or _ncrypt()
                _status(cng.NCryptFreeObject(handle), "NCryptFreeObject")
            else:
                _require(security.CryptReleaseContext(handle, 0), "CryptReleaseContext")


def _read_descriptor(security, key, cng):
    size = _DWORD()
    if cng is None:
        _require(
            security.CryptGetProvParam(key, 8, None, ctypes.byref(size), 4),
            "CryptGetProvParam (descriptor size)",
        )
        buffer = ctypes.create_string_buffer(size.value)
        _require(
            security.CryptGetProvParam(key, 8, buffer, ctypes.byref(size), 4),
            "CryptGetProvParam (descriptor)",
        )
    else:
        _status(
            cng.NCryptGetProperty(
                key, "Security Descr", None, 0, ctypes.byref(size), 0x44
            ),
            "NCryptGetProperty (descriptor size)",
        )
        buffer = ctypes.create_string_buffer(size.value)
        _status(
            cng.NCryptGetProperty(
                key, "Security Descr", buffer, size.value, ctypes.byref(size), 0x44
            ),
            "NCryptGetProperty (descriptor)",
        )
    _require(security.IsValidSecurityDescriptor(buffer), "IsValidSecurityDescriptor")
    control, revision = ctypes.c_uint16(), _DWORD()
    _require(
        security.GetSecurityDescriptorControl(
            buffer, ctypes.byref(control), ctypes.byref(revision)
        ),
        "GetSecurityDescriptorControl",
    )
    present, defaulted, dacl = _BOOL(), _BOOL(), _POINTER()
    _require(
        security.GetSecurityDescriptorDacl(
            buffer, ctypes.byref(present), ctypes.byref(dacl), ctypes.byref(defaulted)
        ),
        "GetSecurityDescriptorDacl",
    )
    acl = None
    if present.value and dacl.value:
        size = ctypes.c_uint16.from_address(dacl.value + 2).value
        acl = ctypes.string_at(dacl, size)
        # All native ACL adapters share the managed-rule normalization boundary.
        # pylint: disable-next=protected-access
        acl = inheritance._normalize_acl(acl, False)
    return {
        "protected": bool(control.value & 0x1000),
        "dacl": acl,
        "registry": False,
        "container": False,
        "kind": "certificate",
        "certificate_provider": "capi" if cng is None else "cng",
    }, control.value


def _write_descriptor(security, key, cng, snapshot, control):
    dacl = snapshot["dacl"]
    # SECURITY_DESCRIPTOR_RELATIVE has a 20-byte header. Only the DACL is
    # supplied; its defaulted/auto-inheritance flags and protection are retained.
    control = 0x8004 | (control & 0x508) | (0x1000 if snapshot["protected"] else 0)
    data = struct.pack(
        "<BBHIIII", 1, 0, control, 0, 0, 0, 20 if dacl is not None else 0
    )
    data += dacl if dacl is not None else b""
    buffer = ctypes.create_string_buffer(data)
    _require(security.IsValidSecurityDescriptor(buffer), "IsValidSecurityDescriptor")
    if cng is None:
        _require(
            security.CryptSetProvParam(key, 8, buffer, 4), "CryptSetProvParam (DACL)"
        )
    else:
        _status(
            cng.NCryptSetProperty(key, "Security Descr", buffer, len(data), 0x44),
            "NCryptSetProperty (DACL)",
        )


@contextlib.contextmanager
# Pylint's Sphinx parser has no yield fields; returns documents this context.
# pylint: disable-next=missing-yield-doc,missing-yield-type-doc
def open_acl(target):
    """Hold a certificate key while inspecting or updating its DACL.

    The yielded writer accepts a changed snapshot and is valid only inside the
    context. Certificate contents, key material, owner, group and SACL are not
    written. Providers requiring interactive prompts fail in silent mode.

    :param target: Existing certificate target returned by :func:`resolve_target`.
    :type target: dict
    :returns: Context yielding a DACL snapshot and its update writer.
    :rtype: context manager
    :raises OSError: If certificate, key, descriptor or cleanup operations fail.
    :raises ValueError: If the path is malformed or the host is not Windows.
    """
    with _certificate(target["path"]) as (crypt, certificate):
        security = _advapi32()
        with _private_key(crypt, certificate, security) as (key, cng):
            snapshot, control = _read_descriptor(security, key, cng)

            def writer(updated):
                _write_descriptor(security, key, cng, updated, control)

            yield snapshot, writer
