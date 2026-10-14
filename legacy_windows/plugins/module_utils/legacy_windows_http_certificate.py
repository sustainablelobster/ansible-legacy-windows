# -*- coding: utf-8 -*-
# Copyright 2026 sustainablelobster
# SPDX-License-Identifier: GPL-3.0-or-later

"""Own a reopenable PFX key for the lifetime of a native HTTP request."""

import ctypes
import uuid
from contextlib import ExitStack, contextmanager

import legacy_windows_certificate_store as certificates  # pylint: disable=import-error

_POINTER = ctypes.c_void_p
_DWORD = ctypes.c_uint32
_BOOL = ctypes.c_int32
_WIDE = ctypes.c_wchar_p


# These structures describe native layouts rather than objects with behavior.
# pylint: disable=too-few-public-methods
class _ProviderInfo(ctypes.Structure):
    _fields_ = [
        ("container", _WIDE),
        ("provider", _WIDE),
        ("provider_type", _DWORD),
        ("flags", _DWORD),
        ("parameter_count", _DWORD),
        ("parameters", _POINTER),
        ("key_specification", _DWORD),
    ]


class _KeyBuffer(ctypes.Structure):
    _fields_ = [("size", _DWORD), ("kind", _DWORD), ("data", _POINTER)]


class _KeyBuffers(ctypes.Structure):
    _fields_ = [
        ("version", _DWORD),
        ("count", _DWORD),
        ("buffers", ctypes.POINTER(_KeyBuffer)),
    ]


# pylint: enable=too-few-public-methods


def _require(success):
    if not success:
        _raise_error(ctypes.get_last_error())


def _require_status(status):
    if status:
        _raise_error(status)


def _raise_error(status):
    code = status & 0xFFFFFFFF
    raise OSError(
        code,
        "Temporary HTTP client key: {0} (Windows error {1} / 0x{1:08X})".format(
            certificates.error_message(code).rstrip("\r\n ."), code
        ),
    )


def _cryptoapi():
    return certificates._library(  # pylint: disable=protected-access
        "advapi32",
        {
            "CryptGetProvParam": (
                _BOOL,
                [_POINTER, _DWORD, _POINTER, _POINTER, _DWORD],
            ),
            "CryptGetUserKey": (_BOOL, [_POINTER, _DWORD, _POINTER]),
            "CryptExportKey": (
                _BOOL,
                [_POINTER, _POINTER, _DWORD, _DWORD, _POINTER, _POINTER],
            ),
            "CryptAcquireContextW": (_BOOL, [_POINTER, _WIDE, _WIDE, _DWORD, _DWORD]),
            "CryptImportKey": (
                _BOOL,
                [_POINTER, _POINTER, _DWORD, _POINTER, _DWORD, _POINTER],
            ),
            "CryptDestroyKey": (_BOOL, [_POINTER]),
            "CryptReleaseContext": (_BOOL, [_POINTER, _DWORD]),
        },
    )


def _cng():
    return certificates._library(  # pylint: disable=protected-access
        "ncrypt",
        {
            "NCryptOpenStorageProvider": (_BOOL, [_POINTER, _WIDE, _DWORD]),
            "NCryptExportKey": (
                _BOOL,
                [
                    _POINTER,
                    _POINTER,
                    _WIDE,
                    _POINTER,
                    _POINTER,
                    _DWORD,
                    _POINTER,
                    _DWORD,
                ],
            ),
            "NCryptImportKey": (
                _BOOL,
                [
                    _POINTER,
                    _POINTER,
                    _WIDE,
                    _POINTER,
                    _POINTER,
                    _POINTER,
                    _DWORD,
                    _DWORD,
                ],
            ),
            "NCryptFreeObject": (_BOOL, [_POINTER]),
            "NCryptDeleteKey": (_BOOL, [_POINTER, _DWORD]),
            "NCryptSetProperty": (_BOOL, [_POINTER, _WIDE, _POINTER, _DWORD, _DWORD]),
        },
    )


def _copy_cryptoapi_key(stack, library, source, specification, name):
    def _parameter(identifier):
        size = _DWORD()
        _require(
            library.CryptGetProvParam(source, identifier, None, ctypes.byref(size), 0)
        )
        value = ctypes.create_string_buffer(size.value)
        _require(
            library.CryptGetProvParam(source, identifier, value, ctypes.byref(size), 0)
        )
        return value

    provider = _parameter(4).value.decode("mbcs")  # PP_NAME
    provider_type = ctypes.cast(_parameter(16), ctypes.POINTER(_DWORD))[
        0
    ]  # PP_PROVTYPE
    source_key, target, imported, size = _POINTER(), _POINTER(), _POINTER(), _DWORD()
    _require(library.CryptGetUserKey(source, specification, ctypes.byref(source_key)))
    stack.callback(lambda: _require(library.CryptDestroyKey(source_key)))
    _require(library.CryptExportKey(source_key, None, 7, 0, None, ctypes.byref(size)))
    data = ctypes.create_string_buffer(size.value)
    try:
        _require(
            library.CryptExportKey(source_key, None, 7, 0, data, ctypes.byref(size))
        )
        # NEWKEYSET refuses collisions. Never overwrite or delete an existing key.
        _require(
            library.CryptAcquireContextW(
                ctypes.byref(target), name, provider, provider_type, 0x48
            )
        )
        stack.callback(
            lambda: _require(
                library.CryptAcquireContextW(
                    ctypes.byref(_POINTER()), name, provider, provider_type, 0x50
                )
            )
        )
        stack.callback(lambda: _require(library.CryptReleaseContext(target, 0)))
        _require(
            library.CryptImportKey(
                target, data, size.value, None, 0, ctypes.byref(imported)
            )
        )
        stack.callback(lambda: _require(library.CryptDestroyKey(imported)))
    finally:
        ctypes.memset(data, 0, len(data))
    return _ProviderInfo(name, provider, provider_type, 0, 0, None, specification)


def _copy_cng_key(stack, library, source, name):
    provider_name = "Microsoft Software Key Storage Provider"
    provider, target, size = _POINTER(), _POINTER(), _DWORD()
    _require_status(
        library.NCryptOpenStorageProvider(ctypes.byref(provider), provider_name, 0)
    )
    stack.callback(lambda: _require_status(library.NCryptFreeObject(provider)))
    # PFX CRYPT_EXPORTABLE permits encrypted export only for CNG keys. This
    # source is our ephemeral import, not an existing user's stored key.
    policy = _DWORD(3)  # ALLOW_EXPORT | ALLOW_PLAINTEXT_EXPORT
    _require_status(
        library.NCryptSetProperty(
            source, "Export Policy", ctypes.byref(policy), ctypes.sizeof(policy), 0
        )
    )
    _require_status(
        library.NCryptExportKey(
            source, None, "PKCS8_PRIVATEKEY", None, None, 0, ctypes.byref(size), 0x40
        )
    )
    data = ctypes.create_string_buffer(size.value)
    # PKCS#8 preserves non-RSA keys; a named import persists without overwrite.
    wide_name = ctypes.create_unicode_buffer(name)
    name_buffer = _KeyBuffer(
        ctypes.sizeof(wide_name), 45, ctypes.cast(wide_name, _POINTER)
    )
    parameters = _KeyBuffers(0, 1, ctypes.pointer(name_buffer))
    try:
        _require_status(
            library.NCryptExportKey(
                source,
                None,
                "PKCS8_PRIVATEKEY",
                None,
                data,
                size.value,
                ctypes.byref(size),
                0x40,
            )
        )
        _require_status(
            library.NCryptImportKey(
                provider,
                None,
                "PKCS8_PRIVATEKEY",
                ctypes.byref(parameters),
                ctypes.byref(target),
                data,
                size.value,
                0x40,
            )
        )
        # NCryptDeleteKey releases the successfully deleted owned key handle.
        stack.callback(lambda: _require_status(library.NCryptDeleteKey(target, 0x40)))
    finally:
        ctypes.memset(data, 0, len(data))
    return _ProviderInfo(name, provider_name, 0, 0, 0, None, 0)


@contextmanager
def temporary_certificate(collection, record):
    """Copy a PFX credential into an owned user key and memory-only chain store.

    Keep this context open until every WinHTTP handle has closed. Schannel can
    reopen the named key across process boundaries, unlike a PFX ephemeral key.
    Existing certificate stores and key containers are never modified.

    :param certificates.Collection collection: Open ephemeral file collection.
    :param dict record: Selected private-key-bearing certificate in the collection.
    :returns: Context manager yielding a native context while its key remains open.
    :rtype: context manager
    :raises OSError: If key export, owned key creation, or cleanup fails.
    """
    crypt = certificates._library(  # pylint: disable=protected-access
        "crypt32",
        {
            "CryptAcquireCertificatePrivateKey": (
                _BOOL,
                [_POINTER, _DWORD, _POINTER, _POINTER, _POINTER, _POINTER],
            ),
            "CertOpenStore": (_POINTER, [_POINTER, _DWORD, _POINTER, _DWORD, _POINTER]),
            "CertCloseStore": (_BOOL, [_POINTER, _DWORD]),
            "CertAddEncodedCertificateToStore": (
                _BOOL,
                [_POINTER, _DWORD, _POINTER, _DWORD, _DWORD, _POINTER],
            ),
            "CertSetCertificateContextProperty": (
                _BOOL,
                [_POINTER, _DWORD, _DWORD, _POINTER],
            ),
            "CertFreeCertificateContext": (_BOOL, [_POINTER]),
        },
    )
    with ExitStack() as stack:
        source, specification, release = _POINTER(), _DWORD(), _BOOL()
        # CACHE reuses the actual ephemeral PFX key rather than reopening its name.
        _require(
            crypt.CryptAcquireCertificatePrivateKey(
                record["context"],
                0x10041,
                None,
                ctypes.byref(source),
                ctypes.byref(specification),
                ctypes.byref(release),
            )
        )
        name = "legacy-windows-http-" + uuid.uuid4().hex
        if specification.value == 0xFFFFFFFF:
            library = _cng()
            if release.value:
                stack.callback(
                    lambda: _require_status(library.NCryptFreeObject(source))
                )
            provider = _copy_cng_key(stack, library, source, name)
        else:
            library = _cryptoapi()
            if release.value:
                stack.callback(lambda: _require(library.CryptReleaseContext(source, 0)))
            provider = _copy_cryptoapi_key(
                stack, library, source, specification.value, name
            )
        store = crypt.CertOpenStore(2, 0, None, 0, None)
        _require(store)
        stack.callback(lambda: _require(crypt.CertCloseStore(store, 0)))
        selected = _POINTER()
        for item in collection.records:
            encoded = certificates.encoded_certificate(item)
            data = ctypes.create_string_buffer(encoded)
            _require(
                crypt.CertAddEncodedCertificateToStore(
                    store,
                    1,
                    data,
                    len(encoded),
                    4,
                    ctypes.byref(selected) if item is record else None,
                )
            )
            if item is record:
                stack.callback(
                    lambda: _require(crypt.CertFreeCertificateContext(selected))
                )
        _require(
            crypt.CertSetCertificateContextProperty(
                selected, 2, 0, ctypes.byref(provider)
            )
        )
        yield selected.value
