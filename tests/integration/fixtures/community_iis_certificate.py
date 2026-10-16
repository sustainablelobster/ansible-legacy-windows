# -*- coding: utf-8 -*-
# Copyright 2026 sustainablelobster
# SPDX-License-Identifier: GPL-3.0-or-later

"""Create and remove an exactly named disposable IIS certificate and CAPI key."""

import binascii
import ctypes
import json
import re
import sys

_POINTER, _DWORD = ctypes.c_void_p, ctypes.c_uint32
_PROVIDER = "Microsoft Enhanced Cryptographic Provider v1.0"


# CryptoAPI structures carry no behavior beyond their documented native fields.
# pylint: disable=too-few-public-methods
class _Blob(ctypes.Structure):
    _fields_ = [("size", _DWORD), ("data", _POINTER)]


class _ProviderInfo(ctypes.Structure):
    _fields_ = [
        ("container", ctypes.c_wchar_p),
        ("provider", ctypes.c_wchar_p),
        ("provider_type", _DWORD),
        ("flags", _DWORD),
        ("count", _DWORD),
        ("parameters", _POINTER),
        ("key_spec", _DWORD),
    ]


class _Algorithm(ctypes.Structure):
    _fields_ = [("oid", ctypes.c_char_p), ("parameters", _Blob)]


class _Extension(ctypes.Structure):
    _fields_ = [
        ("oid", ctypes.c_char_p),
        ("critical", ctypes.c_int32),
        ("value", _Blob),
    ]


class _Extensions(ctypes.Structure):
    _fields_ = [("count", _DWORD), ("entries", ctypes.POINTER(_Extension))]


# pylint: enable=too-few-public-methods


def _libraries():
    crypt, advapi = ctypes.WinDLL("crypt32", use_last_error=True), ctypes.WinDLL(
        "advapi32", use_last_error=True
    )
    functions = {
        "CertOpenStore": (_POINTER, [_POINTER, _DWORD, _POINTER, _DWORD, _POINTER]),
        "CertCloseStore": (ctypes.c_int32, [_POINTER, _DWORD]),
        "CertStrToNameW": (
            ctypes.c_int32,
            [
                _DWORD,
                ctypes.c_wchar_p,
                _DWORD,
                _POINTER,
                _POINTER,
                ctypes.POINTER(_DWORD),
                _POINTER,
            ],
        ),
        "CertCreateSelfSignCertificate": (
            _POINTER,
            [
                _POINTER,
                ctypes.POINTER(_Blob),
                _DWORD,
                ctypes.POINTER(_ProviderInfo),
                ctypes.POINTER(_Algorithm),
                _POINTER,
                _POINTER,
                _POINTER,
            ],
        ),
        "CertAddCertificateContextToStore": (
            ctypes.c_int32,
            [_POINTER, _POINTER, _DWORD, _POINTER],
        ),
        "CertGetCertificateContextProperty": (
            ctypes.c_int32,
            [_POINTER, _DWORD, _POINTER, ctypes.POINTER(_DWORD)],
        ),
        "CertFreeCertificateContext": (ctypes.c_int32, [_POINTER]),
        "CertFindCertificateInStore": (
            _POINTER,
            [_POINTER, _DWORD, _DWORD, _DWORD, _POINTER, _POINTER],
        ),
        "CertDeleteCertificateFromStore": (ctypes.c_int32, [_POINTER]),
    }
    for name, (result, arguments) in functions.items():
        function = getattr(crypt, name)
        function.restype, function.argtypes = result, arguments
    advapi.CryptAcquireContextW.argtypes = [
        ctypes.POINTER(_POINTER),
        ctypes.c_wchar_p,
        ctypes.c_wchar_p,
        _DWORD,
        _DWORD,
    ]
    advapi.CryptAcquireContextW.restype = ctypes.c_int32
    advapi.CryptGenKey.argtypes = [_POINTER, _DWORD, _DWORD, ctypes.POINTER(_POINTER)]
    advapi.CryptGenKey.restype = ctypes.c_int32
    advapi.CryptDestroyKey.argtypes = [_POINTER]
    advapi.CryptDestroyKey.restype = ctypes.c_int32
    advapi.CryptReleaseContext.argtypes = [_POINTER, _DWORD]
    advapi.CryptReleaseContext.restype = ctypes.c_int32
    return crypt, advapi


def _require(value):
    if not value:
        raise ctypes.WinError()
    return value


def _thumbprint(crypt, certificate):
    fingerprint, size = ctypes.create_string_buffer(20), _DWORD(20)
    _require(
        crypt.CertGetCertificateContextProperty(
            certificate, 3, fingerprint, ctypes.byref(size)
        )
    )
    return binascii.hexlify(fingerprint.raw).decode("ascii").upper()


def _gateway_extensions():
    # DER encodes Server Authentication EKU and digital-signature/key-encipherment
    # key usage. Retain the buffers alongside the native extension array.
    eku = ctypes.create_string_buffer(
        b"\x30\x0a\x06\x08\x2b\x06\x01\x05\x05\x07\x03\x01"
    )
    usage = ctypes.create_string_buffer(b"\x03\x02\x05\xa0")
    entries = (_Extension * 2)(
        _Extension(b"2.5.29.37", 0, _Blob(12, ctypes.cast(eku, _POINTER))),
        _Extension(b"2.5.29.15", 1, _Blob(4, ctypes.cast(usage, _POINTER))),
    )
    return _Extensions(2, entries), (eku, usage, entries)


# Keep the certificate, key and optional extension buffers under one cleanup
# scope so a failed fixture creation cannot orphan its persisted key.
# pylint: disable-next=too-many-locals
def _create(crypt, advapi, store, name, server_dns=None):
    provider, key, certificate = _POINTER(), _POINTER(), None
    completed = False
    _require(
        advapi.CryptAcquireContextW(ctypes.byref(provider), name, _PROVIDER, 1, 0x28)
    )
    try:
        _require(advapi.CryptGenKey(provider, 1, 2048 << 16, ctypes.byref(key)))
        length = _DWORD()
        _require(
            crypt.CertStrToNameW(
                1,
                "CN=" + (server_dns or name),
                3,
                None,
                None,
                ctypes.byref(length),
                None,
            )
        )
        subject = ctypes.create_string_buffer(length.value)
        _require(
            crypt.CertStrToNameW(
                1,
                "CN=" + (server_dns or name),
                3,
                None,
                subject,
                ctypes.byref(length),
                None,
            )
        )
        blob = _Blob(length, ctypes.cast(subject, _POINTER))
        info = _ProviderInfo(name, _PROVIDER, 1, 0x20, 0, None, 1)
        algorithm = _Algorithm(b"1.2.840.113549.1.1.5", _Blob())
        extensions = _gateway_extensions() if server_dns else (None, None)
        certificate = _require(
            crypt.CertCreateSelfSignCertificate(
                provider,
                ctypes.byref(blob),
                0,
                ctypes.byref(info),
                ctypes.byref(algorithm),
                None,
                None,
                ctypes.byref(extensions[0]) if extensions[0] is not None else None,
            )
        )
        result = {"container": name, "thumbprint": _thumbprint(crypt, certificate)}
        _require(crypt.CertAddCertificateContextToStore(store, certificate, 1, None))
        completed = True
        return result
    finally:
        if certificate:
            crypt.CertFreeCertificateContext(certificate)
        if key:
            advapi.CryptDestroyKey(key)
        advapi.CryptReleaseContext(provider, 0)
        if not completed:
            cleanup_provider = _POINTER()
            _require(
                advapi.CryptAcquireContextW(
                    ctypes.byref(cleanup_provider), name, _PROVIDER, 1, 0x30
                )
            )


def _remove(crypt, advapi, store, name, thumbprint):
    data = ctypes.create_string_buffer(binascii.unhexlify(thumbprint))
    blob = _Blob(20, ctypes.cast(data, _POINTER))
    certificate = crypt.CertFindCertificateInStore(
        store, 0x10001, 0, 0x10000, ctypes.byref(blob), None
    )
    if certificate:
        size = _DWORD()
        _require(
            crypt.CertGetCertificateContextProperty(
                certificate, 2, None, ctypes.byref(size)
            )
        )
        information = ctypes.create_string_buffer(size.value)
        _require(
            crypt.CertGetCertificateContextProperty(
                certificate, 2, information, ctypes.byref(size)
            )
        )
        if _ProviderInfo.from_buffer(information).container != name:
            crypt.CertFreeCertificateContext(certificate)
            raise ValueError(
                "The selected certificate does not belong to this fixture key."
            )
        _require(crypt.CertDeleteCertificateFromStore(certificate))
    provider = _POINTER()
    if not advapi.CryptAcquireContextW(
        ctypes.byref(provider), name, _PROVIDER, 1, 0x30
    ):
        if ctypes.get_last_error() != 0x80090016:
            raise ctypes.WinError()
    return {"removed": True, "container": name}


def main():
    """Operate only on the caller's uniquely owned test certificate/key pair.

    :raises ValueError: The operation or uniquely owned fixture name is invalid.
    """
    operation, name = sys.argv[1:3]
    if not re.match(r"^legacy-community-iis-[A-Za-z0-9_.-]+$", name):
        raise ValueError(
            "Only uniquely named legacy-community-iis fixture keys are accepted."
        )
    crypt, advapi = _libraries()
    store_name = ctypes.create_unicode_buffer("My")
    store = _require(
        crypt.CertOpenStore(10, 0, None, 0x24000, ctypes.byref(store_name))
    )
    try:
        if operation == "create":
            result = _create(
                crypt, advapi, store, name, sys.argv[3] if len(sys.argv) == 4 else None
            )
        elif operation == "remove" and re.match(r"^[0-9A-Fa-f]{40}$", sys.argv[3]):
            result = _remove(crypt, advapi, store, name, sys.argv[3])
        else:
            raise ValueError("Use create NAME or remove NAME THUMBPRINT.")
        print(json.dumps(result))
    finally:
        crypt.CertCloseStore(store, 0)


if __name__ == "__main__":
    main()
