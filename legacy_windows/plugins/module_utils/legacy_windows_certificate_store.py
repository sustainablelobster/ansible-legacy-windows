# -*- coding: utf-8 -*-
# Copyright 2026 sustainablelobster
# SPDX-License-Identifier: GPL-3.0-or-later

"""Manage existing certificates through Windows CryptoAPI."""

import base64
import binascii
import ctypes
import fnmatch
import sys

from legacy_windows_module import DOTNET_WHITESPACE  # pylint: disable=import-error

_POINTER = ctypes.c_void_p
_DWORD = ctypes.c_uint32
_BOOL = ctypes.c_int32
_ENCODING = 0x10001
_NOT_FOUND = 0x80092004
_SERVICE_STORES = (
    "AuthRoot",
    "CA",
    "ClientAuthIssuer",
    "Disallowed",
    "My",
    "Root",
    "Trust",
    "TrustedPeople",
    "TrustedPublisher",
)


# These types describe native layouts, not objects with behavior.
# pylint: disable=too-few-public-methods
class _Blob(ctypes.Structure):
    _fields_ = [("size", _DWORD), ("data", _POINTER)]


class _CertificateContext(ctypes.Structure):
    _fields_ = [
        ("encoding", _DWORD),
        ("encoded", _POINTER),
        ("size", _DWORD),
        ("info", _POINTER),
        ("store", _POINTER),
    ]


class _ServiceStatus(ctypes.Structure):
    _fields_ = [("values", _DWORD * 9)]


class _ServiceEntry(ctypes.Structure):
    _fields_ = [
        ("name", ctypes.c_wchar_p),
        ("display_name", ctypes.c_wchar_p),
        ("status", _ServiceStatus),
    ]


# pylint: enable=too-few-public-methods


def _library(name, signatures):
    # Store stages its own small binder without inspection's calendar dependencies.
    # pylint: disable=duplicate-code
    library = ctypes.WinDLL(name, use_last_error=True)
    for operation, signature in signatures.items():
        function = getattr(library, operation)
        function.restype, function.argtypes = signature
    return library
    # pylint: enable=duplicate-code


def _crypt32():
    return _library(
        "crypt32",
        {
            "CertOpenStore": (_POINTER, [_POINTER, _DWORD, _POINTER, _DWORD, _POINTER]),
            "CertCloseStore": (_BOOL, [_POINTER, _DWORD]),
            "CertEnumCertificatesInStore": (_POINTER, [_POINTER, _POINTER]),
            "CertDuplicateCertificateContext": (_POINTER, [_POINTER]),
            "CertFreeCertificateContext": (_BOOL, [_POINTER]),
            "CertGetCertificateContextProperty": (
                _BOOL,
                [_POINTER, _DWORD, _POINTER, _POINTER],
            ),
            "CertAddCertificateContextToStore": (
                _BOOL,
                [_POINTER, _POINTER, _DWORD, _POINTER],
            ),
            "CertDeleteCertificateFromStore": (_BOOL, [_POINTER]),
            "CertRegisterSystemStore": (
                _BOOL,
                [ctypes.c_wchar_p, _DWORD, _POINTER, _POINTER],
            ),
            "CryptQueryObject": (
                _BOOL,
                [_DWORD, _POINTER, _DWORD, _DWORD, _DWORD] + [_POINTER] * 6,
            ),
            "PFXImportCertStore": (_POINTER, [_POINTER, ctypes.c_wchar_p, _DWORD]),
            "PFXExportCertStoreEx": (
                _BOOL,
                [_POINTER, _POINTER, ctypes.c_wchar_p, _POINTER, _DWORD],
            ),
            "CryptAcquireCertificatePrivateKey": (
                _BOOL,
                [_POINTER, _DWORD, _POINTER, _POINTER, _POINTER, _POINTER],
            ),
        },
    )


def error_message(code):
    """Read the untrimmed Windows error text used by cryptographic exceptions.

    :param int code: Native Win32 or HRESULT error number.
    :returns: Localized system message including its trailing line break.
    :rtype: str
    :raises OSError: If the system cannot format the error.
    """
    kernel = _library(
        "kernel32",
        {
            "FormatMessageW": (
                _DWORD,
                [_DWORD, _POINTER, _DWORD, _DWORD, ctypes.c_wchar_p, _DWORD, _POINTER],
            ),
        },
    )
    buffer = ctypes.create_unicode_buffer(4096)
    if not kernel.FormatMessageW(
        0x1200, None, code & 0xFFFFFFFF, 0, buffer, len(buffer), None
    ):
        raise ctypes.WinError(ctypes.get_last_error())
    return buffer.value


def _require(success):
    if not success:
        code = ctypes.get_last_error() & 0xFFFFFFFF
        raise OSError(code, error_message(code))


def store_error(code):
    """Format the pinned source's custom certificate-store opening exception.

    :param int code: Native store-opening error.
    :returns: Operation, localized message and exact decimal/hexadecimal code.
    :rtype: str
    :raises OSError: If Windows cannot format the error.
    """
    return "CertOpenStore failed ({0}, Win32ErrorCode {1} - 0x{1:08X})".format(
        error_message(code).rstrip("\r\n ."), code
    )


def _property(library, context, identifier):
    size = _DWORD()
    if not library.CertGetCertificateContextProperty(
        context, identifier, None, ctypes.byref(size)
    ):
        return None
    buffer = ctypes.create_string_buffer(size.value)
    _require(
        library.CertGetCertificateContextProperty(
            context, identifier, buffer, ctypes.byref(size)
        )
    )
    return buffer.raw[: size.value]


def _record(library, context):
    fingerprint = _property(library, context, 3)
    _require(fingerprint is not None)
    return {
        "context": context,
        "thumbprint": binascii.hexlify(fingerprint).decode("ascii").upper(),
        "has_private_key": (
            _property(library, context, 2) is not None
            or _property(library, context, 5) is not None
        ),
    }


def _records(library, handle):
    records, context = [], None
    try:
        while True:
            previous, context = context, None
            context = library.CertEnumCertificatesInStore(handle, previous)
            if not context:
                if ctypes.get_last_error() & 0xFFFFFFFF not in (_NOT_FOUND, 18):
                    _require(False)
                break
            duplicate = library.CertDuplicateCertificateContext(context)
            _require(duplicate)
            try:
                records.append(_record(library, duplicate))
            except BaseException:
                _require(library.CertFreeCertificateContext(duplicate))
                raise
        return records
    except BaseException:
        for record in records:
            _require(library.CertFreeCertificateContext(record["context"]))
        raise
    finally:
        if context:
            _require(library.CertFreeCertificateContext(context))


def _hex_digit(code):
    # Avoid staging the inspection and calendar helpers for this small converter.
    # pylint: disable=duplicate-code
    if 48 <= code <= 57:
        return code - 48
    if 65 <= code <= 70:
        return code - 55
    if 97 <= code <= 102:
        return code - 87
    return 255
    # pylint: enable=duplicate-code


def matches(records, thumbprint):
    """Select snapshot certificates with the source's permissive hex decoder.

    :param list records: Certificate snapshot from an open collection.
    :param str thumbprint: Requested SHA-1 hexadecimal selector.
    :returns: Matching records in their original enumeration order.
    :rtype: list
    :raises ValueError: If the selector is an explicit null.
    """
    if thumbprint is None:
        raise ValueError("Value cannot be null.\r\nParameter name: findValue")
    compact = "".join(
        character for character in thumbprint if character not in DOTNET_WHITESPACE
    )
    encoded = compact.encode("utf-16-le", "surrogatepass")
    units = [
        encoded[index] | encoded[index + 1] << 8 for index in range(0, len(encoded), 2)
    ]
    digest = bytes(
        ((_hex_digit(units[index]) << 4) | _hex_digit(units[index + 1])) & 255
        for index in range(0, len(units) - 1, 2)
    )
    return [
        record
        for record in records
        if binascii.unhexlify(record["thumbprint"]) == digest
    ]


class Collection:
    """Own one native store handle and its retained certificate snapshot."""

    def __init__(self, library, handle):
        self.library, self.handle = library, handle
        self.records = []

    def __enter__(self):
        try:
            self.records = _records(self.library, self.handle)
        except BaseException:
            _require(self.library.CertCloseStore(self.handle, 0))
            raise
        return self

    def __exit__(self, _kind, _error, _traceback):
        try:
            for record in self.records:
                _require(self.library.CertFreeCertificateContext(record["context"]))
        finally:
            _require(self.library.CertCloseStore(self.handle, 0))

    def add(self, record):
        """Import one certificate and its associated key-provider properties.

        :param dict record: Certificate from a still-open input collection.
        :raises OSError: If native certificate replacement fails.
        """
        # X509Store.Add inherits properties when replacing an existing context.
        _require(
            self.library.CertAddCertificateContextToStore(
                self.handle, record["context"], 5, None
            )
        )

    def remove(self, record):
        """Remove one certificate without deleting its persisted private key.

        :param dict record: Selected certificate from this collection's snapshot.
        :raises OSError: If duplicating or deleting its context fails.
        """
        duplicate = self.library.CertDuplicateCertificateContext(record["context"])
        _require(duplicate)
        # Delete consumes its context even when it fails; the snapshot stays owned.
        _require(self.library.CertDeleteCertificateFromStore(duplicate))


def open_store(name, location, store_type, read_only):
    """Open only an existing system or service store and retain its snapshot.

    :param str name: Native store name, including custom names.
    :param str location: CurrentUser, LocalMachine, or canonical service name.
    :param str store_type: system or service.
    :param bool read_only: Forbid certificate writes when exporting.
    :returns: Context-managed collection of native certificates.
    :rtype: Collection
    :raises OSError: If the existing store cannot be opened or enumerated.
    """
    library = _crypt32()
    flags = 0x4 | 0x4000 | (0x8000 if read_only else 0x1000)
    if store_type == "service":
        flags |= 0x50000
        name = location + "\\" + name
    else:
        flags |= 0x10000 if location.lower() == "currentuser" else 0x20000
    native_name = ctypes.create_unicode_buffer(name)
    handle = library.CertOpenStore(10, 0, None, flags, native_name)
    _require(handle)
    return Collection(library, handle)


def read_file(path, password, exportable, key_storage, persist=True):
    """Import a certificate file into memory, persisting PFX keys by default.

    :param str path: Existing certificate file in any source-supported encoding.
    :param str password: Optional PFX password, or None.
    :param bool exportable: Permit later private-key exports.
    :param str key_storage: default, machine, or user key-container scope.
    :param bool persist: Retain imported private keys after collection closure.
    :returns: Context-managed collection preserving native file enumeration order.
    :rtype: Collection
    :raises OSError: If reading, decoding or importing the file fails.
    :raises NotImplementedError: If temporary PFX inspection is unavailable.
    """
    library = _crypt32()
    content, handle = _DWORD(), _POINTER()
    native_path = ctypes.create_unicode_buffer(path)
    # These are the X509Certificate2Collection-supported content flags.
    flags = sum(1 << kind for kind in (1, 4, 5, 8, 9, 10, 12))
    _require(
        library.CryptQueryObject(
            1,
            native_path,
            flags,
            0xE,
            0,
            None,
            ctypes.byref(content),
            None,
            ctypes.byref(handle),
            None,
            None,
        )
    )
    if content.value == 12:
        if handle:
            _require(library.CertCloseStore(handle, 0))
        with open(path, "rb") as stream:
            data = stream.read()
        buffer = ctypes.create_string_buffer(data)
        blob = _Blob(len(data), ctypes.cast(buffer, _POINTER))
        flags = 1 if exportable else 0
        flags |= {"machine": 0x20, "user": 0x1000}.get(key_storage, 0)
        if not persist:
            # This ephemeral import flag is unavailable on XP/Server 2003.
            # Do not silently persist or delete an input's existing key instead.
            # pylint: disable-next=no-member
            if sys.getwindowsversion().major < 6:
                raise NotImplementedError(
                    "Temporary PFX inspection requires Windows Vista or newer"
                )
            flags |= 0x8000
        handle = library.PFXImportCertStore(ctypes.byref(blob), password, flags)
        _require(handle)
    _require(handle)
    return Collection(library, handle)


def encoded_certificate(record):
    """Read a retained certificate's exact DER bytes.

    :param dict record: Certificate from a still-open collection.
    :returns: Encoded certificate bytes.
    :rtype: bytes
    """
    context = ctypes.cast(record["context"], ctypes.POINTER(_CertificateContext))
    return ctypes.string_at(context.contents.encoded, context.contents.size)


def export_certificate(record, file_type, password):
    """Serialize one certificate, including its private key for PKCS12.

    :param dict record: Selected certificate from a still-open collection.
    :param str file_type: der, pem or pkcs12.
    :param str password: Optional password protecting a PKCS12 export.
    :returns: Encoded file bytes.
    :rtype: bytes
    :raises OSError: If the native export fails, including a nonexportable key.
    """
    if file_type != "pkcs12":
        data = encoded_certificate(record)
        if file_type == "pem":
            text = base64.b64encode(data).decode("ascii")
            lines = "\r\n".join(
                text[index : index + 76] for index in range(0, len(text), 76)
            )
            return (
                "-----BEGIN CERTIFICATE-----\r\n"
                + lines
                + "\r\n-----END CERTIFICATE-----"
            ).encode("ascii")
        return data
    library = _crypt32()
    handle = library.CertOpenStore(2, _ENCODING, None, 0x2000, None)
    _require(handle)
    try:
        _require(
            library.CertAddCertificateContextToStore(handle, record["context"], 4, None)
        )
        blob = _Blob()
        _require(
            library.PFXExportCertStoreEx(handle, ctypes.byref(blob), password, None, 6)
        )
        buffer = ctypes.create_string_buffer(blob.size)
        blob = _Blob(blob.size, ctypes.cast(buffer, _POINTER))
        _require(
            library.PFXExportCertStoreEx(handle, ctypes.byref(blob), password, None, 6)
        )
        return buffer.raw[: blob.size]
    finally:
        _require(library.CertCloseStore(handle, 0))


def key_exportable(record):
    """Read the selected certificate's native private-key export policy.

    :param dict record: Retained certificate known to have a private key.
    :returns: Whether its CAPI or CNG key permits export.
    :rtype: bool
    :raises OSError: If acquiring, reading or releasing the key fails.
    """
    library = _crypt32()
    handle, specification, owned = _POINTER(), _DWORD(), _BOOL()
    # CNG acquisition flags are not supported by XP/Server 2003.
    # pylint: disable-next=no-member
    flags = 0x40 | (0x10000 if sys.getwindowsversion().major >= 6 else 0)
    # This query retains ownership flags for releasing the acquired private key.
    # pylint: disable=duplicate-code
    _require(
        library.CryptAcquireCertificatePrivateKey(
            record["context"],
            flags,
            None,
            ctypes.byref(handle),
            ctypes.byref(specification),
            ctypes.byref(owned),
        )
    )
    # pylint: enable=duplicate-code
    if specification.value == 0xFFFFFFFF:
        cng = _library(
            "ncrypt",
            {
                "NCryptGetProperty": (
                    ctypes.c_int32,
                    [_POINTER, ctypes.c_wchar_p, _POINTER, _DWORD, _POINTER, _DWORD],
                ),
                "NCryptFreeObject": (ctypes.c_int32, [_POINTER]),
            },
        )
        try:
            policy, size = _DWORD(), _DWORD()
            status = cng.NCryptGetProperty(
                handle, "Export Policy", ctypes.byref(policy), 4, ctypes.byref(size), 0
            )
            if status:
                raise OSError(status & 0xFFFFFFFF, error_message(status))
            return bool(policy.value & 3)
        finally:
            if owned.value:
                status = cng.NCryptFreeObject(handle)
                if status:
                    raise OSError(status & 0xFFFFFFFF, error_message(status))
    security = _library(
        "advapi32",
        {
            "CryptGetUserKey": (_BOOL, [_POINTER, _DWORD, _POINTER]),
            "CryptGetKeyParam": (_BOOL, [_POINTER, _DWORD, _POINTER, _POINTER, _DWORD]),
            "CryptDestroyKey": (_BOOL, [_POINTER]),
            "CryptReleaseContext": (_BOOL, [_POINTER, _DWORD]),
        },
    )
    key = _POINTER()
    try:
        _require(security.CryptGetUserKey(handle, specification, ctypes.byref(key)))
        permissions, size = _DWORD(), _DWORD(4)
        _require(
            security.CryptGetKeyParam(
                key, 6, ctypes.byref(permissions), ctypes.byref(size), 0
            )
        )
        return bool(permissions.value & 4)
    finally:
        try:
            if key:
                _require(security.CryptDestroyKey(key))
        finally:
            if owned.value:
                _require(security.CryptReleaseContext(handle, 0))


def service_name(pattern):
    """Resolve a Windows service-name selector without starting its service.

    :param str pattern: Source-compatible case-insensitive service-name pattern.
    :returns: Matching canonical service names in SCM enumeration order.
    :rtype: list[str]
    :raises OSError: If the service catalogue cannot be read.
    """
    library = _library(
        "advapi32",
        {
            "OpenSCManagerW": (_POINTER, [ctypes.c_wchar_p, ctypes.c_wchar_p, _DWORD]),
            "EnumServicesStatusExW": (
                _BOOL,
                [
                    _POINTER,
                    _DWORD,
                    _DWORD,
                    _DWORD,
                    _POINTER,
                    _DWORD,
                    _POINTER,
                    _POINTER,
                    _POINTER,
                    ctypes.c_wchar_p,
                ],
            ),
            "CloseServiceHandle": (_BOOL, [_POINTER]),
        },
    )
    manager = library.OpenSCManagerW(None, None, 4)
    _require(manager)
    try:
        buffer = ctypes.create_string_buffer(262144)
        needed, count, resume = _DWORD(), _DWORD(), _DWORD()
        # This certificate-store selector owns its service-enumeration buffer.
        # pylint: disable=duplicate-code
        _require(
            library.EnumServicesStatusExW(
                manager,
                0,
                0x30,
                3,
                buffer,
                len(buffer),
                ctypes.byref(needed),
                ctypes.byref(count),
                ctypes.byref(resume),
                None,
            )
        )
        # pylint: enable=duplicate-code
        entries = ctypes.cast(buffer, ctypes.POINTER(_ServiceEntry))
        return [
            entries[index].name
            for index in range(count.value)
            if fnmatch.fnmatchcase(entries[index].name.lower(), pattern.lower())
        ]
    finally:
        _require(library.CloseServiceHandle(manager))


def missing_service_stores(service):
    """Read the nine service-store registrations performed by the source.

    :param str service: Canonical service name.
    :returns: Names of service stores whose registry keys are absent.
    :rtype: list[str]
    :raises OSError: If registry access fails for a reason other than absence.
    """
    import winreg  # pylint: disable=import-outside-toplevel,import-error

    root = "SOFTWARE\\Microsoft\\Cryptography\\Services\\" + service
    missing = []
    for name in _SERVICE_STORES:
        path = root + "\\SystemCertificates\\" + name
        try:
            with winreg.OpenKey(
                winreg.HKEY_LOCAL_MACHINE,
                path,
                0,
                winreg.KEY_READ | winreg.KEY_WOW64_64KEY,
            ):
                pass
        except OSError as error:
            if getattr(error, "winerror", error.errno) not in (2, 3):
                raise
            missing.append(name)
    return missing


def register_service_store(service, name):
    """Register one missing service store using its native provider.

    :param str service: Canonical service name.
    :param str name: Standard service-store name.
    :raises OSError: If native registration fails.
    """
    _require(
        _crypt32().CertRegisterSystemStore(service + "\\" + name, 0x50000, None, None)
    )
