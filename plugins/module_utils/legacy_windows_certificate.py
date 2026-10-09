# -*- coding: utf-8 -*-
# Copyright 2026 Joe Lustri
# SPDX-License-Identifier: GPL-3.0-or-later

"""Read certificate-store metadata through Windows CryptoAPI."""

import base64
import binascii
import ctypes
import datetime

# The action stages these Python 3.4-compatible siblings beside the payload.
# pylint: disable=import-error
import legacy_windows_calendar as calendar
from legacy_windows_module import DOTNET_WHITESPACE

# pylint: enable=import-error

_DWORD = ctypes.c_uint32
_BOOL = ctypes.c_int32
_BYTE_POINTER = ctypes.POINTER(ctypes.c_ubyte)
_ENCODING = 0x10001  # X509_ASN_ENCODING | PKCS_7_ASN_ENCODING.
_NOT_FOUND = 0x80092004
_KEY_USAGES = (
    (0x0001, "EncipherOnly"),
    (0x0002, "CrlSign"),
    (0x0004, "KeyCertSign"),
    (0x0008, "KeyAgreement"),
    (0x0010, "DataEncipherment"),
    (0x0020, "KeyEncipherment"),
    (0x0040, "NonRepudiation"),
    (0x0080, "DigitalSignature"),
    (0x8000, "DecipherOnly"),
)


# These classes describe native data layouts; adding methods obscures that role.
# pylint: disable=too-few-public-methods
class _Blob(ctypes.Structure):
    _fields_ = [("size", _DWORD), ("data", _BYTE_POINTER)]


class _BitBlob(ctypes.Structure):
    _fields_ = [("size", _DWORD), ("data", _BYTE_POINTER), ("unused_bits", _DWORD)]


class _FileTime(ctypes.Structure):
    _fields_ = [("low", _DWORD), ("high", _DWORD)]


class _Algorithm(ctypes.Structure):
    _fields_ = [("oid", ctypes.c_char_p), ("parameters", _Blob)]


class _PublicKey(ctypes.Structure):
    _fields_ = [("algorithm", _Algorithm), ("key", _BitBlob)]


class _Extension(ctypes.Structure):
    _fields_ = [("oid", ctypes.c_char_p), ("critical", _BOOL), ("value", _Blob)]


class _CertificateInfo(ctypes.Structure):
    _fields_ = [
        ("version", _DWORD),
        ("serial", _Blob),
        ("signature", _Algorithm),
        ("issuer", _Blob),
        ("not_before", _FileTime),
        ("not_after", _FileTime),
        ("subject", _Blob),
        ("public_key", _PublicKey),
        ("issuer_id", _BitBlob),
        ("subject_id", _BitBlob),
        ("extension_count", _DWORD),
        ("extensions", ctypes.POINTER(_Extension)),
    ]


class _CertificateContext(ctypes.Structure):
    _fields_ = [
        ("encoding", _DWORD),
        ("encoded", _BYTE_POINTER),
        ("size", _DWORD),
        ("info", ctypes.POINTER(_CertificateInfo)),
        ("store", ctypes.c_void_p),
    ]


class _OidInfo(ctypes.Structure):
    # Only the stable prefix of CRYPT_OID_INFO is read; Windows owns this data.
    _fields_ = [
        ("size", _DWORD),
        ("oid", ctypes.c_char_p),
        ("name", ctypes.c_wchar_p),
    ]


class _BasicConstraints(ctypes.Structure):
    _fields_ = [
        ("subject_type", _BitBlob),
        ("has_path_length", _BOOL),
        ("path_length", _DWORD),
        ("subtree_count", _DWORD),
        ("subtrees", ctypes.POINTER(_Blob)),
    ]


class _BasicConstraints2(ctypes.Structure):
    _fields_ = [
        ("is_ca", _BOOL),
        ("has_path_length", _BOOL),
        ("path_length", _DWORD),
    ]


class _EnhancedKeyUsage(ctypes.Structure):
    _fields_ = [("count", _DWORD), ("oids", ctypes.POINTER(ctypes.c_char_p))]


# pylint: enable=too-few-public-methods


def _crypt32():
    library = ctypes.WinDLL("crypt32", use_last_error=True)
    pointer = ctypes.c_void_p
    context = ctypes.POINTER(_CertificateContext)
    size = ctypes.POINTER(_DWORD)
    signatures = {
        "CertOpenStore": (
            pointer,
            [pointer, _DWORD, pointer, _DWORD, ctypes.c_wchar_p],
        ),
        "CertCloseStore": (_BOOL, [pointer, _DWORD]),
        "CertEnumCertificatesInStore": (context, [pointer, context]),
        "CertFindCertificateInStore": (
            context,
            [pointer, _DWORD, _DWORD, _DWORD, pointer, context],
        ),
        "CertFreeCertificateContext": (_BOOL, [context]),
        "CertGetCertificateContextProperty": (_BOOL, [context, _DWORD, pointer, size]),
        "CertGetNameStringW": (
            _DWORD,
            [context, _DWORD, _DWORD, pointer, ctypes.c_wchar_p, _DWORD],
        ),
        "CryptFindOIDInfo": (
            ctypes.POINTER(_OidInfo),
            [_DWORD, ctypes.c_char_p, _DWORD],
        ),
        "CryptFormatObject": (
            _BOOL,
            [
                _DWORD,
                _DWORD,
                _DWORD,
                pointer,
                ctypes.c_char_p,
                pointer,
                _DWORD,
                pointer,
                size,
            ],
        ),
        "CryptDecodeObjectEx": (
            _BOOL,
            [_DWORD, ctypes.c_char_p, pointer, _DWORD, _DWORD, pointer, pointer, size],
        ),
    }
    for name, signature in signatures.items():
        operation = getattr(library, name)
        operation.restype, operation.argtypes = signature
    return library


def _native_error(operation):
    code = ctypes.get_last_error()
    return OSError(
        code, "{0} failed: {1}".format(operation, ctypes.FormatError(code).strip())
    )


def _store_open_error(code):
    # ctypes.FormatError strips the message's trailing CRLF; X509Store.Open's
    # exception retains it. Read the system message without that normalization.
    kernel = ctypes.WinDLL("kernel32", use_last_error=True)
    formatter = kernel.FormatMessageW
    formatter.argtypes = [
        _DWORD,
        ctypes.c_void_p,
        _DWORD,
        _DWORD,
        ctypes.POINTER(ctypes.c_void_p),
        _DWORD,
        ctypes.c_void_p,
    ]
    formatter.restype = _DWORD
    release = kernel.LocalFree
    release.argtypes = [ctypes.c_void_p]
    release.restype = ctypes.c_void_p
    message = ctypes.c_void_p()
    try:
        # Allocate the system's message and leave insertion markers untouched.
        length = formatter(0x1300, None, code, 0, ctypes.byref(message), 0, None)
        if not length:
            raise _native_error("FormatMessageW (certificate store open)")
        return RuntimeError(
            'Exception calling "Open" with "1" argument(s): "{0}"'.format(
                ctypes.wstring_at(message, length)
            )
        )
    finally:
        if message and release(message):
            raise _native_error("LocalFree (certificate store error)")


def _bytes(blob):
    return ctypes.string_at(blob.data, blob.size) if blob.size else b""


def _hex(value):
    return binascii.hexlify(value).decode("ascii").upper()


def _property(library, context, property_id):
    size = _DWORD()
    operation = library.CertGetCertificateContextProperty
    if not operation(context, property_id, None, ctypes.byref(size)):
        return None
    buffer = ctypes.create_string_buffer(size.value)
    if not operation(context, property_id, buffer, ctypes.byref(size)):
        return None
    return buffer.raw[: size.value]


def _has_property(library, context, property_id):
    size = _DWORD()
    return bool(
        library.CertGetCertificateContextProperty(
            context, property_id, None, ctypes.byref(size)
        )
    )


def _name(library, context, name_type, issuer=False):
    flags = int(issuer)
    style = _DWORD(0x02000003)  # CERT_X500_NAME_STR | CERT_NAME_STR_REVERSE_FLAG.
    operation = library.CertGetNameStringW
    size = operation(context, name_type, flags, ctypes.byref(style), None, 0)
    if not size:
        raise _native_error("CertGetNameStringW")
    buffer = ctypes.create_unicode_buffer(size)
    if not operation(context, name_type, flags, ctypes.byref(style), buffer, size):
        raise _native_error("CertGetNameStringW")
    return buffer.value


def _oid_name(library, oid, group):
    value = library.CryptFindOIDInfo(1, oid, group)
    if not value and group:
        value = library.CryptFindOIDInfo(1, oid, 0)
    return value.contents.name if value else None


def _format_extension(library, extension, multiline=False):
    if not extension.value.size:
        return ""
    size = _DWORD()
    arguments = (
        _ENCODING,
        0,
        int(multiline),
        None,
        extension.oid,
        extension.value.data,
        extension.value.size,
    )
    operation = library.CryptFormatObject
    if operation(*(arguments + (None, ctypes.byref(size)))):
        buffer = ctypes.create_string_buffer(size.value)
        if operation(*(arguments + (buffer, ctypes.byref(size)))):
            return buffer.raw[: size.value].decode("utf-16-le").split("\0", 1)[0]
    # AsnEncodedData.Format falls back to unseparated uppercase hexadecimal.
    return _hex(_bytes(extension.value))


def _decode_extension(library, extension):
    size = _DWORD()
    arguments = (
        _ENCODING,
        extension.oid,
        extension.value.data,
        extension.value.size,
        0,
        None,
    )
    operation = library.CryptDecodeObjectEx
    if not operation(*(arguments + (None, ctypes.byref(size)))):
        raise _native_error(
            "CryptDecodeObjectEx ({0})".format(extension.oid.decode("ascii"))
        )
    buffer = ctypes.create_string_buffer(size.value)
    if not operation(*(arguments + (buffer, ctypes.byref(size)))):
        raise _native_error(
            "CryptDecodeObjectEx ({0})".format(extension.oid.decode("ascii"))
        )
    return buffer


def _key_usage_names(blob):
    data = _bytes(blob)[:4]
    value = int.from_bytes(data, "little")
    if value & ~0x80FF:
        # Enum.ToString returns a decimal value if any flag is unrecognized.
        return [str(ctypes.c_int32(value).value)]
    return [name for flag, name in _KEY_USAGES if flag & value] or ["None"]


def _extension_fields(library, extension, result):
    oid = extension.oid
    if oid == b"2.5.29.17":
        formatted = _format_extension(library, extension, multiline=True)
        for line in formatted.replace("\r", "\n").split("\n"):
            parts = line.split("=")
            if (
                len(parts) >= 2
                and parts[0].strip(DOTNET_WHITESPACE).lower() == "dns name"
            ):
                result["dns_names"].append(parts[1].strip(DOTNET_WHITESPACE))
        return
    if oid not in (
        b"2.5.29.10",
        b"2.5.29.19",
        b"2.5.29.37",
        b"2.5.29.15",
        b"2.5.29.14",
    ):
        return
    # Decoded pointers refer into this Python-owned buffer, kept alive throughout.
    decoded = _decode_extension(library, extension)
    if oid == b"2.5.29.10":
        constraints = _BasicConstraints.from_buffer(decoded)
        result["is_ca"] = bool(_bytes(constraints.subject_type)[0] & 0x80)
        result["path_length_constraint"] = ctypes.c_int32(constraints.path_length).value
    elif oid == b"2.5.29.19":
        constraints = _BasicConstraints2.from_buffer(decoded)
        result["is_ca"] = bool(constraints.is_ca)
        result["path_length_constraint"] = ctypes.c_int32(constraints.path_length).value
    elif oid == b"2.5.29.37":
        usage = _EnhancedKeyUsage.from_buffer(decoded)
        names = [
            _oid_name(library, usage.oids[index], 6) for index in range(usage.count)
        ]
        result["intended_purposes"] = [name or "" for name in names] if names else None
    elif oid == b"2.5.29.15":
        result["key_usages"] = _key_usage_names(_Blob.from_buffer(decoded))
    else:
        result["ski"] = _hex(_bytes(_Blob.from_buffer(decoded)))


def _date(file_time, culture, epoch_ticks):
    ticks = (file_time.high << 32) | file_time.low
    value = datetime.datetime(1601, 1, 1) + datetime.timedelta(microseconds=ticks // 10)
    calendar_id = culture["calendar_id"]
    if calendar_id in (3, 8):
        date_text = calendar.format_alternative_date(calendar_id, value.date())
    else:
        year, month, day, _ = calendar.calendar_fields(culture, value.date())
        # The framework's Taiwan calendar uses a two-digit minimum era year.
        date_text = "{0:0{3}d}-{1:02d}-{2:02d}".format(
            year, month, day, 2 if calendar_id == 4 else 4
        )
    return (
        (ticks - epoch_ticks) / 10000000.0,
        "{0}T{1:02d}{4}{2:02d}{4}{3:02d}Z".format(
            date_text, value.hour, value.minute, value.second, culture["time_separator"]
        ),
    )


# Keeping this complete native-field mapping together makes missing result fields visible.
# pylint: disable-next=too-many-locals
def _certificate(library, context, culture=None):
    if culture is None:
        culture = calendar.get_culture()
    try:
        epoch = calendar.calendar_date(culture, 1970, 1, 1)
    except ValueError as error:
        raise RuntimeError(
            "Cannot bind parameter 'Date'. Cannot convert value \"01/01/1970\" "
            'to type "System.DateTime". Error: "String was not recognized as a '
            'valid DateTime."'
        ) from error
    epoch_ticks = (epoch - datetime.date(1601, 1, 1)).days * 864000000000
    native = context.contents
    info = native.info.contents
    fingerprint = _property(library, context, 3)  # CERT_SHA1_HASH_PROP_ID.
    if fingerprint is None:
        raise _native_error("CertGetCertificateContextProperty (SHA1 hash)")
    friendly = _property(library, context, 11)  # CERT_FRIENDLY_NAME_PROP_ID.
    valid_from, valid_from_iso = _date(info.not_before, culture, epoch_ticks)
    valid_to, valid_to_iso = _date(info.not_after, culture, epoch_ticks)
    issued_to = _name(library, context, 4)
    result = {
        "friendly_name": (
            friendly.decode("utf-16-le").split("\0", 1)[0] if friendly else ""
        ),
        "thumbprint": _hex(fingerprint),
        "subject": _name(library, context, 2),
        "issuer": _name(library, context, 2, issuer=True),
        "valid_from": valid_from,
        "valid_from_iso8601": valid_from_iso,
        "valid_to": valid_to,
        "valid_to_iso8601": valid_to_iso,
        "serial_number": _hex(_bytes(info.serial)[::-1]),
        "archived": _has_property(library, context, 19),
        "version": info.version + 1,
        "has_private_key": _has_property(library, context, 5)
        or _has_property(library, context, 2),
        "issued_by": _name(library, context, 4, issuer=True),
        "issued_to": issued_to,
        "signature_algorithm": _oid_name(library, info.signature.oid, 4),
        "dns_names": [issued_to],
        "raw": base64.b64encode(ctypes.string_at(native.encoded, native.size)).decode(
            "ascii"
        ),
        "public_key": base64.b64encode(_bytes(info.public_key.key)).decode("ascii"),
        "extensions": [],
    }
    for index in range(info.extension_count):
        extension = info.extensions[index]
        result["extensions"].append(
            {
                "critical": bool(extension.critical),
                "field": _oid_name(library, extension.oid, 6),
                "value": _format_extension(library, extension),
            }
        )
        _extension_fields(library, extension, result)
    return result


def _hex_digit(code):
    if 48 <= code <= 57:
        return code - 48
    if 65 <= code <= 70:
        return code - 55
    if 97 <= code <= 102:
        return code - 87
    return 255


def _thumbprint_bytes(value):
    # X509Certificate2Collection.Find discards .NET whitespace, ignores a final
    # unmatched UTF-16 code unit, and maps invalid hexadecimal digits to 0xFF.
    compact = "".join(
        character for character in value if character not in DOTNET_WHITESPACE
    )
    encoded = compact.encode("utf-16-le", "surrogatepass")
    units = [
        encoded[index] | encoded[index + 1] << 8 for index in range(0, len(encoded), 2)
    ]
    return bytes(
        ((_hex_digit(units[index]) << 4) | _hex_digit(units[index + 1])) & 255
        for index in range(0, len(units) - 1, 2)
    )


# The loop and nested cleanup keep current-context ownership explicit on every failure.
# pylint: disable-next=too-many-branches
def read_certificates(store_name, store_location, thumbprint=None):
    """Read an X.509 system store and return the upstream certificate metadata.

    :param str store_name: Native system-store name, for example ``My`` or ``Root``.
    :param str store_location: ``CurrentUser`` or ``LocalMachine``.
    :param str thumbprint: Optional SHA-1 selector with upstream hex parsing.
    :returns: Certificate dictionaries ordered by uppercase thumbprint. Archived
        certificates are excluded. A missing store or unmatched selector returns
        an empty list. Extension strings and OID names use Windows localization.
        Date strings use the account's calendar and time separator; numeric
        timestamps count from January 1, 1970 in that calendar, matching upstream.
    :rtype: list[dict]
    :raises ValueError: The store location is invalid or native metadata is malformed.
    :raises OSError: A required native store, certificate, or extension read fails.
    :raises RuntimeError: Opening the store fails, or the account's calendar
        cannot parse the upstream epoch literal ``01/01/1970``.
    :raises NotImplementedError: Windows lacks required calendar conversion APIs.
    """
    locations = {"currentuser": 0x10000, "localmachine": 0x20000}
    location = store_location.lower() if isinstance(store_location, str) else None
    if location not in locations:
        raise ValueError("store_location must be CurrentUser or LocalMachine")
    library = _crypt32()
    # ReadOnly matches X509Store.Open, including an empty view of a missing store.
    # Omitting IncludeArchived preserves the upstream default enumeration.
    store = library.CertOpenStore(10, 0, None, locations[location] | 0x8000, store_name)
    if not store:
        raise _store_open_error(ctypes.get_last_error())
    context = None
    try:
        selector = None
        if thumbprint is not None:
            data = _thumbprint_bytes(thumbprint)
            buffer = ctypes.create_string_buffer(data)
            selector = _Blob(len(data), ctypes.cast(buffer, _BYTE_POINTER))
        results = []
        culture = None
        while True:
            previous, context = context, None
            # Both APIs release the previous context even when the call fails.
            if selector is None:
                context = library.CertEnumCertificatesInStore(store, previous)
            else:
                context = library.CertFindCertificateInStore(
                    store, _ENCODING, 0, 0x10000, ctypes.byref(selector), previous
                )
            if not context:
                if ctypes.get_last_error() & 0xFFFFFFFF not in (_NOT_FOUND, 18):
                    raise _native_error("Certificate enumeration")
                break
            if culture is None:
                culture = calendar.get_culture()
            results.append(_certificate(library, context, culture))
        return sorted(results, key=lambda certificate: certificate["thumbprint"])
    finally:
        try:
            if context and not library.CertFreeCertificateContext(context):
                raise _native_error("CertFreeCertificateContext")
        finally:
            if not library.CertCloseStore(store, 0):
                raise _native_error("CertCloseStore")
