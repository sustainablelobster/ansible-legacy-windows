"""Exercise certificate metadata and native handle ownership without Windows."""

# SPDX-License-Identifier: GPL-3.0-or-later

# Native structure and API boundaries stay private in the target-facing contract.
# pylint: disable=protected-access

import ctypes
import datetime
import json
from types import ModuleType, SimpleNamespace
from typing import Any
from unittest.mock import Mock, call

import pytest

from tests.unit.payload_support import ROOT, load_module

REFERENCE = json.loads(
    (ROOT / "tests/fixtures/certificate_reference.json").read_text(encoding="utf-8")
)


@pytest.fixture(name="helper")
def certificate_helper(monkeypatch: pytest.MonkeyPatch) -> ModuleType:
    """Load the target helper with its staged common dependency.

    :param monkeypatch: Scoped import-path changes.
    :returns: Certificate helper using the development interpreter.
    """
    monkeypatch.syspath_prepend(str(ROOT / "plugins/module_utils"))
    helper = load_module(
        ROOT / "plugins/module_utils/legacy_windows_certificate.py",
        "tested_certificate",
    )
    monkeypatch.setattr(
        helper.calendar,
        "get_culture",
        Mock(return_value={"calendar_id": 1, "time_separator": ":"}),
    )
    return helper


def _blob(helper: ModuleType, data: bytes) -> Any:
    buffer = ctypes.create_string_buffer(data)
    return helper._Blob(len(data), ctypes.cast(buffer, helper._BYTE_POINTER))


def _context(helper: ModuleType, serial: bytes = b"\xff\x00") -> Any:
    info = helper._CertificateInfo()
    info.version = 2
    info.serial = _blob(helper, serial)
    info.signature.oid = b"1.2.840.113549.1.1.11"
    before = 116444736000000000
    after = before + 10000000
    info.not_before = helper._FileTime(before & 0xFFFFFFFF, before >> 32)
    info.not_after = helper._FileTime(after & 0xFFFFFFFF, after >> 32)
    key = _blob(helper, b"public key")
    info.public_key.key = helper._BitBlob(key.size, key.data, 0)
    raw = _blob(helper, b"encoded certificate")
    context = helper._CertificateContext(
        0x10001, raw.data, raw.size, ctypes.pointer(info), 71
    )
    return ctypes.pointer(context)


def _address(pointer: Any) -> int:
    return int(ctypes.cast(pointer, ctypes.c_void_p).value or 0)


def _set_size(destination: Any, size: int) -> None:
    ctypes.cast(destination, ctypes.POINTER(ctypes.c_uint32))[0] = size


@pytest.fixture(name="api")
def native_api(helper: ModuleType, monkeypatch: pytest.MonkeyPatch) -> SimpleNamespace:
    """Supply native buffers and observable handles behind the real reader.

    :param helper: Loaded target reader and native structure definitions.
    :param monkeypatch: Scoped CryptoAPI and Windows last-error substitutions.
    :returns: Native substitutes with configurable certificates and failure codes.
    """
    native = SimpleNamespace(
        queue=[],
        released=[],
        error=0x80092004,
        properties={3: bytes(range(20)), 11: "Fixture\0".encode("utf-16-le")},
        names={
            (2, 0): "CN=fixture",
            (2, 1): "CN=issuer",
            (4, 0): "fixture",
            (4, 1): "issuer",
        },
        oids={b"1.2.840.113549.1.1.11": "sha256RSA"},
        formats={},
        decoded={},
    )

    def _enumerate(_store: Any, previous: Any) -> Any:
        if previous:
            native.released.append(_address(previous))
        return native.queue.pop(0) if native.queue else None

    def _free(context: Any) -> bool:
        native.released.append(_address(context))
        return True

    def _property(_context: Any, identifier: int, buffer: Any, size: Any) -> bool:
        value = native.properties.get(identifier)
        if value is None:
            return False
        _set_size(size, len(value))
        if buffer is not None and value:
            ctypes.memmove(buffer, value, len(value))
        return True

    # Keep each Windows signature visible so tests catch pointer/size mistakes.
    # pylint: disable=too-many-arguments,too-many-positional-arguments
    def _name(
        _context: Any, kind: int, flags: int, style: Any, buffer: Any, count: int
    ) -> int:
        assert ctypes.cast(style, ctypes.POINTER(ctypes.c_uint32))[0] == 0x02000003
        value = native.names[kind, flags]
        if buffer is not None:
            assert count == len(value) + 1
            buffer.value = value
        return len(value) + 1

    def _format(
        encoding: int,
        kind: int,
        multiline: int,
        settings: Any,
        oid: bytes,
        _data: Any,
        _count: int,
        buffer: Any,
        size: Any,
    ) -> bool:
        assert encoding == 0x10001 and kind == 0 and settings is None
        value = native.formats.get((oid, multiline))
        if value is None:
            return False
        encoded = (value + "\0").encode("utf-16-le")
        _set_size(size, len(encoded))
        if buffer is not None:
            ctypes.memmove(buffer, encoded, len(encoded))
        return True

    def _decode(
        encoding: int,
        oid: bytes,
        _data: Any,
        _count: int,
        flags: int,
        allocation: Any,
        buffer: Any,
        size: Any,
    ) -> bool:
        assert encoding == 0x10001 and flags == 0 and allocation is None
        value = native.decoded.get(oid)
        if value is None:
            return False
        _set_size(size, ctypes.sizeof(value))
        if buffer is not None:
            ctypes.memmove(buffer, ctypes.byref(value), ctypes.sizeof(value))
        return True

    # pylint: enable=too-many-arguments,too-many-positional-arguments

    def _oid(kind: int, value: bytes, _group: int) -> Any:
        assert kind == 1
        name = native.oids.get(value)
        if name is None:
            return None
        return ctypes.pointer(
            helper._OidInfo(ctypes.sizeof(helper._OidInfo), value, name)
        )

    native.CertOpenStore = Mock(return_value=71)
    native.CertCloseStore = Mock(return_value=True)
    native.CertFreeCertificateContext = Mock(side_effect=_free)
    native.CertEnumCertificatesInStore = Mock(side_effect=_enumerate)
    native.CertFindCertificateInStore = Mock()
    native.CertGetCertificateContextProperty = Mock(side_effect=_property)
    native.CertGetNameStringW = Mock(side_effect=_name)
    native.CryptFindOIDInfo = Mock(side_effect=_oid)
    native.CryptFormatObject = Mock(side_effect=_format)
    native.CryptDecodeObjectEx = Mock(side_effect=_decode)
    monkeypatch.setattr(helper, "_crypt32", lambda: native)
    monkeypatch.setattr(ctypes, "get_last_error", lambda: native.error, raising=False)
    monkeypatch.setattr(
        ctypes, "FormatError", lambda _code: "native read failed\r\n", raising=False
    )
    return native


@pytest.fixture(name="message_api")
def message_api_fixture(monkeypatch: pytest.MonkeyPatch) -> SimpleNamespace:
    """Expose the system error-message allocation separately from ctypes cleanup.

    :param monkeypatch: Scoped Windows DLL substitution.
    :returns: Message formatter with an owned buffer and observable release.
    """
    native = SimpleNamespace(text="native read failed\r\n", allocated=[])

    # Preserve FormatMessageW's seven native parameters at the substitute boundary.
    # pylint: disable-next=too-many-arguments,too-many-positional-arguments
    def _format(
        flags: int,
        source: Any,
        _code: int,
        language: int,
        destination: Any,
        minimum: int,
        inserts: Any,
    ) -> int:
        assert (flags, source, language, minimum, inserts) == (0x1300, None, 0, 0, None)
        buffer = ctypes.create_unicode_buffer(native.text)
        native.allocated.append(buffer)
        ctypes.cast(destination, ctypes.POINTER(ctypes.c_void_p))[0] = ctypes.addressof(
            buffer
        )
        return len(native.text)

    native.FormatMessageW = Mock(side_effect=_format)
    native.LocalFree = Mock(return_value=None)
    loader = Mock(return_value=native)
    monkeypatch.setattr(ctypes, "WinDLL", loader, raising=False)
    return native


def test_complete_metadata_with_no_extensions(
    helper: ModuleType, api: SimpleNamespace
) -> None:
    context = _context(helper)
    api.queue.append(context)
    assert helper.read_certificates("Root", "LocalMachine") == [
        {
            "friendly_name": "Fixture",
            "thumbprint": "000102030405060708090A0B0C0D0E0F10111213",
            "subject": "CN=fixture",
            "issuer": "CN=issuer",
            "valid_from": 0.0,
            "valid_from_iso8601": "1970-01-01T00:00:00Z",
            "valid_to": 1.0,
            "valid_to_iso8601": "1970-01-01T00:00:01Z",
            "serial_number": "00FF",
            "archived": False,
            "version": 3,
            "has_private_key": False,
            "issued_by": "issuer",
            "issued_to": "fixture",
            "signature_algorithm": "sha256RSA",
            "dns_names": ["fixture"],
            "raw": "ZW5jb2RlZCBjZXJ0aWZpY2F0ZQ==",
            "public_key": "cHVibGljIGtleQ==",
            "extensions": [],
        }
    ]
    api.CertOpenStore.assert_called_once_with(10, 0, None, 0x28000, "Root")
    api.CertCloseStore.assert_called_once_with(71, 0)
    assert api.released == [_address(context)]
    api.CertFreeCertificateContext.assert_not_called()


def test_readonly_empty_store_and_case_insensitive_location(
    helper: ModuleType, api: SimpleNamespace
) -> None:
    assert helper.read_certificates("absent-store", "currentuser") == []
    api.CertOpenStore.assert_called_once_with(10, 0, None, 0x18000, "absent-store")
    api.CertCloseStore.assert_called_once_with(71, 0)
    helper.calendar.get_culture.assert_not_called()


@pytest.mark.parametrize("location", [None, "", "CurrentService", " CurrentUser"])
def test_invalid_location_is_rejected_before_open(
    helper: ModuleType, api: SimpleNamespace, location: Any
) -> None:
    with pytest.raises(ValueError, match="store_location"):
        helper.read_certificates("My", location)
    api.CertOpenStore.assert_not_called()


@pytest.mark.parametrize("store_name", ["Root", "", None])
def test_open_failure_preserves_wrapper_and_does_not_close_unowned_handle(
    helper: ModuleType,
    api: SimpleNamespace,
    message_api: SimpleNamespace,
    store_name: str | None,
) -> None:
    api.CertOpenStore.return_value = None
    api.error = 5
    with pytest.raises(RuntimeError) as caught:
        helper.read_certificates(store_name, "LocalMachine")
    assert str(caught.value) == (
        'Exception calling "Open" with "1" argument(s): "native read failed\r\n"'
    )
    api.CertCloseStore.assert_not_called()
    message_api.LocalFree.assert_called_once()
    assert message_api.LocalFree.call_args.args[0].value == ctypes.addressof(
        message_api.allocated[0]
    )


@pytest.mark.parametrize(
    "message",
    [
        "The parameter is incorrect.\r\n",
        "Paramètre incorrect.\r\n",
        "Message without a newline",
    ],
)
def test_store_open_error_uses_raw_message_and_releases_its_allocation(
    helper: ModuleType,
    message_api: SimpleNamespace,
    message: str,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    message_api.text = message
    normalized = Mock(
        side_effect=AssertionError("ctypes.FormatError must not format this error")
    )
    monkeypatch.setattr(ctypes, "FormatError", normalized, raising=False)
    assert str(helper._store_open_error(87)) == (
        'Exception calling "Open" with "1" argument(s): "' + message + '"'
    )
    normalized.assert_not_called()
    assert message_api.FormatMessageW.call_args.args[2] == 87
    message_api.LocalFree.assert_called_once()
    assert message_api.LocalFree.call_args.args[0].value == ctypes.addressof(
        message_api.allocated[0]
    )


def test_store_message_format_failure_has_no_unowned_buffer_to_release(
    helper: ModuleType,
    api: SimpleNamespace,
    message_api: SimpleNamespace,
) -> None:
    api.error = 317
    message_api.FormatMessageW.side_effect = None
    message_api.FormatMessageW.return_value = 0
    with pytest.raises(OSError, match="FormatMessageW"):
        helper._store_open_error(87)
    message_api.LocalFree.assert_not_called()


def test_store_message_read_failure_releases_buffer_and_recovers(
    helper: ModuleType,
    message_api: SimpleNamespace,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    reader = ctypes.wstring_at
    failing = Mock(side_effect=ValueError("message read failed"))
    monkeypatch.setattr(ctypes, "wstring_at", failing)
    with pytest.raises(ValueError, match="message read failed"):
        helper._store_open_error(87)
    message_api.LocalFree.assert_called_once()
    monkeypatch.setattr(ctypes, "wstring_at", reader)
    assert str(helper._store_open_error(87)).endswith('native read failed\r\n"')
    assert message_api.LocalFree.call_count == 2


def test_store_message_release_failure_is_reported(
    helper: ModuleType,
    api: SimpleNamespace,
    message_api: SimpleNamespace,
) -> None:
    api.error = 6
    message_api.LocalFree.return_value = 123
    with pytest.raises(OSError, match="LocalFree"):
        helper._store_open_error(87)


@pytest.mark.parametrize("end_error", [0x80092004, -2146885628, 18])
def test_normal_enumeration_end_codes(
    helper: ModuleType, api: SimpleNamespace, end_error: int
) -> None:
    api.error = end_error
    assert helper.read_certificates("My", "CurrentUser") == []


def test_enumeration_error_releases_previous_once_and_recovers(
    helper: ModuleType, api: SimpleNamespace
) -> None:
    context = _context(helper)
    api.queue.append(context)
    api.error = 5
    with pytest.raises(OSError, match="Certificate enumeration"):
        helper.read_certificates("My", "LocalMachine")
    assert api.released == [_address(context)]
    api.CertFreeCertificateContext.assert_not_called()
    api.CertCloseStore.assert_called_once_with(71, 0)
    api.error = 0x80092004
    api.queue.append(context)
    assert len(helper.read_certificates("My", "LocalMachine")) == 1


@pytest.mark.parametrize("failure", ["name", "hash", "decode"])
def test_metadata_failure_frees_current_context_and_store(
    helper: ModuleType, api: SimpleNamespace, failure: str
) -> None:
    context = _context(helper)
    api.queue.append(context)
    if failure == "name":
        api.CertGetNameStringW.return_value = 0
        api.CertGetNameStringW.side_effect = None
    elif failure == "hash":
        del api.properties[3]
    else:
        extension = helper._Extension(b"2.5.29.19", 1, _blob(helper, b"broken"))
        context.contents.info.contents.extension_count = 1
        context.contents.info.contents.extensions = ctypes.pointer(extension)
    with pytest.raises(OSError):
        helper.read_certificates("Root", "LocalMachine")
    assert api.released == [_address(context)]
    api.CertFreeCertificateContext.assert_called_once()
    api.CertCloseStore.assert_called_once_with(71, 0)


def test_close_failure_is_reported(helper: ModuleType, api: SimpleNamespace) -> None:
    api.CertCloseStore.return_value = False
    with pytest.raises(OSError, match="CertCloseStore"):
        helper.read_certificates("My", "LocalMachine")


def test_context_release_failure_still_closes_store(
    helper: ModuleType, api: SimpleNamespace
) -> None:
    api.queue.append(_context(helper))
    del api.properties[3]
    api.CertFreeCertificateContext.side_effect = None
    api.CertFreeCertificateContext.return_value = False
    with pytest.raises(OSError, match="CertFreeCertificateContext"):
        helper.read_certificates("My", "LocalMachine")
    api.CertCloseStore.assert_called_once_with(71, 0)


@pytest.mark.parametrize(
    ("text", "expected"),
    [
        ("", b""),
        ("A", b""),
        ("abc", b"\xab"),
        (" AB\u00a0cd\tEF\r\n", b"\xab\xcd\xef"),
        ("G0", b"\xf0"),
        ("0G", b"\xff"),
        ("\u200eAB", b"\xfa"),
        ("\U0001f600AA", b"\xff\xaa"),
        ("\x1c0", b"\xf0"),
    ],
)
def test_thumbprint_find_uses_framework_hex_parsing(
    helper: ModuleType, api: SimpleNamespace, text: str, expected: bytes
) -> None:
    # Keep the native search signature visible at the substitute boundary.
    # pylint: disable-next=too-many-arguments,too-many-positional-arguments
    def _find(
        store: int, encoding: int, flags: int, kind: int, blob: Any, previous: Any
    ) -> None:
        assert (store, encoding, flags, kind, previous) == (
            71,
            0x10001,
            0,
            0x10000,
            None,
        )
        assert (
            helper._bytes(ctypes.cast(blob, ctypes.POINTER(helper._Blob)).contents)
            == expected
        )

    api.CertFindCertificateInStore.side_effect = _find
    assert helper.read_certificates("My", "CurrentUser", text) == []
    api.CertEnumCertificatesInStore.assert_not_called()
    api.CertCloseStore.assert_called_once()


def test_sorted_results_and_private_key_flags(
    helper: ModuleType, api: SimpleNamespace
) -> None:
    contexts = [_context(helper), _context(helper)]
    api.queue.extend(contexts)
    original = api.CertGetCertificateContextProperty.side_effect

    def _property(context: Any, identifier: int, buffer: Any, size: Any) -> bool:
        if identifier == 3:
            api.properties[3] = (
                b"\xff" if _address(context) == _address(contexts[0]) else b"\x00"
            )
        return bool(original(context, identifier, buffer, size))

    api.CertGetCertificateContextProperty.side_effect = _property
    api.properties[5] = b"key context"
    api.properties[19] = b""
    del api.properties[11]
    result = helper.read_certificates("Root", "LocalMachine")
    assert [row["thumbprint"] for row in result] == ["00", "FF"]
    assert all(row["has_private_key"] and row["archived"] for row in result)
    assert all(row["friendly_name"] == "" for row in result)
    assert all(
        arguments.args[1] != 2
        for arguments in api.CertGetCertificateContextProperty.call_args_list
    )


def test_provider_info_alone_indicates_private_key(
    helper: ModuleType, api: SimpleNamespace
) -> None:
    api.properties[2] = b"provider info"
    assert helper._certificate(api, _context(helper))["has_private_key"] is True


def test_unreadable_friendly_name_second_read_preserves_other_metadata(
    helper: ModuleType, api: SimpleNamespace
) -> None:
    original = api.CertGetCertificateContextProperty.side_effect

    def _property(context: Any, identifier: int, buffer: Any, size: Any) -> bool:
        if identifier == 11 and buffer is not None:
            return False
        return bool(original(context, identifier, buffer, size))

    api.CertGetCertificateContextProperty.side_effect = _property
    result = helper._certificate(api, _context(helper))
    assert result["friendly_name"] == ""
    assert result["thumbprint"] == "000102030405060708090A0B0C0D0E0F10111213"


def test_typed_extensions_preserve_order_and_conditional_fields(
    helper: ModuleType, api: SimpleNamespace
) -> None:
    definitions = [
        (b"2.5.29.19", "Basic Constraints"),
        (b"2.5.29.15", "Key Usage"),
        (b"2.5.29.14", "Subject Key Identifier"),
        (b"2.5.29.37", "Enhanced Key Usage"),
        (b"2.5.29.17", "Subject Alternative Name"),
        (b"1.2.3.4", None),
    ]
    extensions = (helper._Extension * len(definitions))(
        *(
            helper._Extension(oid, index % 2, _blob(helper, b"\x05\x00"))
            for index, (oid, _name) in enumerate(definitions)
        )
    )
    context = _context(helper)
    context.contents.info.contents.extension_count = len(extensions)
    context.contents.info.contents.extensions = extensions
    api.oids.update(dict(definitions))
    api.oids[b"1.3.6.1.5.5.7.3.1"] = "Server Authentication"
    api.decoded[b"2.5.29.19"] = helper._BasicConstraints2(1, 1, 2)
    api.decoded[b"2.5.29.15"] = _blob(helper, b"\x86\x80")
    api.decoded[b"2.5.29.14"] = _blob(helper, b"\xaa\x00\xff")
    purposes = (ctypes.c_char_p * 2)(b"1.3.6.1.5.5.7.3.1", b"1.2.3.99")
    api.decoded[b"2.5.29.37"] = helper._EnhancedKeyUsage(2, purposes)
    api.formats.update(
        {(oid, 0): "formatted " + oid.decode() for oid, _name in definitions}
    )
    api.formats[b"2.5.29.17", 1] = (
        "DNS Name=fixture\r\nDNS Name = www.example.com\n"
        "RFC822 Name=mail@example.com\rDNS Name=left=right\r\nDNS Name=fixture\r\n"
    )
    result = helper._certificate(api, context)
    assert result["is_ca"] is True and result["path_length_constraint"] == 2
    assert result["key_usages"] == [
        "CrlSign",
        "KeyCertSign",
        "DigitalSignature",
        "DecipherOnly",
    ]
    assert result["ski"] == "AA00FF"
    assert result["intended_purposes"] == ["Server Authentication", ""]
    assert result["dns_names"] == [
        "fixture",
        "fixture",
        "www.example.com",
        "left",
        "fixture",
    ]
    assert result["extensions"] == [
        {
            "field": name,
            "critical": bool(index % 2),
            "value": "formatted " + oid.decode(),
        }
        for index, (oid, name) in enumerate(definitions)
    ]


def test_legacy_basic_constraints_and_empty_typed_values(
    helper: ModuleType, api: SimpleNamespace
) -> None:
    subject = _blob(helper, b"\x80")
    api.decoded[b"2.5.29.10"] = helper._BasicConstraints(
        helper._BitBlob(subject.size, subject.data, 0), 0, 0, 0, None
    )
    api.decoded[b"2.5.29.37"] = helper._EnhancedKeyUsage(0, None)
    api.decoded[b"2.5.29.15"] = _blob(helper, b"")
    api.decoded[b"2.5.29.14"] = _blob(helper, b"")
    result: dict[str, Any] = {}
    for oid in api.decoded:
        helper._extension_fields(
            api, helper._Extension(oid, 0, _blob(helper, b"encoded")), result
        )
    assert result == {
        "is_ca": True,
        "path_length_constraint": 0,
        "intended_purposes": None,
        "key_usages": ["None"],
        "ski": "",
    }


@pytest.mark.parametrize(
    ("value", "expected"),
    [
        (b"\x00\x01", ["256"]),
        (b"\xff\xff\xff\xff", ["-1"]),
        (b"\x80\x00\x00\x00\xff", ["DigitalSignature"]),
    ],
)
def test_key_usage_unknown_bits_keep_framework_enum_shape(
    helper: ModuleType, value: bytes, expected: list[str]
) -> None:
    assert helper._key_usage_names(_blob(helper, value)) == expected


def test_oid_fallback_preserves_unknown_as_null(
    helper: ModuleType, api: SimpleNamespace
) -> None:
    assert helper._oid_name(api, b"1.2.3.unknown", 6) is None
    assert api.CryptFindOIDInfo.call_args_list == [
        call(1, b"1.2.3.unknown", 6),
        call(1, b"1.2.3.unknown", 0),
    ]


@pytest.mark.parametrize("failure_call", [1, 2])
def test_format_failure_returns_hex_and_empty_input_stays_empty(
    helper: ModuleType, api: SimpleNamespace, failure_call: int
) -> None:
    extension = helper._Extension(b"1.2.3", 0, _blob(helper, b"\x30\xff"))
    api.formats[b"1.2.3", 0] = "formatted"
    original = api.CryptFormatObject.side_effect
    count = 0

    def _format(*arguments: Any) -> bool:
        nonlocal count
        count += 1
        return False if count == failure_call else bool(original(*arguments))

    api.CryptFormatObject.side_effect = _format
    assert helper._format_extension(api, extension) == "30FF"
    assert (
        helper._format_extension(
            api, helper._Extension(b"1.2.3", 0, _blob(helper, b""))
        )
        == ""
    )


def test_native_binding_uses_fixed_width_windows_types(
    helper: ModuleType, monkeypatch: pytest.MonkeyPatch
) -> None:
    library = Mock()
    loader = Mock(return_value=library)
    monkeypatch.setattr(ctypes, "WinDLL", loader, raising=False)
    assert helper._crypt32() is library
    loader.assert_called_once_with("crypt32", use_last_error=True)
    assert library.CertOpenStore.restype is ctypes.c_void_p
    assert library.CertOpenStore.argtypes == [
        ctypes.c_void_p,
        ctypes.c_uint32,
        ctypes.c_void_p,
        ctypes.c_uint32,
        ctypes.c_wchar_p,
    ]
    assert library.CryptFindOIDInfo.restype is ctypes.POINTER(helper._OidInfo)


@pytest.mark.parametrize(
    "case",
    [case for case in REFERENCE["date_cultures"] if "error" not in case],
    ids=lambda case: case["culture"],
)
def test_dates_match_captured_calendar_and_separator_behavior(
    helper: ModuleType, api: SimpleNamespace, case: dict[str, Any]
) -> None:
    context = _context(helper)
    for field, seconds in (("not_before", 946782245), ("not_after", 2064816550)):
        ticks = 116444736000000000 + seconds * 10000000
        setattr(
            context.contents.info.contents,
            field,
            helper._FileTime(ticks & 0xFFFFFFFF, ticks >> 32),
        )
    culture = {
        "calendar_id": 7 if case["culture"] == "th-TH" else 1,
        "time_separator": "." if case["culture"] == "en-US-custom-time" else ":",
    }
    result = helper._certificate(api, context, culture)
    for field, expected in case.items():
        if field != "culture":
            assert result[field] == expected
    helper.calendar.get_culture.assert_not_called()


def test_epoch_parse_failure_matches_capture_and_releases_handles_before_recovery(
    helper: ModuleType, api: SimpleNamespace, monkeypatch: pytest.MonkeyPatch
) -> None:
    context = _context(helper)
    api.queue.append(context)
    native_conversion = Mock(
        side_effect=ValueError("Calendar year outside native range")
    )
    monkeypatch.setattr(helper.calendar, "calendar_date", native_conversion)
    with pytest.raises(RuntimeError) as caught:
        helper.read_certificates("Root", "LocalMachine")
    expected = next(
        case["error"] for case in REFERENCE["date_cultures"] if "error" in case
    )
    assert str(caught.value) == expected
    assert api.released == [_address(context)]
    api.CertCloseStore.assert_called_once_with(71, 0)
    api.CertGetCertificateContextProperty.assert_not_called()
    native_conversion.side_effect = None
    native_conversion.return_value = datetime.date(1970, 1, 1)
    api.queue.append(context)
    assert helper.read_certificates("Root", "LocalMachine")[0]["valid_from"] == 0.0


def test_account_culture_is_read_once_for_selected_certificates(
    helper: ModuleType, api: SimpleNamespace
) -> None:
    api.queue.extend([_context(helper), _context(helper)])
    assert len(helper.read_certificates("Root", "LocalMachine")) == 2
    helper.calendar.get_culture.assert_called_once_with()
