"""Check credential ABI, buffer ownership and bounded native lookups off-target."""

# SPDX-License-Identifier: GPL-3.0-or-later
# Native boundary tests intentionally inspect private ABI records.
# pylint: disable=protected-access

import ctypes
import re
import struct
from types import ModuleType, SimpleNamespace
from typing import Any
from unittest.mock import Mock

import pytest

from tests.unit.payload_support import ROOT, load_module


@pytest.fixture(name="helper")
def credential_helper() -> ModuleType:
    """Load only the module-local native helper.

    :returns: Imported helper with no Windows calls performed.
    """
    return load_module(
        ROOT / "legacy_windows/plugins/module_utils/legacy_windows_credential.py",
        "tested_credential_native",
    )


@pytest.fixture(name="native")
def native_library(helper: ModuleType, monkeypatch: pytest.MonkeyPatch) -> Any:
    """Substitute native calls while keeping returned storage alive.

    :param helper: Native helper under test.
    :param monkeypatch: Scoped boundary replacements.
    :returns: Configurable DLL mock and error status.
    """
    state = SimpleNamespace(library=Mock(), error=1168)
    monkeypatch.setattr(helper, "_advapi", lambda: state.library)
    monkeypatch.setattr(
        helper.ctypes, "get_last_error", lambda: state.error, raising=False
    )
    monkeypatch.setattr(
        helper.ctypes,
        "FormatError",
        lambda unused: "Native failure.\r\n",
        raising=False,
    )
    return state


def test_native_abi_offsets_use_fixed_dword_and_pointer_width(
    helper: ModuleType,
) -> None:
    width = ctypes.sizeof(ctypes.c_void_p)
    assert helper._Credential.target.offset == 8
    assert helper._Credential.secret.offset == (40 if width == 8 else 28)
    assert helper._Credential.attributes.offset == (56 if width == 8 else 40)
    assert ctypes.sizeof(helper._Credential) == (80 if width == 8 else 52)
    assert ctypes.sizeof(helper._Attribute) == (24 if width == 8 else 16)
    assert ctypes.sizeof(helper._FileTime) == 8


@pytest.mark.parametrize(
    "code,expected",
    [
        (1168, None),
        (1312, "run the module with become"),
        (5, "CredEnumerateW() failed"),
    ],
)
def test_named_read_distinguishes_absence_logon_session_and_other_errors(
    helper: ModuleType, native: Any, code: int, expected: str | None
) -> None:
    native.error = code
    native.library.CredReadW.return_value = 0
    if expected is None:
        assert helper.read("owned", 1) is None
    else:
        with pytest.raises(OSError, match=re.escape(expected)):
            helper.read("owned", 1)
    native.library.CredReadW.assert_called_once()
    assert native.library.CredReadW.call_args.args[:3] == ("owned", 1, 0)
    native.library.CredFree.assert_not_called()


def test_read_copies_counted_secret_and_duplicate_attributes_before_free(
    helper: ModuleType, native: Any
) -> None:
    secret = ctypes.create_string_buffer(b"a\0b")
    value = ctypes.create_string_buffer(b"\xff\0")
    attributes = (helper._Attribute * 2)()
    attributes[0] = helper._Attribute("same", 0, 2, ctypes.cast(value, ctypes.c_void_p))
    attributes[1] = helper._Attribute("same", 0, 0, None)
    record = helper._Credential()
    record.kind, record.target, record.username = 1, "owned", "user"
    record.persistence, record.secret_size = 2, 3
    record.secret, record.attributes = ctypes.cast(secret, ctypes.c_void_p), attributes
    record.attribute_count = 2

    def _read(
        unused_name: str, unused_kind: int, unused_flags: int, output: Any
    ) -> int:
        output._obj.value = ctypes.addressof(record)
        return 1

    native.library.CredReadW.side_effect = _read
    result = helper.read("owned", 1)
    assert result["secret"] == b"a\0b"
    assert result["attributes"] == [
        {"name": "same", "flags": 0, "data": b"\xff\0"},
        {"name": "same", "flags": 0, "data": b""},
    ]
    native.library.CredFree.assert_called_once()
    secret.raw = b"xxxx"
    value.raw = b"xxx"
    assert result["secret"] == b"a\0b" and result["attributes"][0]["data"] == b"\xff\0"


def test_write_keeps_all_buffers_alive_and_preserve_flag_explicit(
    helper: ModuleType, native: Any
) -> None:
    record = {
        "name": "owned",
        "type": 1,
        "persistence": 3,
        "alias": "Alias",
        "comment": "Comment",
        "username": "User",
        "secret": None,
        "attributes": [{"name": "one", "data": b"a\0b"}, {"name": "two", "data": b""}],
    }

    def _write(pointer: Any, flags: int) -> int:
        value = pointer._obj
        assert value.flags == 0 and flags == 1
        assert value.secret_size == 0
        assert value.target == "owned" and value.username == "User"
        assert value.persistence == 3 and value.attribute_count == 2
        assert value.attributes[0].keyword == "one"
        assert (
            ctypes.string_at(value.attributes[0].value, value.attributes[0].size)
            == b"a\0b"
        )
        assert value.attributes[1].size == 0
        return 1

    native.library.CredWriteW.side_effect = _write
    helper.write(record, True)
    native.library.CredWriteW.assert_called_once()
    native.library.CredFree.assert_not_called()


def test_null_attribute_rejected_before_native_write(
    helper: ModuleType, native: Any
) -> None:
    record = {
        "name": "owned",
        "type": 1,
        "persistence": 2,
        "alias": None,
        "comment": None,
        "username": "User",
        "secret": b"",
        "attributes": [{"name": "a", "data": None}],
    }
    with pytest.raises(ValueError, match="Object reference"):
        helper.write(record)
    native.library.CredWriteW.assert_not_called()


def test_certificate_marshalling_and_unmarshalling_release_native_outputs(
    helper: ModuleType, native: Any
) -> None:
    text = ctypes.create_unicode_buffer("@@certificate")
    info = ctypes.create_string_buffer(struct.pack("<I", 24) + bytes(range(20)))

    def _marshal(kind: int, data: Any, output: Any) -> int:
        assert kind == 1
        assert ctypes.string_at(data, 24) == info.raw[:24]
        output._obj.value = ctypes.addressof(text)
        return 1

    def _unmarshal(value: str, kind: Any, output: Any) -> int:
        assert value == "@@certificate"
        kind._obj.value = 1
        output._obj.value = ctypes.addressof(info)
        return 1

    native.library.CredMarshalCredentialW.side_effect = _marshal
    native.library.CredUnmarshalCredentialW.side_effect = _unmarshal
    thumbprint = "000102030405060708090A0B0C0D0E0F10111213"
    assert helper._marshal_certificate(native.library, thumbprint) == "@@certificate"
    assert helper._unmarshal_certificate(native.library, "@@certificate") == thumbprint
    assert native.library.CredFree.call_count == 2


def test_failed_unmarshal_releases_credential_and_any_returned_buffer(
    helper: ModuleType, native: Any
) -> None:
    record = helper._Credential()
    record.kind, record.username = 3, "@@invalid"
    info = ctypes.create_string_buffer(b"x")

    def _read(
        unused_name: str, unused_kind: int, unused_flags: int, output: Any
    ) -> int:
        output._obj.value = ctypes.addressof(record)
        return 1

    def _unmarshal(unused_value: str, unused_kind: Any, output: Any) -> int:
        output._obj.value = ctypes.addressof(info)
        return 0

    native.library.CredReadW.side_effect = _read
    native.library.CredUnmarshalCredentialW.side_effect = _unmarshal
    with pytest.raises(OSError, match="CredUnmarshalCredentialW"):
        helper.read("owned", 3)
    assert native.library.CredFree.call_count == 2


@pytest.mark.parametrize("found", [False, True])
@pytest.mark.parametrize("code", [0x80092004, -2146885628, 1168])
def test_certificate_lookup_uses_current_user_readonly_store_and_releases_handles(
    helper: ModuleType,
    native: Any,
    monkeypatch: pytest.MonkeyPatch,
    found: bool,
    code: int,
) -> None:
    library = Mock()
    library.CertOpenStore.return_value = 11
    library.CertFindCertificateInStore.return_value = 12 if found else None
    native.error = code
    monkeypatch.setattr(
        helper, "_library", lambda unused_name, unused_signatures: library
    )
    assert helper.certificate_exists("AB" * 20) is found
    assert library.CertOpenStore.call_args.args == (10, 0, None, 0x1C000, "My")
    library.CertCloseStore.assert_called_once_with(11, 0)
    assert library.CertFreeCertificateContext.call_count == int(found)


def test_invalid_certificate_thumbprint_does_not_open_store(
    helper: ModuleType, monkeypatch: pytest.MonkeyPatch
) -> None:
    loader = Mock()
    monkeypatch.setattr(helper, "_library", loader)
    assert helper.certificate_exists("Not hex") is False
    loader.assert_not_called()


@pytest.mark.parametrize("code", [0x80092005, -2146885627])
def test_certificate_lookup_retains_high_bit_native_failure_and_closes_store(
    helper: ModuleType, native: Any, monkeypatch: pytest.MonkeyPatch, code: int
) -> None:
    library = Mock()
    library.CertOpenStore.return_value = 11
    library.CertFindCertificateInStore.return_value = None
    native.error = code
    monkeypatch.setattr(
        helper, "_library", lambda unused_name, unused_signatures: library
    )

    def _format(error: int) -> str:
        assert error == -2146885627
        return "Native certificate failure.\r\n"

    monkeypatch.setattr(helper.ctypes, "FormatError", _format)
    with pytest.raises(
        OSError,
        match=re.escape(
            "CertFindCertificateInStore() failed - Native certificate failure. "
            "(Win32 Error Code -2146885627: 0x80092005)"
        ),
    ):
        helper.certificate_exists("AB" * 20)
    library.CertCloseStore.assert_called_once_with(11, 0)
    library.CertFreeCertificateContext.assert_not_called()


def test_library_declares_native_signatures(
    helper: ModuleType, monkeypatch: pytest.MonkeyPatch
) -> None:
    library = Mock()
    monkeypatch.setattr(helper, "os", SimpleNamespace(name="nt"))
    monkeypatch.setattr(
        helper.ctypes, "WinDLL", Mock(return_value=library), raising=False
    )
    assert helper._advapi() is library
    assert library.CredWriteW.argtypes == [
        ctypes.POINTER(helper._Credential),
        ctypes.c_uint32,
    ]
    assert library.CredFree.restype is None
    assert library.CredReadW.argtypes[-1] == ctypes.POINTER(ctypes.c_void_p)
