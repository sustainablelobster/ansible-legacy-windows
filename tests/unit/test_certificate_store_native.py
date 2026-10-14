"""Exercise certificate-store native layouts, buffers and handle ownership."""

# SPDX-License-Identifier: GPL-3.0-or-later
# Native ABI tests inspect private boundaries rather than substitute public behavior.
# pylint: disable=protected-access

import ctypes
from pathlib import Path
from types import ModuleType, SimpleNamespace
from typing import Any
from unittest.mock import Mock, call

import pytest

from tests.unit.payload_support import ROOT, load_module


@pytest.fixture(name="helper")
def certificate_store_helper(monkeypatch: pytest.MonkeyPatch) -> ModuleType:
    """Load the Python3.4-compatible helper without opening native libraries.

    :param monkeypatch: Scoped sibling-import path.
    :returns: Fresh native helper module.
    """
    monkeypatch.syspath_prepend(str(ROOT / "legacy_windows/plugins/module_utils"))
    helper = load_module(
        ROOT
        / "legacy_windows/plugins/module_utils/legacy_windows_certificate_store.py",
        "tested_certificate_store",
    )
    monkeypatch.setattr(
        helper, "error_message", lambda code: f"native error {code}\r\n"
    )
    return helper


def _pointer(destination: Any, value: int) -> None:
    ctypes.cast(destination, ctypes.POINTER(ctypes.c_void_p))[0] = value


def test_store_exception_trims_componentmodel_period_and_linebreaks(
    helper: ModuleType,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(
        helper,
        "error_message",
        lambda _code: "The system cannot find the file specified.\r\n",
    )
    assert helper.store_error(2) == (
        "CertOpenStore failed (The system cannot find the file specified, "
        "Win32ErrorCode 2 - 0x00000002)"
    )


def _size(destination: Any, value: int) -> None:
    ctypes.cast(destination, ctypes.POINTER(ctypes.c_uint32))[0] = value


@pytest.fixture(name="api")
def certificate_store_api(helper: ModuleType, monkeypatch: pytest.MonkeyPatch) -> Any:
    """Provide exact native signatures and observable output buffers.

    :param helper: Loaded native helper.
    :param monkeypatch: Scoped native last-error and Windows-version substitutes.
    :returns: CryptoAPI substitute including contexts, properties and error state.
    """
    state = SimpleNamespace(
        error=0x80092004,
        contexts=[41, 42],
        properties={
            (41, 3): bytes(range(20)),
            (42, 3): bytes(range(20, 40)),
            (42, 2): b"key info",
        },
    )

    def _enumerate_context(_handle: Any, _previous: Any) -> Any:
        return state.contexts.pop(0) if state.contexts else None

    def _get_property(context: Any, identifier: int, buffer: Any, size: Any) -> bool:
        value = state.properties.get((context, identifier))
        if value is None:
            return False
        _size(size, len(value))
        if buffer is not None:
            ctypes.memmove(buffer, value, len(value))
        return True

    def _query(
        _kind: Any,
        _path: Any,
        _flags: Any,
        _format: Any,
        _reserved: Any,
        _encoding: Any,
        content: Any,
        _format_out: Any,
        handle: Any,
        _message: Any,
        _context: Any,
    ) -> bool:
        _size(content, state.content_type)
        _pointer(handle, 73)
        return True

    state.content_type = 1
    state.CertOpenStore = Mock(return_value=71)
    state.CertCloseStore = Mock(return_value=True)
    state.CertEnumCertificatesInStore = Mock(side_effect=_enumerate_context)
    state.CertDuplicateCertificateContext = Mock(side_effect=lambda context: context)
    state.CertFreeCertificateContext = Mock(return_value=True)
    state.CertGetCertificateContextProperty = Mock(side_effect=_get_property)
    state.CertAddCertificateContextToStore = Mock(return_value=True)
    state.CertDeleteCertificateFromStore = Mock(return_value=True)
    state.CryptQueryObject = Mock(side_effect=_query)
    state.PFXImportCertStore = Mock(return_value=75)
    state.PFXExportCertStoreEx = Mock(return_value=True)
    monkeypatch.setattr(helper, "_crypt32", lambda: state)
    monkeypatch.setattr(
        helper.ctypes, "get_last_error", lambda: state.error, raising=False
    )
    # This workflow keeps an independent fixture and expected-result oracle.
    # pylint: disable=duplicate-code
    monkeypatch.setattr(
        helper.sys,
        "getwindowsversion",
        lambda: SimpleNamespace(major=10),
        raising=False,
    )
    # pylint: enable=duplicate-code
    return state


@pytest.mark.parametrize(
    "location,store_type,readonly,flags,name",
    [
        ("CurrentUser", "system", False, 0x15004, "Owned"),
        ("LocalMachine", "system", True, 0x2C004, "Owned"),
        ("ServiceName", "service", False, 0x55004, "ServiceName\\Owned"),
    ],
)
# Keeping each ABI input explicit makes failures identify the mismatched flag.
# pylint: disable-next=too-many-arguments,too-many-positional-arguments
def test_store_open_uses_pinned_native_flags_and_frees_snapshot(
    helper: ModuleType,
    api: Any,
    location: str,
    store_type: str,
    readonly: bool,
    flags: int,
    name: str,
) -> None:
    with helper.open_store("Owned", location, store_type, readonly) as collection:
        assert [row["has_private_key"] for row in collection.records] == [False, True]
        args = api.CertOpenStore.call_args.args
        assert args[:4] == (10, 0, None, flags)
        assert args[4].value == name
    assert api.CertFreeCertificateContext.call_args_list == [call(41), call(42)]
    api.CertCloseStore.assert_called_once_with(71, 0)


def test_context_property_failure_frees_duplicate_previous_and_store(
    helper: ModuleType,
    api: Any,
) -> None:
    api.properties.pop((41, 3))
    with pytest.raises(OSError):
        with helper.open_store("Owned", "CurrentUser", "system", True):
            pytest.fail("Missing fingerprint must not produce a partial snapshot")
    assert api.CertFreeCertificateContext.call_args_list == [call(41), call(41)]
    api.CertCloseStore.assert_called_once_with(71, 0)


def test_enumeration_failure_frees_all_retained_duplicates(
    helper: ModuleType,
    api: Any,
) -> None:
    api.error = 5
    with pytest.raises(OSError):
        with helper.open_store("Owned", "CurrentUser", "system", True):
            pytest.fail("Enumeration failure must not return a partial snapshot")
    assert api.CertFreeCertificateContext.call_args_list == [call(41), call(42)]
    api.CertCloseStore.assert_called_once_with(71, 0)


def test_removal_consumes_only_an_additional_duplicate(
    helper: ModuleType, api: Any
) -> None:
    with helper.open_store("Owned", "CurrentUser", "system", False) as collection:
        collection.remove(collection.records[0])
        api.CertDeleteCertificateFromStore.assert_called_once_with(41)
        api.CertFreeCertificateContext.assert_not_called()
    assert api.CertFreeCertificateContext.call_args_list == [call(41), call(42)]


def test_native_replacement_inherits_existing_properties(
    helper: ModuleType, api: Any
) -> None:
    with helper.open_store("Owned", "CurrentUser", "system", False) as collection:
        collection.add({"context": 81})
        api.CertAddCertificateContextToStore.assert_called_once_with(71, 81, 5, None)


@pytest.mark.parametrize(
    "storage,exportable,persist,expected",
    [
        ("default", True, True, 1),
        ("machine", False, True, 0x20),
        ("user", True, True, 0x1001),
        ("default", False, False, 0x8000),
    ],
)
# Each independent input contributes directly to the native flag bitmask.
# pylint: disable-next=too-many-arguments,too-many-positional-arguments
def test_pfx_import_flags_persist_default_and_only_explicit_inspection_is_ephemeral(
    helper: ModuleType,
    api: Any,
    tmp_path: Path,
    storage: str,
    exportable: bool,
    persist: bool,
    expected: int,
) -> None:
    path = tmp_path / "owned.pfx"
    path.write_bytes(b"owned PFX bytes")
    api.content_type = 12
    with helper.read_file(
        str(path), "owned password", exportable, storage, persist=persist
    ):
        args = api.PFXImportCertStore.call_args.args
        blob = ctypes.cast(args[0], ctypes.POINTER(helper._Blob)).contents
        assert ctypes.string_at(blob.data, blob.size) == b"owned PFX bytes"
        assert args[1:] == ("owned password", expected)
    assert len(api.CertCloseStore.call_args_list) == 2
    assert api.CertCloseStore.call_args_list[0].args[0].value == 73
    assert api.CertCloseStore.call_args_list[0].args[1] == 0
    assert api.CertCloseStore.call_args_list[1] == call(75, 0)


def test_pfx_import_failure_closes_query_store_before_attempt(
    helper: ModuleType,
    api: Any,
    tmp_path: Path,
) -> None:
    path = tmp_path / "owned.pfx"
    path.write_bytes(b"owned PFX")
    api.content_type = 12
    api.PFXImportCertStore.return_value = None
    with pytest.raises(OSError):
        helper.read_file(str(path), "wrong", True, "default")
    assert api.CertCloseStore.call_count == 1


def test_public_only_import_does_not_create_private_keys(
    helper: ModuleType, api: Any
) -> None:
    with helper.read_file("owned.pem", None, True, "default"):
        api.PFXImportCertStore.assert_not_called()
    args = api.CryptQueryObject.call_args.args
    assert args[0] == 1 and args[3:5] == (0xE, 0)
    assert args[2] == sum(1 << kind for kind in (1, 4, 5, 8, 9, 10, 12))


@pytest.mark.parametrize(
    "selector,digest",
    [
        ("00 01\t02\n03\r04", b"\0\1\2\3\4"),
        ("0x1gZ", b"\xff\xff"),
        ("0", b""),
    ],
)
def test_selector_decoder_matches_pinned_find_semantics(
    helper: ModuleType,
    selector: str,
    digest: bytes,
) -> None:
    rows = [{"thumbprint": digest.hex().upper()}]
    assert helper.matches(rows, selector) == rows


def test_der_and_pem_export_use_exact_bytes_and_76_column_crlf(
    helper: ModuleType,
) -> None:
    data = bytes(range(100))
    buffer = ctypes.create_string_buffer(data)
    context = helper._CertificateContext(
        0x10001, ctypes.cast(buffer, ctypes.c_void_p), len(data), None, None
    )
    record = {"context": ctypes.pointer(context)}
    assert helper.export_certificate(record, "der", None) == data
    pem = helper.export_certificate(record, "pem", None)
    lines = pem.split(b"\r\n")
    assert lines[0] == b"-----BEGIN CERTIFICATE-----"
    assert len(lines[1]) == 76 and lines[-1] == b"-----END CERTIFICATE-----"
    assert not pem.endswith(b"\r\n")
    assert helper.base64.b64decode(b"".join(lines[1:-1])) == data


def test_pfx_export_uses_one_cert_and_exact_report_private_key_flags(
    helper: ModuleType,
    api: Any,
) -> None:
    def _export(
        _store: Any, output: Any, _password: Any, _reserved: Any, _flags: Any
    ) -> bool:
        blob = ctypes.cast(output, ctypes.POINTER(helper._Blob)).contents
        if blob.data:
            ctypes.memmove(blob.data, b"PFX", 3)
        blob.size = 3
        return True

    api.PFXExportCertStoreEx.side_effect = _export
    assert helper.export_certificate({"context": 41}, "pkcs12", "owned") == b"PFX"
    api.CertAddCertificateContextToStore.assert_called_once_with(71, 41, 4, None)
    assert api.PFXExportCertStoreEx.call_count == 2
    assert all(
        row.args[2:] == ("owned", None, 6)
        for row in api.PFXExportCertStoreEx.call_args_list
    )
    api.CertCloseStore.assert_called_once_with(71, 0)


def test_failed_pfx_export_closes_its_temporary_store(
    helper: ModuleType, api: Any
) -> None:
    api.PFXExportCertStoreEx.return_value = False
    with pytest.raises(OSError):
        helper.export_certificate({"context": 41}, "pkcs12", "owned")
    api.CertCloseStore.assert_called_once_with(71, 0)
