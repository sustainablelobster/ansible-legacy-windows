"""Exercise owned native client keys, collisions, and cleanup without Windows."""

# SPDX-License-Identifier: GPL-3.0-or-later
# Native ABI substitutes inspect private lifetime boundaries, not TLS support.
# pylint: disable=protected-access

import codecs
import ctypes
from contextlib import ExitStack
from types import SimpleNamespace
from typing import Any
from unittest.mock import Mock

import pytest

from tests.unit.payload_support import ROOT, load_module


def _output(pointer: Any, value: int, kind: Any = ctypes.c_void_p) -> int:
    ctypes.cast(pointer, ctypes.POINTER(kind))[0] = value
    return 0


@pytest.fixture(name="native")
# Keep both key ABIs together to observe their shared certificate lifetime.
# pylint: disable-next=too-many-locals
def native_fixture(monkeypatch: pytest.MonkeyPatch) -> Any:
    """Provide observable key/certificate handles and private-blob buffers.

    :param monkeypatch: Scoped native platform substitutes.
    :returns: Helper, native libraries, and observed resources.
    """
    monkeypatch.syspath_prepend(str(ROOT / "plugins/module_utils"))
    helper = load_module(
        ROOT / "plugins/module_utils/legacy_windows_http_certificate.py",
        "tested_http_certificate",
    )
    monkeypatch.setattr(helper.certificates, "error_message", str)
    monkeypatch.setattr(
        helper.ctypes, "get_last_error", lambda: 0x8009000F, raising=False
    )
    monkeypatch.setattr(helper.uuid, "uuid4", lambda: SimpleNamespace(hex="owned"))
    state = SimpleNamespace(events=[], blobs=[], specification=1, release=False)

    def _record(event: str, value: Any = True) -> Any:
        state.events.append(event)
        return value

    def _export(buffer: Any, size: Any) -> None:
        _output(size, 8, ctypes.c_uint32)
        if buffer is not None:
            ctypes.memmove(buffer, b"private!", 8)
            state.blobs.append(buffer)

    def _parameter(
        _source: Any, identifier: int, buffer: Any, size: Any, _flags: int
    ) -> bool:
        data = b"provider\x00" if identifier == 4 else (24).to_bytes(4, "little")
        _output(size, len(data), ctypes.c_uint32)
        if buffer is not None:
            ctypes.memmove(buffer, data, len(data))
        return True

    def _acquire(
        pointer: Any, _name: str, _provider: str, _kind: int, flags: int
    ) -> bool:
        if flags == 0x50:
            return bool(_record("delete-container"))
        _output(pointer, 20)
        return True

    def _capi_export(
        _key: Any, _parent: Any, _kind: int, _flags: int, buffer: Any, size: Any
    ) -> bool:
        _export(buffer, size)
        return True

    capi = SimpleNamespace(
        CryptGetProvParam=Mock(side_effect=_parameter),
        CryptGetUserKey=Mock(
            side_effect=lambda _source, _spec, pointer: _output(pointer, 11) or True
        ),
        CryptExportKey=Mock(side_effect=_capi_export),
        CryptAcquireContextW=Mock(side_effect=_acquire),
        CryptImportKey=Mock(side_effect=lambda *_args: _output(_args[-1], 21) or True),
        CryptDestroyKey=Mock(
            side_effect=lambda handle: _record("destroy-" + str(handle.value))
        ),
        CryptReleaseContext=Mock(
            side_effect=lambda handle, _flags: _record("release-" + str(handle.value))
        ),
    )

    def _cng_export(
        _source: Any,
        _parent: Any,
        _kind: str,
        _parameters: Any,
        buffer: Any,
        _length: int,
        size: Any,
        _flags: int,
    ) -> int:
        _export(buffer, size)
        return 0

    cng = SimpleNamespace(
        NCryptOpenStorageProvider=Mock(
            side_effect=lambda pointer, *_args: _output(pointer, 30) or 0
        ),
        NCryptExportKey=Mock(side_effect=_cng_export),
        NCryptImportKey=Mock(side_effect=lambda *_args: _output(_args[4], 31) or 0),
        NCryptFreeObject=Mock(
            side_effect=lambda handle: _record("free-" + str(handle.value), 0)
        ),
        NCryptDeleteKey=Mock(
            side_effect=lambda handle, _flags: _record("delete-" + str(handle.value), 0)
        ),
        NCryptSetProperty=Mock(return_value=0),
    )

    def _source(
        _context: Any, _flags: int, _reserved: Any, key: Any, spec: Any, release: Any
    ) -> bool:
        _output(key, 10)
        _output(spec, state.specification, ctypes.c_uint32)
        _output(release, int(state.release), ctypes.c_int32)
        return True

    def _add(
        _store: Any,
        _encoding: int,
        _data: Any,
        _length: int,
        _disposition: int,
        context: Any,
    ) -> bool:
        if context is not None:
            _output(context, 41)
        return True

    def _property_value(
        _context: Any, _identifier: int, _flags: int, info: Any
    ) -> bool:
        value = ctypes.cast(info, ctypes.POINTER(helper._ProviderInfo)).contents
        state.provider = (value.container, value.provider_type, value.key_specification)
        return True

    crypt = SimpleNamespace(
        CryptAcquireCertificatePrivateKey=Mock(side_effect=_source),
        CertOpenStore=Mock(return_value=40),
        CertCloseStore=Mock(side_effect=lambda *_args: _record("close-store")),
        CertAddEncodedCertificateToStore=Mock(side_effect=_add),
        CertSetCertificateContextProperty=Mock(side_effect=_property_value),
        CertFreeCertificateContext=Mock(
            side_effect=lambda *_args: _record("free-certificate")
        ),
    )
    monkeypatch.setattr(
        helper.certificates, "_library", lambda _name, _signatures: crypt
    )
    monkeypatch.setattr(
        helper.certificates,
        "encoded_certificate",
        lambda item: bytes([item["context"]]),
    )
    monkeypatch.setattr(helper, "_cryptoapi", lambda: capi)
    monkeypatch.setattr(helper, "_cng", lambda: cng)

    # Linux has no Windows mbcs codec; scope an ASCII provider-name substitute.
    def _provider_codec(name: str) -> Any:
        return codecs.lookup("ascii") if name == "mbcs" else None

    codecs.register(_provider_codec)
    try:
        yield helper, capi, cng, crypt, state
    finally:
        codecs.unregister(_provider_codec)


@pytest.mark.parametrize("specification", [1, 0xFFFFFFFF])
@pytest.mark.parametrize("failure", [False, True])
def test_owned_chain_and_key_survive_request_then_cleanup(
    native: Any, specification: int, failure: bool
) -> None:
    helper, capi, cng, crypt, state = native
    state.specification = specification
    leaf = {"context": 2}
    collection = SimpleNamespace(records=[{"context": 1}, leaf])
    try:
        with helper.temporary_certificate(collection, leaf) as context:
            assert context == 41
            assert state.events == []
            assert state.provider == (
                "legacy-windows-http-owned",
                24 if specification == 1 else 0,
                1 if specification == 1 else 0,
            )
            assert all(not any(blob.raw) for blob in state.blobs)
            if failure:
                raise ValueError("request failed")
    except ValueError:
        assert failure
    assert state.events[:2] == ["free-certificate", "close-store"]
    assert state.events[2:] == (
        ["destroy-21", "release-20", "delete-container", "destroy-11"]
        if specification == 1
        else ["delete-31", "free-30"]
    )
    assert crypt.CryptAcquireCertificatePrivateKey.call_args.args[1] == 0x10041
    assert crypt.CertAddEncodedCertificateToStore.call_count == 2
    if specification == 1:
        assert capi.CryptAcquireContextW.call_args_list[0].args[-1] == 0x48
    else:
        policy = cng.NCryptSetProperty.call_args.args
        assert policy[0].value == 10
        assert policy[1] == "Export Policy" and policy[-1] == 0
        assert ctypes.cast(policy[2], ctypes.POINTER(ctypes.c_uint32))[0] == 3
        args = cng.NCryptImportKey.call_args.args
        assert args[2] == "PKCS8_PRIVATEKEY"
        assert args[-1] == 0x40  # SILENT, never OVERWRITE or MACHINE.


@pytest.mark.parametrize("cng_key", [False, True])
def test_key_collision_never_deletes_preexisting_container(
    native: Any, cng_key: bool
) -> None:
    helper, capi, cng, _crypt, state = native
    if cng_key:
        cng.NCryptImportKey.side_effect = None
        cng.NCryptImportKey.return_value = -2146893809
    else:
        capi.CryptAcquireContextW.side_effect = None
        capi.CryptAcquireContextW.return_value = False
    with pytest.raises(OSError, match="0x8009000F"):
        with ExitStack() as stack:
            if cng_key:
                helper._copy_cng_key(stack, cng, ctypes.c_void_p(10), "existing")
            else:
                helper._copy_cryptoapi_key(
                    stack, capi, ctypes.c_void_p(10), 1, "existing"
                )
    assert "delete-container" not in state.events
    cng.NCryptDeleteKey.assert_not_called()
    assert state.blobs and all(not any(blob.raw) for blob in state.blobs)


def test_certificate_property_failure_still_deletes_owned_key(native: Any) -> None:
    helper, _capi, cng, crypt, state = native
    state.specification = 0xFFFFFFFF
    crypt.CertSetCertificateContextProperty.side_effect = None
    crypt.CertSetCertificateContextProperty.return_value = False
    leaf = {"context": 2}
    with pytest.raises(OSError):
        with helper.temporary_certificate(SimpleNamespace(records=[leaf]), leaf):
            pytest.fail("failed credential must not reach HTTP")
    cng.NCryptDeleteKey.assert_called_once()
    assert state.events == ["free-certificate", "close-store", "delete-31", "free-30"]


def test_cleanup_error_is_reported_and_other_resources_still_close(native: Any) -> None:
    helper, _capi, cng, _crypt, state = native
    state.specification = 0xFFFFFFFF
    cng.NCryptDeleteKey.side_effect = None
    cng.NCryptDeleteKey.return_value = -2146893809
    leaf = {"context": 2}
    with pytest.raises(OSError, match="0x8009000F"):
        with helper.temporary_certificate(SimpleNamespace(records=[leaf]), leaf):
            pass
    assert state.events == ["free-certificate", "close-store", "free-30"]


def test_bool_failure_raises_even_when_native_last_error_is_zero(
    native: Any, monkeypatch: pytest.MonkeyPatch
) -> None:
    helper, *_unused = native
    monkeypatch.setattr(helper.ctypes, "get_last_error", lambda: 0)
    with pytest.raises(OSError, match="0x00000000"):
        helper._require(False)
    helper._require_status(0)


def test_ephemeral_cng_policy_failure_does_not_create_or_delete_a_key(
    native: Any,
) -> None:
    helper, _capi, cng, _crypt, state = native
    cng.NCryptSetProperty.return_value = -2146893809
    with pytest.raises(OSError, match="0x8009000F"):
        with ExitStack() as stack:
            helper._copy_cng_key(stack, cng, ctypes.c_void_p(10), "owned")
    cng.NCryptImportKey.assert_not_called()
    cng.NCryptDeleteKey.assert_not_called()
    assert state.events == ["free-30"]
