"""Verify certificate lookup, key permissions and native handle ownership."""

# SPDX-License-Identifier: GPL-3.0-or-later
# The native boundary is private; tests inspect its handles and binary buffers.
# pylint: disable=protected-access

import ctypes
import struct
from types import ModuleType, SimpleNamespace
from typing import Any
from unittest.mock import Mock

import pytest

from tests.unit.payload_support import ROOT, load_module

PATH = "Cert:\\CurrentUser\\My\\" + "01" * 20
ACL = struct.pack("<BBHHH", 2, 0, 8, 0, 0)


@pytest.fixture(name="helper")
def certificate_acl_helper(monkeypatch: pytest.MonkeyPatch) -> ModuleType:
    """Load the certificate adapter with its staged ACL sibling.

    :param monkeypatch: Scoped target helper import path.
    :returns: Loaded native certificate ACL adapter.
    """
    monkeypatch.syspath_prepend(str(ROOT / "plugins/module_utils"))
    return load_module(
        ROOT / "plugins/module_utils/legacy_windows_certificate_acl.py",
        "tested_certificate_acl",
    )


@pytest.fixture(name="api")
def certificate_acl_api(helper: ModuleType, monkeypatch: pytest.MonkeyPatch) -> Any:
    """Supply observable native handles and DACL reads without a Windows host.

    :param helper: Loaded target helper.
    :param monkeypatch: Scoped DLL, platform and last-error replacements.
    :returns: Native API substitutes with configurable key ownership.
    """
    api = SimpleNamespace(
        crypt=Mock(),
        security=Mock(),
        cng=Mock(),
        owned=True,
        cng_key=False,
        control=0x9404,
        error=5,
        descriptor=b"descriptor",
        writes=[],
        dacl=ctypes.create_string_buffer(ACL),
    )
    api.crypt.CertOpenStore.return_value = 0x1234567800000001
    api.crypt.CertFindCertificateInStore.return_value = 0x1234567800000002
    api.crypt.CertFreeCertificateContext.return_value = True
    api.crypt.CertCloseStore.return_value = True
    api.security.CryptReleaseContext.return_value = True
    api.cng.NCryptFreeObject.return_value = 0
    api.security.IsValidSecurityDescriptor.return_value = True

    def _find(*args: Any) -> Any:
        api.digest = ctypes.string_at(args[4]._obj.data, 20)
        return api.crypt.CertFindCertificateInStore.return_value

    def _acquire(*args: Any) -> bool:
        args[3]._obj.value = 0x1234567800000003
        args[4]._obj.value = 0xFFFFFFFF if api.cng_key else 1
        args[5]._obj.value = api.owned
        return True

    def _capi_read(_key: Any, kind: int, buffer: Any, size: Any, flags: int) -> bool:
        assert kind == 8 and flags == 4
        size._obj.value = len(api.descriptor)
        if buffer is not None:
            ctypes.memmove(buffer, api.descriptor, len(api.descriptor))
        return True

    def _cng_read(*args: Any) -> int:
        assert args[1] == "Security Descr" and args[5] == 0x44
        args[4]._obj.value = len(api.descriptor)
        if args[2] is not None:
            ctypes.memmove(args[2], api.descriptor, len(api.descriptor))
        return 0

    def _control(_descriptor: Any, value: Any, revision: Any) -> bool:
        value._obj.value = api.control
        revision._obj.value = 1
        return True

    def _dacl(_descriptor: Any, present: Any, value: Any, defaulted: Any) -> bool:
        present._obj.value = 1
        defaulted._obj.value = 0
        value._obj.value = ctypes.addressof(api.dacl) if api.dacl is not None else None
        return True

    def _capi_write(key: Any, kind: int, buffer: Any, flags: int) -> bool:
        assert key.value == 0x1234567800000003 and kind == 8 and flags == 4
        api.writes.append(buffer.raw[:-1])
        return True

    def _cng_write(key: Any, name: str, buffer: Any, size: int, flags: int) -> int:
        assert key.value == 0x1234567800000003 and name == "Security Descr"
        assert flags == 0x44
        api.writes.append(ctypes.string_at(buffer, size))
        return 0

    api.crypt.CryptAcquireCertificatePrivateKey.side_effect = _acquire
    api.crypt.CertFindCertificateInStore.side_effect = _find
    api.security.CryptGetProvParam.side_effect = _capi_read
    api.cng.NCryptGetProperty.side_effect = _cng_read
    api.security.GetSecurityDescriptorControl.side_effect = _control
    api.security.GetSecurityDescriptorDacl.side_effect = _dacl
    api.security.CryptSetProvParam.side_effect = _capi_write
    api.cng.NCryptSetProperty.side_effect = _cng_write
    monkeypatch.setattr(helper, "_crypt32", lambda: api.crypt)
    monkeypatch.setattr(helper, "_advapi32", lambda: api.security)
    api.load_cng = Mock(return_value=api.cng)
    monkeypatch.setattr(helper, "_ncrypt", api.load_cng)
    monkeypatch.setattr(ctypes, "get_last_error", lambda: api.error, raising=False)

    def _format_error(code: int) -> str:
        # Python 3.4's Windows binding accepts a signed C long, not a DWORD.
        if not -2147483648 <= code <= 2147483647:
            raise OverflowError("Python int too large to convert to C long")
        return "native error " + str(code)

    monkeypatch.setattr(ctypes, "FormatError", _format_error, raising=False)
    monkeypatch.setattr(
        helper.sys, "getwindowsversion", lambda: SimpleNamespace(major=6), raising=False
    )
    return api


def test_lookup_uses_readonly_existing_store_and_never_acquires_key(
    helper: ModuleType,
    api: Any,
) -> None:
    target = helper.resolve_target(PATH)
    assert target == {"path": PATH, "kind": "certificate", "container": False}
    api.crypt.CertOpenStore.assert_called_once_with(10, 0, None, 0x1C000, "My")
    arguments = api.crypt.CertFindCertificateInStore.call_args.args
    assert arguments[1:4] == (0x10001, 0, 0x10000)
    assert api.digest == b"\x01" * 20
    api.crypt.CryptAcquireCertificatePrivateKey.assert_not_called()
    api.crypt.CertFreeCertificateContext.assert_called_once()
    api.crypt.CertCloseStore.assert_called_once()
    api.load_cng.assert_not_called()


@pytest.mark.parametrize("missing_store", [False, True])
@pytest.mark.parametrize("error", [0x80092004, -2146885628])
def test_missing_certificate_returns_none_and_closes_opened_store(
    helper: ModuleType,
    api: Any,
    missing_store: bool,
    error: int,
) -> None:
    api.error = error
    if missing_store:
        api.crypt.CertOpenStore.return_value = None
    else:
        api.crypt.CertFindCertificateInStore.return_value = None
    assert helper.resolve_target(PATH) is None
    assert api.crypt.CertCloseStore.call_count == (0 if missing_store else 1)
    api.crypt.CertFreeCertificateContext.assert_not_called()
    api.crypt.CryptAcquireCertificatePrivateKey.assert_not_called()


def test_access_denied_lookup_is_not_missing(helper: ModuleType, api: Any) -> None:
    api.crypt.CertFindCertificateInStore.return_value = None
    with pytest.raises(OSError, match="CertFindCertificateInStore"):
        helper.resolve_target(PATH)
    api.crypt.CertCloseStore.assert_called_once()


@pytest.mark.parametrize(
    "path", ["Cert:\\CurrentUser\\My", PATH + "00", PATH[:-1] + "z"]
)
def test_invalid_certificate_paths_do_not_open_stores(
    helper: ModuleType,
    api: Any,
    path: str,
) -> None:
    with pytest.raises(ValueError, match="Certificate ACL paths"):
        helper.resolve_target(path)
    api.crypt.CertOpenStore.assert_not_called()


@pytest.mark.parametrize("cng_key", [False, True])
@pytest.mark.parametrize("owned", [False, True])
def test_read_write_holds_key_and_preserves_dacl_control(
    helper: ModuleType,
    api: Any,
    cng_key: bool,
    owned: bool,
) -> None:
    api.cng_key, api.owned = cng_key, owned
    with helper.open_acl({"path": PATH}) as (snapshot, write):
        assert snapshot == {
            "protected": True,
            "dacl": ACL,
            "registry": False,
            "container": False,
            "kind": "certificate",
            "certificate_provider": "cng" if cng_key else "capi",
        }
        api.security.CryptReleaseContext.assert_not_called()
        api.cng.NCryptFreeObject.assert_not_called()
        api.crypt.CertFreeCertificateContext.assert_not_called()
        write(snapshot)
    assert api.writes == [struct.pack("<BBHIIII", 1, 0, 0x9404, 0, 0, 0, 20) + ACL]
    assert api.security.CryptReleaseContext.call_count == int(owned and not cng_key)
    assert api.cng.NCryptFreeObject.call_count == int(owned and cng_key)
    assert api.load_cng.call_count == int(cng_key)
    api.crypt.CertFreeCertificateContext.assert_called_once()
    api.crypt.CertCloseStore.assert_called_once()


def test_xp_uses_capi_without_cng_flags_or_loading(
    helper: ModuleType,
    api: Any,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(
        helper.sys, "getwindowsversion", lambda: SimpleNamespace(major=5)
    )
    with helper.open_acl({"path": PATH}):
        pass
    assert api.crypt.CryptAcquireCertificatePrivateKey.call_args.args[1] == 0x40
    api.load_cng.assert_not_called()


def test_newer_windows_allows_cng_but_does_not_load_it_for_capi(
    helper: ModuleType,
    api: Any,
) -> None:
    with helper.open_acl({"path": PATH}):
        pass
    assert api.crypt.CryptAcquireCertificatePrivateKey.call_args.args[1] == 0x10040
    api.load_cng.assert_not_called()


@pytest.mark.parametrize("cng_key", [False, True])
def test_write_failure_releases_owned_handles(
    helper: ModuleType,
    api: Any,
    cng_key: bool,
) -> None:
    api.cng_key = cng_key
    api.security.CryptSetProvParam.side_effect = None
    api.security.CryptSetProvParam.return_value = False
    api.cng.NCryptSetProperty.side_effect = None
    api.cng.NCryptSetProperty.return_value = -2146893785
    with pytest.raises(OSError, match="(CryptSetProvParam|NCryptSetProperty)"):
        with helper.open_acl({"path": PATH}) as (snapshot, write):
            write(snapshot)
    assert api.security.CryptReleaseContext.call_count == int(not cng_key)
    assert api.cng.NCryptFreeObject.call_count == int(cng_key)
    api.crypt.CertFreeCertificateContext.assert_called_once()
    api.crypt.CertCloseStore.assert_called_once()


def test_missing_private_key_closes_certificate_without_releasing_key(
    helper: ModuleType,
    api: Any,
) -> None:
    api.crypt.CryptAcquireCertificatePrivateKey.side_effect = None
    api.crypt.CryptAcquireCertificatePrivateKey.return_value = False
    with pytest.raises(OSError, match="CryptAcquireCertificatePrivateKey"):
        with helper.open_acl({"path": PATH}):
            pytest.fail("Acquisition failure must not yield a snapshot")
    api.security.CryptReleaseContext.assert_not_called()
    api.crypt.CertFreeCertificateContext.assert_called_once()
    api.crypt.CertCloseStore.assert_called_once()


def test_descriptor_failure_releases_key_and_certificates(
    helper: ModuleType,
    api: Any,
) -> None:
    api.security.IsValidSecurityDescriptor.return_value = False
    with pytest.raises(OSError, match="IsValidSecurityDescriptor"):
        with helper.open_acl({"path": PATH}):
            pytest.fail("Invalid descriptor must not yield a snapshot")
    api.security.CryptReleaseContext.assert_called_once()
    api.crypt.CertFreeCertificateContext.assert_called_once()
    api.crypt.CertCloseStore.assert_called_once()


def test_cleanup_failure_still_closes_certificate_store(
    helper: ModuleType,
    api: Any,
) -> None:
    api.security.CryptReleaseContext.return_value = False
    api.crypt.CertFreeCertificateContext.return_value = False
    with pytest.raises(OSError):
        with helper.open_acl({"path": PATH}):
            pass
    api.crypt.CertFreeCertificateContext.assert_called_once()
    api.crypt.CertCloseStore.assert_called_once()


def test_null_dacl_stays_distinct_from_empty_dacl(helper: ModuleType, api: Any) -> None:
    api.dacl = None
    with helper.open_acl({"path": PATH}) as (snapshot, write):
        assert snapshot["dacl"] is None
        write(snapshot)
    assert api.writes == [struct.pack("<BBHIIII", 1, 0, 0x9404, 0, 0, 0, 0)]


@pytest.mark.parametrize("cng_key", [False, True])
def test_writer_persists_changed_ace_bytes_without_owner_or_group(
    helper: ModuleType,
    api: Any,
    cng_key: bool,
) -> None:
    api.cng_key = cng_key
    everyone = b"\x01\x01\x00\x00\x00\x00\x00\x01\x00\x00\x00\x00"
    entry = struct.pack("<BBHI", 0, 0, 20, 0x80120089) + everyone
    changed_acl = struct.pack("<BBHHH", 2, 0, 28, 1, 0) + entry
    with helper.open_acl({"path": PATH}) as (snapshot, write):
        write(dict(snapshot, dacl=changed_acl))
        assert snapshot["dacl"] == ACL
    assert api.writes == [
        struct.pack("<BBHIIII", 1, 0, 0x9404, 0, 0, 0, 20) + changed_acl
    ]


def test_native_bindings_keep_handles_pointer_sized(
    helper: ModuleType,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    libraries = {name: Mock() for name in ("crypt32", "advapi32", "ncrypt")}
    monkeypatch.setattr(helper, "os", SimpleNamespace(name="nt"))
    monkeypatch.setattr(
        ctypes, "WinDLL", lambda name, **_kwargs: libraries[name], raising=False
    )
    crypt, security, cng = helper._crypt32(), helper._advapi32(), helper._ncrypt()
    assert crypt.CertOpenStore.restype is ctypes.c_void_p
    assert crypt.CertFindCertificateInStore.restype is ctypes.c_void_p
    assert security.CryptReleaseContext.argtypes[0] is ctypes.c_void_p
    assert cng.NCryptFreeObject.argtypes[0] is ctypes.c_void_p
    assert ctypes.sizeof(cng.NCryptGetProperty.restype) == 4
    assert ctypes.sizeof(crypt.CryptAcquireCertificatePrivateKey.argtypes[1]) == 4


def test_non_windows_native_load_fails_clearly(helper: ModuleType) -> None:
    with pytest.raises(ValueError, match="requires Windows"):
        helper._crypt32()
