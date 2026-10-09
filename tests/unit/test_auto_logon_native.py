"""Exercise LSA resource ownership and Winlogon registry operations off-target."""

# SPDX-License-Identifier: GPL-3.0-or-later
# Native tests inspect ABI records and ownership boundaries directly.
# pylint: disable=protected-access

import ctypes
from types import ModuleType, SimpleNamespace
from typing import Any
from unittest.mock import MagicMock, Mock

import pytest

from tests.unit.payload_support import ROOT, load_module


@pytest.fixture(name="helper")
def native_helper(monkeypatch: pytest.MonkeyPatch) -> ModuleType:
    """Import the helper without calling Windows APIs.

    :param monkeypatch: Scoped adjacent-helper import path.
    :returns: Imported helper.
    """
    monkeypatch.syspath_prepend(str(ROOT / "plugins/module_utils"))
    return load_module(
        ROOT / "plugins/module_utils/legacy_windows_auto_logon.py",
        "tested_auto_logon_native",
    )


@pytest.fixture(name="lsa")
def lsa_boundaries(helper: ModuleType, monkeypatch: pytest.MonkeyPatch) -> Any:
    """Keep native output records alive and record allocated-handle cleanup.

    :param helper: Loaded native helper.
    :param monkeypatch: Scoped native library substitute.
    :returns: Configurable LSA boundary.
    """
    library = Mock()
    library.LsaNtStatusToWinError.return_value = 5
    library.LsaStorePrivateData.return_value = 0
    state = SimpleNamespace(library=library, password="Original", status=0, buffers=[])

    def _open(unused_system: Any, attributes: Any, access: int, output: Any) -> int:
        assert attributes._obj.length == 0 and access == 0x24
        output._obj.value = 123
        return 0

    def _read(handle: Any, key: Any, output: Any) -> int:
        assert handle.value == 123
        assert (
            ctypes.string_at(key._obj.buffer, key._obj.length).decode("utf-16-le")
            == "DefaultPassword"
        )
        if state.password is not None:
            record = helper._string(state.password)
            state.buffers.append(record)
            output._obj.value = ctypes.addressof(record)
        return int(state.status)

    library.LsaOpenPolicy.side_effect = _open
    library.LsaRetrievePrivateData.side_effect = _read
    monkeypatch.setattr(helper, "_lsa", lambda: library)
    monkeypatch.setattr(
        helper.ctypes,
        "FormatError",
        lambda code: "Access is denied.\r\n",
        raising=False,
    )
    return state


@pytest.mark.parametrize("password", ["", "ordinary", "雪😀", "prefix\0suffix"])
def test_counted_secrets_preserve_unicode_nuls_and_free_memory(
    helper: ModuleType, lsa: Any, password: str
) -> None:
    lsa.password = password
    with helper.SecretStore() as secret:
        assert secret.read() == password
        assert lsa.library.LsaFreeMemory.call_count == 1
    assert lsa.library.LsaClose.call_args.args[0].value == 123


def test_absent_secret_and_absent_deletion_are_idempotent(
    helper: ModuleType, lsa: Any
) -> None:
    lsa.password, lsa.status = None, 0xC0000034
    lsa.library.LsaStorePrivateData.return_value = 0xC0000034
    with helper.SecretStore() as secret:
        assert secret.read() is None
        secret.write(None)
    lsa.library.LsaFreeMemory.assert_not_called()
    assert lsa.library.LsaStorePrivateData.call_args.args[2] is None


@pytest.mark.parametrize("password", [None, "", "a\0雪😀"])
def test_writer_distinguishes_null_and_empty_without_returning_secret(
    helper: ModuleType, lsa: Any, password: str | None
) -> None:
    def _write(handle: Any, key: Any, value: Any) -> int:
        assert handle.value == 123 and key._obj.length == 30
        if password is None:
            assert value is None
        else:
            assert (
                ctypes.string_at(value._obj.buffer, value._obj.length).decode(
                    "utf-16-le"
                )
                == password
            )
        return 0

    lsa.library.LsaStorePrivateData.side_effect = _write
    with helper.SecretStore() as secret:
        assert secret.write(password) is None
    lsa.library.LsaFreeMemory.assert_not_called()


def test_read_failure_frees_partial_buffer_closes_policy_and_allows_retry(
    helper: ModuleType, lsa: Any
) -> None:
    lsa.status = 0xC0000022
    with pytest.raises(OSError, match="LsaRetrievePrivateData.*Win32 Error Code 5"):
        with helper.SecretStore() as secret:
            secret.read()
    assert lsa.library.LsaFreeMemory.call_count == lsa.library.LsaClose.call_count == 1
    lsa.status = 0
    with helper.SecretStore() as secret:
        assert secret.read() == "Original"


def test_store_failure_closes_policy_without_exposing_password(
    helper: ModuleType, lsa: Any
) -> None:
    lsa.library.LsaStorePrivateData.return_value = 0xC0000022
    with pytest.raises(OSError) as raised:
        with helper.SecretStore() as secret:
            secret.write("Do-Not-Expose")
    assert "Do-Not-Expose" not in str(raised.value)
    assert lsa.library.LsaClose.call_count == 1


def test_failed_policy_open_closes_partial_handle(helper: ModuleType, lsa: Any) -> None:
    def _fail(
        unused_system: Any, unused_attributes: Any, unused_access: int, output: Any
    ) -> int:
        output._obj.value = 123
        return 0xC0000022

    lsa.library.LsaOpenPolicy.side_effect = _fail
    with pytest.raises(OSError, match="LsaOpenPolicy"):
        with helper.SecretStore():
            pytest.fail("Failed policy open must not enter the context")
    lsa.library.LsaClose.assert_called_once()


def test_account_round_trip_uses_name_only_translation(
    helper: ModuleType, monkeypatch: pytest.MonkeyPatch
) -> None:
    account = SimpleNamespace(
        account_name_to_sid=Mock(return_value="SID"),
        sid_to_name=Mock(return_value="DOMAIN\\Canonical"),
    )
    monkeypatch.setattr(helper, "accounts", account)
    assert helper.resolve_account("supplied") == ("DOMAIN", "Canonical")
    account.account_name_to_sid.assert_called_once_with("supplied")
    account.sid_to_name.assert_called_once_with("SID")


def test_unmapped_account_has_actionable_failure(
    helper: ModuleType, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(
        helper.accounts,
        "account_name_to_sid",
        Mock(side_effect=OSError(1332, "unmapped")),
    )
    with pytest.raises(
        ValueError,
        match="Failed to find a local or domain user with the name 'missing'",
    ):
        helper.resolve_account("missing")


def test_registry_uses_native_view_preserves_absence_and_signed_dwords(
    helper: ModuleType, monkeypatch: pytest.MonkeyPatch
) -> None:
    registry = SimpleNamespace(
        HKEY_LOCAL_MACHINE=1,
        KEY_WOW64_64KEY=256,
        REG_DWORD=4,
        REG_SZ=1,
        REG_EXPAND_SZ=2,
        OpenKey=MagicMock(),
        QueryValueEx=Mock(),
        SetValueEx=Mock(),
        DeleteValue=Mock(),
        ExpandEnvironmentStrings=Mock(return_value="Expanded"),
    )
    registry.QueryValueEx.side_effect = [
        (1, 4),
        ("%VAR%", 2),
        OSError(2, "absent"),
        (0xFFFFFFFF, 4),
        OSError(2, "absent"),
    ]
    monkeypatch.setattr(helper, "winreg", registry)
    assert helper.read_values() == {
        "AutoAdminLogon": 1,
        "DefaultUserName": "Expanded",
        "AutoLogonCount": -1,
    }
    assert registry.OpenKey.call_args.args[-1] == 257
    registry.QueryValueEx.side_effect = [(0xFFFFFFFF, 4)]
    helper.write_value("AutoLogonCount", -1)
    key = registry.OpenKey.return_value.__enter__.return_value
    registry.SetValueEx.assert_called_once_with(key, "AutoLogonCount", 0, 4, 0xFFFFFFFF)
    assert registry.OpenKey.call_args.args[-1] == 259
    helper.delete_value("DefaultPassword")
    registry.DeleteValue.assert_called_once_with(key, "DefaultPassword")


@pytest.mark.parametrize(
    "name,previous,requested_and_expected",
    [
        ("AutoLogonCount", ("2", 1), (3, 1, "3")),
        ("AutoLogonCount", ("2", 2), (3, 2, "3")),
        ("AutoLogonCount", (2, 4), (3, 4, 3)),
        ("AutoLogonCount", OSError(2, "absent"), (-1, 4, 0xFFFFFFFF)),
        ("DefaultUserName", OSError(2, "absent"), ("User", 1, "User")),
        ("AutoAdminLogon", ("0", 1), (1, 4, 1)),
    ],
)
def test_writes_preserve_inferred_kind_but_activation_is_explicit_dword(
    helper: ModuleType,
    monkeypatch: pytest.MonkeyPatch,
    name: str,
    previous: Any,
    requested_and_expected: tuple[Any, int, Any],
) -> None:
    value, kind, stored = requested_and_expected
    registry = SimpleNamespace(
        HKEY_LOCAL_MACHINE=1,
        KEY_WOW64_64KEY=256,
        REG_DWORD=4,
        REG_SZ=1,
        REG_EXPAND_SZ=2,
        OpenKey=MagicMock(),
        QueryValueEx=Mock(side_effect=[previous]),
        SetValueEx=Mock(),
    )
    monkeypatch.setattr(helper, "winreg", registry)
    helper.write_value(name, value)
    key = registry.OpenKey.return_value.__enter__.return_value
    registry.SetValueEx.assert_called_once_with(key, name, 0, kind, stored)
    if name == "AutoAdminLogon":
        registry.QueryValueEx.assert_not_called()
    else:
        registry.QueryValueEx.assert_called_once_with(key, name)


def test_registry_type_read_failure_does_not_overwrite_existing_value(
    helper: ModuleType, monkeypatch: pytest.MonkeyPatch
) -> None:
    registry = SimpleNamespace(
        HKEY_LOCAL_MACHINE=1,
        KEY_WOW64_64KEY=256,
        REG_DWORD=4,
        REG_SZ=1,
        OpenKey=MagicMock(),
        QueryValueEx=Mock(side_effect=OSError(5, "denied")),
        SetValueEx=Mock(),
    )
    monkeypatch.setattr(helper, "winreg", registry)
    with pytest.raises(OSError, match="denied"):
        helper.write_value("AutoLogonCount", 3)
    registry.SetValueEx.assert_not_called()


def test_native_layout_and_library_signatures(
    helper: ModuleType, monkeypatch: pytest.MonkeyPatch
) -> None:
    width = ctypes.sizeof(ctypes.c_void_p)
    assert helper._UnicodeString.buffer.offset == width
    assert ctypes.sizeof(helper._UnicodeString) == width * 2
    assert ctypes.sizeof(helper._ObjectAttributes) == width * 6
    library = Mock()
    monkeypatch.setattr(helper, "os", SimpleNamespace(name="nt"))
    loader = Mock(return_value=library)
    monkeypatch.setattr(helper.ctypes, "WinDLL", loader, raising=False)
    assert helper._lsa() is library
    loader.assert_called_once_with("advapi32")
    assert library.LsaOpenPolicy.argtypes[-1] == ctypes.POINTER(ctypes.c_void_p)
    assert library.LsaStorePrivateData.restype is ctypes.c_uint32


def test_non_windows_rejected_before_library_load(
    helper: ModuleType, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(helper, "os", SimpleNamespace(name="posix"))
    with pytest.raises(OSError, match="require a Windows target"):
        helper._lsa()
