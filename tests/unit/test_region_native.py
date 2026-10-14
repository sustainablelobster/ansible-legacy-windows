"""Test native regional settings, registry copying, and failed-operation cleanup."""

# SPDX-License-Identifier: GPL-3.0-or-later

import ctypes
from types import ModuleType, SimpleNamespace
from typing import Any
from unittest.mock import MagicMock, Mock, call

import pytest

from tests.unit.payload_support import ROOT, load_module, native_error


@pytest.fixture(name="helper")
def region_helper(monkeypatch: pytest.MonkeyPatch) -> ModuleType:
    """Import the native helper without invoking any Windows operation.

    :param monkeypatch: Scoped helper imports and portable WinError substitute.
    :returns: Imported regional helper.
    """
    monkeypatch.syspath_prepend(str(ROOT / "legacy_windows/plugins/module_utils"))
    module = load_module(
        ROOT / "legacy_windows/plugins/module_utils/legacy_windows_region.py",
        "tested_region_native",
    )
    monkeypatch.setattr(
        module, "values_equal", lambda left, right: left.lower() == right.lower()
    )
    monkeypatch.setattr(ctypes, "WinError", native_error, raising=False)
    monkeypatch.setattr(ctypes, "get_last_error", lambda: 5, raising=False)
    monkeypatch.setattr(
        ctypes, "FormatError", lambda code: "native failure", raising=False
    )
    return module


@pytest.fixture(name="registry")
def region_registry(helper: ModuleType, monkeypatch: pytest.MonkeyPatch) -> Any:
    """Record registry requests while controlling existing International values.

    :param helper: Imported native helper.
    :param monkeypatch: Scoped standard-library registry substitute.
    :returns: Mock registry and a caller-owned key context.
    """
    api = Mock(
        HKEY_CURRENT_USER=1,
        HKEY_LOCAL_MACHINE=2,
        HKEY_USERS=3,
        KEY_READ=0x20019,
        KEY_WRITE=0x20006,
        KEY_SET_VALUE=2,
        REG_SZ=1,
        REG_BINARY=3,
        REG_DWORD=4,
        REG_MULTI_SZ=7,
    )
    key = MagicMock()
    key.__enter__.return_value = key
    api.OpenKey.return_value = key
    api.CreateKeyEx.return_value = key
    monkeypatch.setattr(helper, "winreg", api)
    return SimpleNamespace(api=api, key=key)


def test_modern_location_check_and_repeat_never_call_setter(
    helper: ModuleType,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    kernel = Mock()
    kernel.GetUserGeoID.return_value = 244
    monkeypatch.setattr(helper, "_kernel", lambda: kernel)
    assert helper.change_location("12", True)
    kernel.SetUserGeoID.assert_not_called()
    assert not helper.change_location("244", False)
    kernel.SetUserGeoID.assert_not_called()
    kernel.SetUserGeoID.return_value = True
    assert helper.change_location("12", False)
    kernel.SetUserGeoID.assert_called_once_with(12)


def test_modern_location_denial_is_reported_as_native_error(
    helper: ModuleType,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    kernel = Mock()
    kernel.GetUserGeoID.return_value = 244
    kernel.SetUserGeoID.return_value = False
    monkeypatch.setattr(helper, "_kernel", lambda: kernel)
    with pytest.raises(OSError) as raised:
        helper.change_location("12")
    assert raised.value.errno == 5


def test_legacy_location_preserves_string_spelling_and_check_mode(
    helper: ModuleType,
    registry: Any,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(helper, "_kernel", SimpleNamespace)
    registry.api.QueryValueEx.return_value = ("244", 1)
    assert helper.change_location("12", True)
    registry.api.SetValueEx.assert_not_called()
    assert registry.api.OpenKey.call_args.args[-1] == registry.api.KEY_READ
    assert helper.change_location("012", False)
    registry.api.SetValueEx.assert_called_once_with(registry.key, "Nation", 0, 1, "012")


def test_format_uses_existing_names_types_and_clears_unknown_values(
    helper: ModuleType,
    registry: Any,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(helper, "_culture", lambda name: 2057)
    monkeypatch.setattr(helper, "_kernel", Mock())
    info = Mock(side_effect=lambda name, kind: f"value-{kind:x}")
    monkeypatch.setattr(helper, "_info", info)
    values = [
        ("Locale", "00000409", 1),
        ("LocaleName", "en-US", 1),
        ("sShortTime", "h:mm tt", 1),
        ("UnknownSetting", "keep?", 1),
        ("DefaultBlindDialFlag", b"\0", 3),
        ("UnknownDword", 5, 4),
        ("UnknownMulti", ["before"], 7),
    ]
    registry.api.QueryInfoKey.return_value = (0, len(values), 0)
    registry.api.EnumValue.side_effect = lambda unused, index: values[index]
    helper.change_format("en-GB", True)
    registry.api.SetValueEx.assert_not_called()
    assert registry.api.OpenKey.call_args.args[-1] == registry.api.KEY_READ
    helper.change_format("en-GB", False)
    assert registry.api.SetValueEx.call_args_list == [
        call(registry.key, "Locale", 0, 1, "00000809"),
        call(registry.key, "LocaleName", 0, 1, "en-GB"),
        call(registry.key, "sShortTime", 0, 1, "value-79"),
        call(registry.key, "UnknownSetting", 0, 1, ""),
        call(registry.key, "DefaultBlindDialFlag", 0, 3, b""),
        call(registry.key, "UnknownDword", 0, 4, 0),
        call(registry.key, "UnknownMulti", 0, 7, []),
    ]
    assert call("en-GB", 0x79) in info.call_args_list


def test_format_does_not_create_missing_registry_values(
    helper: ModuleType,
    registry: Any,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(helper, "_culture", lambda name: 2057)
    monkeypatch.setattr(helper, "_kernel", SimpleNamespace)
    info = Mock(return_value="new")
    monkeypatch.setattr(helper, "_info", info)
    registry.api.QueryInfoKey.return_value = (0, 1, 0)
    registry.api.EnumValue.return_value = ("sDate", "old", 1)
    helper.change_format("en-GB")
    registry.api.SetValueEx.assert_called_once_with(registry.key, "sDate", 0, 1, "new")
    assert call(2057, 0x79) not in info.call_args_list


@pytest.mark.parametrize("check_mode", [False, True])
@pytest.mark.parametrize("previous", [bytes(range(1, 9)), b"\0" * 8])
def test_unknown_qword_uses_fixed_width_zero_bytes_without_a_modern_constant(
    helper: ModuleType,
    registry: Any,
    monkeypatch: pytest.MonkeyPatch,
    check_mode: bool,
    previous: bytes,
) -> None:
    del registry.api.REG_QWORD
    monkeypatch.setattr(helper, "_culture", lambda name: 2057)
    monkeypatch.setattr(helper, "_kernel", SimpleNamespace)
    monkeypatch.setattr(helper, "_info", Mock(return_value="new"))
    registry.api.QueryInfoKey.return_value = (0, 1, 0)
    registry.api.EnumValue.return_value = ("LegacyRegionQword", previous, 11)
    helper.change_format("en-GB", check_mode)
    if check_mode or previous == b"\0" * 8:
        registry.api.SetValueEx.assert_not_called()
    else:
        registry.api.SetValueEx.assert_called_once_with(
            registry.key, "LegacyRegionQword", 0, 11, b"\0" * 8
        )


@pytest.mark.parametrize("check_mode", [False, True])
def test_modern_system_locale_uses_the_original_native_entry_point_and_flags(
    helper: ModuleType,
    monkeypatch: pytest.MonkeyPatch,
    check_mode: bool,
) -> None:
    kernel, library = Mock(), Mock()
    monkeypatch.setattr(helper, "_kernel", lambda: kernel)
    monkeypatch.setattr(helper, "_locale_name", Mock(return_value="en-US"))
    monkeypatch.setattr(helper, "cultures", Mock(return_value={"en-GB": 2057}))
    loader = Mock(return_value=library)
    monkeypatch.setattr(ctypes, "WinDLL", loader, raising=False)
    assert helper.change_system_locale("EN-gb", check_mode)
    if check_mode:
        loader.assert_not_called()
        library.IntlUpdateSystemLocale.assert_not_called()
    else:
        loader.assert_called_once_with("intl.cpl", use_last_error=True)
        library.IntlUpdateSystemLocale.assert_called_once_with("en-GB", 2)
        assert library.IntlUpdateSystemLocale.argtypes == [
            ctypes.c_wchar_p,
            ctypes.c_int32,
        ]
        assert library.IntlUpdateSystemLocale.restype is ctypes.c_int32


def test_modern_system_locale_repeat_compares_the_active_not_pending_locale(
    helper: ModuleType,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(helper, "_kernel", Mock())
    monkeypatch.setattr(helper, "_locale_name", Mock(return_value="en-GB"))
    loader = Mock()
    monkeypatch.setattr(ctypes, "WinDLL", loader, raising=False)
    assert not helper.change_system_locale("EN-gb", False)
    loader.assert_not_called()


def test_modern_system_locale_preserves_the_original_ignored_return_value(
    helper: ModuleType,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(helper, "_kernel", Mock())
    monkeypatch.setattr(helper, "_locale_name", Mock(return_value="en-US"))
    monkeypatch.setattr(helper, "cultures", Mock(return_value={"en-GB": 2057}))
    library = Mock()
    library.IntlUpdateSystemLocale.return_value = -2147024891
    monkeypatch.setattr(ctypes, "WinDLL", Mock(return_value=library), raising=False)
    assert helper.change_system_locale("en-GB")
    library.IntlUpdateSystemLocale.assert_called_once_with("en-GB", 2)


def test_legacy_system_locale_sets_only_differing_values_and_named_default(
    helper: ModuleType,
    registry: Any,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(helper, "_kernel", SimpleNamespace)
    monkeypatch.setattr(helper, "_culture", lambda name: 2057)
    codepages = {0x1004: "1252", 0x0B: "850", 0x1011: "10000"}
    monkeypatch.setattr(helper, "_info", lambda locale, kind: codepages[kind])
    values = {
        "Default": "0409",
        "(Default)": "00000409",
        "ACP": "1252",
        "OEMCP": "437",
        "MACCP": "10000",
    }
    registry.api.QueryValueEx.side_effect = lambda key, name: (values[name], 1)
    assert helper.change_system_locale("en-GB", True)
    registry.api.SetValueEx.assert_not_called()
    assert all(
        request.args[-1] == registry.api.KEY_READ
        for request in registry.api.OpenKey.call_args_list
    )
    assert helper.change_system_locale("en-GB", False)
    assert registry.api.SetValueEx.call_args_list == [
        call(registry.key, "Default", 0, 1, "0809"),
        call(registry.key, "(Default)", 0, 1, "00000809"),
        call(registry.key, "OEMCP", 0, 1, "850"),
    ]


def test_profile_copy_unloads_hive_on_failure_without_changing_privileges(
    helper: ModuleType,
    registry: Any,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    registry.api.OpenKey.side_effect = FileNotFoundError()
    copying = Mock(side_effect=OSError("copy denied"))
    monkeypatch.setattr(helper, "_copy_key", copying)
    unloading = Mock()
    monkeypatch.setattr(helper, "_unload_hive", unloading)
    with pytest.raises(OSError, match="copy denied"):
        helper.copy_user_settings()
    registry.api.LoadKey.assert_called_once_with(
        3, "ANSIBLE", r"C:\Users\Default\NTUSER.DAT"
    )
    unloading.assert_called_once_with()
    assert "ownership_privileges" not in vars(helper)


def test_failed_hive_load_does_not_unload_an_unloaded_hive(
    helper: ModuleType,
    registry: Any,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    registry.api.OpenKey.side_effect = FileNotFoundError()
    registry.api.LoadKey.side_effect = native_error(1314)
    copying = Mock()
    monkeypatch.setattr(helper, "_copy_key", copying)
    unloading = Mock()
    monkeypatch.setattr(helper, "_unload_hive", unloading)
    with pytest.raises(helper.HiveLoadError, match="Win32ErrorCode 1314"):
        helper.copy_user_settings()
    copying.assert_not_called()
    unloading.assert_not_called()


def test_profile_copy_targets_all_source_trees_and_unloads_after_success(
    helper: ModuleType,
    registry: Any,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    registry.api.OpenKey.side_effect = FileNotFoundError()
    copying = Mock()
    monkeypatch.setattr(helper, "_copy_key", copying)
    unloading = Mock()
    monkeypatch.setattr(helper, "_unload_hive", unloading)
    assert helper.copy_user_settings() == []
    expected = [
        call(path, sid + "\\" + path)
        for sid in ("ANSIBLE", ".DEFAULT", "S-1-5-19", "S-1-5-20")
        for path in (
            r"Keyboard Layout",
            r"Control Panel\International",
            r"Control Panel\Input Method",
        )
    ]
    assert copying.call_args_list == expected
    unloading.assert_called_once_with()
