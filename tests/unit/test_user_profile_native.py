"""Exercise Userenv buffer contracts, registry reads and native failures."""

# SPDX-License-Identifier: GPL-3.0-or-later
# Native substitutes fill ctypes by-reference output buffers; inspecting those
# backing objects here keeps the production ABI unchanged.
# pylint: disable=protected-access

import ctypes
from types import SimpleNamespace
from typing import Any
from unittest.mock import Mock

import pytest

from tests.unit.payload_support import ROOT, load_module


@pytest.fixture(name="provider")
def profile_provider(monkeypatch: pytest.MonkeyPatch) -> Any:
    """Supply observable Userenv calls with real ctypes output buffers.

    :param monkeypatch: Scoped native-library replacement.
    :returns: Helper and substitutable library calls.
    """
    module = load_module(
        ROOT / "legacy_windows/plugins/module_utils/legacy_windows_user_profile.py",
        "tested_profiles",
    )

    def _directory(output: Any, size: Any) -> int:
        size._obj.value = len(r"C:\Users") + 1
        if output is None:
            return 0
        output.value = r"C:\Users"
        return 1

    def _create(_sid: str, _name: str, output: Any, capacity: int) -> int:
        assert capacity == 260
        output.value = r"C:\Users\fixture.000"
        return 0

    library = SimpleNamespace(
        GetProfilesDirectoryW=Mock(side_effect=_directory),
        CreateProfile=Mock(side_effect=_create),
        DeleteProfileW=Mock(return_value=1),
    )
    monkeypatch.setattr(module, "_library", lambda: library)
    monkeypatch.setattr(module.ctypes, "get_last_error", lambda: 5, raising=False)
    monkeypatch.setattr(
        module.ctypes, "WinError", lambda code: OSError(code, "denied"), raising=False
    )
    monkeypatch.setattr(
        module.ctypes,
        "FormatError",
        lambda _code: "Access is denied.\r\n",
        raising=False,
    )
    return SimpleNamespace(module=module, library=library)


def test_directory_uses_native_sizing_and_retains_the_full_path(provider: Any) -> None:
    assert provider.module.profiles_directory() == r"C:\Users"
    assert provider.library.GetProfilesDirectoryW.call_count == 2


def test_directory_failure_raises_native_error(provider: Any) -> None:
    provider.library.GetProfilesDirectoryW.side_effect = [0, 0]
    with pytest.raises(OSError) as error:
        provider.module.profiles_directory()
    assert error.value.errno == 5


def test_create_uses_fixed_reference_buffer_and_native_collision_result(
    provider: Any,
) -> None:
    assert (
        provider.module.create_profile("S-1-5-21-1", "fixture")
        == r"C:\Users\fixture.000"
    )
    assert provider.library.CreateProfile.restype is ctypes.c_int32
    assert provider.library.CreateProfile.call_args.args[:2] == (
        "S-1-5-21-1",
        "fixture",
    )


def test_absent_create_entrypoint_is_lazy_and_does_not_block_deletion(
    provider: Any,
) -> None:
    del provider.library.CreateProfile
    with pytest.raises(ValueError, match="creation API is unavailable"):
        provider.module.create_profile("S-1-5-21-1", "fixture")
    provider.module.delete_profile("S-1-5-21-1")
    provider.library.DeleteProfileW.assert_called_once_with("S-1-5-21-1", None, None)


def test_failed_creation_retains_signed_hresult(provider: Any) -> None:
    provider.library.CreateProfile.side_effect = None
    provider.library.CreateProfile.return_value = -2147024891
    with pytest.raises(OSError) as error:
        provider.module.create_profile("S-1-5-21-1", "fixture")
    assert getattr(error.value, "hresult") == -2147024891
    assert "0x80070005" in str(error.value)


@pytest.mark.parametrize(
    "status,native,expected",
    [
        (
            -2147024891,
            "Access is denied.",
            "Access is denied. (Exception from HRESULT: 0x80070005 (E_ACCESSDENIED))",
        ),
        (-2147024809, "not used", "Value does not fall within the expected range."),
        (
            -2147467259,
            "not used",
            "Error HRESULT E_FAIL has been returned from a call to a COM component.",
        ),
        (
            -2147024773,
            "The filename, directory name, or volume label syntax is incorrect.",
            "The filename, directory name, or volume label syntax is incorrect. "
            "(Exception from HRESULT: 0x8007007B)",
        ),
        (
            -2147024713,
            "Cannot create a file when that file already exists.",
            "Cannot create a file when that file already exists. "
            "(Exception from HRESULT: 0x800700B7)",
        ),
        (
            -2147024888,
            "Not enough memory resources are available to process this command.",
            "Not enough memory resources are available to process this command. "
            "(Exception from HRESULT: 0x80070008)",
        ),
    ],
)
def test_creation_error_matches_retained_original_runtime_messages(
    provider: Any,
    monkeypatch: pytest.MonkeyPatch,
    status: int,
    native: str,
    expected: str,
) -> None:
    monkeypatch.setattr(
        provider.module.ctypes, "FormatError", lambda _code: native + "\r\n"
    )
    provider.library.CreateProfile.side_effect = None
    provider.library.CreateProfile.return_value = status
    with pytest.raises(OSError) as error:
        provider.module.create_profile("S-1-5-21-1", "fixture")
    assert str(error.value) == expected
    assert getattr(error.value, "hresult") == status


def test_failed_deletion_retains_native_error(provider: Any) -> None:
    provider.library.DeleteProfileW.return_value = 0
    with pytest.raises(OSError) as error:
        provider.module.delete_profile("S-1-5-21-1")
    assert error.value.errno == 5


def test_registry_enumeration_closes_keys_and_expands_only_expandable_paths(
    provider: Any, monkeypatch: pytest.MonkeyPatch
) -> None:
    root, first, second = Mock(), Mock(), Mock()
    for key in (root, first, second):
        key.__enter__ = Mock(return_value=key)
        key.__exit__ = Mock(return_value=False)
    registry = SimpleNamespace(
        HKEY_LOCAL_MACHINE=17,
        REG_EXPAND_SZ=2,
        OpenKey=Mock(side_effect=[root, first, second]),
        QueryInfoKey=Mock(return_value=(2, 0, 0)),
        EnumKey=Mock(side_effect=["second", "first"]),
        QueryValueEx=Mock(side_effect=[(r"%ROOT%\second", 2), (r"%ROOT%\first", 1)]),
        ExpandEnvironmentStrings=Mock(return_value=r"C:\Users\second"),
    )
    monkeypatch.setattr(provider.module, "winreg", registry)
    assert provider.module.profile_sids() == ["second", "first"]
    registry.QueryValueEx.assert_not_called()
    assert provider.module.profile_path("second") == r"C:\Users\second"
    assert provider.module.profile_path("first") == r"%ROOT%\first"
    registry.ExpandEnvironmentStrings.assert_called_once_with(r"%ROOT%\second")
    assert all(key.__exit__.call_count == 1 for key in (root, first, second))
