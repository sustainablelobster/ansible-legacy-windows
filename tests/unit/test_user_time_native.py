"""Check account-expiration storage against saved Windows conversion results."""

# SPDX-License-Identifier: GPL-3.0-or-later
# Native substitutions do not establish execution support on Windows.
# pylint: disable=protected-access

import ctypes
import json
from datetime import datetime
from types import ModuleType, SimpleNamespace
from typing import Any
from unittest.mock import Mock

import pytest

from tests.unit.payload_support import ROOT, load_module, native_error

REFERENCE = json.loads(
    (ROOT / "tests/fixtures/user_expiration_storage.json").read_text(encoding="utf-8")
)
STORAGE = {case["input"]: case for case in REFERENCE["storage"]}
NATIVE_CASES = [
    (case, conversion)
    for case in REFERENCE["native"]
    for conversion in case["conversions"]
]
SECOND = 10000000
FILETIME_EPOCH = 504911232000000000
UNIX_FILETIME = 116444736000000000
MAX_TICKS = 3155378975999999999
NEVER = 0xFFFFFFFF


def _ticks(value: str) -> int:
    date = datetime.fromisoformat(value)
    return (
        (date.toordinal() - 1) * 86400 * SECOND
        + (date.hour * 3600 + date.minute * 60 + date.second) * SECOND
        + date.microsecond * 10
    )


def _filetime(helper: ModuleType, pointer: Any) -> int:
    value = ctypes.cast(pointer, ctypes.POINTER(helper._FileTime)).contents
    return int((value.high << 32) | value.low)


def _set_filetime(helper: ModuleType, pointer: Any, ticks: int) -> None:
    value = ctypes.cast(pointer, ctypes.POINTER(helper._FileTime)).contents
    value.low = ticks & 0xFFFFFFFF
    value.high = ticks >> 32


@pytest.fixture(name="helper")
def time_helper() -> ModuleType:
    """Import the target helper without using a Windows runtime.

    :returns: Fresh module loaded by the developer interpreter.
    """
    return load_module(
        ROOT / "legacy_windows/plugins/module_utils/legacy_windows_user_time.py",
        "tested_user_time",
    )


@pytest.fixture(name="libraries")
def native_libraries(
    helper: ModuleType, monkeypatch: pytest.MonkeyPatch
) -> SimpleNamespace:
    """Replace native libraries while retaining their configured ctypes signatures.

    :param helper: Imported target helper.
    :param monkeypatch: Scoped replacements of Windows-only ctypes facilities.
    :returns: Kernel and Automation substitutes plus their loader.
    """
    libraries = SimpleNamespace(kernel=Mock(), automation=Mock(), loader=Mock())
    libraries.loader.side_effect = {
        "kernel32": libraries.kernel,
        "oleaut32": libraries.automation,
    }.__getitem__

    def _load(name: str, *, use_last_error: bool) -> Mock:
        assert use_last_error
        library = libraries.loader(name)
        assert isinstance(library, Mock)
        return library

    monkeypatch.setattr(helper, "os", SimpleNamespace(name="nt"))
    monkeypatch.setattr(helper.ctypes, "WinDLL", _load, raising=False)
    monkeypatch.setattr(
        helper.ctypes, "get_last_error", Mock(return_value=87), raising=False
    )
    monkeypatch.setattr(helper.ctypes, "WinError", native_error, raising=False)
    return libraries


def _recorded_conversion(
    helper: ModuleType,
    libraries: SimpleNamespace,
    case: dict[str, Any],
    conversion: dict[str, Any] | None,
) -> None:
    def _variant(value: float, pointer: Any) -> int:
        assert value == STORAGE[case["input"]]["ole_date"]
        system = ctypes.cast(pointer, ctypes.POINTER(helper._SystemTime)).contents
        for field, expected in case["system"].items():
            setattr(system, field, expected)
        return 1

    def _system(source: Any, destination: Any) -> int:
        system = ctypes.cast(source, ctypes.POINTER(helper._SystemTime)).contents
        assert {field: getattr(system, field) for field in case["system"]} == case[
            "system"
        ]
        if not case["filetime_success"]:
            return 0
        assert conversion is not None
        local_seconds = conversion["seconds"] + conversion["offset_minutes"] * 60
        _set_filetime(helper, destination, UNIX_FILETIME + local_seconds * SECOND)
        return 1

    def _local(source: Any, destination: Any) -> int:
        assert conversion is not None
        local_seconds = conversion["seconds"] + conversion["offset_minutes"] * 60
        assert _filetime(helper, source) == UNIX_FILETIME + local_seconds * SECOND
        _set_filetime(
            helper, destination, UNIX_FILETIME + conversion["seconds"] * SECOND
        )
        return 1

    libraries.automation.VariantTimeToSystemTime.side_effect = _variant
    libraries.kernel.SystemTimeToFileTime.side_effect = _system
    libraries.kernel.LocalFileTimeToFileTime.side_effect = _local


@pytest.mark.parametrize("case", REFERENCE["storage"], ids=lambda case: case["input"])
def test_automation_date_matches_reference(helper: ModuleType, case: Any) -> None:
    if "ole_date" not in case:
        with pytest.raises(ValueError, match="Not a legal OleAut date"):
            helper._ole_date(case["local_ticks"])
    else:
        assert helper._ole_date(case["local_ticks"]) == case["ole_date"]


@pytest.mark.parametrize(("case", "conversion"), NATIVE_CASES)
def test_native_rounding_and_current_bias_match_recorded_results(
    helper: ModuleType,
    libraries: SimpleNamespace,
    case: Any,
    conversion: Any,
) -> None:
    _recorded_conversion(helper, libraries, case, conversion)
    # The provider's margin was measured separately from native conversion.
    seconds = conversion["seconds"]
    expected = seconds if 86400 < seconds < 4294880895 else NEVER
    if conversion["platform"] == "Windows Server 2025 x64":
        assert expected == STORAGE[case["input"]]["seconds"]

    assert (
        helper.account_expiration_seconds(STORAGE[case["input"]]["local_ticks"])
        == expected
    )
    libraries.automation.VariantTimeToSystemTime.assert_called_once()
    libraries.kernel.SystemTimeToFileTime.assert_called_once()
    libraries.kernel.LocalFileTimeToFileTime.assert_called_once()


@pytest.mark.parametrize(
    "case", [case for case in REFERENCE["native"] if not case["filetime_success"]]
)
def test_pre_filetime_dates_preserve_native_put_failure(
    helper: ModuleType, libraries: SimpleNamespace, case: Any
) -> None:
    _recorded_conversion(helper, libraries, case, None)

    with pytest.raises(OSError) as failed:
        helper.account_expiration_seconds(STORAGE[case["input"]]["local_ticks"])

    assert failed.value.errno == case["error"] == 87
    libraries.kernel.LocalFileTimeToFileTime.assert_not_called()


@pytest.mark.parametrize(
    ("seconds", "expected"),
    [
        (-1, NEVER),
        (0, NEVER),
        (1, NEVER),
        (86400, NEVER),
        (86401, 86401),
        (4294880894, 4294880894),
        (4294880895, NEVER),
        (NEVER - 1, NEVER),
        (NEVER, NEVER),
    ],
)
def test_storage_margin_is_applied_after_native_utc_conversion(
    helper: ModuleType, libraries: SimpleNamespace, seconds: int, expected: int
) -> None:
    def _universal(_source: Any, destination: Any) -> int:
        _set_filetime(helper, destination, UNIX_FILETIME + seconds * SECOND)
        return 1

    libraries.kernel.LocalFileTimeToFileTime.side_effect = _universal

    assert helper.account_expiration_seconds(643705326000000000) == expected
    libraries.kernel.LocalFileTimeToFileTime.assert_called_once()


@pytest.mark.parametrize("case", REFERENCE["readback"])
def test_readback_recognizes_only_the_exact_never_sentinel(
    helper: ModuleType, libraries: SimpleNamespace, case: Any
) -> None:
    def _local(source: Any, destination: Any) -> int:
        assert _filetime(helper, source) == UNIX_FILETIME + case["seconds"] * SECOND
        _set_filetime(helper, destination, _ticks(case["stored"]) - FILETIME_EPOCH)
        return 1

    libraries.kernel.FileTimeToLocalFileTime.side_effect = _local

    actual = helper.account_expiration_ticks(case["seconds"])

    if case["stored"] == "never":
        assert actual is None
        libraries.loader.assert_not_called()
    else:
        assert actual == _ticks(case["stored"])
        libraries.kernel.FileTimeToLocalFileTime.assert_called_once()
        libraries.automation.VariantTimeToSystemTime.assert_not_called()


@pytest.mark.parametrize("ticks", [864000000000, 31241375999999999])
def test_invalid_automation_dates_fail_before_loading_native_libraries(
    helper: ModuleType, libraries: SimpleNamespace, ticks: int
) -> None:
    with pytest.raises(ValueError, match="Not a legal OleAut date"):
        helper.account_expiration_seconds(ticks)
    libraries.loader.assert_not_called()


@pytest.mark.parametrize("ticks", [-1, MAX_TICKS + 1, None, "0", 0.5])
def test_invalid_ticks_are_rejected_before_native_calls(
    helper: ModuleType, libraries: SimpleNamespace, ticks: Any
) -> None:
    with pytest.raises(ValueError, match="between years 1 and 9999"):
        helper.account_expiration_seconds(ticks)
    libraries.loader.assert_not_called()


@pytest.mark.parametrize("seconds", [-1, NEVER + 1, None, "0", 0.5])
def test_invalid_expiration_dwords_are_rejected_before_native_calls(
    helper: ModuleType, libraries: SimpleNamespace, seconds: Any
) -> None:
    with pytest.raises(ValueError, match="unsigned DWORD"):
        helper.account_expiration_ticks(seconds)
    libraries.loader.assert_not_called()


def test_automation_failure_does_not_use_an_unrelated_last_error(
    helper: ModuleType, libraries: SimpleNamespace
) -> None:
    libraries.automation.VariantTimeToSystemTime.return_value = 0

    with pytest.raises(ValueError, match="Not a legal OleAut date"):
        helper.account_expiration_seconds(643705326000000000)

    libraries.kernel.SystemTimeToFileTime.assert_not_called()
    helper.ctypes.get_last_error.assert_not_called()


@pytest.mark.parametrize("operation", ["write", "read"])
def test_timezone_conversion_preserves_native_failure(
    helper: ModuleType, libraries: SimpleNamespace, operation: str
) -> None:
    libraries.kernel.LocalFileTimeToFileTime.return_value = 0
    libraries.kernel.FileTimeToLocalFileTime.return_value = 0

    with pytest.raises(OSError) as failed:
        if operation == "write":
            helper.account_expiration_seconds(643705326000000000)
        else:
            helper.account_expiration_ticks(2234961000)

    assert failed.value.errno == 87


def test_non_windows_conversion_is_explicit(helper: ModuleType) -> None:
    with pytest.raises(ValueError, match="requires a Windows target"):
        helper.account_expiration_seconds(643705326000000000)
    with pytest.raises(ValueError, match="requires a Windows target"):
        helper.account_expiration_ticks(0)
    assert helper.account_expiration_ticks(NEVER) is None


@pytest.mark.parametrize(
    ("ticks", "expected"),
    [
        (599263488000000000, -1.0),
        (599263704000000000, -1.25),
        (599264351999999999, 0.0),
        (599263488000000001, -1.0000000115740741),
        (599263488000010001, -1.000000023148148),
    ],
)
def test_pre_epoch_automation_dates_use_signed_millisecond_truncation(
    helper: ModuleType, ticks: int, expected: float
) -> None:
    assert helper._ole_date(ticks) == expected
