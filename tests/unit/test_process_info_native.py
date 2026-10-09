"""Check process snapshot and GetOwner behavior without contacting Windows."""

# SPDX-License-Identifier: GPL-3.0-or-later

from datetime import datetime
from types import ModuleType
from typing import Any
from unittest.mock import MagicMock, Mock

import pytest

from tests.unit.payload_support import ROOT, load_module


@pytest.fixture(name="helper")
def process_helper(monkeypatch: pytest.MonkeyPatch) -> ModuleType:
    """Load the process reader with its adjacent WMI helper.

    :param monkeypatch: Scoped target import path.
    :returns: Process reader imported with the development interpreter.
    """
    monkeypatch.syspath_prepend(str(ROOT / "plugins/module_utils"))
    helper = load_module(
        ROOT / "plugins/module_utils/legacy_windows_process_info.py",
        "tested_process_info",
    )
    monkeypatch.setattr(
        helper.native_time, "utc_ticks_to_local_ticks", lambda ticks: ticks
    )
    return helper


@pytest.fixture(name="connection")
def process_connection(helper: ModuleType, monkeypatch: pytest.MonkeyPatch) -> Any:
    """Substitute only the native WMI service interface.

    :param helper: Loaded process reader.
    :param monkeypatch: Scoped connection substitution.
    :returns: Context-managed WMI connection with one process snapshot.
    """
    native = MagicMock()
    native.__enter__.return_value = native
    native.query.return_value = [
        {
            "ProcessId": 42,
            "Name": "worker.exe",
            "CreationDate": "20260102030405.123456+000",
            "__PATH": 'Win32_Process.Handle="42"',
        },
        {
            "ProcessId": 4,
            "Name": "System",
            "CreationDate": None,
            "__PATH": 'Win32_Process.Handle="4"',
        },
    ]
    native.call_method.return_value = {"Domain": "LAB", "User": "owner"}
    monkeypatch.setattr(helper, "WmiConnection", lambda: native)
    return native


def test_snapshot_precedes_endpoints_and_owner_is_read_per_endpoint(
    helper: ModuleType, connection: Any
) -> None:
    with helper.ProcessReader() as reader:
        connection.query.assert_called_once_with(
            "SELECT ProcessId, Name, CreationDate FROM Win32_Process",
            ["ProcessId", "Name", "CreationDate", "__PATH"],
        )
        connection.call_method.assert_not_called()
        first = reader.get(42)
        second = reader.get(42)
        assert first == second
        assert first["name"] == "worker.exe"
        assert first["user"] == "LAB\\owner"
        assert first["creation_time"].tzinfo is None
        assert first["creation_time"].microsecond == 123456
        assert connection.query.call_count == 1
        assert connection.call_method.call_count == 2
        connection.call_method.assert_called_with(
            'Win32_Process.Handle="42"', "GetOwner", ["Domain", "User"]
        )
    connection.__exit__.assert_called_once()


@pytest.mark.parametrize(
    ("domain", "user", "expected"),
    [
        (None, "owner", None),
        ("LAB", None, None),
        (None, None, None),
        ("", "", "\\"),
        ("域", "用户", "域\\用户"),
    ],
)
def test_owner_joins_only_non_null_fields(
    helper: ModuleType, connection: Any, domain: Any, user: Any, expected: Any
) -> None:
    connection.call_method.return_value = {
        "Domain": domain,
        "User": user,
        "ReturnValue": 2,
    }
    with helper.ProcessReader() as reader:
        assert reader.get(42)["user"] == expected


def test_null_creation_time_stays_null(helper: ModuleType, connection: Any) -> None:
    with helper.ProcessReader() as reader:
        assert reader.get(4)["creation_time"] is None
    connection.__exit__.assert_called_once()


def test_missing_process_fails_without_inventing_details(
    helper: ModuleType, connection: Any
) -> None:
    with helper.ProcessReader() as reader:
        with pytest.raises(OSError, match="Process 99.*snapshot"):
            reader.get(99)
        connection.call_method.assert_not_called()


def test_snapshot_failure_releases_connection(
    helper: ModuleType, connection: Any
) -> None:
    connection.query.side_effect = OSError("snapshot denied")
    with pytest.raises(OSError, match="snapshot denied"):
        with helper.ProcessReader():
            pytest.fail("failed snapshot must not enter")
    connection.__exit__.assert_called_once()


def test_owner_failure_propagates_and_connection_recovers(
    helper: ModuleType, connection: Any
) -> None:
    connection.call_method.side_effect = [
        OSError("process exited"),
        {"Domain": "LAB", "User": "owner"},
    ]
    with helper.ProcessReader() as reader:
        with pytest.raises(OSError, match="process exited"):
            reader.get(42)
        assert reader.get(42)["user"] == "LAB\\owner"
    connection.__exit__.assert_called_once()


def test_creation_time_converts_dmtf_offset_to_local_time(
    helper: ModuleType, connection: Any, monkeypatch: pytest.MonkeyPatch
) -> None:
    convert = Mock(side_effect=lambda ticks: ticks - 4 * 3600 * 10000000)
    monkeypatch.setattr(helper.native_time, "utc_ticks_to_local_ticks", convert)
    connection.query.return_value[0]["CreationDate"] = "20260702060405.123456+180"
    with helper.ProcessReader() as reader:
        assert reader.get(42)["creation_time"] == datetime(2026, 7, 1, 23, 4, 5, 123456)
    utc = datetime(2026, 7, 2, 3, 4, 5, 123456)
    expected_ticks = ((utc.toordinal() - 1) * 86400 + 3 * 3600 + 4 * 60 + 5) * 10000000
    convert.assert_called_once_with(expected_ticks + 1234560)


def test_native_timezone_failure_does_not_fall_back_to_runtime_utc(
    helper: ModuleType, connection: Any, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(
        helper.native_time,
        "utc_ticks_to_local_ticks",
        Mock(side_effect=OSError("timezone unavailable")),
    )
    with helper.ProcessReader() as reader:
        with pytest.raises(OSError, match="timezone unavailable"):
            reader.get(42)
    connection.__exit__.assert_called_once()
