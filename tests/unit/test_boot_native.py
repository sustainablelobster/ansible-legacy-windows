"""Keep boot timestamp behavior stable while sharing the native WMI reader."""

# SPDX-License-Identifier: GPL-3.0-or-later

from datetime import datetime
from types import ModuleType
from typing import Any
from unittest.mock import MagicMock

import pytest

from tests.unit.payload_support import ROOT, load_module


@pytest.fixture(name="helper")
def boot_helper(monkeypatch: pytest.MonkeyPatch) -> ModuleType:
    """Load the boot reader with its adjacent shared WMI helper.

    :param monkeypatch: Scoped target import path.
    :returns: Boot reader imported with the development interpreter.
    """
    monkeypatch.syspath_prepend(str(ROOT / "plugins/module_utils"))
    return load_module(
        ROOT / "plugins/module_utils/legacy_windows_boot.py", "tested_boot"
    )


@pytest.fixture(name="connection")
def boot_connection(helper: ModuleType, monkeypatch: pytest.MonkeyPatch) -> Any:
    """Substitute a WMI connection without contacting Windows.

    :param helper: Loaded boot reader.
    :param monkeypatch: Scoped connection substitute.
    :returns: Context-managed connection substitute.
    """
    native = MagicMock()
    native.__enter__.return_value = native
    monkeypatch.setattr(helper, "WmiConnection", lambda: native)
    return native


@pytest.mark.parametrize(
    ("value", "expected"),
    [
        ("20260928081141.679063+000", datetime(2026, 9, 28, 8, 11, 41, 679063)),
        ("20260928111141.679063+180", datetime(2026, 9, 28, 8, 11, 41, 679063)),
        ("20260928041141.679063-240", datetime(2026, 9, 28, 8, 11, 41, 679063)),
        ("20240101001500.123456+060", datetime(2023, 12, 31, 23, 15, 0, 123456)),
        ("20000229000000.999999-000", datetime(2000, 2, 29, microsecond=999999)),
    ],
)
def test_boot_preserves_utc_and_precision(
    helper: ModuleType, connection: Any, value: str, expected: datetime
) -> None:
    connection.query.return_value = [{"LastBootUpTime": value}]
    assert helper.last_boot_time() == expected
    connection.query.assert_called_once_with(
        "SELECT LastBootUpTime FROM Win32_OperatingSystem", ["LastBootUpTime"]
    )
    connection.__exit__.assert_called_once()


def test_empty_operating_system_result_fails(
    helper: ModuleType, connection: Any
) -> None:
    connection.query.return_value = []
    with pytest.raises(OSError, match="no Win32_OperatingSystem instance"):
        helper.last_boot_time()
    connection.__exit__.assert_called_once()


@pytest.mark.parametrize("value", [None, 42, "", "20260928081141.679063+***"])
def test_invalid_boot_timestamp_fails(
    helper: ModuleType, connection: Any, value: Any
) -> None:
    connection.query.return_value = [{"LastBootUpTime": value}]
    with pytest.raises(ValueError, match="LastBootUpTime"):
        helper.last_boot_time()
    connection.__exit__.assert_called_once()


@pytest.mark.parametrize(
    "value", ["00010101000000.000000+001", "99991231235959.999999-001"]
)
def test_utc_range_overflow_still_fails(
    helper: ModuleType, connection: Any, value: str
) -> None:
    connection.query.return_value = [{"LastBootUpTime": value}]
    with pytest.raises(OverflowError):
        helper.last_boot_time()
    connection.__exit__.assert_called_once()


def test_query_failure_closes_connection(helper: ModuleType, connection: Any) -> None:
    connection.query.side_effect = OSError("WMI unavailable")
    with pytest.raises(OSError, match="WMI unavailable"):
        helper.last_boot_time()
    connection.__exit__.assert_called_once()
