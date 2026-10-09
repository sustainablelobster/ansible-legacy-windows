"""Fault-test complete dynamic facts and independent native observation bounds."""

# SPDX-License-Identifier: GPL-3.0-or-later

import copy
import datetime
import importlib.util
import json
import struct
import sys
from pathlib import Path
from types import ModuleType, SimpleNamespace
from typing import Any
from unittest.mock import Mock

import pytest

from tests.integration import verify_setup_dynamic as verifier


def _date(instant: datetime.datetime) -> dict[str, object]:
    epoch = instant.replace(tzinfo=datetime.timezone.utc).timestamp()
    return {
        "date": instant.strftime("%Y-%m-%d"),
        "day": instant.strftime("%d"),
        "epoch": str(epoch),
        "epoch_local": str(epoch),
        "epoch_int": round(epoch),
        "hour": instant.strftime("%H"),
        "iso8601": instant.strftime("%Y-%m-%dT%H:%M:%SZ"),
        "iso8601_basic": instant.strftime("%Y%m%dT%H%M%S%f"),
        "iso8601_basic_short": instant.strftime("%Y%m%dT%H%M%S"),
        "iso8601_micro": instant.strftime("%Y-%m-%dT%H:%M:%S.%fZ"),
        "minute": instant.strftime("%M"),
        "month": instant.strftime("%m"),
        "second": instant.strftime("%S"),
        "time": instant.strftime("%H:%M:%S"),
        "tz": "UTC",
        "tz_offset": "+00:00",
        "weekday": "Friday",
        "weekday_number": "5",
        "weeknumber": "39",
        "year": instant.strftime("%Y"),
    }


@pytest.fixture(name="record")
def dynamic_record() -> dict[str, Any]:
    """Construct complete raw results with independent native windows.

    :returns: A new valid paired dynamic capture.
    """
    instant = datetime.datetime(2026, 10, 2, 18, 25, 29, 140783)
    epoch = instant.replace(tzinfo=datetime.timezone.utc).timestamp()
    sample = {
        "protected": {"sha256": "protected"},
        "configuration": {
            "timezone": [{"name": "TimeZoneKeyName", "kind": 1, "value": "UTC"}]
        },
        "physical_total_bytes": 6000 * 1048576,
        "physical_available_bytes": 4000 * 1048576,
    }
    facts = {
        "gather_subset": ["!all", "!min", "date_time", "memory", "uptime"],
        "module_setup": True,
        "ansible_date_time": _date(instant),
        "ansible_lastboot": (instant - datetime.timedelta(seconds=100)).strftime(
            "%Y-%m-%d %H:%M:%SZ"
        ),
        "ansible_uptime_seconds": 100,
        "ansible_memtotal_mb": 6000,
        "ansible_memfree_mb": 4000,
        "ansible_swaptotal_mb": 0,
        "ansible_pagefiletotal_mb": 1664,
        "ansible_pagefilefree_mb": 1621,
    }
    result: dict[str, Any] = {}
    for name in ("native", "original"):
        result[name] = {
            "changed": False,
            "failed": False,
            "ansible_facts": copy.deepcopy(facts),
        }
        result["before_" + name] = {
            "stdout": json.dumps(dict(sample, epoch=epoch - 1, tick_milliseconds=99000))
        }
        result["after_" + name] = {
            "stdout": json.dumps(
                dict(sample, epoch=epoch + 1, tick_milliseconds=101000)
            )
        }
    result["original"]["ansible_facts"]["ansible_date_time"] = _date(
        instant + datetime.timedelta(microseconds=200000)
    )
    result["original"]["ansible_facts"]["ansible_memfree_mb"] = 3999
    result["original"]["ansible_facts"]["ansible_pagefilefree_mb"] = 1620
    return result


def test_every_dynamic_field_is_retained_validated_and_raw_capture_is_unmodified(
    record: dict[str, Any],
) -> None:
    original = copy.deepcopy(record)
    qualification = verifier.validate(record)
    assert len(qualification["date_fields"]) == 20  # type: ignore[arg-type]
    assert "not contemporaneous" in str(qualification["free_ram"])
    assert record == original


@pytest.mark.parametrize(
    "field,value",
    [
        ("ansible_uptime_seconds", 102),
        ("ansible_uptime_seconds", True),
        ("ansible_lastboot", "2026-10-02 18:00:00Z"),
        ("ansible_memtotal_mb", 6001),
        ("ansible_memfree_mb", 6001),
        ("ansible_memfree_mb", 1.0),
        ("ansible_pagefilefree_mb", 1665),
        ("ansible_pagefilefree_mb", True),
        ("ansible_swaptotal_mb", 1),
    ],
)
def test_out_of_bound_types_and_nondynamic_differences_fail(
    record: dict[str, Any], field: str, value: object
) -> None:
    record["native"]["ansible_facts"][field] = value
    with pytest.raises(ValueError):
        verifier.validate(record)


@pytest.mark.parametrize(
    "field,value",
    [
        ("epoch_int", True),
        ("epoch", "0"),
        ("iso8601_micro", "2026-10-02T18:25:31.140783Z"),
        ("weekday", "Saturday"),
        ("weeknumber", "40"),
        ("tz", "Not the protected timezone"),
        ("tz_offset", "UTC"),
        ("second", "00"),
    ],
)
def test_complete_date_shape_types_internal_relationships_and_window_are_required(
    record: dict[str, Any], field: str, value: object
) -> None:
    record["native"]["ansible_facts"]["ansible_date_time"][field] = value
    with pytest.raises(ValueError):
        verifier.validate(record)


def test_no_public_keys_or_warnings_can_be_silently_dropped(
    record: dict[str, Any],
) -> None:
    record["native"]["warnings"] = ["unexpected collector failure"]
    with pytest.raises(ValueError, match="nonvarying public"):
        verifier.validate(record)
    del record["native"]["warnings"]
    del record["native"]["ansible_facts"]["ansible_date_time"]["weeknumber"]
    with pytest.raises(ValueError, match="complete date"):
        verifier.validate(record)


def test_protected_configuration_change_is_rejected(record: dict[str, Any]) -> None:
    after = json.loads(record["after_native"]["stdout"])
    after["configuration"] = {"timezone": []}
    record["after_native"]["stdout"] = json.dumps(after)
    with pytest.raises(ValueError, match="changed configuration"):
        verifier.validate(record)


def _fixture(monkeypatch: pytest.MonkeyPatch) -> ModuleType:
    monkeypatch.setitem(sys.modules, "winreg", ModuleType("winreg"))
    path = Path(__file__).resolve().parents[1] / "integration/fixtures/setup.py"
    spec = importlib.util.spec_from_file_location("setup_dynamic_fixture", path)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


@pytest.mark.parametrize("error", [5, 87])
def test_dynamic_native_sampling_reports_actual_private_winerror(
    monkeypatch: pytest.MonkeyPatch, error: int
) -> None:
    fixture = _fixture(monkeypatch)
    monkeypatch.setattr(fixture, "_observe", lambda _root: {})
    kernel = SimpleNamespace(
        GetTickCount64=Mock(), GlobalMemoryStatusEx=Mock(return_value=0)
    )
    monkeypatch.setattr(
        fixture.ctypes, "WinDLL", Mock(return_value=kernel), raising=False
    )
    monkeypatch.setattr(fixture.ctypes, "get_last_error", lambda: error, raising=False)
    monkeypatch.setattr(
        fixture.ctypes,
        "WinError",
        lambda number: OSError(number, "native"),
        raising=False,
    )
    with pytest.raises(OSError) as caught:
        fixture._observe_dynamic("owned")  # pylint: disable=protected-access
    assert caught.value.errno == error


def test_dynamic_native_sampling_uses_complete_fixed_windows_abi(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    fixture = _fixture(monkeypatch)
    monkeypatch.setattr(fixture, "_observe", lambda _root: {"protected": "retained"})

    def _memory(buffer: object) -> int:
        assert fixture.ctypes.sizeof(buffer) == 64
        fixture.ctypes.memmove(
            buffer, struct.pack("<II7Q", 64, 0, 6000, 4000, 0, 0, 0, 0, 0), 64
        )
        return 1

    kernel = SimpleNamespace(
        GetTickCount64=Mock(return_value=1000),
        GlobalMemoryStatusEx=Mock(side_effect=_memory),
    )
    monkeypatch.setattr(
        fixture.ctypes, "WinDLL", Mock(return_value=kernel), raising=False
    )
    monkeypatch.setattr(fixture.time, "time", lambda: 2000)
    assert fixture._observe_dynamic("owned") == {  # pylint: disable=protected-access
        "protected": "retained",
        "physical_total_bytes": 6000,
        "physical_available_bytes": 4000,
        "tick_milliseconds": 1000,
        "epoch": 2000,
    }
