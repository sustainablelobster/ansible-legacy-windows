"""Protect public field/type/order fidelity around generated information clocks."""

# SPDX-License-Identifier: GPL-3.0-or-later

import json
from copy import deepcopy
from typing import Any

import pytest

from scripts.verify_win_powershell_capture import compare_record


def _record() -> dict[str, Any]:
    result = {
        "changed": False,
        "output": [1, None, {"time_generated": "literal user value"}],
        "information": [
            {
                "message_data": {"value": 2},
                "source": "Write-Information",
                "tags": ["first", "second"],
                "time_generated": "2026-10-02T20:00:00.1234567Z",
            }
        ],
    }
    state = {
        "protected": {"sentinel": "literal"},
        "environment": {"TEMP": "original"},
        "python": "3.4.4",
        "output": {"output.txt": None},
    }
    before = {"stdout": json.dumps(dict(state, utc="2026-10-02T20:00:00.000000Z"))}
    after = {"stdout": json.dumps(dict(state, utc="2026-10-02T20:00:01.000000Z"))}
    return {
        "case": {"name": "information"},
        "native": result,
        "original": deepcopy(result),
        "before_native": before,
        "after_native": after,
        "before_original": deepcopy(before),
        "after_original": deepcopy(after),
    }


def test_generated_timestamp_is_bounded_and_raw_capture_preserved() -> None:
    record = _record()
    record["original"]["information"][0][
        "time_generated"
    ] = "2026-10-02T20:00:00.9876543Z"
    original = deepcopy(record)
    assert compare_record(record) == 2
    assert record == original


@pytest.mark.parametrize(
    "timestamp",
    [
        "2026-10-02T19:59:59.1234567Z",
        "2026-10-02T20:00:01.0000001Z",
        "2026-10-02T20:00:00.123456Z",
        "2026-10-02T20:00:00.1234567+00:00",
    ],
)
def test_unbounded_or_unknown_timestamp_shape_is_rejected(timestamp: str) -> None:
    record = _record()
    record["native"]["information"][0]["time_generated"] = timestamp
    record["original"]["information"][0]["time_generated"] = timestamp
    with pytest.raises(AssertionError):
        compare_record(record)


@pytest.mark.parametrize("change", ["protected", "environment", "unexpected_output"])
def test_source_effects_are_verified_independently(change: str) -> None:
    record = _record()
    state = json.loads(record["after_original"]["stdout"])
    if change == "unexpected_output":
        state["output"]["output.txt"] = {"body_base64": "unexpected"}
    else:
        state[change] = {"changed": "unexpected"}
    record["after_original"]["stdout"] = json.dumps(state)
    with pytest.raises(AssertionError):
        compare_record(record)


def test_changed_files_compare_bytes_security_and_attributes_not_call_clocks() -> None:
    record = _record()
    record["case"].update(changed=True, output="owned")
    file_state = {
        "attributes": 32,
        "body_base64": "b3duZWQ=",
        "ctime": 1.0,
        "directory": False,
        "mtime": 1.0,
        "security": "literal security",
    }
    for phase, clock in (("native", 1.0), ("original", 2.0)):
        state = json.loads(record[f"after_{phase}"]["stdout"])
        state["output"]["output.txt"] = dict(file_state, ctime=clock, mtime=clock)
        record[f"after_{phase}"]["stdout"] = json.dumps(state)
    assert compare_record(record) == 2
    state["output"]["output.txt"]["security"] = "unexpected permissions"
    record["after_original"]["stdout"] = json.dumps(state)
    with pytest.raises(AssertionError):
        compare_record(record)


@pytest.mark.parametrize(
    "change", ["field", "type", "tags", "message", "user_clock", "null_information"]
)
def test_nonclock_fields_and_types_are_not_normalized(change: str) -> None:
    record = _record()
    native = record["native"]
    if change == "field":
        native["extra"] = "value"
    elif change == "type":
        native["changed"] = 0
    elif change == "tags":
        native["information"][0]["tags"].reverse()
    elif change == "message":
        native["information"][0]["message_data"]["value"] = 3
    elif change == "user_clock":
        native["output"][2]["time_generated"] = "different user value"
    else:
        native["information"] = None
        record["original"]["information"] = None
    with pytest.raises(AssertionError):
        compare_record(record)


def _async_record() -> dict[str, Any]:
    record = _record()
    record["workspace"] = r"C:\Temp\legacy-windows-win-powershell-async-test"
    for phase, pid in (("native", 42), ("original", 84)):
        launch = {
            "changed": False,
            "started": True,
            "finished": False,
            "ansible_job_id": f"j100.{pid}",
            "ansible_async_watchdog_pid": pid,
            "results_file": record["workspace"] + f"\\{phase}-cache\\j100.{pid}",
        }
        record[f"launch_{phase}"] = launch
        record[phase].update(launch, finished=True, attempts=pid)
        record[f"pin_{phase}"] = {
            "stdout": json.dumps(
                {
                    "launch": launch,
                    "chain": [
                        {
                            "identity": {
                                "pid": pid,
                                "created": 12345678,
                                "alive": True,
                            },
                            "process": {
                                "ProcessId": pid,
                                "ParentProcessId": 1,
                                "Name": "powershell.exe",
                            },
                        }
                    ],
                }
            ),
        }
    return record


def test_async_launch_and_complete_status_qualify_only_observed_allocations() -> None:
    record = _async_record()
    original = deepcopy(record)
    assert compare_record(record) == 2
    assert record == original


@pytest.mark.parametrize(
    "change",
    [
        "pid_type",
        "job",
        "path",
        "counter",
        "flag",
        "birth",
        "engine",
        "public_value",
        "array",
    ],
)
def test_async_unproved_identity_or_public_difference_is_not_qualified(
    change: str,
) -> None:
    record = _async_record()
    if change == "pid_type":
        record["native"]["ansible_async_watchdog_pid"] = 42.0
    elif change == "job":
        record["native"]["ansible_job_id"] = "j999.42"
    elif change == "path":
        record["native"]["results_file"] = r"C:\unrelated\j100.42"
    elif change == "counter":
        record["native"]["attempts"] = True
    elif change == "flag":
        record["native"]["finished"] = 1
    elif change in ("birth", "engine"):
        pin = json.loads(record["pin_native"]["stdout"])
        if change == "birth":
            pin["chain"][0]["identity"]["created"] = 0
        else:
            pin["chain"][0]["process"]["Name"] = "unrelated.exe"
        record["pin_native"]["stdout"] = json.dumps(pin)
    elif change == "public_value":
        record["native"]["output"][2]["time_generated"] = "different user value"
    else:
        record["native"]["output"].reverse()
    with pytest.raises(AssertionError):
        compare_record(record)
