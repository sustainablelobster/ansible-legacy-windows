"""Reject incomplete or normalized Slurp parity and owned-resource evidence."""

# SPDX-License-Identifier: GPL-3.0-or-later

import copy
import json
from typing import Any

import pytest

from scripts.verify_slurp_inputs_capture import verify_capture


def _capture() -> dict[str, Any]:
    cases = [
        {"name": str(index), "src": " ", "success": False, "check": check}
        for check in (False, True)
        for index in range(8)
    ]
    rows = [
        {"item": case, "changed": False, "failed": True, "msg": "Path   is a directory"}
        for case in cases
    ]
    before = {
        "root": "C:\\Temp\\legacy-slurp-inputs-owned",
        "runtime": {
            "python": [3, 4, 4],
            "windows_version": [10, 0],
            "mac": '"BC-24-11-3E-87-91","owned"\r\n',
            "staging": ["preexisting"],
        },
        "files": {"binary.bin": {"bytes": "AA==", "attributes": 32, "mtime_ns": 100}},
    }
    after = dict(copy.deepcopy(before), root_absent=True)
    return {
        "cases": cases,
        "expected_windows_version": [10, 0],
        "expected_mac": "BC:24:11:3E:87:91",
        "before": {"rc": 0, "stdout": json.dumps(before)},
        "after": {"rc": 0, "stdout": json.dumps(after)},
        "native": {"results": copy.deepcopy(rows)},
        "source": {"results": copy.deepcopy(rows)},
    }


def test_complete_capture_is_not_modified() -> None:
    document = _capture()
    original = copy.deepcopy(document)
    assert verify_capture(document) == 16
    assert document == original


@pytest.mark.parametrize(
    "field,value",
    [
        ("changed", 0),
        ("failed", 1),
        ("msg", "Path   is not found"),
        ("extra", None),
    ],
)
def test_whole_public_presence_values_and_types_are_literal(
    field: str,
    value: Any,
) -> None:
    document = _capture()
    document["native"]["results"][0][field] = value
    with pytest.raises(AssertionError):
        verify_capture(document)


@pytest.mark.parametrize(
    "key,value",
    [
        ("bytes", "AQ=="),
        ("attributes", 0),
        ("mtime_ns", 101),
    ],
)
def test_protected_file_bytes_attributes_and_mtime_cannot_change(
    key: str,
    value: Any,
) -> None:
    document = _capture()
    after = json.loads(document["after"]["stdout"])
    after["files"]["binary.bin"][key] = value
    document["after"]["stdout"] = json.dumps(after)
    with pytest.raises(AssertionError):
        verify_capture(document)


@pytest.mark.parametrize(
    "key,value",
    [
        ("python", [3, 12, 0]),
        ("mac", "wrong guest"),
        ("staging", ["leaked"]),
    ],
)
def test_runtime_guest_and_staging_are_mandatory(key: str, value: Any) -> None:
    document = _capture()
    for field in ("after",) if key == "staging" else ("before", "after"):
        observation = json.loads(document[field]["stdout"])
        observation["runtime"][key] = value
        document[field]["stdout"] = json.dumps(observation)
    with pytest.raises(AssertionError):
        verify_capture(document)


def test_absent_workspace_and_complete_calls_are_required() -> None:
    document = _capture()
    observation = json.loads(document["after"]["stdout"])
    observation["root_absent"] = False
    document["after"]["stdout"] = json.dumps(observation)
    with pytest.raises(AssertionError):
        verify_capture(document)
    document = _capture()
    document["native"]["results"].pop()
    with pytest.raises(AssertionError):
        verify_capture(document)


def test_normal_and_check_inputs_keep_boolean_types() -> None:
    document = _capture()
    document["cases"][0]["check"] = 0
    with pytest.raises(AssertionError):
        verify_capture(document)
