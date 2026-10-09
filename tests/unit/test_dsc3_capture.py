"""Reject DSC public, clock and recovery mismatches without contacting Windows."""

# SPDX-License-Identifier: GPL-3.0-or-later

import ast
import copy
import json
from typing import Any

import pytest

# PyYAML is supplied by the pinned Nix development environment.
import yaml  # type: ignore[import-untyped]

from scripts.verify_dsc3_capture import verify_capture
from tests.unit.payload_support import ROOT


def _capture() -> dict[str, Any]:
    before = {"utc": 1767225600.0, "key_present": False, "values": [], "keys": []}
    after = dict(before, utc=1767225602.0)
    result: dict[str, Any] = {
        "changed": False,
        "rc": 0,
        "stderr": "",
        "result": {
            "metadata": {
                "Microsoft.DSC": {
                    "startDatetime": "2026-01-01T00:00:00.200000000+00:00",
                    "endDatetime": "2026-01-01T00:00:00.300000000+00:00",
                    "duration": "PT0.1S",
                    "operation": "set",
                    "version": "3.1.0",
                }
            },
            "results": [
                {
                    "metadata": {"Microsoft.DSC": {"duration": "PT0.05S"}},
                    "result": {"beforeState": {"output": True}},
                }
            ],
        },
    }
    native: dict[str, Any] = {
        "validated": True,
        "case": "echo",
        "phase": "native",
        "request": {"config": {}},
        "check_mode": True,
        "before": before,
        "after": after,
        "result": result,
    }
    original = copy.deepcopy(native)
    original["phase"] = "original"
    original["result"]["invocation"] = {"module_args": {}}
    metadata = original["result"]["result"]["metadata"]["Microsoft.DSC"]
    metadata.update(
        startDatetime="2026-01-01T00:00:01.000000000+00:00",
        endDatetime="2026-01-01T00:00:01.250000000+00:00",
        duration="PT0.25S",
    )
    return {
        "records": [native, original],
        "workspace_removed": True,
        "recovery": {
            "rc": 0,
            "stdout": json.dumps(
                {
                    "restored": True,
                    "original_keys": [],
                    "final_keys": [],
                    "final": {"key_present": False},
                }
            ),
        },
        "staging_before": {"stdout": "[]"},
        "staging_after": {"stdout": "[]"},
    }


def test_measured_clocks_only_and_raw_capture_preserved() -> None:
    capture = _capture()
    original = copy.deepcopy(capture)
    report = verify_capture(capture, paired=True)
    assert capture == original
    assert report["verified"]
    assert report["cases"] == [
        {
            "case": "echo",
            "qualified_clock_paths": [
                "result.metadata.Microsoft.DSC.startDatetime",
                "result.metadata.Microsoft.DSC.endDatetime",
                "result.metadata.Microsoft.DSC.duration",
                "result.results[0].metadata.Microsoft.DSC.duration",
            ],
        }
    ]


@pytest.mark.parametrize("field", ["operation", "version", "unknown"])
def test_nonclock_metadata_never_qualified(field: str) -> None:
    capture = _capture()
    metadata = capture["records"][1]["result"]["result"]["metadata"]["Microsoft.DSC"]
    metadata[field] = "different"
    with pytest.raises(AssertionError):
        verify_capture(capture, paired=True)


@pytest.mark.parametrize(
    "field,value",
    [
        ("startDatetime", "2025-12-31T23:59:59+00:00"),
        ("endDatetime", "2026-01-01T00:00:03+00:00"),
        ("duration", "PT0.2S"),
        ("duration", "unparsable"),
    ],
)
def test_clocks_must_match_their_own_operation_bounds(field: str, value: str) -> None:
    capture = _capture()
    metadata = capture["records"][0]["result"]["result"]["metadata"]["Microsoft.DSC"]
    metadata[field] = value
    with pytest.raises(AssertionError):
        verify_capture(capture, paired=True)


def test_resource_duration_cannot_exceed_full_configuration() -> None:
    capture = _capture()
    metadata = capture["records"][0]["result"]["result"]["results"][0]["metadata"]
    metadata["Microsoft.DSC"]["duration"] = "PT5S"
    with pytest.raises(AssertionError):
        verify_capture(capture, paired=True)


def test_public_json_types_are_not_coerced() -> None:
    capture = _capture()
    capture["records"][1]["result"]["result"]["results"][0]["result"]["beforeState"][
        "output"
    ] = 1
    with pytest.raises(AssertionError):
        verify_capture(capture, paired=True)


@pytest.mark.parametrize("side", ["before", "after"])
def test_owned_observations_must_match_between_implementations(side: str) -> None:
    capture = _capture()
    capture["records"][1][side]["values"] = [["unexpected", "value", 1]]
    with pytest.raises(AssertionError):
        verify_capture(capture, paired=True)


@pytest.mark.parametrize("change", ["workspace", "staging", "unvalidated", "unpaired"])
def test_failed_or_incomplete_recovery_is_not_evidence(change: str) -> None:
    capture = _capture()
    if change == "workspace":
        capture["workspace_removed"] = False
    elif change == "staging":
        capture["staging_after"]["stdout"] = '["ansible-tmp-leaked"]'
    elif change == "unvalidated":
        capture["records"][1]["validated"] = False
    else:
        capture["records"].pop()
    with pytest.raises(AssertionError):
        verify_capture(capture, paired=True)


def test_actual_fixture_syntax_is_python_34() -> None:
    document = yaml.safe_load(
        (ROOT / "tests/integration/vars/dsc3_fixture.yml").read_text(encoding="utf-8")
    )
    ast.parse(document["dsc3_fixture"], feature_version=(3, 4))


def test_trace_qualifies_only_bounded_timestamp_not_message() -> None:
    capture = _capture()
    for index, record in enumerate(capture["records"]):
        text = f"2026-01-01T00:00:00.{index + 1}Z ERROR resource failure\n"
        record["result"].update(stderr=text, stderr_lines=text.splitlines())
    assert verify_capture(capture, paired=True)["verified"]
    capture["records"][1]["result"][
        "stderr"
    ] = "2026-01-01T00:00:00.2Z ERROR different failure\n"
    capture["records"][1]["result"]["stderr_lines"] = capture["records"][1]["result"][
        "stderr"
    ].splitlines()
    with pytest.raises(AssertionError):
        verify_capture(capture, paired=True)


def test_trace_timestamp_outside_its_operation_is_not_qualified() -> None:
    capture = _capture()
    capture["records"][0]["result"].update(
        stderr="2026-01-01T00:00:10.0Z ERROR failure\n",
        stderr_lines=["2026-01-01T00:00:10.0Z ERROR failure"],
    )
    with pytest.raises(AssertionError):
        verify_capture(capture, paired=True)
