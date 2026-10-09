"""Reject incomplete command input, public failure and runtime recovery proof."""

# SPDX-License-Identifier: GPL-3.0-or-later

import copy
import json
from typing import Any

import pytest

from scripts.verify_command_inputs_capture import verify_capture


def _capture() -> dict[str, Any]:
    cases = [{"name": str(index), "args": {"cmd": None}} for index in range(12)]
    rows = [
        {"item": case, "changed": False, "failed": True, "msg": "literal failure"}
        for case in cases
    ]
    observation = {
        "python": [3, 4, 4],
        "windows_version": [10, 0],
        "mac": '"BC-24-11-00-00-00","owned"\r\n',
        "staging": ["preexisting"],
    }
    return {
        "mode": "paired",
        "expected_windows_version": [10, 0],
        "cases": cases,
        "native": {"results": copy.deepcopy(rows)},
        "source": {"results": copy.deepcopy(rows)},
        "before": {"rc": 0, "stdout": json.dumps(observation)},
        "after": {"rc": 0, "stdout": json.dumps(observation)},
    }


# This workflow keeps an independent fixture and expected-result oracle.
# pylint: disable=duplicate-code
def test_complete_raw_capture_is_not_modified() -> None:
    document = _capture()
    original = copy.deepcopy(document)
    assert verify_capture(document) == 12
    assert document == original


# pylint: enable=duplicate-code


# This workflow keeps an independent fixture and expected-result oracle.
# pylint: disable=duplicate-code
@pytest.mark.parametrize(
    "field,value",
    [("changed", 0), ("failed", 1), ("msg", "different"), ("extra", None)],
)
def test_public_types_values_and_presence_are_not_normalized(
    field: str, value: Any
) -> None:
    document = _capture()
    document["native"]["results"][0][field] = value
    with pytest.raises(AssertionError):
        verify_capture(document)


# pylint: enable=duplicate-code


# This workflow keeps an independent fixture and expected-result oracle.
# pylint: disable=duplicate-code
@pytest.mark.parametrize("side", ["native", "source"])
def test_missing_call_and_wrong_input_fail(side: str) -> None:
    document = _capture()
    document[side]["results"].pop()
    with pytest.raises(AssertionError):
        verify_capture(document)
    document = _capture()
    document[side]["results"][0]["item"]["args"] = {"cmd": "different"}
    with pytest.raises(AssertionError):
        verify_capture(document)


# pylint: enable=duplicate-code


def test_misbound_free_form_dictionary_is_never_validated() -> None:
    document = _capture()
    for side in ("native", "source"):
        document[side]["results"][0]["cmd"] = "System.Collections.Hashtable"
    with pytest.raises(AssertionError):
        verify_capture(document)


@pytest.mark.parametrize(
    "field,value",
    [
        ("python", [3, 12, 0]),
        ("windows_version", [5, 1]),
        ("mac", "different"),
        ("staging", ["leaked"]),
    ],
)
def test_runtime_or_staging_change_blocks_verification(field: str, value: Any) -> None:
    document = _capture()
    final = json.loads(document["after"]["stdout"])
    final[field] = value
    document["after"]["stdout"] = json.dumps(final)
    with pytest.raises(AssertionError):
        verify_capture(document)


def test_native_only_requires_complete_verified_reference_and_identical_inputs() -> (
    None
):
    reference = _capture()
    document = _capture()
    document["mode"] = "native"
    document["source"] = {"skipped": True}
    with pytest.raises(AssertionError):
        verify_capture(document)
    assert verify_capture(document, reference) == 12
    reference["native"]["results"].pop()
    with pytest.raises(AssertionError):
        verify_capture(document, reference)


def test_failed_observer_and_boolean_return_code_fail() -> None:
    for return_code in (1, False):
        document = _capture()
        document["after"]["rc"] = return_code
        with pytest.raises(AssertionError):
            verify_capture(document)
