"""Reject incomplete public, wire and ownership proof in HTTP timeout captures."""

# SPDX-License-Identifier: GPL-3.0-or-later

import copy
import json
from typing import Any

import pytest

from scripts.verify_http_zero_capture import verify_capture


def _capture() -> dict[str, Any]:
    observation = {
        "output": {"attributes": 16, "children": {}},
        "sentinel": {"attributes": 32, "hex": "70726f746563746564", "mtime": 1.0},
        "source": {"attributes": 32, "hex": "00ff", "mtime": 1.0},
        "time": 10.0,
    }
    after = dict(
        observation,
        time=11.0,
        requests=[
            {
                "method": "GET",
                "path": "/fixture",
                "headers": {"Host": "owned"},
                "header_pairs": [["Host", "owned"]],
                "body_base64": "",
                "body_complete": True,
                "peer_closed": False,
            }
        ],
    )
    record: dict[str, Any] = {
        "name": "owned",
        "module": "uri",
        "params": {"url_timeout": 0},
        "check": False,
        "side": "native",
        "result": {
            "changed": False,
            "failed": True,
            "status_code": None,
            "msg": "literal receive failure",
            "elapsed": 0.1,
        },
        "before": {"rc": 0, "stdout": json.dumps(observation)},
        "after": {"rc": 0, "stdout": json.dumps(after)},
    }
    original = copy.deepcopy(record)
    original["side"] = "original"
    original["result"]["elapsed"] = 0.2
    original["result"]["exception"] = "controller traceback wrapper"
    process = {"pid": 123, "creation": 456}
    protected = dict(observation, process=process)
    recovery = dict(protected, before=protected, restored=True, server_stopped=True)
    return {
        "mode": "paired",
        "cases": [{"name": "owned"}],
        "results": [record, original],
        "setup": {
            "rc": 0,
            "stdout": json.dumps(
                {
                    "before": protected,
                    "server": process,
                }
            ),
        },
        "recovery": {"rc": 0, "stdout": json.dumps(recovery)},
        "workspace_absent": True,
        "staging_before": {"rc": 0, "stdout": '{"ansible-tmp-*": []}'},
        "staging_after": {"rc": 0, "stdout": '{"ansible-tmp-*": []}'},
    }


def test_complete_capture_preserves_raw_dynamic_clocks_and_wrappers() -> None:
    capture = _capture()
    original = copy.deepcopy(capture)
    assert verify_capture(capture) == 1
    assert capture == original


@pytest.mark.parametrize(
    "field,value",
    [
        ("status_code", 200),
        ("changed", True),
        ("changed", 0),
        ("extra", None),
        ("elapsed", True),
        ("elapsed", 1.1),
        ("elapsed", float("nan")),
    ],
)
def test_public_presence_types_values_and_independent_duration_bound_are_required(
    field: str,
    value: Any,
) -> None:
    capture = _capture()
    capture["results"][0]["result"][field] = value
    with pytest.raises(AssertionError):
        verify_capture(capture)


def test_elapsed_field_presence_is_not_discarded() -> None:
    capture = _capture()
    del capture["results"][0]["result"]["elapsed"]
    with pytest.raises(AssertionError):
        verify_capture(capture)


@pytest.mark.parametrize(
    "field,value",
    [
        ("body_base64", "AA=="),
        ("body_complete", False),
        ("body_complete", 1),
        ("peer_closed", True),
        ("peer_closed", 0),
        ("header_pairs", [["Host", "changed"]]),
        ("headers", {"Host": "changed"}),
        ("method", "POST"),
        ("path", "/elsewhere"),
    ],
)
def test_literal_received_wire_fields_are_not_normalized(
    field: str, value: Any
) -> None:
    capture = _capture()
    record = capture["results"][0]
    after = json.loads(record["after"]["stdout"])
    after["requests"][0][field] = value
    record["after"]["stdout"] = json.dumps(after)
    with pytest.raises(AssertionError):
        verify_capture(capture)


@pytest.mark.parametrize(
    "boundary", ["process", "protected", "staging", "absent", "rc"]
)
def test_failed_final_ownership_and_recovery_never_validate(boundary: str) -> None:
    capture = _capture()
    if boundary in ("process", "protected"):
        recovered = json.loads(capture["recovery"]["stdout"])
        if boundary == "process":
            recovered["before"]["process"]["creation"] += 1
        else:
            recovered["sentinel"]["hex"] = "00"
        capture["recovery"]["stdout"] = json.dumps(recovered)
    elif boundary == "staging":
        capture["staging_after"]["stdout"] = '{"ansible-tmp-*": ["leak"]}'
    elif boundary == "absent":
        capture["workspace_absent"] = False
    else:
        capture["recovery"]["rc"] = 2
    with pytest.raises(AssertionError):
        verify_capture(capture)
