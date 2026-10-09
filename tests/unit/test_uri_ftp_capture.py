"""Keep the FTP URI capture gate literal and its fixture scope bounded."""

# SPDX-License-Identifier: GPL-3.0-or-later

import copy
import importlib.util
import json
from typing import Any

import pytest
import yaml  # type: ignore[import-untyped]

from tests.unit.payload_support import ROOT

# This workflow keeps an independent fixture and expected-result oracle.
# pylint: disable=duplicate-code
SPEC = importlib.util.spec_from_file_location(
    "verify_uri_ftp", ROOT / "tests/integration/verify_uri_ftp.py"
)
assert SPEC is not None and SPEC.loader is not None
VERIFIER = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(VERIFIER)
# pylint: enable=duplicate-code


# This workflow keeps an independent fixture and expected-result oracle.
# pylint: disable=duplicate-code
def _capture() -> dict[str, Any]:
    rows = []
    for name in VERIFIER.CASES:
        changed = name in ("destination_download", "check_destination")
        failed = name == "unaccepted_final_status"
        method = {"file_timestamp": "MDTM", "working_directory": "PWD"}.get(
            name, "RETR"
        )
        filename = "preliminary-125.bin" if name == "preliminary_125" else "payload.bin"
        result = {
            "changed": changed,
            "failed": failed,
            "elapsed": 0 if failed else 0.1,
            "banner_message": "220 Banner\r\n",
            "welcome_message": "230 Welcome\r\n",
            "status_description": "150 Reply\r\n",
            "content_type": None,
            "content_length": -1,
            "headers": [],
        }
        observed = {
            "result": result,
            "before": {
                "sentinel": {"hex": "00", "mtime": 100, "attributes": 32},
                "source": {"hex": "ff", "mtime": 100, "attributes": 32},
                "output": None,
            },
            "after": {
                "sentinel": {"hex": "00", "mtime": 100, "attributes": 32},
                "source": {"hex": "ff", "mtime": 100, "attributes": 32},
                "output": None,
                "portable_output": None,
                "requests": [],
                "modified_in_request": True,
            },
            "wire": {
                "protected": {"server.py": {"hex": "11", "mtime_ns": 10}},
                "wire": [
                    {"kind": "reply", "response": value}
                    for value in ("220 Banner\r\n", "230 Welcome\r\n", "150 Reply\r\n")
                ],
            },
        }
        observations = {}
        for implementation in ("native", "original"):
            observation = copy.deepcopy(observed)
            argument = (
                ""
                if method == "PWD"
                else (filename if implementation == "original" else "/" + filename)
            )
            observation["wire"]["wire"].append(
                {"kind": "command", "command": method, "argument": argument}
            )
            observations[implementation] = observation
        rows.append(
            {
                "name": name,
                "case": {
                    "changed": changed,
                    "failed": failed,
                    "check": name == "check_destination",
                },
                "params": {"url_method": method},
                "observations": observations,
            }
        )
    return {
        "identity": {"stdout": json.dumps({"mac": "BC-24-11-3E-87-91"})},
        "results": rows,
        "recovery": {"stdout": json.dumps({"restored": True, "server_stopped": True})},
        "controller_recovery": {
            "stdout": json.dumps({"restored": True, "server_stopped": True})
        },
        "unforward": {"stdout": json.dumps({"forwards_cancelled": True})},
        "guest_closed": {"stdout": json.dumps({"guest_forward_ports_closed": True})},
        "controller_absence": {"stat": {"exists": False}},
        "staging_before": {"stdout": json.dumps({"staging": ["unrelated"]})},
        "staging_after": {
            "stdout": json.dumps({"workspace_absent": True, "staging": ["unrelated"]})
        },
    }


# pylint: enable=duplicate-code


def test_complete_capture_keeps_explicit_wire_and_time_qualifications() -> None:
    result = VERIFIER.verify(_capture())
    assert result["pairs"] == 9 and result["whole_typed_public"] is True
    assert len(result["qualifications"]) == 3 and result["recovery"] is True


@pytest.mark.parametrize(
    "key,value",
    [
        ("content_length", True),
        ("content_type", ""),
        ("headers", ["Content-Type"]),
    ],
)
def test_public_field_type_presence_and_value_cannot_be_normalized(
    key: str, value: Any
) -> None:
    capture = _capture()
    capture["results"][0]["observations"]["native"]["result"][key] = value
    with pytest.raises(AssertionError):
        VERIFIER.verify(capture)


@pytest.mark.parametrize("key", ["mtime", "attributes", "hex"])
def test_protected_file_fields_remain_literal(key: str) -> None:
    capture = _capture()
    capture["results"][0]["observations"]["native"]["after"]["sentinel"][
        key
    ] = "changed"
    with pytest.raises(AssertionError):
        VERIFIER.verify(capture)


def test_failure_elapsed_is_exact_integer_zero() -> None:
    capture = _capture()
    capture["results"][2]["observations"]["native"]["result"]["elapsed"] = 0.0
    with pytest.raises(AssertionError):
        VERIFIER.verify(capture)


def test_changed_ftp_resource_or_unsupported_write_command_fails() -> None:
    capture = _capture()
    events = capture["results"][0]["observations"]["native"]["wire"]["wire"]
    events[-1]["argument"] = "/another.bin"
    with pytest.raises(AssertionError):
        VERIFIER.verify(capture)
    events[-1].update(command="DELE", argument="/payload.bin")
    with pytest.raises(AssertionError):
        VERIFIER.verify(capture)


@pytest.mark.parametrize("key", ["server_stopped", "restored"])
def test_failed_owned_server_or_material_recovery_is_not_accepted(key: str) -> None:
    capture = _capture()
    capture["controller_recovery"]["stdout"] = json.dumps(
        {
            "server_stopped": True,
            "restored": True,
            key: False,
        }
    )
    with pytest.raises(AssertionError):
        VERIFIER.verify(capture)


def test_staging_or_workspace_leaks_are_not_accepted() -> None:
    capture = _capture()
    capture["staging_after"]["stdout"] = json.dumps(
        {
            "workspace_absent": False,
            "staging": ["unrelated"],
        }
    )
    with pytest.raises(AssertionError):
        VERIFIER.verify(capture)
    capture["staging_after"]["stdout"] = json.dumps(
        {
            "workspace_absent": True,
            "staging": ["unrelated", "owned-leak"],
        }
    )
    with pytest.raises(AssertionError):
        VERIFIER.verify(capture)


def test_play_reuses_existing_servers_and_has_identity_before_allocation() -> None:
    document = yaml.safe_load(
        (ROOT / "tests/integration/uri_ftp.yml").read_text(encoding="utf-8")
    )[0]
    assert document["hosts"] == "legacy_windows"
    assert "vars/get_url_ftp_fixture.yml" in document["vars_files"]
    assert "vars/get_url_fixture.yml" in document["vars_files"]
    assert "get_url_ftp_mode" not in document["vars"]
    tasks = document["tasks"]
    assert "BC-24-11-3E-87-91" in str(tasks[2])
    assert "uri_ftp_identity" in str(tasks[1])
    assert tasks[-2]["ansible.builtin.meta"] == "reset_connection"
    cases = yaml.safe_load(
        (ROOT / "tests/integration/vars/uri_ftp.yml").read_text(encoding="utf-8")
    )["uri_ftp_cases"]
    assert tuple(case["name"] for case in cases) == VERIFIER.CASES
    assert any(case.get("check") is True for case in cases)
    assert any(case.get("fixture_payload") is True for case in cases)
    assert any(case.get("failed") is True for case in cases)
