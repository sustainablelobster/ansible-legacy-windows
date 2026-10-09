"""Keep rejection comparisons typed, wire-proven and bounded to owned recovery."""

# SPDX-License-Identifier: GPL-3.0-or-later

import copy
import importlib.util
import json
from typing import Any

import pytest
import yaml  # type: ignore[import-untyped]
from jinja2 import Environment

from tests.unit.payload_support import ROOT

SPEC = importlib.util.spec_from_file_location(
    "verify_uri_ftp_rejections", ROOT / "tests/integration/verify_uri_ftp_rejections.py"
)
assert SPEC is not None and SPEC.loader is not None
VERIFIER = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(VERIFIER)


def _capture() -> dict[str, Any]:
    rows = []
    for name in VERIFIER.CASES:
        login = name == "login_rejected"
        status = 530 if login else 550
        failed = not name.endswith("accepted_error")
        method = "SIZE" if name.startswith("size") else "RETR"
        path = "/missing.bin" if name.startswith("missing") else "/payload.bin"
        result: dict[str, Any] = {
            "changed": False,
            "failed": failed,
            "elapsed": 0 if failed else 0.1,
            "banner_message": "220 Banner\r\n",
            "welcome_message": "" if login else "230 Welcome\r\n",
            "status_description": str(status) + " Rejected\r\n",
            "status_code": status,
            "content": "",
            "content_length": 0,
            "content_type": None,
            "headers": [],
        }
        observations = {}
        for side in ("native", "original"):
            wire = [
                {"kind": "reply", "response": value}
                for value in (result["banner_message"], result["status_description"])
            ]
            if not login:
                wire.append({"kind": "reply", "response": result["welcome_message"]})
                wire.append(
                    {
                        "kind": "command",
                        "command": method,
                        "argument": path.lstrip("/") if side == "original" else path,
                    }
                )
            protected = {
                "sentinel": {"data": "00", "attributes": 32, "mtime_ns": 100},
                "source": {"data": "ff", "attributes": 32, "mtime_ns": 200},
                "output": None,
                "time": 100.0,
            }
            observations[side] = {
                "result": copy.deepcopy(result),
                "before": protected,
                "after": dict(protected, requests=[], time=103.0),
                "wire": {
                    "wire": wire,
                    "protected": {"server.py": {"data": "00", "mtime_ns": 300}},
                },
            }
        rows.append(
            {
                "name": name,
                "validated": True,
                "case": {"failed": failed},
                "params": {"url_method": method, "url": "ftp://example.test" + path},
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
            "stdout": json.dumps({"staging": ["unrelated"], "workspace_absent": True})
        },
    }


def test_complete_five_rejection_pairs_do_not_mutate_raw_capture() -> None:
    document = _capture()
    before = copy.deepcopy(document)
    assert VERIFIER.verify(document)["pairs"] == 5
    assert document == before


@pytest.mark.parametrize("elapsed", [3.000000001, 10.0, float("inf"), float("nan")])
def test_matching_public_elapsed_cannot_exceed_observed_clock_window(
    elapsed: float,
) -> None:
    document = _capture()
    for row in document["results"]:
        if row["name"].endswith("accepted_error"):
            for observed in row["observations"].values():
                observed["result"]["elapsed"] = elapsed
    with pytest.raises(AssertionError):
        VERIFIER.verify(document)


def test_elapsed_exactly_at_recorded_bound_needs_no_sampling_tolerance() -> None:
    document = _capture()
    for row in document["results"]:
        if row["name"].endswith("accepted_error"):
            for observed in row["observations"].values():
                observed["result"]["elapsed"] = 3.0
    assert VERIFIER.verify(document)["pairs"] == 5


@pytest.mark.parametrize("field", ["before", "after"])
@pytest.mark.parametrize("value", [False, "100.0", None, float("inf"), float("nan")])
def test_sampled_clocks_must_be_finite_numbers(field: str, value: Any) -> None:
    document = _capture()
    document["results"][1]["observations"]["native"][field]["time"] = value
    with pytest.raises(AssertionError):
        VERIFIER.verify(document)


@pytest.mark.parametrize("before,after", [(104.0, 103.0), (-1e308, 1e308)])
def test_observed_duration_must_be_ordered_and_finite(
    before: float,
    after: float,
) -> None:
    document = _capture()
    observed = document["results"][1]["observations"]["native"]
    observed["before"]["time"], observed["after"]["time"] = before, after
    with pytest.raises(AssertionError):
        VERIFIER.verify(document)


def test_failed_elapsed_stays_integer_zero_with_valid_clocks() -> None:
    document = _capture()
    document["results"][0]["observations"]["native"]["result"]["elapsed"] = 0.0
    with pytest.raises(AssertionError):
        VERIFIER.verify(document)


@pytest.mark.parametrize(
    "key,value",
    [
        ("content_length", False),
        ("content_type", ""),
        ("welcome_message", "\r\n"),
        ("elapsed", False),
        ("status_code", 213),
        ("changed", True),
    ],
)
def test_public_values_and_types_cannot_be_normalized(key: str, value: Any) -> None:
    document = _capture()
    document["results"][0]["observations"]["native"]["result"][key] = value
    with pytest.raises(AssertionError):
        VERIFIER.verify(document)


def test_size_must_not_issue_an_extra_binary_mode_command() -> None:
    document = _capture()
    document["results"][0]["observations"]["native"]["wire"]["wire"].append(
        {"kind": "command", "command": "TYPE", "argument": "I"}
    )
    with pytest.raises(AssertionError):
        VERIFIER.verify(document)


@pytest.mark.parametrize("key", ["data", "attributes", "mtime_ns"])
def test_protected_fields_remain_literal(key: str) -> None:
    document = _capture()
    document["results"][0]["observations"]["native"]["after"] = copy.deepcopy(
        document["results"][0]["observations"]["native"]["after"]
    )
    document["results"][0]["observations"]["native"]["after"]["sentinel"][
        key
    ] = "changed"
    with pytest.raises(AssertionError):
        VERIFIER.verify(document)


def test_false_case_validation_or_failed_closure_is_not_a_pass() -> None:
    document = _capture()
    document["results"][0]["validated"] = False
    with pytest.raises(AssertionError):
        VERIFIER.verify(document)
    document = _capture()
    document["staging_after"]["stdout"] = json.dumps(
        {"staging": ["leak"], "workspace_absent": True}
    )
    with pytest.raises(AssertionError):
        VERIFIER.verify(document)


def test_reused_play_default_verifier_and_new_selection_remain_explicit() -> None:
    play = yaml.safe_load((ROOT / "tests/integration/uri_ftp.yml").read_text())[0]
    verifier = play["tasks"][-1]["ansible.builtin.command"]["argv"][1]
    environment = Environment()
    assert (
        environment.from_string(verifier).render(playbook_dir="/fixture")
        == "/fixture/verify_uri_ftp.py"
    )
    assert (
        environment.from_string(verifier).render(
            playbook_dir="/fixture",
            uri_ftp_capture_verifier="verify_uri_ftp_rejections.py",
        )
        == "/fixture/verify_uri_ftp_rejections.py"
    )
    wrapper = yaml.safe_load(
        (ROOT / "tests/integration/uri_ftp_rejections.yml").read_text()
    )
    assert wrapper[1]["ansible.builtin.import_playbook"] == "uri_ftp.yml"
    prebind = wrapper[0]["tasks"][0]["ansible.builtin.set_fact"]
    assert tuple(prebind["uri_ftp_expected_case_names"]) == VERIFIER.CASES
    assert prebind["uri_ftp_capture_verifier"] == "verify_uri_ftp_rejections.py"


def test_geturl_prebind_does_not_require_unallocated_server_metadata() -> None:
    wrapper = yaml.safe_load(
        (ROOT / "tests/integration/uri_ftp_rejections_get_url.yml").read_text()
    )
    prebind = wrapper[0]["tasks"][0]["ansible.builtin.set_fact"]
    assert prebind["get_url_ftp_mode"] == "paired"
    assert len(prebind["get_url_ftp_cases"]) == 3
    assert "get_url_ftp_setup_data" not in str(prebind)
    assert wrapper[1]["ansible.builtin.import_playbook"] == "win_get_url_ftp.yml"
