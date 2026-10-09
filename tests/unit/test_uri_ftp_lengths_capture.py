"""Keep length-bearing public results tied to wire replies, clocks and cleanup."""

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
    "verify_uri_ftp_lengths", ROOT / "tests/integration/verify_uri_ftp_lengths.py"
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
        status = 125 if "125" in name else 150
        consumed = name.endswith("consumed")
        description = f"{status} Transfer starting. (26 bytes).\r\n"
        result: dict[str, Any] = {
            "changed": False,
            "failed": False,
            "elapsed": 0.1,
            "content_length": 26,
            "status_code": status,
            "content_type": None,
            "headers": [],
            "status_description": description,
        }
        if consumed:
            result["content"] = VERIFIER.PAYLOAD.decode("utf-8", "replace")
        observations = {}
        for side in ("native", "original"):
            filename = f"length-{status}.bin"
            wire = [
                {
                    "kind": "command",
                    "command": "RETR",
                    "argument": filename if side == "original" else "/" + filename,
                },
                {"kind": "passive", "port": 2122},
                {"kind": "reply", "response": description},
            ]
            if consumed:
                wire.append({"kind": "reply", "response": "226 Transfer complete\r\n"})
            protected = {
                "sentinel": {"data": "00", "mtime_ns": 100},
                "source": {"data": "ff", "mtime_ns": 200},
                "output": None,
                "time": 100.0,
            }
            observations[side] = {
                "result": copy.deepcopy(result),
                "before": protected,
                "after": dict(protected, time=103.0, requests=[]),
                "wire": {"wire": wire, "protected": {"server.py": {"mtime_ns": 300}}},
            }
        rows.append(
            {
                "name": name,
                "validated": True,
                "params": {"status_code": [226 if consumed else status]},
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


# pylint: enable=duplicate-code


# This workflow keeps an independent fixture and expected-result oracle.
# pylint: disable=duplicate-code
def test_four_complete_pairs_preserve_raw_capture() -> None:
    document = _capture()
    before = copy.deepcopy(document)
    assert VERIFIER.verify(document)["pairs"] == 4
    assert document == before


# pylint: enable=duplicate-code


@pytest.mark.parametrize("value", [-1, 26.0, True, "26", 27])
def test_matching_lengths_require_exact_advertised_integer(value: Any) -> None:
    document = _capture()
    for observed in document["results"][0]["observations"].values():
        observed["result"]["content_length"] = value
    with pytest.raises(AssertionError):
        VERIFIER.verify(document)


@pytest.mark.parametrize("value", [10.0, False, float("nan"), float("inf"), -0.1])
def test_matching_elapsed_stays_inside_independent_clock_window(value: Any) -> None:
    document = _capture()
    for observed in document["results"][0]["observations"].values():
        observed["result"]["elapsed"] = value
    with pytest.raises(AssertionError):
        VERIFIER.verify(document)


@pytest.mark.parametrize("field", ["before", "after"])
@pytest.mark.parametrize("value", [False, "100.0", None, float("inf"), float("nan")])
def test_sampled_clock_requires_finite_number(field: str, value: Any) -> None:
    document = _capture()
    document["results"][0]["observations"]["native"][field]["time"] = value
    with pytest.raises(AssertionError):
        VERIFIER.verify(document)


@pytest.mark.parametrize("before,after", [(104.0, 103.0), (-1e308, 1e308)])
def test_observed_clock_duration_requires_ordered_finite_bound(
    before: float, after: float
) -> None:
    document = _capture()
    observed = document["results"][0]["observations"]["native"]
    observed["before"]["time"], observed["after"]["time"] = before, after
    with pytest.raises(AssertionError):
        VERIFIER.verify(document)


def test_elapsed_at_exact_independent_bound_passes_without_tolerance() -> None:
    document = _capture()
    for row in document["results"]:
        for observed in row["observations"].values():
            observed["result"]["elapsed"] = 3.0
    assert VERIFIER.verify(document)["pairs"] == 4


@pytest.mark.parametrize(
    "mutation", ["unvalidated", "protected", "wire", "body", "status", "closure"]
)
def test_matching_public_pairs_do_not_hide_independent_evidence_failure(
    mutation: str,
) -> None:
    document = _capture()
    row = document["results"][1]
    if mutation == "unvalidated":
        row["validated"] = False
    elif mutation == "closure":
        document["controller_absence"]["stat"]["exists"] = True
    else:
        for observed in row["observations"].values():
            if mutation == "protected":
                observed["after"]["source"] = {"data": "ff", "mtime_ns": 201}
            elif mutation == "wire":
                observed["wire"]["wire"][2]["response"] = "150 Transfer starting\r\n"
            elif mutation == "body":
                observed["result"]["content"] = "wrong"
            else:
                observed["result"]["status_code"] = 226
    with pytest.raises(AssertionError):
        VERIFIER.verify(document)


def test_length_wrapper_selects_only_four_new_cases_and_existing_lifecycle() -> None:
    wrapper = yaml.safe_load(
        (ROOT / "tests/integration/uri_ftp_lengths.yml").read_text()
    )
    selection = wrapper[0]["tasks"][0]["ansible.builtin.set_fact"]
    assert selection == {
        "uri_ftp_cases": "{{ uri_ftp_length_cases }}",
        "uri_ftp_capture_verifier": "verify_uri_ftp_lengths.py",
        "get_url_ftp_include_lengths": True,
    }
    assert wrapper[1] == {
        "name": "Compare preliminary length using unchanged FTP ownership and recovery",
        "ansible.builtin.import_playbook": "uri_ftp.yml",
    }
    cases = yaml.safe_load(
        (ROOT / "tests/integration/vars/uri_ftp_lengths.yml").read_text()
    )
    assert (
        tuple(case["name"] for case in cases["uri_ftp_length_cases"]) == VERIFIER.CASES
    )
