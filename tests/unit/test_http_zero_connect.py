"""Reject missing endpoint and typed public failure evidence in the six-case gate."""

# SPDX-License-Identifier: GPL-3.0-or-later

import copy
import json
import subprocess
import sys
from pathlib import Path
from typing import Any

import pytest
import yaml  # type: ignore[import-untyped]

from scripts.verify_http_zero_capture import verify_capture
from scripts.verify_http_zero_connect_capture import verify_connect_capture
from tests.unit.test_http_zero_capture import _capture


def connect_capture() -> dict[str, Any]:
    """Reuse the maintained complete capture contract with six failure endpoints.

    :returns: Independent synthetic native/source observations and recovery.
    """
    document = _capture()
    setup = json.loads(document["setup"]["stdout"])
    setup["server"]["refused_port"] = 43123
    document["setup"]["stdout"] = json.dumps(setup)
    recovery = json.loads(document["recovery"]["stdout"])
    recovery["refused_port_closed"] = True
    document["recovery"]["stdout"] = json.dumps(recovery)
    root = Path(__file__).resolve().parents[2]
    document["cases"] = yaml.safe_load(
        (root / "tests/integration/vars/http_zero_connect.yml").read_text()
    )["http_zero_cases"]
    templates = document["results"]
    document["results"] = []
    for case in document["cases"]:
        for template in templates:
            record = copy.deepcopy(template)
            record.update(
                name=case["name"], module=case["module"], check=case.get("check", False)
            )
            record["params"] = {
                "url_timeout": 0,
                "use_proxy": False,
                "path" if case["module"] == "package" else "url": (
                    "http://legacy-windows-http-zero.invalid/fixture"
                    if case["connection_failure"] == "dns"
                    else "http://127.0.0.1:43123/fixture"
                ),
            }
            after = json.loads(record["after"]["stdout"])
            after["requests"] = []
            record["after"]["stdout"] = json.dumps(after)
            for field, clock in (
                ("connection_before", 9.0),
                ("connection_after", 12.0),
            ):
                record[field] = {
                    "rc": 0,
                    "stdout": json.dumps(
                        {
                            "dns_host": "legacy-windows-http-zero.invalid",
                            "dns_error": 11001,
                            "refused_host": "127.0.0.1",
                            "refused_port": 43123,
                            "refused_error": 10061,
                            "process": setup["before"]["process"],
                            "time": clock,
                        }
                    ),
                }
            document["results"].append(record)
    return document


def test_complete_six_case_failures_preserve_capture_values() -> None:
    capture = connect_capture()
    original = copy.deepcopy(capture)
    assert verify_connect_capture(capture) == 6
    assert capture == original


@pytest.mark.parametrize(
    "field,value",
    [
        ("dns_error", 11002),
        ("dns_error", 11001.0),
        ("dns_host", "example.com"),
        ("refused_error", 0),
        ("refused_port", 43124),
        ("refused_host", "0.0.0.0"),
        ("process", {"pid": 123, "creation": 457}),
        ("time", float("nan")),
    ],
)
def test_independent_probe_failure_and_owned_identity_are_required(
    field: str, value: Any
) -> None:
    capture = connect_capture()
    probe = capture["results"][0]["connection_before"]
    observation = json.loads(probe["stdout"])
    observation[field] = value
    probe["stdout"] = json.dumps(observation)
    with pytest.raises(AssertionError):
        verify_connect_capture(capture)


def test_same_wrong_public_endpoint_on_both_sides_is_rejected() -> None:
    capture = connect_capture()
    for record in capture["results"][:2]:
        record["params"]["url"] = "http://example.com/fixture"
    with pytest.raises(AssertionError):
        verify_connect_capture(capture)


def test_endpoint_availability_is_not_inferred_from_a_refused_connection() -> None:
    capture = connect_capture()
    recovery = json.loads(capture["recovery"]["stdout"])
    recovery["refused_port_closed"] = False
    capture["recovery"]["stdout"] = json.dumps(recovery)
    with pytest.raises(AssertionError):
        verify_connect_capture(capture)


# This workflow keeps an independent fixture and expected-result oracle.
# pylint: disable=duplicate-code
@pytest.mark.parametrize("indices", [[0], [0, 3], list(range(6))])
def test_selected_replay_runs_six_case_gate_only_for_complete_matrix(
    tmp_path: Path, indices: list[int]
) -> None:
    capture = connect_capture()
    capture["cases"] = [capture["cases"][index] for index in indices]
    capture["results"] = [
        record
        for index in indices
        for record in capture["results"][index * 2 : index * 2 + 2]
    ]
    assert verify_capture(capture) == len(indices)
    retained = tmp_path / "selected-capture.json"
    retained.write_text(json.dumps(capture), encoding="utf-8")
    root = Path(__file__).resolve().parents[2]
    maintained = yaml.safe_load(
        (root / "tests/integration/http_zero_timeout.yml").read_text()
    )
    task = maintained[0]["tasks"][-1]
    # Map only the verifier's checkout location into this temporary playbook;
    # execute the maintained task and its selection condition unchanged.
    task["ansible.builtin.command"]["chdir"] = str(root)
    task["register"] = "selected_verification"
    playbook = tmp_path / "selected-replay.yml"
    playbook.write_text(
        yaml.safe_dump(
            [
                {
                    "hosts": "localhost",
                    "connection": "local",
                    "gather_facts": False,
                    "vars": {
                        "http_zero_mode": "paired",
                        "http_zero_selected_cases": capture["cases"],
                        "http_zero_capture": {"path": str(retained)},
                        "expected_skip": len(indices) != 6,
                    },
                    "tasks": [
                        task,
                        {
                            "ansible.builtin.assert": {
                                "that": [
                                    "selected_verification.skipped | "
                                    "default(false) == expected_skip",
                                    "expected_skip or selected_verification.rc == 0",
                                ]
                            }
                        },
                    ],
                }
            ]
        ),
        encoding="utf-8",
    )
    run = subprocess.run(
        [
            sys.executable,
            "-m",
            "ansible.cli.playbook",
            "-i",
            "localhost,",
            str(playbook),
        ],
        capture_output=True,
        text=True,
        check=False,
        timeout=30,
    )
    assert run.returncode == 0, run.stdout + run.stderr


# pylint: enable=duplicate-code
