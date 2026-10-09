"""Exercise DSC async metadata qualification and maintained fixture selection."""

# SPDX-License-Identifier: GPL-3.0-or-later

import ast
import base64
import copy
import json
import ntpath
from typing import Any

import pytest
import yaml  # type: ignore[import-untyped]

from scripts.verify_dsc3_capture import verify_capture
from tests.unit.payload_support import ROOT
from tests.unit.test_dsc3_capture import _capture


def _async_capture() -> dict[str, Any]:
    capture = _capture()
    capture["workspace"] = r"C:\Owned"
    for index, record in enumerate(capture["records"]):
        job_id = f"j{index}.123"
        launch = {
            "ansible_job_id": job_id,
            "ansible_async_watchdog_pid": index + 1,
            "results_file": ntpath.join(r"C:\Owned\cache", job_id),
            "started": True,
            "finished": False,
            "changed": False,
        }
        record.update(launch=launch)
        record["result"].update(launch, finished=True, attempts=index + 1)
    jobs = []
    for record in capture["records"]:
        cached = dict(record["result"])
        jobs.append(
            {
                "name": record["launch"]["ansible_job_id"],
                "process": None,
                "cache": {
                    "json": cached,
                    "body_base64": base64.b64encode(
                        json.dumps(cached).encode()
                    ).decode(),
                },
            }
        )
    capture["async_recovery"] = {
        "rc": 0,
        "stdout": json.dumps(
            {
                "restored": True,
                "cache_after": [],
                "staging": [],
                "engine_processes": [],
                "jobs": jobs,
            }
        ),
    }
    return capture


def test_only_independently_validated_async_identifiers_and_counters_are_qualified() -> (
    None
):
    capture = _async_capture()
    raw = copy.deepcopy(capture)
    report = verify_capture(capture, paired=True)
    assert report["verified"]
    assert report["cases"][0]["qualified_async_paths"] == [
        "async.ansible_job_id",
        "async.results_file",
        "async.ansible_async_watchdog_pid",
        "async.attempts",
    ]
    assert all(
        not path.startswith("async.")
        for path in report["cases"][0]["qualified_clock_paths"]
    )
    assert capture == raw


@pytest.mark.parametrize(
    "field,value",
    [
        ("ansible_job_id", "unrelated"),
        ("ansible_async_watchdog_pid", True),
        ("results_file", r"C:\Unowned\j0.123"),
        ("finished", False),
        ("started", 1),
        ("attempts", 31),
        ("attempts", True),
        ("unknown", "must not disappear"),
    ],
)
def test_async_qualification_rejects_wrong_public_metadata(
    field: str, value: object
) -> None:
    capture = _async_capture()
    capture["records"][0]["result"][field] = value
    with pytest.raises(AssertionError):
        verify_capture(capture, paired=True)


@pytest.mark.parametrize(
    "change", ["empty", "alive", "engine", "cache", "staging", "bytes"]
)
def test_async_worker_and_cache_recovery_is_not_inferred_from_finished_status(
    change: str,
) -> None:
    capture = _async_capture()
    closure = json.loads(capture["async_recovery"]["stdout"])
    if change == "empty":
        closure["jobs"] = []
    elif change == "alive":
        closure["jobs"][0]["process"] = {"alive": True}
    elif change == "engine":
        closure["engine_processes"] = [{"ProcessId": 1}]
    elif change == "bytes":
        closure["jobs"][0]["cache"]["body_base64"] = base64.b64encode(b"{}").decode()
    else:
        closure["cache_after" if change == "cache" else "staging"] = ["leftover"]
    capture["async_recovery"]["stdout"] = json.dumps(closure)
    with pytest.raises(AssertionError):
        verify_capture(capture, paired=True)


def test_effective_async_fixture_cases_and_target_syntax() -> None:
    play = yaml.safe_load((ROOT / "tests/integration/dsc3_async.yml").read_text())[0]
    assert play["vars_files"] == ["vars/dsc3_fixture.yml", "vars/dsc3_async.yml"]
    variables = yaml.safe_load(
        (ROOT / "tests/integration/vars/dsc3_async.yml").read_text()
    )
    cases = variables["dsc3_async_cases"]
    assert len(cases) == 4
    assert sum(not case.get("local_rejection", False) for case in cases) == 3
    assert cases[1]["params"]["remote_config_file"] is True
    assert cases[2]["error"] == "Resource error (ExitCode=2)"
    assert cases[3]["local_rejection"] is True
    assert cases[3]["params"]["remote_config_file"] is False
    block = next(task["block"] for task in play["tasks"] if "block" in task)
    selected = next(task for task in block if "ansible.builtin.include_tasks" in task)
    assert (
        selected["loop"]
        == '{{ dsc3_async_cases | product(["native", "original"]) | list }}'
    )
    assert "fixtures/native_async.py" in variables["dsc3_async_program"]
    ast.parse(
        (ROOT / "tests/integration/fixtures/dsc3_async.py").read_text(),
        feature_version=(3, 4),
    )


def test_cache_boolean_cannot_masquerade_as_its_allocated_integer_pid() -> None:
    capture = _async_capture()
    closure = json.loads(capture["async_recovery"]["stdout"])
    cache = closure["jobs"][0]["cache"]
    cache["json"]["ansible_async_watchdog_pid"] = True
    cache["body_base64"] = base64.b64encode(json.dumps(cache["json"]).encode()).decode()
    capture["async_recovery"]["stdout"] = json.dumps(closure)
    with pytest.raises(AssertionError):
        verify_capture(capture, paired=True)
