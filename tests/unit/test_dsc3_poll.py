"""Exercise public automatic DSC polling and independent evidence rejection."""

# SPDX-License-Identifier: GPL-3.0-or-later

import ast
import base64
import copy
import json
import ntpath
import subprocess
import sys
from pathlib import Path
from typing import Any

import pytest
import yaml  # type: ignore[import-untyped]
from jinja2 import Environment

from scripts.verify_dsc3_poll_capture import CASES, verify_capture
from tests.unit.payload_support import ROOT
from tests.unit.test_dsc3_capture import _capture


def _cached(value: dict[str, Any]) -> dict[str, Any]:
    return {
        "json": value,
        "body_base64": base64.b64encode(json.dumps(value).encode()).decode(),
    }


def _sample_job(row: dict[str, Any], index: int, phase: str) -> dict[str, Any]:
    number = index * 2 + (phase == "original") + 1
    identifier = f"j{number}.123"
    launch = {
        "ansible_job_id": identifier,
        "ansible_async_watchdog_pid": number,
        "results_file": ntpath.join(r"C:\Owned", "cache", identifier),
        "started": True,
        "finished": False,
    }
    if index == 2:
        row["result"] = {
            "changed": False,
            "rc": 2,
            "stderr": "failure",
            "stderr_lines": ["failure"],
            "failed": True,
            "msg": "Resource error (ExitCode=2)",
        }
    row["result"].update(launch, finished=True)
    worker = {
        "pid": number,
        "created": int((row["before"]["utc"] + 0.05 + 11644473600) * 10000000),
        "alive": True,
    }
    return {
        "startup": _cached(launch),
        "completed": _cached(row["result"]),
        "worker": {"identity": worker, "sid": "S-1-5-21-1000"},
        "started_at": row["before"]["utc"] + 0.1,
        "completed_at": row["after"]["utc"] - 0.1,
    }


def _poll_capture() -> dict[str, Any]:
    base = _capture()
    root, sid = r"C:\Owned", "S-1-5-21-1000"
    protected = {
        "registry": [["key", "value", index, 4] for index in range(4)],
        "python_executable": "a" * 64,
        "network": [{"MACAddress": "BC:24:11:3E:87:91"}],
        "services": [{"Name": "Owned", "State": "Running", "StartMode": "Auto"}],
    }
    records, jobs = [], {}
    for index, case in enumerate(CASES):
        for phase in ("native", "original"):
            row = copy.deepcopy(base["records"][0 if phase == "native" else 1])
            row.update(
                case=case, phase=phase, check_mode=False, local_rejection=index == 3
            )
            row["request"] = {"config": {}}
            if index == 3:
                row["result"] = {
                    "changed": False,
                    "failed": True,
                    "msg": "async operations are not supported with local config_file",
                }
            else:
                job = _sample_job(row, index, phase)
                jobs[row["result"]["ansible_job_id"]] = job
            row["observation"] = {
                "staging": [],
                "jobs": [],
                "observed_jobs": copy.deepcopy(jobs),
                "original_protected": copy.deepcopy(protected),
                "protected": copy.deepcopy(protected),
            }
            records.append(row)
    monitor = {"pid": 50, "created": 100, "alive": True}
    closure = {
        "jobs": jobs,
        "workers_closed": [
            {"expected": job["worker"]["identity"], "actual": None}
            for job in jobs.values()
        ],
        "monitor_identity": monitor,
        "monitor_final": None,
        "before_cleanup": {
            "original_protected": copy.deepcopy(protected),
            "protected": copy.deepcopy(protected),
        },
        "recovery": {
            "restored": True,
            "cache_after": [],
            "staging": [],
            "engine_processes": [],
            "original_protected": copy.deepcopy(protected),
            "protected": copy.deepcopy(protected),
        },
    }
    base.update(
        workspace=root,
        records=records,
        identity={"account": {"sid": sid}},
        poll_setup={
            "stdout": json.dumps(
                {"monitor": monitor, "protected": {"protected": protected}}
            )
        },
        poll_recovery={"rc": 0, "stdout": json.dumps(closure)},
        guard={
            "stdout": json.dumps(
                {"python": [3, 4, 4], "mac": "BC-24-11-3E-87-91", "staging": []}
            )
        },
    )
    return base


def test_complete_automatic_poll_pairs_keep_raw_values_unchanged() -> None:
    capture = _poll_capture()
    before = copy.deepcopy(capture)
    assert verify_capture(capture)["public_pairs"] == 4
    assert capture == before


@pytest.mark.parametrize(
    "field,value",
    [
        ("finished", False),
        ("started", 1),
        ("ansible_async_watchdog_pid", True),
        ("results_file", r"C:\Unowned\job"),
        ("rc", 7),
        ("unknown", "retained"),
    ],
)
def test_whole_public_field_and_type_differences_fail(field: str, value: Any) -> None:
    capture = _poll_capture()
    capture["records"][0]["result"][field] = value
    with pytest.raises(AssertionError):
        verify_capture(capture)


@pytest.mark.parametrize(
    "fault",
    [
        "missing",
        "startup",
        "bytes",
        "sid",
        "birth",
        "clock",
        "alive",
        "cache",
        "engine",
        "monitor",
    ],
)
def test_cache_birth_identity_and_recovery_are_not_inferred(fault: str) -> None:
    capture = _poll_capture()
    closure = json.loads(capture["poll_recovery"]["stdout"])
    job = closure["jobs"]["j1.123"]
    if fault == "missing":
        del closure["jobs"]["j1.123"]
    elif fault == "startup":
        job["startup"] = _cached(dict(job["startup"]["json"], finished=True))
    elif fault == "bytes":
        job["completed"]["body_base64"] = base64.b64encode(b"{}").decode()
    elif fault == "sid":
        job["worker"]["sid"] = "S-1-5-18"
    elif fault == "birth":
        job["worker"]["identity"]["created"] = 1
    elif fault == "clock":
        job["completed_at"] = float("inf")
    elif fault == "alive":
        closure["workers_closed"][0]["actual"] = closure["workers_closed"][0][
            "expected"
        ]
    elif fault == "monitor":
        closure["monitor_final"] = closure["monitor_identity"]
    else:
        closure["recovery"][
            "cache_after" if fault == "cache" else "engine_processes"
        ] = ["unclosed"]
    capture["poll_recovery"]["stdout"] = json.dumps(closure)
    with pytest.raises((AssertionError, KeyError)):
        verify_capture(capture)


@pytest.mark.parametrize("value", [True, float("inf"), float("nan"), "clock"])
def test_same_both_sides_unbounded_operation_clocks_fail(value: Any) -> None:
    capture = _poll_capture()
    for row in capture["records"][:2]:
        row["after"]["utc"] = value
    with pytest.raises(AssertionError):
        verify_capture(capture)


def test_source_local_file_rejection_cannot_gain_a_job_or_rc() -> None:
    capture = _poll_capture()
    for row in capture["records"][-2:]:
        row["result"]["ansible_job_id"] = "j99.123"
    with pytest.raises(AssertionError):
        verify_capture(capture)


@pytest.mark.parametrize(
    "field", ["registry", "python_executable", "network", "services"]
)
def test_same_both_sides_protected_changes_fail(field: str) -> None:
    capture = _poll_capture()
    for row in capture["records"][:2]:
        row["observation"]["protected"][field] = []
    with pytest.raises(AssertionError):
        verify_capture(capture)


def test_recovery_flags_cannot_hide_changed_persistent_state() -> None:
    capture = _poll_capture()
    closure = json.loads(capture["poll_recovery"]["stdout"])
    closure["recovery"]["protected"]["services"][0]["StartMode"] = "Disabled"
    capture["poll_recovery"]["stdout"] = json.dumps(closure)
    with pytest.raises(AssertionError):
        verify_capture(capture)


def test_runtime_service_transitions_are_retained_without_claiming_stasis() -> None:
    capture = _poll_capture()
    capture["records"][0]["observation"]["protected"]["services"][0][
        "State"
    ] = "Stopped"
    assert verify_capture(capture)["public_pairs"] == 4


def test_genuine_engine_failure_must_also_close_automatic_poll_cache() -> None:
    capture = _poll_capture()
    capture["records"][4]["observation"]["jobs"] = [{"name": "j5.123"}]
    with pytest.raises(AssertionError):
        verify_capture(capture)


def test_fixed_poll_fixture_uses_existing_observers_and_both_shell_routes() -> None:
    play = yaml.safe_load((ROOT / "tests/integration/dsc3_poll.yml").read_text())[0]
    variables = yaml.safe_load(
        (ROOT / "tests/integration/vars/dsc3_poll.yml").read_text()
    )
    cases = variables["dsc3_poll_cases"]
    assert [case["name"] for case in cases] == list(CASES)
    assert cases[1]["params"]["remote_config_file"] is True
    assert cases[3]["local_rejection"] is True
    assert "win_updates_runas.py" in variables["dsc3_poll_sources"]
    assert "dsc3_async.py" in variables["dsc3_poll_sources"]
    assert play["vars_files"] == ["vars/dsc3_fixture.yml", "vars/dsc3_poll.yml"]
    tasks = yaml.safe_load(
        (ROOT / "tests/integration/tasks/dsc3_poll_case.yml").read_text()
    )
    requests = [task for task in tasks if "async" in task]
    assert len(requests) == 2 and all(task["poll"] == 1 for task in requests)
    assert requests[1]["vars"]["ansible_shell_type"] == "cmd"
    assert not any("async_status" in key for task in tasks for key in task)
    ast.parse(
        (ROOT / "tests/integration/fixtures/dsc3_poll.py").read_text(),
        feature_version=(3, 4),
    )


def test_standalone_capture_command_works_outside_the_checkout(tmp_path: Path) -> None:
    capture = tmp_path / "capture.json"
    capture.write_text(json.dumps(_poll_capture()), encoding="utf-8")
    result = subprocess.run(
        [
            sys.executable,
            str(ROOT / "scripts/verify_dsc3_poll_capture.py"),
            str(capture),
        ],
        cwd=tmp_path,
        capture_output=True,
        text=True,
        check=True,
    )
    assert json.loads(result.stdout)["public_pairs"] == 4


def test_all_new_fixture_templates_parse_before_target_allocation() -> None:
    def inspect(value: Any) -> None:
        if isinstance(value, str):
            Environment().parse(value)
        elif isinstance(value, dict):
            for item in value.values():
                inspect(item)
        elif isinstance(value, list):
            for item in value:
                inspect(item)

    for relative in ("dsc3_poll.yml", "vars/dsc3_poll.yml", "tasks/dsc3_poll_case.yml"):
        inspect(yaml.safe_load((ROOT / "tests/integration" / relative).read_text()))
